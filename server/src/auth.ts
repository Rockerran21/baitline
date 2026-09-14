import { createHash, randomBytes, randomInt } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { Config } from "./config.ts";
import type { Passkey, Session, Store, User } from "./db.ts";

/**
 * Sign-in without passwords. A product about stolen passwords stores none.
 *   - Sessions: random 256-bit secret in an HttpOnly cookie, hashed at rest, idle and absolute expiry.
 *   - Magic links, invites and device codes: one-time tokens, hashed at rest, short lived.
 *   - Passkeys: the second factor, and a complete sign-in on their own when the authenticator verified the user.
 *   - Recovery codes: for the day the phone with the passkey is gone.
 */

export const SESSION_COOKIE = "bl_session";

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

// ---------------------------------------------------------------- sessions

export function startSession(store: Store, cfg: Config, user: User, mfaDone: boolean, now = Date.now()): string {
  const secret = randomToken();
  store.createSession({
    id: sha256(secret),
    user_id: user.id,
    created_at: now,
    last_seen_at: now,
    authenticated_at: now,
    mfa_done: mfaDone ? 1 : 0,
    expires_at: Math.min(now + cfg.sessionIdleMs, now + cfg.sessionMaxMs),
  });
  return secret;
}

export function readSession(store: Store, cfg: Config, secret: string | undefined, now = Date.now()): { session: Session; user: User } | null {
  if (!secret) return null;
  const id = sha256(secret);
  const session = store.session(id);
  if (!session) return null;
  if (session.expires_at <= now) {
    store.deleteSession(id);
    return null;
  }
  const user = store.userById(session.user_id);
  if (!user) {
    store.deleteSession(id);
    return null;
  }
  const expires = Math.min(now + cfg.sessionIdleMs, session.created_at + cfg.sessionMaxMs);
  store.touchSession(id, now, expires);
  return { session: { ...session, last_seen_at: now, expires_at: expires }, user };
}

export function isFresh(session: Session, cfg: Config, now = Date.now()): boolean {
  return now - session.authenticated_at < cfg.freshMs;
}

// ------------------------------------------------------- one-time tokens

export type TokenPurpose = "signin" | "signup" | "invite" | "device" | "reset";

export function issueToken(store: Store, user: User, purpose: TokenPurpose, ttlMs: number, now = Date.now()): string {
  const raw = randomToken();
  store.putToken(sha256(raw), purpose, { userId: user.id }, now + ttlMs);
  return raw;
}

/** A sign-up link names only an address. No account exists until it is redeemed, so nobody can reserve someone else's email. */
export function issueSignupToken(store: Store, email: string, ttlMs: number, now = Date.now()): string {
  const raw = randomToken();
  store.putToken(sha256(raw), "signup", { email }, now + ttlMs);
  return raw;
}

export type Redeemed = { user: User; email?: undefined } | { user?: undefined; email: string };

export function redeemToken(store: Store, purpose: TokenPurpose | TokenPurpose[], raw: string, now = Date.now()): Redeemed | undefined {
  const purposes = Array.isArray(purpose) ? purpose : [purpose];
  for (const p of purposes) {
    const hit = store.useToken(sha256(raw), p, now);
    if (!hit) continue;
    if (hit.userId !== null) {
      const user = store.userById(hit.userId);
      return user ? { user } : undefined;
    }
    if (hit.email) return { email: hit.email };
  }
  return undefined;
}

// ------------------------------------------------------------- passkeys

export function needsMfa(store: Store, userId: number): boolean {
  return store.passkeysFor(userId).length > 0;
}

interface Challenge {
  challenge: string;
  userId: number | null;
  expiresAt: number;
}
const CHALLENGE_MS = 5 * 60 * 1000;
const challenges = new Map<string, Challenge>();

/**
 * These maps are fed by unauthenticated endpoints, so they must not grow without bound.
 * Sweep expired entries when the map gets large; past a hard cap, evict the oldest.
 */
export function remember<T extends { expiresAt: number }>(map: Map<string, T>, key: string, value: T, cap = 5000): void {
  if (map.size >= cap) {
    const now = Date.now();
    for (const [k, v] of map) if (v.expiresAt < now) map.delete(k);
    while (map.size >= cap) map.delete(map.keys().next().value as string);
  }
  map.set(key, value);
}

function takeChallenge(flow: string): Challenge {
  const c = challenges.get(flow);
  challenges.delete(flow);
  if (!c || c.expiresAt < Date.now()) throw new Error("challenge expired");
  return c;
}

function toBytes(id: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(id));
  return out;
}

function fromBase64(s: string): Uint8Array<ArrayBuffer> {
  const b = Buffer.from(s, "base64");
  const out = new Uint8Array(b.byteLength);
  out.set(b);
  return out;
}

export async function registrationOptions(store: Store, cfg: Config, user: User): Promise<{ flow: string; options: PublicKeyCredentialCreationOptionsJSON }> {
  const options = await generateRegistrationOptions({
    rpName: cfg.rpName,
    rpID: cfg.rpId,
    userName: user.email,
    userID: toBytes(user.id),
    attestationType: "none",
    excludeCredentials: store.passkeysFor(user.id).map((p) => ({ id: p.credential_id, transports: p.transports ? p.transports.split(",") : undefined })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });
  const flow = randomToken(16);
  remember(challenges, flow, { challenge: options.challenge, userId: user.id, expiresAt: Date.now() + CHALLENGE_MS });
  return { flow, options };
}

export async function verifyRegistration(store: Store, cfg: Config, user: User, flow: string, response: RegistrationResponseJSON, name: string): Promise<Passkey> {
  const c = takeChallenge(flow);
  if (c.userId !== user.id) throw new Error("challenge belongs to another sign-in");
  const v = await verifyRegistrationResponse({ response, expectedChallenge: c.challenge, expectedOrigin: cfg.rpOrigin, expectedRPID: cfg.rpId });
  if (!v.verified) throw new Error("passkey could not be verified");
  const cred = v.registrationInfo.credential;
  return store.addPasskey({
    user_id: user.id,
    credential_id: cred.id,
    public_key: Buffer.from(cred.publicKey).toString("base64"),
    counter: cred.counter,
    transports: (cred.transports ?? []).join(","),
    name: name.slice(0, 40) || "passkey",
  });
}

/** user = null means "any passkey on this device", for sign-in with nothing typed. */
export async function authenticationOptions(store: Store, cfg: Config, user: User | null): Promise<{ flow: string; options: PublicKeyCredentialRequestOptionsJSON }> {
  const options = await generateAuthenticationOptions({
    rpID: cfg.rpId,
    userVerification: user ? "preferred" : "required",
    allowCredentials: user ? store.passkeysFor(user.id).map((p) => ({ id: p.credential_id, transports: p.transports ? p.transports.split(",") : undefined })) : undefined,
  });
  const flow = randomToken(16);
  remember(challenges, flow, { challenge: options.challenge, userId: user?.id ?? null, expiresAt: Date.now() + CHALLENGE_MS });
  return { flow, options };
}

export async function verifyAuthentication(
  store: Store,
  cfg: Config,
  flow: string,
  response: AuthenticationResponseJSON,
): Promise<{ user: User; userVerified: boolean }> {
  const c = takeChallenge(flow);
  const pk = store.passkeyByCredentialId(response.id);
  if (!pk) throw new Error("unknown passkey");
  if (c.userId !== null && c.userId !== pk.user_id) throw new Error("passkey belongs to another account");
  const v = await verifyAuthenticationResponse({
    response,
    expectedChallenge: c.challenge,
    expectedOrigin: cfg.rpOrigin,
    expectedRPID: cfg.rpId,
    requireUserVerification: c.userId === null,
    credential: { id: pk.credential_id, publicKey: fromBase64(pk.public_key), counter: pk.counter, transports: pk.transports ? pk.transports.split(",") : undefined },
  });
  if (!v.verified) throw new Error("passkey could not be verified");
  store.updatePasskeyCounter(pk.id, v.authenticationInfo.newCounter);
  const user = store.userById(pk.user_id);
  if (!user) throw new Error("unknown passkey");
  return { user, userVerified: v.authenticationInfo.userVerified };
}

// ------------------------------------------------------- recovery codes

const CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";

export function generateRecoveryCodes(store: Store, userId: number, count = 8): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    let s = "";
    for (let j = 0; j < 10; j++) s += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
    codes.push(`${s.slice(0, 5)}-${s.slice(5)}`);
  }
  store.replaceRecoveryCodes(userId, codes.map((c) => sha256(c)));
  return codes;
}

export function useRecoveryCode(store: Store, userId: number, code: string): boolean {
  const norm = code.trim().toLowerCase().replace(/[^a-z0-9]/g, "");
  if (norm.length !== 10) return false;
  return store.useRecoveryCode(userId, sha256(`${norm.slice(0, 5)}-${norm.slice(5)}`));
}

/** Test hook. */
export function resetChallenges(): void {
  challenges.clear();
}
