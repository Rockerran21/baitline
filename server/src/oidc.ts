import * as oidc from "openid-client";
import type { Org } from "./db.ts";
import { remember, randomToken, sha256 } from "./auth.ts";
import { guardedFetch } from "./netguard.ts";

/**
 * One generic OpenID Connect relying party covers Google Workspace, Microsoft Entra,
 * Okta, Keycloak and any other certified provider. Authorization code flow with PKCE,
 * state and nonce, nothing else.
 */

export interface OidcClaims {
  sub: string;
  email: string;
  emailVerified: boolean;
}

interface Pending {
  orgId: number;
  nonce: string;
  verifier: string;
  next: string;
  /** Hash of the cookie set in the browser that started the flow. The callback must present it. */
  browserHash: string;
  expiresAt: number;
}

const PENDING_MS = 10 * 60 * 1000;
const pending = new Map<string, Pending>();
const configs = new Map<string, { cfg: oidc.Configuration; expiresAt: number }>();

/**
 * Every request the relying party makes (discovery, JWKS, token endpoint) goes through
 * the outbound guard: public https only, pinned to the checked address, no redirects.
 * In development mode (allowLocal) a plain http test provider on localhost is allowed.
 */
function guardedOidcFetch(allowLocal: boolean): oidc.CustomFetch {
  return (url, options) =>
    guardedFetch(String(url), { method: options.method, headers: options.headers as RequestInit["headers"], body: options.body as RequestInit["body"], signal: options.signal }, { schemes: ["https:"], allowLocal });
}

export async function configurationFor(org: Org, allowLocal = false): Promise<oidc.Configuration> {
  if (!org.oidc_issuer || !org.oidc_client_id || !org.oidc_client_secret) throw new Error("OIDC is not configured for this organisation");
  const key = `${org.id}:${org.oidc_issuer}:${org.oidc_client_id}:${allowLocal}`;
  const cached = configs.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.cfg;
  const execute = allowLocal ? [oidc.allowInsecureRequests] : [];
  const cfg = await oidc.discovery(new URL(org.oidc_issuer), org.oidc_client_id, org.oidc_client_secret, undefined, { execute, [oidc.customFetch]: guardedOidcFetch(allowLocal) });
  cfg[oidc.customFetch] = guardedOidcFetch(allowLocal);
  configs.set(key, { cfg, expiresAt: Date.now() + 10 * 60 * 1000 });
  return cfg;
}

export const OIDC_COOKIE = "bl_oidc";

/**
 * Starts the flow and returns the provider URL plus a browser cookie value. The same
 * browser has to bring that cookie to the callback, so a sign-in the attacker started
 * cannot be completed in a victim's browser.
 */
export async function startSignIn(org: Org, redirectUri: string, next: string, allowLocal = false): Promise<{ url: URL; browserCookie: string }> {
  const cfg = await configurationFor(org, allowLocal);
  const verifier = oidc.randomPKCECodeVerifier();
  const challenge = await oidc.calculatePKCECodeChallenge(verifier);
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const browserCookie = randomToken();
  remember(pending, state, { orgId: org.id, nonce, verifier, next, browserHash: sha256(browserCookie), expiresAt: Date.now() + PENDING_MS });
  const url = oidc.buildAuthorizationUrl(cfg, {
    redirect_uri: redirectUri,
    scope: "openid email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return { url, browserCookie };
}

export async function finishSignIn(org: Org, currentUrl: URL, browserCookie: string | undefined, allowLocal = false): Promise<{ claims: OidcClaims; next: string }> {
  const state = currentUrl.searchParams.get("state") ?? "";
  const p = pending.get(state);
  pending.delete(state);
  if (!p || p.expiresAt < Date.now() || p.orgId !== org.id) throw new Error("sign-in expired or did not start here");
  if (!browserCookie || sha256(browserCookie) !== p.browserHash) throw new Error("this sign-in was started in a different browser");
  const cfg = await configurationFor(org, allowLocal);
  const tokens = await oidc.authorizationCodeGrant(cfg, currentUrl, { expectedState: state, expectedNonce: p.nonce, pkceCodeVerifier: p.verifier });
  const c = tokens.claims();
  if (!c) throw new Error("no ID token");
  const email = typeof c.email === "string" ? c.email.trim() : "";
  if (!email) throw new Error("the identity provider did not return an email address");
  return { claims: { sub: c.sub, email, emailVerified: c.email_verified === true }, next: p.next };
}

/** Test hook: forget cached discovery so a test provider can be replaced. */
export function resetOidcCache(): void {
  configs.clear();
  pending.clear();
}
