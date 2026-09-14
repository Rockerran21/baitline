import * as oidc from "openid-client";
import type { Org } from "./db.ts";

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
  expiresAt: number;
}

const PENDING_MS = 10 * 60 * 1000;
const pending = new Map<string, Pending>();
const configs = new Map<string, { cfg: oidc.Configuration; expiresAt: number }>();

function isLocal(issuer: string): boolean {
  const h = new URL(issuer).hostname;
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

export async function configurationFor(org: Org): Promise<oidc.Configuration> {
  if (!org.oidc_issuer || !org.oidc_client_id || !org.oidc_client_secret) throw new Error("OIDC is not configured for this organisation");
  const key = `${org.id}:${org.oidc_issuer}:${org.oidc_client_id}`;
  const cached = configs.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.cfg;
  // Plain http is only tolerated for a local test provider. Production issuers are https.
  const execute = isLocal(org.oidc_issuer) ? [oidc.allowInsecureRequests] : [];
  const cfg = await oidc.discovery(new URL(org.oidc_issuer), org.oidc_client_id, org.oidc_client_secret, undefined, { execute });
  configs.set(key, { cfg, expiresAt: Date.now() + 10 * 60 * 1000 });
  return cfg;
}

export async function startSignIn(org: Org, redirectUri: string, next: string): Promise<URL> {
  const cfg = await configurationFor(org);
  const verifier = oidc.randomPKCECodeVerifier();
  const challenge = await oidc.calculatePKCECodeChallenge(verifier);
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  pending.set(state, { orgId: org.id, nonce, verifier, next, expiresAt: Date.now() + PENDING_MS });
  return oidc.buildAuthorizationUrl(cfg, {
    redirect_uri: redirectUri,
    scope: "openid email",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
}

export async function finishSignIn(org: Org, currentUrl: URL): Promise<{ claims: OidcClaims; next: string }> {
  const state = currentUrl.searchParams.get("state") ?? "";
  const p = pending.get(state);
  pending.delete(state);
  if (!p || p.expiresAt < Date.now() || p.orgId !== org.id) throw new Error("sign-in expired or did not start here");
  const cfg = await configurationFor(org);
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
