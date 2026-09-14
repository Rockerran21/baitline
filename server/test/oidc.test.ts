import { test, after } from "node:test";
import assert from "node:assert/strict";
import { CONTROL, Jar, go, harness, signIn, form } from "./helpers/harness.ts";
import { startFakeIdp } from "./helpers/fake-idp.ts";
import { resetOidcCache } from "../src/oidc.ts";

const idp = await startFakeIdp();
after(() => idp.close());

async function orgWithOidc(domain: string | null) {
  resetOidcCache();
  const h = harness();
  const admin = new Jar();
  await signIn(h.app, admin, "admin@acme.test");
  await go(h.app, admin, "/org/create", form({ name: "Acme" }));
  const org = h.store.org(1)!;
  h.store.updateOrg(org.id, { oidc_issuer: idp.issuer, oidc_client_id: idp.clientId, oidc_client_secret: idp.clientSecret, oidc_email_domain: domain });
  return { ...h, admin, org: h.store.org(org.id)! };
}

/** Drive the browser's part: follow the redirect to the provider and bring the code back. */
async function ssoRoundTrip(app: ReturnType<typeof harness>["app"], jar: Jar, slug: string): Promise<Response> {
  const start = await go(app, jar, `/o/${slug}/oidc/start`);
  assert.equal(start.status, 303, await start.clone().text());
  const authUrl = new URL(start.headers.get("location")!);
  assert.equal(authUrl.origin, idp.issuer);
  assert.equal(authUrl.searchParams.get("code_challenge_method"), "S256");
  assert.ok(authUrl.searchParams.get("nonce"));
  const idpRes = await fetch(authUrl, { redirect: "manual" });
  assert.equal(idpRes.status, 302);
  const back = new URL(idpRes.headers.get("location")!);
  assert.equal(back.origin, CONTROL);
  return go(app, jar, back.pathname + back.search);
}

test("OIDC sign-in with PKCE, state and nonce provisions a member on first sight and signs them in", async () => {
  const { app, store, org } = await orgWithOidc("acme.test");
  idp.account = { sub: "u-alice", email: "alice@acme.test", email_verified: true };
  const jar = new Jar();
  const res = await ssoRoundTrip(app, jar, org.slug);
  assert.equal(res.status, 303, await res.clone().text());
  assert.equal(res.headers.get("location"), "/setup", "first sign-in goes to setup");
  const alice = store.userByEmail("alice@acme.test")!;
  assert.equal(alice.org_id, org.id);
  assert.equal(alice.org_role, "member");
  assert.equal(store.decoysForUser(alice.id).length, 4, "members get their own decoys");
  assert.equal((await go(app, jar, "/dashboard")).status, 200);
  const actions = store.auditFor(org.id).map((e) => e.action);
  assert.ok(actions.includes("member.provisioned.oidc"));
  assert.ok(actions.includes("auth.oidc"));

  // Second sign-in maps to the same user, no duplicate.
  const jar2 = new Jar();
  await ssoRoundTrip(app, jar2, org.slug);
  assert.equal(store.orgMembers(org.id).length, 2, "admin + alice");
});

test("OIDC: wrong email domain and unverified email are refused; a tampered state is refused", async () => {
  const { app, store, org } = await orgWithOidc("acme.test");
  idp.account = { sub: "u-x", email: "mallory@other.test", email_verified: true };
  const r1 = await ssoRoundTrip(app, new Jar(), org.slug);
  assert.match(decodeURIComponent(r1.headers.get("location")!), /only acme\.test accounts/);
  assert.equal(store.userByEmail("mallory@other.test"), undefined);

  idp.account = { sub: "u-y", email: "bob@acme.test", email_verified: false };
  const r2 = await ssoRoundTrip(app, new Jar(), org.slug);
  assert.match(decodeURIComponent(r2.headers.get("location")!), /not verified/);

  const r3 = await go(app, new Jar(), `/o/${org.slug}/oidc/callback?code=x&state=forged`);
  assert.match(decodeURIComponent(r3.headers.get("location")!), /expired or did not start here/);
});

test("OIDC: an email that already belongs to a consumer account cannot be hijacked into the org", async () => {
  const { app, store, org } = await orgWithOidc(null);
  await signIn(app, new Jar(), "solo@acme.test");
  idp.account = { sub: "u-solo", email: "solo@acme.test", email_verified: true };
  const r = await ssoRoundTrip(app, new Jar(), org.slug);
  assert.match(decodeURIComponent(r.headers.get("location")!), /different Baitline account/);
  assert.equal(store.userByEmail("solo@acme.test")!.org_id, null);
});

test("OIDC: with a passkey on the account, SSO is the first factor and the passkey is still required", async () => {
  const { app, store, org } = await orgWithOidc(null);
  idp.account = { sub: "u-carol", email: "carol@acme.test", email_verified: true };
  const jar = new Jar();
  await ssoRoundTrip(app, jar, org.slug);
  const carol = store.userByEmail("carol@acme.test")!;
  store.addPasskey({ user_id: carol.id, credential_id: "fake", public_key: "AA==", counter: 0, transports: "", name: "phone" });
  const jar2 = new Jar();
  const r = await ssoRoundTrip(app, jar2, org.slug);
  assert.match(r.headers.get("location")!, /^\/login\/mfa/);
  assert.equal((await go(app, jar2, "/dashboard")).status, 303);
});
