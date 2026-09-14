/**
 * Regression tests for the adversarial review of 2026-09-14. Each test asserts the
 * fixed behaviour of one finding; the reviewer's reproduce suite asserts the broken one.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { CONTROL, Jar, follow, form, go, harness, json, linkFrom, onboard, signIn } from "./helpers/harness.ts";
import { SoftAuthenticator } from "./helpers/authenticator.ts";
import { startFakeIdp } from "./helpers/fake-idp.ts";
import { startSession } from "../src/auth.ts";
import { resetOidcCache } from "../src/oidc.ts";
import { retryUndelivered } from "../src/dispatch.ts";
import type { Mailer } from "../src/alerts.ts";

const RP_ID = "ctrl.test";
const idp = await startFakeIdp();
after(() => idp.close());

test("1. a second sign-in link never stands in for the passkey", async () => {
  const inbox: string[] = [];
  const { app, store } = harness({}, { async send(_t, _s, body) { inbox.push(body); } });
  const jar = new Jar();
  const email = "victim@example.test";
  const link = async () => {
    await go(app, jar, "/login/email", form({ email }));
    return linkFrom(inbox.at(-1)!);
  };
  const first = await link();
  const user = store.userByEmail(email)!;
  store.addPasskey({ user_id: user.id, credential_id: "existing", public_key: "AA==", counter: 0, transports: "", name: "phone" });
  assert.match((await follow(app, jar, first)).headers.get("location")!, /^\/login\/mfa/);
  const second = await follow(app, jar, await link());
  assert.match(second.headers.get("location")!, /^\/login\/mfa/, "the second link also lands on the second step");
  assert.equal((await go(app, jar, "/dashboard")).status, 303, "still no dashboard without the passkey");
});

test("1b. using one sign-in link burns the others that were issued", async () => {
  const inbox: string[] = [];
  const { app } = harness({}, { async send(_t, _s, body) { inbox.push(body); } });
  const jar = new Jar();
  await go(app, jar, "/login/email", form({ email: "burn@example.test" }));
  const a = linkFrom(inbox[0]!);
  await go(app, jar, "/login/email", form({ email: "burn@example.test" }));
  const b = linkFrom(inbox[1]!);
  assert.equal((await follow(app, jar, b)).status, 303);
  assert.equal((await follow(app, new Jar(), a)).status, 400, "the older, unused link is dead too");
});

test("2. an old stolen session cannot add a passkey, and adding one legitimately signs out every other session", async () => {
  const inbox: Array<{ subject: string; body: string }> = [];
  const { app, store, cfg } = harness({}, { async send(_t, subject, body) { inbox.push({ subject, body }); } });
  const email = "victim@example.test";
  const signInByMail = async (jar: Jar) => {
    await go(app, jar, "/login/email", form({ email }));
    return follow(app, jar, linkFrom(inbox.at(-1)!.body));
  };
  await signInByMail(new Jar());
  const user = store.userByEmail(email)!;
  const stolen = new Jar();
  stolen.cookies.set("bl_session", startSession(store, cfg, user, true, Date.now() - 20 * 60_000));
  assert.equal((await go(app, stolen, "/dashboard")).status, 200, "the stolen session can read");
  assert.equal((await go(app, stolen, "/account/passkeys/options", json({}))).status, 401, "but not start a passkey registration");
  const authn = new SoftAuthenticator(RP_ID, CONTROL);
  assert.equal((await go(app, stolen, "/account/passkeys/verify", json({ flow: "x", response: authn.register("x"), name: "Attacker" }))).status, 401);
  assert.equal(store.passkeysFor(user.id).length, 0);

  // A fresh, legitimate session adds a passkey: the stolen session dies and the owner is told.
  const fresh = new Jar();
  await signInByMail(fresh);
  const o = (await (await go(app, fresh, "/account/passkeys/options", json({}))).json()) as { flow: string; options: { challenge: string } };
  const v = await go(app, fresh, "/account/passkeys/verify", json({ flow: o.flow, response: authn.register(o.options.challenge), name: "Mine" }));
  assert.equal(v.status, 200, await v.clone().text());
  assert.equal((await go(app, stolen, "/dashboard")).status, 303, "stolen session is gone");
  assert.equal((await go(app, fresh, "/dashboard")).status, 200, "the session that did it survives");
  assert.ok(inbox.some((m) => /passkey was added/.test(m.subject)));
});

test("3. a forged sv_fresh cookie does not silence cookie-replay detection", async () => {
  const { app, store } = harness({ ONBOARDING_GRACE_MS: "0" });
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const { cookie, loginPath } = await onboard(app, jar, "192.0.2.1");
  const res = await app.request(`${loginPath}/account`, { headers: { cookie: `sv_session=${cookie}; sv_fresh=1`, "x-forwarded-for": "192.0.2.2" } });
  assert.equal(res.status, 200);
  const trips = store.tripsForUser(1);
  assert.equal(trips.length, 1);
  assert.equal(trips[0]!.kind, "cookie_replay");
});

test("3b. the account page right after a password trip still does not double-alert", async () => {
  const { app, alerts, store } = harness({ ONBOARDING_GRACE_MS: "0" });
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const { loginPath } = await onboard(app, jar, "192.0.2.1");
  const password = store.decoysForUser(1).find((d) => d.kind === "browser_password")!.secret;
  const login = await app.request(`${loginPath}/login`, form({ username: "x", password }, { "x-forwarded-for": "192.0.2.9" }));
  const cookies = login.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  assert.doesNotMatch(cookies, /sv_fresh/, "no forgeable freshness cookie is issued any more");
  await app.request(`${loginPath}/account`, { headers: { cookie: cookies, "x-forwarded-for": "192.0.2.9" } });
  assert.deepEqual(alerts.map((a) => a.trip.kind), ["credential_use"]);
});

test("4. probes have their own budget and cannot starve a high-severity alert", async () => {
  const { app, alerts, store } = harness({ ONBOARDING_GRACE_MS: "0", PROBE_HOURLY_CAP: "3", ALERT_HOURLY_CAP: "6" });
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const { loginPath } = await onboard(app, jar, "192.0.2.1");
  for (let i = 0; i < 10; i++) await app.request(loginPath, { headers: { "x-forwarded-for": `192.0.2.${i + 10}` } });
  assert.equal(alerts.filter((a) => a.trip.severity === "low").length, 3, "probe budget");
  const password = store.decoysForUser(1).find((d) => d.kind === "browser_password")!.secret;
  await app.request(`${loginPath}/login`, form({ username: "x", password }, { "x-forwarded-for": "192.0.2.99" }));
  const high = alerts.find((a) => a.trip.severity === "high");
  assert.ok(high, "the real trip was delivered");
  assert.equal(store.tripsForUser(1).find((t) => t.kind === "credential_use")!.notified, 1);
});

test("5. a trip is marked notified only when a channel accepts it, and failed deliveries are retried", async () => {
  const { store, cfg } = harness();
  let up = false;
  const flaky = async () => {
    if (!up) throw new Error("ntfy down");
    return true;
  };
  const { createApp } = await import("../src/app.ts");
  const app = createApp(store, cfg, flaky, null);
  const j = new Jar();
  const page = await go(app, j, "/login/email", form({ email: "v@example.test" }));
  await follow(app, j, linkFrom(await page.text()));
  const { loginPath } = await onboard(app, j, "192.0.2.1");
  const password = store.decoysForUser(1).find((d) => d.kind === "browser_password")!.secret;
  await app.request(`${loginPath}/login`, form({ username: "x", password }, { "x-forwarded-for": "192.0.2.9" }));
  const trip = store.tripsForUser(1).find((t) => t.kind === "credential_use")!;
  assert.equal(trip.notified, 0, "channel was down: not marked notified");
  assert.equal(trip.notify_attempts, 1);
  assert.equal(await retryUndelivered(store, cfg, flaky, null), 0, "still down");
  up = true;
  assert.equal(await retryUndelivered(store, cfg, flaky, null), 1, "delivered on retry");
  assert.equal(store.tripsForUser(1).find((t) => t.kind === "credential_use")!.notified, 1);
  assert.equal(store.undelivered(cfg.notifyMaxAttempts).length, 0);
});

test("8. forwarded addresses are ignored unless TRUST_PROXY is set", async () => {
  let sent = 0;
  const mailer: Mailer = { async send() { sent++; } };
  const { app } = harness({ TRUST_PROXY: "0", ENROLL_PER_HOUR_PER_IP: "2" }, mailer);
  for (let i = 0; i < 5; i++) await app.request("/login/email", form({ email: `r${i}@example.test` }, { "x-forwarded-for": `192.0.2.${i}` }));
  assert.equal(sent, 2, "rotating the header does not rotate the limit");
});

test("9. organisation URLs cannot point inside the network; a test alert to a loopback webhook is refused in production mode", async () => {
  const sink = createServer((_q, r) => r.end("ok"));
  await new Promise<void>((r) => sink.listen(0, "127.0.0.1", r));
  const port = (sink.address() as { port: number }).port;
  try {
    const { app } = harness({ ALLOW_LOCAL_URLS: "0" });
    const jar = new Jar();
    await signIn(app, jar, "attacker@example.test");
    await go(app, jar, "/org/create", form({ name: "Attacker org" }));
    for (const bad of [`http://127.0.0.1:${port}/internal`, `https://127.0.0.1:${port}/internal`, "https://localhost@external.example/x", "https://10.0.0.5/x", "https://169.254.169.254/latest"]) {
      const r = await go(app, jar, "/org/settings", form({ alert_webhook_url: bad }));
      assert.equal(r.status, 400, bad);
    }
    for (const bad of ["http://10.0.0.5/issuer", "https://user:pw@idp.example/"]) {
      const r = await go(app, jar, "/org/settings", form({ oidc_issuer: bad, oidc_client_id: "a", oidc_client_secret: "b" }));
      assert.equal(r.status, 400, bad);
    }
    const r = await go(app, jar, "/org/settings", form({ ldap_url: "ldaps://10.0.0.5", ldap_user_dn: "uid={username},dc=x" }));
    assert.equal(r.status, 400);
  } finally {
    await new Promise<void>((r) => sink.close(() => r()));
  }
});

test("10. an OpenID callback is only accepted by the browser that started the flow", async () => {
  resetOidcCache();
  const { app, store } = harness();
  const admin = new Jar();
  await signIn(app, admin, "admin@example.test");
  await go(app, admin, "/org/create", form({ name: "Example" }));
  const org = store.org(1)!;
  store.updateOrg(org.id, { oidc_issuer: idp.issuer, oidc_client_id: idp.clientId, oidc_client_secret: idp.clientSecret });
  idp.account = { sub: "attacker", email: "attacker@example.test", email_verified: true };
  const attacker = new Jar();
  const started = await go(app, attacker, `/o/${org.slug}/oidc/start`);
  assert.ok(attacker.cookies.has("bl_oidc"), "the starting browser holds the flow cookie");
  const authorized = await fetch(started.headers.get("location")!, { redirect: "manual" });
  const callback = new URL(authorized.headers.get("location")!);
  const victim = new Jar();
  const r = await go(app, victim, callback.pathname + callback.search);
  assert.match(decodeURIComponent(r.headers.get("location")!), /different browser/);
  assert.equal((await go(app, victim, "/dashboard")).status, 303, "victim is not signed in as the attacker");
  assert.equal(store.userByEmail("attacker@example.test"), undefined, "nothing was provisioned");
});
