/** Regression tests for the second adversarial pass of 2026-09-14. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CONTROL, Jar, follow, form, go, harness, json, linkFrom, onboard, signIn } from "./helpers/harness.ts";
import { retryUndelivered } from "../src/dispatch.ts";
import { issueToken } from "../src/auth.ts";

test("N2. requesting a sign-in link for an address creates nothing; an organisation can still invite that person", async () => {
  const { app, store } = harness();
  const target = "employee@acme.test";
  const page = await go(app, new Jar(), "/login/email", form({ email: target }));
  assert.equal(store.userByEmail(target), undefined, "no account until the link is used");
  const link = linkFrom(await page.text());

  const admin = new Jar();
  await signIn(app, admin, "admin@acme.test");
  await go(app, admin, "/org/create", form({ name: "Acme" }));
  const invited = await go(app, admin, "/org/members", form({ label: "Employee", email: target }));
  assert.match(decodeURIComponent(invited.headers.get("location")!), /Invite/);
  assert.equal(store.userByEmail(target)!.org_id, 1, "the employee is in the organisation");

  // The stale sign-up link now signs into the org account rather than creating a second one.
  const jar = new Jar();
  const r = await follow(app, jar, link);
  assert.equal(r.status, 303);
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM users WHERE email = ?").get(target)!.n, 1);
});

test("N2b. a sign-up link creates the account at redemption and only once", async () => {
  const { app, store } = harness();
  const jar = new Jar();
  const page = await go(app, jar, "/login/email", form({ email: "fresh@example.test" }));
  const link = linkFrom(await page.text());
  assert.equal(store.userByEmail("fresh@example.test"), undefined);
  assert.equal((await follow(app, jar, link)).headers.get("location"), "/setup");
  assert.ok(store.userByEmail("fresh@example.test"));
  assert.equal((await follow(app, new Jar(), link)).status, 400);
});

test("N3. every destination has its own outbox row; one success does not hide another's failure, and the failed one is retried", async () => {
  let webhookUp = false;
  const fakeFetch = (async () => new Response(webhookUp ? "ok" : "down", { status: webhookUp ? 200 : 503 })) as unknown as typeof fetch;
  const { app, store, cfg } = harness({}, null, fakeFetch);
  const admin = new Jar();
  await signIn(app, admin, "admin@acme.test");
  await go(app, admin, "/org/create", form({ name: "Acme" }));
  await go(app, admin, "/org/settings", form({ alert_webhook_url: "https://hooks.example.test/security" }));
  const { loginPath } = await onboard(app, admin, "192.0.2.1");
  const password = store.decoysForUser(1).find((d) => d.kind === "browser_password")!.secret;
  await app.request(`${loginPath}/login`, form({ password }, { "x-forwarded-for": "192.0.2.2" }));
  const trip = store.tripsForUser(1).find((t) => t.kind === "credential_use")!;
  assert.equal(trip.notified, 1, "the person was notified");
  const rows = store.deliveriesForTrip(trip.id);
  assert.deepEqual(rows.map((r) => [r.destination, r.delivered]), [["self:1", 1], ["org:1:webhook", 0]]);
  assert.match(rows[1]!.last_error, /503/);
  assert.equal(store.pendingDeliveries(cfg.notifyMaxAttempts).length, 1, "the webhook copy is still owed");
  assert.equal(await retryUndelivered(store, cfg, async () => true, null, fakeFetch), 0);
  webhookUp = true;
  assert.equal(await retryUndelivered(store, cfg, async () => true, null, fakeFetch), 1);
  assert.equal(store.pendingDeliveries(cfg.notifyMaxAttempts).length, 0);
  assert.equal(store.deliveriesForTrip(trip.id)[1]!.delivered, 1);
});

test("N4. the desktop client's manifest lives on the server; the device token can write it but only a reset code can read it", async () => {
  const { app, store } = harness();
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const user = store.userByEmail("victim@example.test")!;
  const files = [{ path: "/Users/v/Desktop/wallet-recovery-phrase.txt", kind: "wallet_file", sha256: "a".repeat(64) }];
  const token = issueToken(store, user, "manifest", 60_000);
  const put = await app.request("/api/manifest/put", json({ token, files }));
  assert.equal(put.status, 201);
  assert.equal((await app.request(`/api/guard/${user.guard_token}/manifest`, { method: "GET" })).status, 404, "no read with the device token");
  const status = (await (await app.request(`/api/status/${user.guard_token}`)).json()) as Record<string, unknown>;
  assert.equal(JSON.stringify(status).includes("wallet-recovery"), false, "status does not leak paths either");
  // The account page hands out a one-time reset code (fresh sign-in required, which we have).
  const page = await (await go(app, jar, "/account/reset-code", { method: "POST" })).text();
  const code = /--code ([A-Za-z0-9_-]+)/.exec(page)![1]!;
  const read = await app.request("/api/manifest", json({ code }));
  assert.equal(read.status, 200);
  const got = (await read.json()) as { files: unknown[]; done: string };
  assert.deepEqual(got.files, files);
  assert.equal((await app.request("/api/manifest", json({ code }))).status, 401, "single use");
  const { done } = got;
  assert.equal((await app.request("/api/manifest/done", json({ done }))).status, 200);
  assert.equal(store.userById(user.id)!.seed_manifest, null, "cleared once the client confirms");
  // A stolen device token cannot mint a reset code: that route needs a session.
  assert.equal((await app.request("/account/reset-code", { method: "POST", headers: { cookie: `bl_session=${user.guard_token}` } })).status, 303);
});

test("N6. guard events are rate limited per device token and pruned per user", async () => {
  const { app, store } = harness();
  await signIn(app, new Jar(), "victim@example.test");
  const token = store.userById(1)!.guard_token;
  let accepted = 0;
  let limited = 0;
  for (let i = 0; i < 200; i++) {
    const r = await app.request(`/api/guard/${token}`, json({ host: "stolen", rule: "spam", sample: String(i) }));
    if (r.status === 201) accepted++;
    else if (r.status === 429) limited++;
  }
  assert.equal(accepted, 120);
  assert.equal(limited, 80);
  for (let i = 0; i < 600; i++) store.addGuardEvent({ user_id: 1, host: "h", source_app: "a", rule: "r", sample: String(i) });
  assert.equal(store.guardEventsForUser(1, 10_000).length, 500, "retention cap");
});

test("N7. a hanging webhook cannot hold the request or hide a successful personal delivery", async () => {
  const never = (async (_u: unknown, init?: RequestInit) => new Promise<Response>((_res, rej) => init?.signal?.addEventListener("abort", () => rej(new Error("aborted"))))) as unknown as typeof fetch;
  const { app, store } = harness({}, null, never);
  const admin = new Jar();
  await signIn(app, admin, "admin@acme.test");
  await go(app, admin, "/org/create", form({ name: "Acme" }));
  await go(app, admin, "/org/settings", form({ alert_webhook_url: "https://hooks.example.test/security" }));
  const { loginPath } = await onboard(app, admin, "192.0.2.1");
  const password = store.decoysForUser(1).find((d) => d.kind === "browser_password")!.secret;
  const started = Date.now();
  const res = await app.request(`${loginPath}/login`, form({ password }, { "x-forwarded-for": "192.0.2.2" }));
  assert.equal(res.status, 303);
  assert.ok(Date.now() - started < 12_000, "bounded by the delivery deadline");
  const trip = store.tripsForUser(1).find((t) => t.kind === "credential_use")!;
  assert.equal(trip.notified, 1, "the personal delivery was recorded");
  const rows = store.deliveriesForTrip(trip.id);
  assert.equal(rows.find((r) => r.destination.endsWith("webhook"))!.delivered, 0);
});

test("N8. signed-in pages refuse to be framed", async () => {
  const { app } = harness();
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  for (const p of ["/account", "/dashboard", "/org", "/"]) {
    const r = await go(app, jar, p);
    assert.equal(r.headers.get("x-frame-options"), "DENY", p);
    assert.match(r.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/, p);
  }
});

test("N9. oversized bodies are refused before parsing", async () => {
  const { app, store } = harness();
  await signIn(app, new Jar(), "victim@example.test");
  const token = store.userById(1)!.guard_token;
  const big = await app.request(`/api/guard/${token}`, json({ host: "stolen", rule: "spam", sample: "x".repeat(2_000_000) }));
  assert.equal(big.status, 413);
  assert.equal(store.guardEventsForUser(1).length, 0);
  assert.equal((await app.request("/api/link", json({ code: "x".repeat(5_000) }))).status, 413);
  assert.equal((await app.request("/login/email", form({ email: "a@b.co", pad: "x".repeat(40_000) }))).status, 413);
});

test("reset code cannot be minted with a stale session", async () => {
  const { app, store, cfg } = harness({ FRESH_MS: "1000" });
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const { sha256 } = await import("../src/auth.ts");
  store.db.prepare("UPDATE sessions SET authenticated_at = ? WHERE id = ?").run(Date.now() - 5000, sha256(jar.cookies.get("bl_session")!));
  const r = await go(app, jar, "/account/reset-code", { method: "POST" });
  assert.match(r.headers.get("location")!, /^\/login\/reauth/);
  void cfg;
  void issueToken;
  void CONTROL;
});
