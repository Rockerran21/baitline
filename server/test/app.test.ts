import { test } from "node:test";
import assert from "node:assert/strict";
import { CONTROL, Jar, go, harness, json, onboard, signIn, form } from "./helpers/harness.ts";
import type { Account } from "../src/app.ts";

const OWNER = "203.0.113.10";
const ATTACKER = "198.51.100.77";

test("onboarding is silent; cookie replay, password use and API key use from elsewhere are high alerts; probes are lower", async () => {
  const { app, alerts, store } = harness();
  const jar = new Jar();
  await signIn(app, jar, "victim@example.com");
  const { cookie, loginPath } = await onboard(app, jar, OWNER);
  assert.equal(alerts.length, 0);
  const user = store.userByEmail("victim@example.com")!;
  assert.ok(user.enrolled_at);
  assert.equal(user.setup_token, null, "onboarding link is single use");

  const acct = await app.request(`${loginPath}/account?welcome=1`, { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": OWNER } });
  assert.match(await acct.text(), /never need to open this page again/);
  assert.equal(alerts.length, 0, "owner's own visit inside the grace window");

  const replay = await app.request(`${loginPath}/account`, { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": ATTACKER, "user-agent": "Stolen/1.0" } });
  assert.equal(replay.status, 200);
  assert.deepEqual(alerts.map((a) => [a.trip.kind, a.trip.severity, a.trip.ip]), [["cookie_replay", "high", ATTACKER]]);

  const pw = store.decoysForUser(user.id).find((d) => d.kind === "browser_password")!;
  const login = await app.request(`${loginPath}/login`, form({ username: "x", password: pw.secret }, { "x-forwarded-for": "192.0.2.5" }));
  assert.equal(login.status, 303);
  const key = store.decoysForUser(user.id).find((d) => d.kind === "api_key")!;
  const api = await app.request(`/api/v1/${user.slug}/balances`, { headers: { authorization: `Bearer ${key.secret}`, "x-forwarded-for": "192.0.2.6" } });
  assert.equal(api.status, 200);
  await app.request(loginPath, { headers: { "x-forwarded-for": "192.0.2.7" } });
  await app.request(`${loginPath}/login`, form({ username: "x", password: "guess" }, { "x-forwarded-for": "192.0.2.7" }));
  assert.deepEqual(
    alerts.map((a) => a.trip.kind),
    ["cookie_replay", "credential_use", "api_key_use", "vault_visit", "login_attempt"],
  );
  const html = await (await go(app, jar, "/dashboard")).text();
  assert.match(html, /TRIPPED: 3 high-severity events/);
  assert.match(html, /Do this now/);
  assert.doesNotMatch(await (await app.request(loginPath)).text(), /Baitline/, "the decoy never names the product");
});

test("repeat trips are stored but not re-notified inside the window; the hourly cap holds", async () => {
  const { app, alerts, store } = harness({ ALERT_DEDUPE_MS: "600000", ALERT_HOURLY_CAP: "3" });
  const jar = new Jar();
  await signIn(app, jar, "v@example.com");
  const { cookie, loginPath } = await onboard(app, jar, OWNER);
  for (let i = 0; i < 5; i++) await app.request(`${loginPath}/account`, { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": ATTACKER } });
  assert.equal(alerts.length, 1);
  for (let i = 0; i < 5; i++) await app.request(`${loginPath}/account`, { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": `192.0.2.${i}` } });
  assert.equal(alerts.length, 3, "cap");
  const user = store.userByEmail("v@example.com")!;
  assert.equal(store.tripsForUser(user.id).length, 10);
});

test("split hosts: nothing about the product is reachable on the decoy host, and the vault is not on the control host", async () => {
  const { app } = harness({ PUBLIC_URL: "https://custody.example", CONTROL_URL: "https://app.baitline.example" });
  const ctrl = { host: "app.baitline.example" };
  const jar = new Jar();
  const page = await go(app, jar, "/login/email", form({ email: "s@example.com" }, ctrl));
  assert.equal(page.status, 200);
  const link = /\/login\/magic\?t=[A-Za-z0-9_-]+/.exec(await page.text())![0];
  await go(app, jar, link, { headers: ctrl });
  const setup = await (await go(app, jar, "/setup", { headers: ctrl })).text();
  const vaultPath = /href="(?:https?:\/\/[^/"]+)?(\/vault\/[^"?]+)\?setup=/.exec(setup)![1]!;
  for (const p of ["/", "/dashboard", "/setup", "/login/email", "/api/link", "/o/x"]) {
    assert.equal((await go(app, jar, p, { headers: { host: "custody.example" } })).status, 404, `${p} on decoy host`);
  }
  assert.equal((await app.request(vaultPath, { headers: ctrl })).status, 404, "vault on control host");
  const vault = await app.request(vaultPath, { headers: { host: "custody.example" } });
  assert.equal(vault.status, 200);
  assert.equal(vault.headers.get("cache-control"), null);
  assert.equal((await go(app, jar, "/dashboard", { headers: ctrl })).headers.get("strict-transport-security"), "max-age=31536000");
});

test("brand and key prefix come from config", async () => {
  const { app, store } = harness({ DECOY_BRAND: "Northwind Custody", DECOY_COMPANY: "Northwind Ltd", DECOY_KEY_PREFIX: "nwc_sk_" });
  const jar = new Jar();
  await signIn(app, jar, "b@example.com");
  const { loginPath } = await onboard(app, jar, OWNER);
  const page = await (await app.request(loginPath)).text();
  assert.match(page, /Northwind Custody/);
  assert.doesNotMatch(page, /Meridian|Baitline/);
  const key = store.decoysForUser(store.userByEmail("b@example.com")!.id).find((d) => d.kind === "api_key")!;
  assert.match(key.secret, /^nwc_sk_[0-9a-f]{40}$/);
});

test("desktop link: the setup page carries a one-time device code; it returns the secrets exactly once; the device token reads status and writes guard events only", async () => {
  const { app, store } = harness();
  const jar = new Jar();
  await signIn(app, jar, "d@example.com");
  const setup = await (await go(app, jar, "/setup")).text();
  const code = /--link ([A-Za-z0-9_-]+)/.exec(setup)![1]!;
  const linked = await app.request("/api/link", json({ code }));
  assert.equal(linked.status, 200);
  const a = (await linked.json()) as Account;
  assert.equal(a.email, "d@example.com");
  assert.match(a.api.key, /^mvk_live_/);
  assert.equal(a.wallet.seed_phrase.split(" ").length, 12);
  assert.equal((await app.request("/api/link", json({ code }))).status, 401, "code is single use");
  assert.equal((await app.request("/api/link", json({ code: "nope" }))).status, 401);

  const guardToken = a.guard_url.split("/").pop()!;
  const g = await app.request(a.guard_url.replace(CONTROL, ""), json({ host: "mbp", source_app: "Safari", rule: "mshta-remote", sample: "mshta http://x" }));
  assert.equal(g.status, 201);
  const status = (await (await app.request(a.status_url.replace(CONTROL, ""))).json()) as { guard_events: number; enrolled: boolean };
  assert.equal(status.guard_events, 1);
  assert.equal(status.enrolled, false);
  for (const p of ["/dashboard", "/setup", "/account"]) {
    assert.equal((await app.request(p, { headers: { cookie: `bl_session=${guardToken}` } })).status, 303, `${p} does not open with the device token`);
  }
  assert.equal(store.userByGuardToken(guardToken)!.email, "d@example.com");
});

test("family: owner invites a member; the member's trip alerts both with the member's name; owner delete takes the member along", async () => {
  const { app, alerts, store } = harness();
  const owner = new Jar();
  await signIn(app, owner, "owner@example.com");
  const add = await go(app, owner, "/dashboard/members", form({ label: "Mom's laptop", email: "mom@example.com" }));
  const notice = decodeURIComponent(add.headers.get("location")!);
  const inviteLink = /\/login\/magic\?t=[A-Za-z0-9_-]+/.exec(notice)![0];
  const dup = await go(app, owner, "/dashboard/members", form({ label: "Again", email: "mom@example.com" }));
  assert.match(dup.headers.get("location")!, /error=exists/);

  const mom = new Jar();
  assert.equal((await go(app, mom, inviteLink)).headers.get("location"), "/setup");
  const { cookie, loginPath } = await onboard(app, mom, "203.0.113.20");
  await app.request(`${loginPath}/account`, { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": ATTACKER } });
  assert.equal(alerts.length, 2);
  const toOwner = alerts.find((x) => x.user.email === "owner@example.com")!;
  assert.equal(toOwner.label, "Mom's laptop");
  assert.equal(alerts.find((x) => x.user.email === "mom@example.com")!.label, undefined);
  const dash = await (await go(app, owner, "/dashboard")).text();
  assert.match(dash, /Mom&#39;s laptop/);
  assert.match(dash, /TRIPPED \(1\)/);
  assert.match(await (await go(app, mom, "/dashboard")).text(), /part of a family plan/);
  assert.equal((await go(app, mom, "/dashboard/members", form({ label: "x", email: "x@example.com" }))).status, 404);

  const refused = await go(app, owner, "/account/delete", form({ confirm: "delete" }));
  assert.match(refused.headers.get("location")!, /error=/);
  const gone = await go(app, owner, "/account/delete", form({ confirm: "DELETE" }));
  assert.equal(gone.headers.get("location"), "/?deleted=1");
  assert.equal(store.userByEmail("owner@example.com"), undefined);
  assert.equal(store.userByEmail("mom@example.com"), undefined, "member deleted with owner");
  assert.equal((await app.request(loginPath)).status, 404);
  assert.equal((await go(app, mom, "/dashboard")).status, 303, "member's session is gone");
  const counts = store.db.prepare("SELECT (SELECT COUNT(*) FROM users) u, (SELECT COUNT(*) FROM decoys) d, (SELECT COUNT(*) FROM sessions) s").get() as { u: number; d: number; s: number };
  assert.deepEqual({ ...counts }, { u: 0, d: 0, s: 0 });
});

test("test alert goes out and is not counted as a trip", async () => {
  const { app, alerts } = harness();
  const jar = new Jar();
  await signIn(app, jar, "t@example.com");
  await go(app, jar, "/setup/test", { method: "POST" });
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0]!.trip.kind, "test_alert");
  const status = (await (await app.request(alerts[0]!.user.guard_token ? `/api/status/${alerts[0]!.user.guard_token}` : "/x")).json()) as { high_severity_trips: number; trips: unknown[] };
  assert.equal(status.trips.length, 0);
});

test("unknown slugs and paths look like ordinary 404s", async () => {
  const { app } = harness();
  for (const p of ["/vault/doesnotexist", "/api/v1/nope/x", "/o/nope", "/api/status/nope"]) assert.equal((await app.request(p)).status, 404, p);
});
