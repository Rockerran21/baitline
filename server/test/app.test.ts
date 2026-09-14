import { test } from "node:test";
import assert from "node:assert/strict";
import { Store } from "../src/db.ts";
import { loadConfig } from "../src/config.ts";
import { createApp, type AccountView } from "../src/app.ts";
import type { AlertPayload } from "../src/alerts.ts";

const OWNER = "203.0.113.10";
const ATTACKER = "198.51.100.77";

function setup(env: Record<string, string> = {}) {
  const store = new Store(":memory:");
  const cfg = loadConfig({ PUBLIC_URL: "http://vault.test", DB_PATH: ":memory:", ...env });
  const alerts: AlertPayload[] = [];
  const app = createApp(store, cfg, async (p) => {
    alerts.push(p);
  });
  return { store, cfg, app, alerts };
}

async function enroll(app: ReturnType<typeof setup>["app"], headers: Record<string, string> = {}): Promise<AccountView> {
  const res = await app.request("/api/enroll", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ email: "victim@example.com" }),
  });
  assert.equal(res.status, 201);
  return (await res.json()) as AccountView;
}

function path(url: string): string {
  return new URL(url).pathname + new URL(url).search;
}

async function onboard(app: ReturnType<typeof setup>["app"], e: AccountView): Promise<string> {
  const setupToken = new URL(e.vault.onboarding_url!).searchParams.get("setup")!;
  const form = new URLSearchParams({ username: e.vault.username, password: e.vault.password, setup: setupToken });
  const res = await app.request(path(e.vault.login_url) + "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": OWNER, "user-agent": "OwnerBrowser" },
    body: form,
  });
  assert.equal(res.status, 303);
  assert.match(res.headers.get("location")!, /\/account\?welcome=1$/);
  const setCookie = res.headers.get("set-cookie") ?? "";
  const m = /sv_session=([^;]+)/.exec(setCookie);
  assert.ok(m, "session cookie set on onboarding");
  return m![1]!;
}

test("enroll creates decoys and onboarding login produces no alert", async () => {
  const { app, alerts, store } = setup();
  const e = await enroll(app);
  assert.match(e.api.key, /^mvk_live_[0-9a-f]{40}$/);
  assert.equal(e.wallet.seed_phrase.split(" ").length, 12);
  assert.match(e.vault.onboarding_url!, /\?setup=/);
  assert.match(e.ntfy_topic!, /^bl-/, "ntfy topic is auto-generated when not supplied");

  const cookie = await onboard(app, e);
  assert.ok(cookie.length > 20);
  assert.equal(alerts.length, 0);

  // Owner lands on the welcome page right after: still no alert (grace period).
  const acct = await app.request(path(e.vault.login_url) + "/account?welcome=1", {
    headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": OWNER },
  });
  assert.equal(acct.status, 200);
  const acctHtml = await acct.text();
  assert.match(acctHtml, /never need to open this page again/);
  assert.doesNotMatch(acctHtml, /Baitline/, "the decoy site never names the product");
  assert.equal(alerts.length, 0);

  const user = store.userBySlug(new URL(e.vault.login_url).pathname.split("/").pop()!)!;
  assert.ok(user.enrolled_at);
  assert.equal(user.setup_token, null, "setup token is single use");
});

test("cookie replay from another IP fires a high-severity alert", async () => {
  const { app, alerts } = setup();
  const e = await enroll(app);
  const cookie = await onboard(app, e);

  const res = await app.request(path(e.vault.login_url) + "/account", {
    headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": ATTACKER, "user-agent": "StolenSessionBrowser" },
  });
  assert.equal(res.status, 200, "attacker sees a plausible account page");
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0]!.trip.kind, "cookie_replay");
  assert.equal(alerts[0]!.trip.severity, "high");
  assert.equal(alerts[0]!.trip.ip, ATTACKER);
  assert.equal(alerts[0]!.trip.ua, "StolenSessionBrowser");
  assert.match(alerts[0]!.dashboardUrl, /^http:\/\/vault\.test\/dashboard\//);
});

test("stolen password used to log in fires exactly one high alert, not two", async () => {
  const { app, alerts } = setup();
  const e = await enroll(app);
  await onboard(app, e);

  const form = new URLSearchParams({ username: e.vault.username, password: e.vault.password });
  const login = await app.request(path(e.vault.login_url) + "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": ATTACKER },
    body: form,
  });
  assert.equal(login.status, 303);
  const cookies = login.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
  assert.match(cookies, /sv_fresh=1/);

  const acct = await app.request(path(e.vault.login_url) + "/account", {
    headers: { cookie: cookies, "x-forwarded-for": ATTACKER },
  });
  assert.equal(acct.status, 200);
  assert.deepEqual(
    alerts.map((a) => a.trip.kind),
    ["credential_use"],
  );
});

test("wrong password on the decoy vault is a medium probe; visiting the page is low", async () => {
  const { app, alerts } = setup();
  const e = await enroll(app);
  await onboard(app, e);

  await app.request(path(e.vault.login_url), { headers: { "x-forwarded-for": ATTACKER } });
  const bad = await app.request(path(e.vault.login_url) + "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": ATTACKER },
    body: new URLSearchParams({ username: e.vault.username, password: "wrong" }),
  });
  assert.equal(bad.status, 401);
  assert.deepEqual(
    alerts.map((a) => [a.trip.kind, a.trip.severity]),
    [
      ["vault_visit", "low"],
      ["login_attempt", "medium"],
    ],
  );
});

test("decoy API key use fires high alert and returns plausible JSON", async () => {
  const { app, alerts } = setup();
  const e = await enroll(app);
  await onboard(app, e);

  const nope = await app.request(path(e.api.base) + "/v1/balances", { headers: { authorization: "Bearer nope" } });
  assert.equal(nope.status, 401);
  assert.equal(alerts.length, 0);

  const hit = await app.request(path(e.api.base) + "/balances", {
    headers: { authorization: `Bearer ${e.api.key}`, "x-forwarded-for": ATTACKER, "user-agent": "curl/8.0" },
  });
  assert.equal(hit.status, 200);
  const body = (await hit.json()) as { balances: unknown[] };
  assert.equal(body.balances.length, 3);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0]!.trip.kind, "api_key_use");

  const viaHeader = await app.request(path(e.api.base) + "/withdraw", {
    method: "POST",
    headers: { "x-api-key": e.api.key, "x-forwarded-for": "192.0.2.44" },
  });
  assert.equal(viaHeader.status, 200);
  assert.equal(alerts.length, 2, "x-api-key header works; new IP notifies");
  const again = await app.request(path(e.api.base) + "/withdraw", { method: "POST", headers: { "x-api-key": e.api.key, "x-forwarded-for": "192.0.2.44" } });
  assert.equal(again.status, 200);
  assert.equal(alerts.length, 2, "same IP inside the dedupe window is recorded, not re-notified");
});

test("status endpoint and dashboard reflect trips; guard events are recorded", async () => {
  const { app } = setup();
  const e = await enroll(app);
  const cookie = await onboard(app, e);
  await app.request(path(e.vault.login_url) + "/account", {
    headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": ATTACKER },
  });

  const g = await app.request(path(e.guard_url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ host: "victim-mbp", source_app: "Google Chrome", rule: "powershell-hidden", sample: "powershell -w hidden -c ..." }),
  });
  assert.equal(g.status, 201);

  const status = (await (await app.request(path(e.status_url))).json()) as {
    enrolled: boolean;
    high_severity_trips: number;
    guard_events: number;
    decoys: string[];
  };
  assert.equal(status.enrolled, true);
  assert.equal(status.high_severity_trips, 1);
  assert.equal(status.guard_events, 1);
  assert.deepEqual(status.decoys, ["browser_password", "session_cookie", "api_key", "wallet_file"]);

  const dash = await (await app.request(path(e.dashboard_url))).text();
  assert.match(dash, /TRIPPED: 1 high-severity event/);
  assert.match(dash, /cookie_replay/);
  assert.match(dash, /powershell-hidden/);
  assert.match(dash, /Do this now/);
});

test("guard token is write-only and distinct from the dashboard token", async () => {
  const { app } = setup();
  const e = await enroll(app);
  const guardToken = e.guard_url.split("/").pop()!;
  const dashToken = e.dashboard_url.split("/").pop()!;
  assert.notEqual(guardToken, dashToken);
  for (const p of [`/dashboard/${guardToken}`, `/api/status/${guardToken}`, `/api/me/${guardToken}`, `/setup/${guardToken}`]) {
    assert.equal((await app.request(p)).status, 404, `${p} must not open with the guard token`);
  }
  const wrong = await app.request(`/api/guard/${dashToken}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.equal(wrong.status, 404, "dashboard token must not post guard events");
});

test("repeat trips from the same IP are recorded but not re-notified inside the dedupe window", async () => {
  const { app, alerts, store } = setup({ ALERT_DEDUPE_MS: "600000", ALERT_HOURLY_CAP: "100" });
  const e = await enroll(app);
  const cookie = await onboard(app, e);
  for (let i = 0; i < 5; i++) {
    await app.request(path(e.vault.login_url) + "/account", { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": ATTACKER } });
  }
  assert.equal(alerts.length, 1, "one notification");
  const user = store.userByDashboardToken(e.dashboard_url.split("/").pop()!)!;
  assert.equal(store.tripsForUser(user.id).length, 5, "all five trips stored");
  // A different attacker IP is a new notification.
  await app.request(path(e.vault.login_url) + "/account", { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": "192.0.2.9" } });
  assert.equal(alerts.length, 2);
});

test("hourly notification cap stops an alert flood but keeps recording", async () => {
  const { app, alerts, store } = setup({ ALERT_DEDUPE_MS: "0", ALERT_HOURLY_CAP: "3" });
  const e = await enroll(app);
  await onboard(app, e);
  for (let i = 0; i < 10; i++) {
    await app.request(path(e.vault.login_url) + "/login", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": `198.51.100.${i}` },
      body: new URLSearchParams({ username: "x", password: "guess" }),
    });
  }
  assert.equal(alerts.length, 3);
  const user = store.userByDashboardToken(e.dashboard_url.split("/").pop()!)!;
  assert.equal(store.tripsForUser(user.id).length, 10);
  const status = (await (await app.request(path(e.status_url))).json()) as { trips: Array<{ notified: boolean }> };
  assert.equal(status.trips.filter((t) => !t.notified).length, 7);
});

test("split hosts: vault routes only answer on the decoy host, control routes only on the control host", async () => {
  const { app } = setup({ PUBLIC_URL: "https://custody.example", CONTROL_URL: "https://app.baitline.example" });
  const e = await enroll(app, { host: "app.baitline.example" });
  // app.request has no Host by default; set it explicitly.
  const onControl = await app.request(path(e.dashboard_url), { headers: { host: "app.baitline.example" } });
  assert.equal(onControl.status, 200);
  const dashOnVault = await app.request(path(e.dashboard_url), { headers: { host: "custody.example" } });
  assert.equal(dashOnVault.status, 404, "dashboard must not exist on the decoy host");
  const enrollOnVault = await app.request("/api/enroll", { method: "POST", headers: { host: "custody.example", "content-type": "application/json" }, body: "{}" });
  assert.equal(enrollOnVault.status, 404, "enroll must not exist on the decoy host");
  const landingOnVault = await app.request("/", { headers: { host: "custody.example" } });
  assert.equal(landingOnVault.status, 404);
  const vaultOnControl = await app.request(path(e.vault.login_url), { headers: { host: "app.baitline.example" } });
  assert.equal(vaultOnControl.status, 404, "vault must not exist on the control host");
  const vaultOnVault = await app.request(path(e.vault.login_url), { headers: { host: "custody.example" } });
  assert.equal(vaultOnVault.status, 200);
  assert.match(await vaultOnVault.text(), /Meridian Vault/);
  assert.equal(vaultOnVault.headers.get("cache-control"), null, "decoy pages carry no control-plane headers");
  assert.equal(onControl.headers.get("cache-control"), "no-store");
  assert.equal(onControl.headers.get("strict-transport-security"), "max-age=31536000");
});

test("brand and key prefix come from config, so the public defaults can be replaced", async () => {
  const { app } = setup({ DECOY_BRAND: "Northwind Custody", DECOY_COMPANY: "Northwind Ltd", DECOY_KEY_PREFIX: "nwc_sk_" });
  const e = await enroll(app);
  assert.equal(e.brand, "Northwind Custody");
  assert.match(e.api.key, /^nwc_sk_[0-9a-f]{40}$/);
  const page = await (await app.request(path(e.vault.login_url))).text();
  assert.match(page, /Northwind Custody/);
  assert.doesNotMatch(page, /Meridian|Baitline/);
});

test("web sign-up creates an account and shows a setup page with a QR code; test alert notifies", async () => {
  const { app, alerts } = setup();
  const landing = await app.request("/");
  assert.equal(landing.status, 200);
  assert.match(await landing.text(), /Set up my decoys/);

  const res = await app.request("/enroll", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "x-forwarded-for": OWNER },
    body: new URLSearchParams({ email: "web@example.com" }),
  });
  assert.equal(res.status, 303);
  const setupPath = res.headers.get("location")!;
  assert.match(setupPath, /^\/setup\//);
  const page = await (await app.request(setupPath)).text();
  assert.match(page, /<svg/, "QR code rendered");
  assert.match(page, /ntfy\.sh\/bl-/);
  assert.match(page, /Open the decoy vault and sign in/);
  assert.match(page, /baitline\.git/, "CLI install command shown");

  const t = await app.request(setupPath + "/test", { method: "POST" });
  assert.equal(t.status, 303);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0]!.trip.kind, "test_alert");

  const bad = await app.request("/enroll", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: "nope" }),
  });
  assert.equal(bad.status, 400);
});

test("enrollment is rate limited per IP", async () => {
  const { app } = setup({ ENROLL_PER_HOUR_PER_IP: "2" });
  const go = () =>
    app.request("/api/enroll", {
      method: "POST",
      headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.5" },
      body: JSON.stringify({ email: "a@example.com" }),
    });
  assert.equal((await go()).status, 201);
  assert.equal((await go()).status, 201);
  assert.equal((await go()).status, 429);
});

test("/api/me returns everything the desktop client needs to link to a web-created account", async () => {
  const { app } = setup();
  const e = await enroll(app);
  const me = (await (await app.request(path(e.me_url))).json()) as AccountView;
  assert.equal(me.email, "victim@example.com");
  assert.equal(me.enrolled, false);
  assert.equal(me.vault.password, e.vault.password);
  assert.equal(me.api.key, e.api.key);
  assert.equal(me.guard_url, e.guard_url);
  await onboard(app, e);
  const after = (await (await app.request(path(e.me_url))).json()) as AccountView;
  assert.equal(after.enrolled, true);
  assert.equal(after.vault.onboarding_url, null, "setup link is gone once used");
});

test("unknown slugs and tokens look like ordinary 404s", async () => {
  const { app } = setup();
  for (const p of ["/vault/doesnotexist", "/dashboard/nope", "/api/v1/nope/x"]) {
    const r = await app.request(p);
    assert.equal(r.status, 404, p);
  }
});
