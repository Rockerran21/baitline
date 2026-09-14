import { test } from "node:test";
import assert from "node:assert/strict";
import { Store } from "../src/db.ts";
import { loadConfig } from "../src/config.ts";
import { createApp, type EnrollResponse } from "../src/app.ts";
import type { AlertPayload } from "../src/alerts.ts";

const OWNER = "203.0.113.10";
const ATTACKER = "198.51.100.77";

function setup() {
  const store = new Store(":memory:");
  const cfg = loadConfig({ PUBLIC_URL: "http://vault.test", DB_PATH: ":memory:" });
  const alerts: AlertPayload[] = [];
  const app = createApp(store, cfg, async (p) => {
    alerts.push(p);
  });
  return { store, cfg, app, alerts };
}

async function enroll(app: ReturnType<typeof setup>["app"]): Promise<EnrollResponse> {
  const res = await app.request("/api/enroll", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "victim@example.com", ntfy_topic: "tw-test-topic" }),
  });
  assert.equal(res.status, 201);
  return (await res.json()) as EnrollResponse;
}

function path(url: string): string {
  return new URL(url).pathname + new URL(url).search;
}

async function onboard(app: ReturnType<typeof setup>["app"], e: EnrollResponse): Promise<string> {
  const setupToken = new URL(e.vault.onboarding_url).searchParams.get("setup")!;
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
  assert.match(e.vault.onboarding_url, /\?setup=/);

  const cookie = await onboard(app, e);
  assert.ok(cookie.length > 20);
  assert.equal(alerts.length, 0);

  // Owner lands on the welcome page right after: still no alert (grace period).
  const acct = await app.request(path(e.vault.login_url) + "/account?welcome=1", {
    headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": OWNER },
  });
  assert.equal(acct.status, 200);
  assert.match(await acct.text(), /Baitline setup complete/);
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
    headers: { "x-api-key": e.api.key, "x-forwarded-for": ATTACKER },
  });
  assert.equal(viaHeader.status, 200);
  assert.equal(alerts.length, 2);
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

test("unknown slugs and tokens look like ordinary 404s", async () => {
  const { app } = setup();
  for (const p of ["/vault/doesnotexist", "/dashboard/nope", "/api/v1/nope/x"]) {
    const r = await app.request(p);
    assert.equal(r.status, 404, p);
  }
});
