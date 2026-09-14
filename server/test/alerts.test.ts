import { test } from "node:test";
import assert from "node:assert/strict";
import { alertBody, alertTitle, emailNotifier, fanout, ntfyNotifier, type AlertPayload, type Mailer } from "../src/alerts.ts";
import { loadConfig } from "../src/config.ts";
import type { Trip, User } from "../src/db.ts";

const user: User = {
  id: 1, parent_id: null, org_id: null, org_role: null, label: "", email: "v@example.com", ntfy_topic: "tw-topic", guard_token: "g", setup_token: null, slug: "s",
  enroll_ip: "1.1.1.1", enroll_ua: "x", enrolled_at: 1, seed_manifest: null, created_at: 1,
};
const trip: Trip = {
  id: 1, user_id: 1, kind: "cookie_replay", severity: "high", ip: "198.51.100.77", ua: "Bot/1.0", path: "/vault/s/account", details: "{}", notified: 1, notify_attempts: 1, created_at: Date.UTC(2026, 8, 14, 3, 0, 0),
};
const payload: AlertPayload = { user, trip, dashboardUrl: "http://vault.test/dashboard/d" };

test("titles are safe to put in HTTP headers, even with a member label containing emoji", () => {
  for (const sev of ["high", "medium", "low"] as const) {
    const t = alertTitle({ ...trip, severity: sev }, "Mom's 💻");
    assert.ok([...t].every((ch) => ch.charCodeAt(0) < 256), `non-Latin-1 char in title: ${t}`);
    assert.doesNotThrow(() => new Headers({ Title: t }));
  }
  assert.match(alertTitle(trip, "Mom"), /^\[TRIPPED\] Mom: /);
  assert.match(alertBody({ ...payload, label: "Mom" }), /^Mom: /);
});

test("ntfy notifier posts to the topic with priority, click URL and body; a non-2xx response is a failure, not a delivery", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let status = 200;
  const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response("ok", { status });
  }) as unknown as typeof fetch;
  const cfg = loadConfig({ NTFY_BASE: "https://ntfy.example/" });
  assert.equal(await ntfyNotifier(cfg, fakeFetch)(payload), true);
  status = 503;
  await assert.rejects(ntfyNotifier(cfg, fakeFetch)(payload), /503/);
  status = 429;
  await assert.rejects(ntfyNotifier(cfg, fakeFetch)(payload), /429/);
  assert.equal(calls.length, 3);
  assert.equal(calls[0]!.url, "https://ntfy.example/tw-topic");
  const h = calls[0]!.init.headers as Record<string, string>;
  assert.equal(h.Priority, "urgent");
  assert.equal(h.Click, payload.dashboardUrl);
  assert.match(String(calls[0]!.init.body), /198\.51\.100\.77/);
  // Headers must be constructible: this is what blew up with the emoji title.
  assert.doesNotThrow(() => new Headers(h));
});

test("ntfy notifier is a no-op without a topic and reports no delivery", async () => {
  let called = 0;
  const fakeFetch = (async () => {
    called++;
    return new Response("ok");
  }) as unknown as typeof fetch;
  assert.equal(await ntfyNotifier(loadConfig({}), fakeFetch)({ ...payload, user: { ...user, ntfy_topic: null } }), false);
  assert.equal(called, 0);
});

test("fanout reports delivery only when some channel accepted; the console log never counts", async () => {
  const boom = async () => {
    throw new Error("smtp down");
  };
  const ok = async () => true;
  const no = async () => false;
  assert.equal(await fanout([boom, ok])(payload), true);
  assert.equal(await fanout([boom, no])(payload), false);
  assert.equal(await fanout([])(payload), false);
});

test("high severity body tells the user the device is compromised", () => {
  assert.match(alertBody(payload), /Treat the device .* as compromised/);
});

test("email notifier sends to the recipient with the labelled title", async () => {
  const sent: Array<{ to: string; subject: string }> = [];
  const mailer: Mailer = { send: async (to, subject) => void sent.push({ to, subject }) };
  assert.equal(await emailNotifier(mailer)({ ...payload, label: "Dad" }), true);
  assert.deepEqual(sent, [{ to: "v@example.com", subject: "[TRIPPED] Dad: Your decoy session cookie was REPLAYED" }]);
  assert.equal(await emailNotifier(null)(payload), false);
  assert.equal(sent.length, 1);
});
