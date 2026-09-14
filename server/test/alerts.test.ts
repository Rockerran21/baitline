import { test } from "node:test";
import assert from "node:assert/strict";
import { alertBody, alertTitle, fanout, ntfyNotifier, webhookNotifier, type AlertPayload } from "../src/alerts.ts";
import { loadConfig } from "../src/config.ts";
import type { Trip, User } from "../src/db.ts";

const user: User = {
  id: 1, email: "v@example.com", ntfy_topic: "tw-topic", dashboard_token: "d", setup_token: null, slug: "s",
  enroll_ip: "1.1.1.1", enroll_ua: "x", enrolled_at: 1, created_at: 1,
};
const trip: Trip = {
  id: 1, user_id: 1, kind: "cookie_replay", severity: "high", ip: "198.51.100.77", ua: "Bot/1.0", path: "/vault/s/account", details: "{}", created_at: Date.UTC(2026, 8, 14, 3, 0, 0),
};
const payload: AlertPayload = { user, trip, dashboardUrl: "http://vault.test/dashboard/d" };

test("titles are safe to put in HTTP headers", () => {
  for (const sev of ["high", "medium", "low"] as const) {
    const t = alertTitle({ ...trip, severity: sev });
    assert.ok([...t].every((ch) => ch.charCodeAt(0) < 256), `non-Latin-1 char in title: ${t}`);
  }
});

test("ntfy notifier posts to the topic with priority, click URL and body", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response("ok");
  }) as unknown as typeof fetch;
  const cfg = loadConfig({ NTFY_BASE: "https://ntfy.example/" });
  await ntfyNotifier(cfg, fakeFetch)(payload);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, "https://ntfy.example/tw-topic");
  const h = calls[0]!.init.headers as Record<string, string>;
  assert.equal(h.Priority, "urgent");
  assert.equal(h.Click, payload.dashboardUrl);
  assert.match(String(calls[0]!.init.body), /198\.51\.100\.77/);
  // Headers must be constructible: this is what blew up with the emoji title.
  assert.doesNotThrow(() => new Headers(h));
});

test("ntfy notifier is a no-op without a topic", async () => {
  let called = 0;
  const fakeFetch = (async () => {
    called++;
    return new Response("ok");
  }) as unknown as typeof fetch;
  await ntfyNotifier(loadConfig({}), fakeFetch)({ ...payload, user: { ...user, ntfy_topic: null } });
  assert.equal(called, 0);
});

test("webhook notifier sends JSON and fanout survives a failing channel", async () => {
  const seen: string[] = [];
  const fakeFetch = (async (_url: string | URL | Request, init?: RequestInit) => {
    seen.push(String(init?.body));
    return new Response("ok");
  }) as unknown as typeof fetch;
  const cfg = loadConfig({ ALERT_WEBHOOK_URL: "https://hook.example/x" });
  const boom = async () => {
    throw new Error("smtp down");
  };
  await fanout([boom, webhookNotifier(cfg, fakeFetch)])(payload);
  assert.equal(seen.length, 1);
  const body = JSON.parse(seen[0]!) as { severity: string; kind: string };
  assert.equal(body.severity, "high");
  assert.equal(body.kind, "cookie_replay");
});

test("high severity body tells the user the device is compromised", () => {
  assert.match(alertBody(payload), /Treat the device .* as compromised/);
});
