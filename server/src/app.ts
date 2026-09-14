import { Hono, type Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { getConnInfo } from "@hono/node-server/conninfo";
import type { Config } from "./config.ts";
import { Store, type Severity, type TripKind, type User } from "./db.ts";
import {
  decoyApiKey,
  decoyBalanceUsd,
  decoyCookieValue,
  decoyPassword,
  decoySeedPhrase,
  decoyUsername,
  randomSlug,
  randomToken,
} from "./decoys.ts";
import type { Notifier } from "./alerts.ts";
import { dashboardPage, notFoundPage, vaultAccountPage, vaultLoginPage } from "./pages.ts";

const COOKIE = "sv_session";
const FRESH = "sv_fresh";

export interface EnrollResponse {
  dashboard_url: string;
  status_url: string;
  guard_url: string;
  vault: { onboarding_url: string; login_url: string; username: string; password: string };
  api: { base: string; key: string };
  wallet: { seed_phrase: string };
}

export function createApp(store: Store, cfg: Config, notify: Notifier): Hono {
  const app = new Hono();
  const secure = cfg.publicUrl.startsWith("https://");

  function client(c: Context): { ip: string; ua: string } {
    const xff = c.req.header("x-forwarded-for");
    let ip = xff?.split(",")[0]?.trim() ?? "";
    if (!ip) {
      try {
        ip = getConnInfo(c).remote.address ?? "";
      } catch {
        ip = "";
      }
    }
    return { ip: ip || "unknown", ua: c.req.header("user-agent") ?? "" };
  }

  function ownerGrace(user: User, ip: string): boolean {
    return (
      user.enrolled_at !== null && user.enroll_ip === ip && Date.now() - user.enrolled_at < cfg.onboardingGraceMs
    );
  }

  async function trip(user: User, kind: TripKind, severity: Severity, c: Context, details: Record<string, unknown> = {}) {
    const { ip, ua } = client(c);
    const t = store.addTrip({ user_id: user.id, kind, severity, ip, ua, path: c.req.path, details: JSON.stringify(details) });
    const dashboardUrl = `${cfg.publicUrl}/dashboard/${user.dashboard_token}`;
    try {
      await notify({ user, trip: t, dashboardUrl });
    } catch (err) {
      console.error("[alert] notify failed:", err);
    }
  }

  app.get("/healthz", (c) => c.text("ok"));

  app.post("/api/enroll", async (c) => {
    let body: { email?: string; ntfy_topic?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid json" }, 400);
    }
    const email = (body.email ?? "").trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return c.json({ error: "valid email required" }, 400);
    const ntfy = body.ntfy_topic?.trim() || null;
    if (ntfy && !/^[A-Za-z0-9_-]{6,64}$/.test(ntfy)) return c.json({ error: "ntfy_topic must be 6-64 chars [A-Za-z0-9_-]" }, 400);

    const user = store.createUser({
      email,
      ntfy_topic: ntfy,
      dashboard_token: randomToken(),
      setup_token: randomToken(),
      slug: randomSlug(),
      enroll_ip: null,
      enroll_ua: null,
      enrolled_at: null,
    });
    const username = decoyUsername();
    const password = decoyPassword();
    const cookie = decoyCookieValue();
    const apiKey = decoyApiKey();
    const seed = decoySeedPhrase();
    store.addDecoy(user.id, "browser_password", password, { username });
    store.addDecoy(user.id, "session_cookie", cookie, {});
    store.addDecoy(user.id, "api_key", apiKey, {});
    store.addDecoy(user.id, "wallet_file", seed, {});

    const loginUrl = `${cfg.publicUrl}/vault/${user.slug}`;
    const res: EnrollResponse = {
      dashboard_url: `${cfg.publicUrl}/dashboard/${user.dashboard_token}`,
      status_url: `${cfg.publicUrl}/api/status/${user.dashboard_token}`,
      guard_url: `${cfg.publicUrl}/api/guard/${user.dashboard_token}`,
      vault: { onboarding_url: `${loginUrl}?setup=${user.setup_token}`, login_url: loginUrl, username, password },
      api: { base: `${cfg.publicUrl}/api/v1/${user.slug}`, key: apiKey },
      wallet: { seed_phrase: seed },
    };
    return c.json(res, 201);
  });

  app.get("/vault/:slug", async (c) => {
    const user = store.userBySlug(c.req.param("slug"));
    if (!user) return c.html(notFoundPage(), 404);
    const pw = store.decoysForUser(user.id).find((d) => d.kind === "browser_password");
    const username = String((JSON.parse(pw?.meta ?? "{}") as { username?: string }).username ?? "");
    const setup = c.req.query("setup") ?? null;
    const validSetup = setup !== null && user.setup_token !== null && setup === user.setup_token;
    const { ip } = client(c);
    if (user.enrolled_at !== null && !ownerGrace(user, ip)) await trip(user, "vault_visit", "low", c);
    return c.html(
      vaultLoginPage({ slug: user.slug, username, password: validSetup ? (pw?.secret ?? "") : "", setup: validSetup ? setup : null }),
    );
  });

  app.post("/vault/:slug/login", async (c) => {
    const user = store.userBySlug(c.req.param("slug"));
    if (!user) return c.html(notFoundPage(), 404);
    const form = await c.req.parseBody();
    const username = String(form.username ?? "");
    const password = String(form.password ?? "");
    const setup = form.setup ? String(form.setup) : null;
    const pw = store.decoysForUser(user.id).find((d) => d.kind === "browser_password");
    const cookie = store.decoysForUser(user.id).find((d) => d.kind === "session_cookie");
    const { ip, ua } = client(c);
    const cookiePath = `/vault/${user.slug}`;

    if (pw && cookie && password === pw.secret) {
      const onboarding = user.enrolled_at === null && setup !== null && setup === user.setup_token;
      if (onboarding) {
        store.markEnrolled(user.id, ip, ua);
      } else {
        await trip(user, "credential_use", "high", c, { username });
        setCookie(c, FRESH, "1", { path: cookiePath, httpOnly: true, sameSite: "Lax", secure, maxAge: 120 });
      }
      setCookie(c, COOKIE, cookie.secret, { path: cookiePath, httpOnly: true, sameSite: "Lax", secure, maxAge: 400 * 24 * 3600 });
      return c.redirect(`${cookiePath}/account${onboarding ? "?welcome=1" : ""}`, 303);
    }

    if (!ownerGrace(user, ip)) await trip(user, "login_attempt", "medium", c, { username });
    const knownUser = String((JSON.parse(pw?.meta ?? "{}") as { username?: string }).username ?? "");
    return c.html(vaultLoginPage({ slug: user.slug, username: username || knownUser, password: "", setup: null, error: "Incorrect username or password." }), 401);
  });

  app.get("/vault/:slug/account", async (c) => {
    const user = store.userBySlug(c.req.param("slug"));
    if (!user) return c.html(notFoundPage(), 404);
    const cookie = store.decoysForUser(user.id).find((d) => d.kind === "session_cookie");
    const presented = getCookie(c, COOKIE);
    if (!cookie || !presented || presented !== cookie.secret) return c.redirect(`/vault/${user.slug}`, 303);
    const pw = store.decoysForUser(user.id).find((d) => d.kind === "browser_password");
    const username = String((JSON.parse(pw?.meta ?? "{}") as { username?: string }).username ?? "");
    const { ip } = client(c);
    const fresh = getCookie(c, FRESH) === "1";
    const welcome = c.req.query("welcome") === "1" && ownerGrace(user, ip);
    if (!welcome && !fresh && !ownerGrace(user, ip)) await trip(user, "cookie_replay", "high", c);
    return c.html(vaultAccountPage({ username, balance: decoyBalanceUsd(), welcome }));
  });

  app.all("/api/v1/:slug/*", async (c) => {
    const user = store.userBySlug(c.req.param("slug"));
    if (!user) return c.json({ error: "not found" }, 404);
    const auth = c.req.header("authorization") ?? "";
    const key = c.req.header("x-api-key") ?? (auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "");
    const decoy = store.decoysForUser(user.id).find((d) => d.kind === "api_key");
    if (!decoy || !key || key !== decoy.secret) return c.json({ error: "unauthorized" }, 401);
    await trip(user, "api_key_use", "high", c, { path: c.req.path, method: c.req.method });
    return c.json({
      account: { id: user.slug, tier: "custody", kyc: "verified" },
      balances: [
        { asset: "BTC", amount: "0.8412", status: "cold" },
        { asset: "ETH", amount: "14.207", status: "cold" },
        { asset: "USDC", amount: "12500.00", status: "available" },
      ],
      withdrawals: { enabled: true, hold_hours: 24 },
    });
  });

  app.get("/dashboard/:token", (c) => {
    const user = store.userByDashboardToken(c.req.param("token"));
    if (!user) return c.html(notFoundPage(), 404);
    return c.html(
      dashboardPage({
        user,
        decoys: store.decoysForUser(user.id),
        trips: store.tripsForUser(user.id),
        guard: store.guardEventsForUser(user.id),
      }),
    );
  });

  app.get("/api/status/:token", (c) => {
    const user = store.userByDashboardToken(c.req.param("token"));
    if (!user) return c.json({ error: "not found" }, 404);
    const trips = store.tripsForUser(user.id);
    return c.json({
      email: user.email,
      enrolled: user.enrolled_at !== null,
      enrolled_at: user.enrolled_at,
      decoys: store.decoysForUser(user.id).map((d) => d.kind),
      high_severity_trips: trips.filter((t) => t.severity === "high").length,
      trips: trips.map((t) => ({ at: t.created_at, kind: t.kind, severity: t.severity, ip: t.ip, ua: t.ua })),
      guard_events: store.guardEventsForUser(user.id).length,
    });
  });

  app.post("/api/guard/:token", async (c) => {
    const user = store.userByDashboardToken(c.req.param("token"));
    if (!user) return c.json({ error: "not found" }, 404);
    let body: { host?: string; source_app?: string; rule?: string; sample?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid json" }, 400);
    }
    store.addGuardEvent({
      user_id: user.id,
      host: String(body.host ?? "").slice(0, 120),
      source_app: String(body.source_app ?? "").slice(0, 120),
      rule: String(body.rule ?? "").slice(0, 80),
      sample: String(body.sample ?? "").slice(0, 300),
    });
    return c.json({ ok: true }, 201);
  });

  app.notFound((c) => c.html(notFoundPage(), 404));
  return app;
}
