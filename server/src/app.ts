import { Hono, type Context, type Next } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { getConnInfo } from "@hono/node-server/conninfo";
import QRCode from "qrcode";
import type { Config } from "./config.ts";
import { Store, type Severity, type TripKind, type User } from "./db.ts";
import {
  decoyApiKey,
  decoyBalanceUsd,
  decoyCookieValue,
  decoyPassword,
  decoySeedPhrase,
  decoyUsername,
  randomNtfyTopic,
  randomSlug,
  randomToken,
} from "./decoys.ts";
import type { Notifier } from "./alerts.ts";
import { dashboardPage, landingPage, notFoundPage, setupPage, vaultAccountPage, vaultLoginPage } from "./pages.ts";

const COOKIE = "sv_session";
const FRESH = "sv_fresh";

/** Everything the desktop client needs. Returned by enroll and by /api/me. */
export interface AccountView {
  email: string;
  brand: string;
  company: string;
  ntfy_topic: string | null;
  ntfy_subscribe_url: string | null;
  setup_url: string;
  dashboard_url: string;
  status_url: string;
  me_url: string;
  guard_url: string;
  enrolled: boolean;
  vault: { onboarding_url: string | null; login_url: string; username: string; password: string };
  api: { base: string; key: string };
  wallet: { seed_phrase: string };
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

class RateLimiter {
  private hits = new Map<string, number[]>();
  private max: number;
  private windowMs: number;
  constructor(max: number, windowMs: number) {
    this.max = max;
    this.windowMs = windowMs;
  }
  allow(key: string, now = Date.now()): boolean {
    const arr = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (arr.length >= this.max) {
      this.hits.set(key, arr);
      return false;
    }
    arr.push(now);
    this.hits.set(key, arr);
    return true;
  }
}

export function createApp(store: Store, cfg: Config, notify: Notifier): Hono {
  const app = new Hono();
  const secure = cfg.publicUrl.startsWith("https://");
  const decoyHost = new URL(cfg.publicUrl).host;
  const controlHost = new URL(cfg.controlUrl).host;
  const splitHosts = decoyHost !== controlHost;
  const enrollLimiter = new RateLimiter(cfg.enrollPerHourPerIp, 3600_000);

  // ------------------------------------------------------------------ helpers

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
    return user.enrolled_at !== null && user.enroll_ip === ip && Date.now() - user.enrolled_at < cfg.onboardingGraceMs;
  }

  /**
   * Record a trip and decide whether to notify. Every trip is stored. Notifications are
   * skipped when the same (kind, ip) fired inside the dedupe window, or when the hourly
   * cap is reached, so an attacker who finds the vault URL cannot turn it into a siren.
   */
  async function trip(user: User, kind: TripKind, severity: Severity, c: Context, details: Record<string, unknown> = {}) {
    const { ip, ua } = client(c);
    const now = Date.now();
    const prev = kind === "test_alert" ? undefined : store.lastTripFrom(user.id, kind, ip);
    const t = store.addTrip({ user_id: user.id, kind, severity, ip, ua, path: c.req.path, details: JSON.stringify(details) });
    const dup = prev !== undefined && now - prev.created_at < cfg.alertDedupeMs;
    const capped = store.notifiedSince(user.id, now - 3600_000) >= cfg.alertHourlyCap;
    if (dup || capped) return;
    store.markNotified(t.id);
    t.notified = 1;
    try {
      await notify({ user, trip: t, dashboardUrl: `${cfg.controlUrl}/dashboard/${user.dashboard_token}` });
    } catch (err) {
      console.error("[alert] notify failed:", err);
    }
  }

  function accountView(user: User): AccountView {
    const decoys = store.decoysForUser(user.id);
    const pw = decoys.find((d) => d.kind === "browser_password");
    const api = decoys.find((d) => d.kind === "api_key");
    const wallet = decoys.find((d) => d.kind === "wallet_file");
    const username = String((JSON.parse(pw?.meta ?? "{}") as { username?: string }).username ?? "");
    const loginUrl = `${cfg.publicUrl}/vault/${user.slug}`;
    return {
      email: user.email,
      brand: cfg.brand,
      company: cfg.company,
      ntfy_topic: user.ntfy_topic,
      ntfy_subscribe_url: user.ntfy_topic ? `${cfg.ntfyBase}/${user.ntfy_topic}` : null,
      setup_url: `${cfg.controlUrl}/setup/${user.dashboard_token}`,
      dashboard_url: `${cfg.controlUrl}/dashboard/${user.dashboard_token}`,
      status_url: `${cfg.controlUrl}/api/status/${user.dashboard_token}`,
      me_url: `${cfg.controlUrl}/api/me/${user.dashboard_token}`,
      guard_url: `${cfg.controlUrl}/api/guard/${user.guard_token}`,
      enrolled: user.enrolled_at !== null,
      vault: {
        onboarding_url: user.setup_token ? `${loginUrl}?setup=${user.setup_token}` : null,
        login_url: loginUrl,
        username,
        password: pw?.secret ?? "",
      },
      api: { base: `${cfg.publicUrl}/api/v1/${user.slug}`, key: api?.secret ?? "" },
      wallet: { seed_phrase: wallet?.secret ?? "" },
    };
  }

  function createAccount(email: string, ntfyTopic: string | null): User {
    const user = store.createUser({
      email,
      ntfy_topic: ntfyTopic ?? randomNtfyTopic(),
      dashboard_token: randomToken(),
      guard_token: randomToken(),
      setup_token: randomToken(),
      slug: randomSlug(),
      enroll_ip: null,
      enroll_ua: null,
      enrolled_at: null,
    });
    store.addDecoy(user.id, "browser_password", decoyPassword(), { username: decoyUsername() });
    store.addDecoy(user.id, "session_cookie", decoyCookieValue(), {});
    store.addDecoy(user.id, "api_key", decoyApiKey(cfg.keyPrefix), {});
    store.addDecoy(user.id, "wallet_file", decoySeedPhrase(), {});
    return user;
  }

  function cliInstall(): string {
    return `git clone https://github.com/Rockerran21/baitline.git && cd baitline && npm install --silent && node client/src/cli.ts setup --server ${cfg.controlUrl}`;
  }

  async function renderSetup(c: Context, user: User, testSent: boolean) {
    const view = accountView(user);
    const subscribe = view.ntfy_subscribe_url ?? "";
    const deepLink = subscribe.replace(/^https?:\/\//, "ntfy://");
    const svg = subscribe ? await QRCode.toString(deepLink, { type: "svg", margin: 1, errorCorrectionLevel: "M" }) : "";
    return c.html(
      setupPage({
        user,
        dashboardUrl: view.dashboard_url,
        onboardingUrl: view.vault.onboarding_url,
        ntfySubscribeUrl: subscribe,
        ntfyQrSvg: svg,
        testSent,
        hasSmtp: cfg.smtpUrl !== null,
        cliInstall: cliInstall(),
      }),
    );
  }

  // ------------------------------------------------------------ middleware

  const onHost = (host: string) => async (c: Context, next: Next) => {
    if (splitHosts && (c.req.header("host") ?? "") !== host) return c.html(notFoundPage(), 404);
    await next();
  };
  const onDecoy = onHost(decoyHost);
  const onControl = onHost(controlHost);

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    if (secure) c.header("Strict-Transport-Security", "max-age=31536000");
  });
  const privatePage = async (c: Context, next: Next) => {
    await next();
    c.header("Cache-Control", "no-store");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Robots-Tag", "noindex");
  };

  app.get("/healthz", (c) => c.text("ok"));

  // --------------------------------------------------------- control plane

  app.get("/", onControl, privatePage, (c) => c.html(landingPage({})));

  app.post("/enroll", onControl, privatePage, async (c) => {
    const { ip } = client(c);
    if (!enrollLimiter.allow(ip)) return c.html(landingPage({ error: "Too many sign-ups from this address. Try again later." }), 429);
    const form = await c.req.parseBody();
    const email = String(form.email ?? "").trim();
    if (!EMAIL_RE.test(email)) return c.html(landingPage({ error: "That email does not look right." }), 400);
    const user = createAccount(email, null);
    return c.redirect(`/setup/${user.dashboard_token}`, 303);
  });

  app.post("/api/enroll", onControl, privatePage, async (c) => {
    const { ip } = client(c);
    if (!enrollLimiter.allow(ip)) return c.json({ error: "rate limited" }, 429);
    let body: { email?: string; ntfy_topic?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid json" }, 400);
    }
    const email = (body.email ?? "").trim();
    if (!EMAIL_RE.test(email)) return c.json({ error: "valid email required" }, 400);
    const ntfy = body.ntfy_topic?.trim() || null;
    if (ntfy && !/^[A-Za-z0-9_-]{6,64}$/.test(ntfy)) return c.json({ error: "ntfy_topic must be 6-64 chars [A-Za-z0-9_-]" }, 400);
    const user = createAccount(email, ntfy);
    return c.json(accountView(user), 201);
  });

  app.get("/setup/:token", onControl, privatePage, async (c) => {
    const user = store.userByDashboardToken(c.req.param("token") ?? "");
    if (!user) return c.html(notFoundPage(), 404);
    return renderSetup(c, user, c.req.query("test") === "1");
  });

  const sendTest = (back: (u: User) => string) => async (c: Context) => {
    const user = store.userByDashboardToken(c.req.param("token") ?? "");
    if (!user) return c.html(notFoundPage(), 404);
    await trip(user, "test_alert", "low", c);
    return c.redirect(back(user), 303);
  };
  app.post("/setup/:token/test", onControl, privatePage, sendTest((u) => `/setup/${u.dashboard_token}?test=1`));
  app.post("/dashboard/:token/test", onControl, privatePage, sendTest((u) => `/dashboard/${u.dashboard_token}?test=1`));

  app.get("/dashboard/:token", onControl, privatePage, (c) => {
    const user = store.userByDashboardToken(c.req.param("token") ?? "");
    if (!user) return c.html(notFoundPage(), 404);
    return c.html(
      dashboardPage({
        user,
        decoys: store.decoysForUser(user.id),
        trips: store.tripsForUser(user.id),
        guard: store.guardEventsForUser(user.id),
        setupUrl: `${cfg.controlUrl}/setup/${user.dashboard_token}`,
        testSent: c.req.query("test") === "1",
      }),
    );
  });

  app.get("/api/me/:token", onControl, privatePage, (c) => {
    const user = store.userByDashboardToken(c.req.param("token") ?? "");
    if (!user) return c.json({ error: "not found" }, 404);
    return c.json(accountView(user));
  });

  app.get("/api/status/:token", onControl, privatePage, (c) => {
    const user = store.userByDashboardToken(c.req.param("token") ?? "");
    if (!user) return c.json({ error: "not found" }, 404);
    const trips = store.tripsForUser(user.id).filter((t) => t.kind !== "test_alert");
    return c.json({
      email: user.email,
      enrolled: user.enrolled_at !== null,
      enrolled_at: user.enrolled_at,
      decoys: store.decoysForUser(user.id).map((d) => d.kind),
      high_severity_trips: trips.filter((t) => t.severity === "high").length,
      trips: trips.map((t) => ({ at: t.created_at, kind: t.kind, severity: t.severity, ip: t.ip, ua: t.ua, notified: t.notified === 1 })),
      guard_events: store.guardEventsForUser(user.id).length,
    });
  });

  /** Write-only. The guard token cannot read anything, so a stolen client config reveals nothing. */
  app.post("/api/guard/:token", onControl, privatePage, async (c) => {
    const user = store.userByGuardToken(c.req.param("token") ?? "");
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

  // ----------------------------------------------------------- decoy vault

  const brand = { brand: cfg.brand, company: cfg.company };

  app.get("/vault/:slug", onDecoy, async (c) => {
    const user = store.userBySlug(c.req.param("slug") ?? "");
    if (!user) return c.html(notFoundPage(), 404);
    const view = accountView(user);
    const setup = c.req.query("setup") ?? null;
    const validSetup = setup !== null && user.setup_token !== null && setup === user.setup_token;
    const { ip } = client(c);
    if (user.enrolled_at !== null && !ownerGrace(user, ip)) await trip(user, "vault_visit", "low", c);
    return c.html(
      vaultLoginPage(brand, { slug: user.slug, username: view.vault.username, password: validSetup ? view.vault.password : "", setup: validSetup ? setup : null }),
    );
  });

  app.post("/vault/:slug/login", onDecoy, async (c) => {
    const user = store.userBySlug(c.req.param("slug") ?? "");
    if (!user) return c.html(notFoundPage(), 404);
    const form = await c.req.parseBody();
    const username = String(form.username ?? "");
    const password = String(form.password ?? "");
    const setup = form.setup ? String(form.setup) : null;
    const decoys = store.decoysForUser(user.id);
    const pw = decoys.find((d) => d.kind === "browser_password");
    const cookie = decoys.find((d) => d.kind === "session_cookie");
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
    return c.html(vaultLoginPage(brand, { slug: user.slug, username: username || knownUser, password: "", setup: null, error: "Incorrect username or password." }), 401);
  });

  app.get("/vault/:slug/account", onDecoy, async (c) => {
    const user = store.userBySlug(c.req.param("slug") ?? "");
    if (!user) return c.html(notFoundPage(), 404);
    const cookie = store.decoysForUser(user.id).find((d) => d.kind === "session_cookie");
    const presented = getCookie(c, COOKIE);
    if (!cookie || !presented || presented !== cookie.secret) return c.redirect(`/vault/${user.slug}`, 303);
    const view = accountView(user);
    const { ip } = client(c);
    const fresh = getCookie(c, FRESH) === "1";
    const welcome = c.req.query("welcome") === "1" && ownerGrace(user, ip);
    if (!welcome && !fresh && !ownerGrace(user, ip)) await trip(user, "cookie_replay", "high", c);
    return c.html(vaultAccountPage(brand, { username: view.vault.username, balance: decoyBalanceUsd(), welcome, setupUrl: welcome ? view.setup_url : null }));
  });

  app.all("/api/v1/:slug/*", onDecoy, async (c) => {
    const user = store.userBySlug(c.req.param("slug") ?? "");
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

  app.notFound((c) => c.html(notFoundPage(), 404));
  return app;
}
