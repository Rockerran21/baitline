import { Hono, type Context, type Next } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { getConnInfo } from "@hono/node-server/conninfo";
import QRCode from "qrcode";
import type { Config } from "./config.ts";
import { Store, type Org, type OrgRole, type Session, type Severity, type TripKind, type User } from "./db.ts";
import { decoyApiKey, decoyBalanceUsd, decoyCookieValue, decoyPassword, decoySeedPhrase, decoyUsername, randomNtfyTopic, randomSlug, randomToken } from "./decoys.ts";
import { orgChannels, type Mailer, type Notifier } from "./alerts.ts";
import {
  SESSION_COOKIE,
  authenticationOptions,
  generateRecoveryCodes,
  isFresh,
  issueToken,
  needsMfa,
  readSession,
  redeemToken,
  registrationOptions,
  startSession,
  useRecoveryCode,
  verifyAuthentication,
  verifyRegistration,
} from "./auth.ts";
import { finishSignIn, startSignIn } from "./oidc.ts";
import { checkLdapUrl, ldapAuthenticate } from "./ldap.ts";
import {
  accountPage,
  dashboardPage,
  landingPage,
  mfaPage,
  notFoundPage,
  orgAuditPage,
  orgLoginPage,
  orgPage,
  orgSettingsPage,
  reauthPage,
  setupPage,
  vaultAccountPage,
  vaultLoginPage,
  type MemberRow,
} from "./pages.ts";

const COOKIE = "sv_session";
const FRESH = "sv_fresh";
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const INVITE_MS = 7 * 24 * 60 * 60 * 1000;

/** What the desktop client receives once, in exchange for a device code. */
export interface Account {
  email: string;
  brand: string;
  company: string;
  ntfy_topic: string | null;
  ntfy_subscribe_url: string | null;
  setup_url: string;
  status_url: string;
  guard_url: string;
  enrolled: boolean;
  vault: { onboarding_url: string | null; login_url: string; username: string; password: string };
  api: { base: string; key: string };
  wallet: { seed_phrase: string };
}

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

type Vars = { session: Session | null; user: User | null };
type App = Hono<{ Variables: Vars }>;
type Ctx = Context<{ Variables: Vars }>;

export function createApp(store: Store, cfg: Config, notify: Notifier, mailer: Mailer | null = null, fetchImpl: typeof fetch = fetch): App {
  const app: App = new Hono();
  const secure = cfg.controlUrl.startsWith("https://");
  const decoyHost = new URL(cfg.publicUrl).host;
  const controlHost = new URL(cfg.controlUrl).host;
  const splitHosts = decoyHost !== controlHost;
  const HOUR = 3600_000;
  const linkLimiter = new RateLimiter(cfg.enrollPerHourPerIp, HOUR);
  const linkPerEmail = new RateLimiter(5, HOUR);
  const loginLimiter = new RateLimiter(10, HOUR);
  const ldapPerUser = new RateLimiter(5, HOUR);

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

  function safeNext(n: string | undefined | null): string {
    return n && n.startsWith("/") && !n.startsWith("//") ? n : "/dashboard";
  }

  async function deliver(payload: Parameters<Notifier>[0], notifiers: Notifier[]) {
    const results = await Promise.allSettled(notifiers.map((n) => n(payload)));
    for (const r of results) if (r.status === "rejected") console.error("[alert] notify failed:", r.reason);
  }

  /**
   * Record a trip; notify unless throttled. The person gets it on their own channels.
   * A family owner gets a copy with the member's name. An organisation gets a copy on
   * its own channels only, so nobody hears the same alert twice.
   */
  async function trip(user: User, kind: TripKind, severity: Severity, c: Context, details: Record<string, unknown> = {}) {
    const { ip, ua } = client(c);
    const now = Date.now();
    const prev = kind === "test_alert" ? undefined : store.lastTripFrom(user.id, kind, ip);
    const t = store.addTrip({ user_id: user.id, kind, severity, ip, ua, path: c.req.path, details: JSON.stringify(details) });
    const dup = prev !== undefined && now - prev.created_at < cfg.alertDedupeMs;
    const capped = store.notifiedSince(user.id, now - HOUR) >= cfg.alertHourlyCap;
    if (dup || capped) return;
    store.markNotified(t.id);
    t.notified = 1;
    const dashboardUrl = `${cfg.controlUrl}/dashboard`;
    const label = user.label || user.email;
    const jobs: Promise<void>[] = [deliver({ user, trip: t, dashboardUrl }, [notify])];
    const owner = user.parent_id !== null ? store.userById(user.parent_id) : undefined;
    if (owner) jobs.push(deliver({ user: owner, trip: t, dashboardUrl, label }, [notify]));
    const org = user.org_id !== null ? store.org(user.org_id) : undefined;
    if (org) {
      const channels = orgChannels(org, mailer, fetchImpl);
      if (channels.length) jobs.push(deliver({ user, trip: t, dashboardUrl, label }, channels));
    }
    await Promise.all(jobs);
  }

  function accountFor(user: User): Account {
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
      setup_url: `${cfg.controlUrl}/setup`,
      status_url: `${cfg.controlUrl}/api/status/${user.guard_token}`,
      guard_url: `${cfg.controlUrl}/api/guard/${user.guard_token}`,
      enrolled: user.enrolled_at !== null,
      vault: { onboarding_url: user.setup_token ? `${loginUrl}?setup=${user.setup_token}` : null, login_url: loginUrl, username, password: pw?.secret ?? "" },
      api: { base: `${cfg.publicUrl}/api/v1/${user.slug}`, key: api?.secret ?? "" },
      wallet: { seed_phrase: wallet?.secret ?? "" },
    };
  }

  function createUser(email: string, opts: { parentId?: number; orgId?: number; role?: OrgRole; label?: string } = {}): User {
    const user = store.createUser({
      parent_id: opts.parentId ?? null,
      org_id: opts.orgId ?? null,
      org_role: opts.role ?? null,
      label: opts.label ?? "",
      email,
      ntfy_topic: randomNtfyTopic(),
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

  /** Email a one-time sign-in link. Without a mail server (development) the link is returned so the page can show it. */
  async function sendLink(user: User, purpose: "signin" | "invite", ttl = cfg.magicLinkMs): Promise<string | null> {
    const raw = issueToken(store, user, purpose, ttl);
    const url = `${cfg.controlUrl}/login/magic?t=${raw}`;
    if (!mailer) {
      console.log(`[dev] ${purpose} link for ${user.email}: ${url}`);
      return url;
    }
    const subject = purpose === "invite" ? "You have been added to Baitline" : "Your Baitline sign-in link";
    const text =
      purpose === "invite"
        ? `Someone who looks after your security added you to Baitline. Open this link on your computer to finish setup:\n\n${url}\n\nIt works once and expires in 7 days.`
        : `Sign in to Baitline:\n\n${url}\n\nThe link works once and expires in 15 minutes. If you did not ask for it, ignore this email.`;
    await mailer.send(user.email, subject, text);
    return null;
  }

  function setSessionCookie(c: Context, secret: string) {
    setCookie(c, SESSION_COOKIE, secret, { path: "/", httpOnly: true, sameSite: "Lax", secure, maxAge: Math.floor(cfg.sessionMaxMs / 1000) });
  }

  /** Sign a user in after a first factor. Returns where to send them. */
  function signIn(c: Ctx, user: User, next: string, opts: { mfaDone?: boolean } = {}): string {
    const mfaDone = opts.mfaDone ?? !needsMfa(store, user.id);
    setSessionCookie(c, startSession(store, cfg, user, mfaDone));
    return mfaDone ? next : `/login/mfa?next=${encodeURIComponent(next)}`;
  }

  function orgMemberRows(users: User[]): MemberRow[] {
    return users.map((m) => ({
      id: m.id,
      label: m.label || m.email,
      email: m.email,
      enrolled: m.enrolled_at !== null,
      high: store.tripsForUser(m.id).filter((t) => t.severity === "high").length,
    }));
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

  /** Control-plane pages: never cached, never referred, never indexed, and cross-site POSTs are refused. */
  const control = async (c: Ctx, next: Next) => {
    if (splitHosts && (c.req.header("host") ?? "") !== controlHost) return c.html(notFoundPage(), 404);
    if (c.req.method !== "GET" && c.req.method !== "HEAD") {
      const origin = c.req.header("origin");
      if (origin && origin !== cfg.rpOrigin) return c.text("cross-site request refused", 403);
    }
    const loaded = readSession(store, cfg, getCookie(c, SESSION_COOKIE));
    c.set("session", loaded?.session ?? null);
    c.set("user", loaded?.user ?? null);
    await next();
    c.header("Cache-Control", "no-store");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Robots-Tag", "noindex");
  };

  const requireAuth = async (c: Ctx, next: Next) => {
    const s = c.get("session");
    if (!s) return c.redirect(`/?next=${encodeURIComponent(c.req.path)}`, 303);
    if (!s.mfa_done) return c.redirect(`/login/mfa?next=${encodeURIComponent(c.req.path)}`, 303);
    await next();
  };

  /** Sensitive actions: a sign-in within the last few minutes, so a stolen session cookie alone is not enough. */
  const requireFresh = async (c: Ctx, next: Next) => {
    const s = c.get("session")!;
    if (!isFresh(s, cfg)) {
      const back = c.req.header("referer") && new URL(c.req.header("referer")!).origin === cfg.rpOrigin ? new URL(c.req.header("referer")!).pathname : "/dashboard";
      return c.redirect(`/login/reauth?next=${encodeURIComponent(back)}`, 303);
    }
    await next();
  };

  const requireOrgAdmin = async (c: Ctx, next: Next) => {
    const u = c.get("user")!;
    if (u.org_id === null || u.org_role !== "admin") return c.html(notFoundPage(), 404);
    await next();
  };

  app.get("/healthz", (c) => c.text("ok"));

  // ------------------------------------------------------------- sign-in

  app.get("/", control, (c) => {
    if (c.get("session")?.mfa_done) return c.redirect("/dashboard", 303);
    return c.html(landingPage({ notice: c.req.query("deleted") === "1" ? "Your account and all its decoys were deleted." : undefined }));
  });

  app.post("/login/email", control, async (c) => {
    const { ip } = client(c);
    const form = await c.req.parseBody();
    const email = String(form.email ?? "").trim();
    if (!EMAIL_RE.test(email)) return c.html(landingPage({ error: "That email does not look right." }), 400);
    if (!linkLimiter.allow(ip) || !linkPerEmail.allow(email.toLowerCase())) return c.html(landingPage({ sent: true }));
    let user = store.userByEmail(email);
    if (!user) user = createUser(email);
    const devLink = await sendLink(user, "signin");
    return c.html(landingPage({ sent: true, devLink: devLink ?? undefined }));
  });

  app.get("/login/magic", control, (c) => {
    const raw = c.req.query("t") ?? "";
    const user = raw ? redeemToken(store, ["signin", "invite"], raw) : undefined;
    if (!user) return c.html(landingPage({ error: "That link is invalid or has expired. Ask for a new one." }), 400);
    const current = c.get("session");
    if (current && current.user_id === user.id) {
      // Already signed in as this person: the link proves it is still them. Refresh, no new session.
      store.completeMfa(current.id, Date.now());
      return c.redirect(safeNext(c.req.query("next")), 303);
    }
    const next = user.enrolled_at === null ? "/setup" : "/dashboard";
    return c.redirect(signIn(c, user, next), 303);
  });

  app.post("/login/passkey/options", control, async (c) => c.json(await authenticationOptions(store, cfg, null)));
  app.post("/login/passkey/verify", control, async (c) => {
    const { ip } = client(c);
    if (!loginLimiter.allow(ip)) return c.text("too many attempts", 429);
    try {
      const body = (await c.req.json()) as { flow: string; response: Parameters<typeof verifyAuthentication>[3] };
      const { user, userVerified } = await verifyAuthentication(store, cfg, body.flow, body.response);
      if (!userVerified) return c.text("this passkey did not verify you", 401);
      return c.json({ next: signIn(c, user, user.enrolled_at === null ? "/setup" : "/dashboard", { mfaDone: true }) });
    } catch (err) {
      return c.text((err as Error).message, 401);
    }
  });

  app.get("/login/mfa", control, (c) => {
    const s = c.get("session");
    if (!s) return c.redirect("/", 303);
    if (s.mfa_done) return c.redirect(safeNext(c.req.query("next")), 303);
    return c.html(mfaPage({ error: c.req.query("error") ?? undefined }));
  });
  app.post("/login/mfa/options", control, async (c) => {
    const u = c.get("user");
    if (!u) return c.text("not signed in", 401);
    return c.json(await authenticationOptions(store, cfg, u));
  });
  app.post("/login/mfa/verify", control, async (c) => {
    const s = c.get("session");
    const u = c.get("user");
    if (!s || !u) return c.text("not signed in", 401);
    try {
      const body = (await c.req.json()) as { flow: string; response: Parameters<typeof verifyAuthentication>[3] };
      const { user } = await verifyAuthentication(store, cfg, body.flow, body.response);
      if (user.id !== u.id) return c.text("wrong account", 401);
      store.completeMfa(s.id, Date.now());
      return c.json({ next: safeNext(c.req.query("next")) });
    } catch (err) {
      return c.text((err as Error).message, 401);
    }
  });
  app.post("/login/mfa/recovery", control, async (c) => {
    const s = c.get("session");
    const u = c.get("user");
    if (!s || !u) return c.redirect("/", 303);
    const { ip } = client(c);
    const form = await c.req.parseBody();
    if (!loginLimiter.allow(ip) || !useRecoveryCode(store, u.id, String(form.code ?? ""))) {
      return c.redirect("/login/mfa?error=" + encodeURIComponent("That code is not valid."), 303);
    }
    store.completeMfa(s.id, Date.now());
    store.audit(u.org_id, u.id, "auth.recovery_code_used");
    return c.redirect("/account?notice=" + encodeURIComponent("Signed in with a recovery code. Add a new passkey if the old one is gone."), 303);
  });

  app.get("/login/reauth", control, requireAuth, (c) => {
    const u = c.get("user")!;
    return c.html(reauthPage({ next: safeNext(c.req.query("next")), hasPasskey: needsMfa(store, u.id), sent: c.req.query("sent") === "1", devLink: c.req.query("dev") ?? undefined }));
  });
  app.post("/login/reauth/email", control, requireAuth, async (c) => {
    const u = c.get("user")!;
    const form = await c.req.parseBody();
    const next = safeNext(String(form.next ?? ""));
    const { ip } = client(c);
    const dev = linkLimiter.allow(ip) && linkPerEmail.allow(u.email.toLowerCase()) ? await sendLink(u, "signin") : null;
    return c.redirect(`/login/reauth?next=${encodeURIComponent(next)}&sent=1${dev ? `&dev=${encodeURIComponent(dev)}` : ""}`, 303);
  });
  app.post("/login/reauth/verify", control, requireAuth, async (c) => {
    const s = c.get("session")!;
    const u = c.get("user")!;
    try {
      const body = (await c.req.json()) as { flow: string; response: Parameters<typeof verifyAuthentication>[3] };
      const { user } = await verifyAuthentication(store, cfg, body.flow, body.response);
      if (user.id !== u.id) return c.text("wrong account", 401);
      store.completeMfa(s.id, Date.now());
      return c.json({ next: safeNext(c.req.query("next")) });
    } catch (err) {
      return c.text((err as Error).message, 401);
    }
  });

  app.post("/logout", control, (c) => {
    const s = c.get("session");
    if (s) store.deleteSession(s.id);
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
    return c.redirect("/", 303);
  });

  // ------------------------------------------------------ organisation sign-in

  function orgOrNotFound(c: Ctx): Org | undefined {
    return store.orgBySlug(c.req.param("slug") ?? "");
  }

  /** Map an identity-provider email to a user of this org, creating a member on first sight. */
  function resolveOrgUser(org: Org, email: string, via: string): User {
    if (org.oidc_email_domain && via === "oidc" && !email.toLowerCase().endsWith(`@${org.oidc_email_domain.toLowerCase()}`)) {
      throw new Error(`only ${org.oidc_email_domain} accounts can sign in here`);
    }
    const existing = store.userByEmail(email);
    if (existing) {
      if (existing.org_id !== org.id) throw new Error("that email belongs to a different Baitline account");
      return existing;
    }
    const user = createUser(email, { orgId: org.id, role: "member", label: email });
    store.audit(org.id, null, `member.provisioned.${via}`, email);
    return user;
  }

  app.get("/o/:slug", control, (c) => {
    const org = orgOrNotFound(c);
    if (!org) return c.html(notFoundPage(), 404);
    return c.html(orgLoginPage(org, { next: safeNext(c.req.query("next")), error: c.req.query("error") ?? undefined }));
  });

  app.get("/o/:slug/oidc/start", control, async (c) => {
    const org = orgOrNotFound(c);
    if (!org || !org.oidc_issuer) return c.html(notFoundPage(), 404);
    try {
      const url = await startSignIn(org, `${cfg.controlUrl}/o/${org.slug}/oidc/callback`, safeNext(c.req.query("next")));
      return c.redirect(url.toString(), 303);
    } catch (err) {
      console.error("[oidc] start failed:", err);
      return c.redirect(`/o/${org.slug}?error=${encodeURIComponent("Single sign-on is not reachable right now.")}`, 303);
    }
  });

  app.get("/o/:slug/oidc/callback", control, async (c) => {
    const org = orgOrNotFound(c);
    if (!org) return c.html(notFoundPage(), 404);
    try {
      const { claims, next } = await finishSignIn(org, new URL(c.req.url, cfg.controlUrl));
      if (!claims.emailVerified) throw new Error("the identity provider has not verified this email address");
      const user = resolveOrgUser(org, claims.email, "oidc");
      store.audit(org.id, user.id, "auth.oidc", claims.sub);
      return c.redirect(signIn(c, user, user.enrolled_at === null ? "/setup" : next), 303);
    } catch (err) {
      return c.redirect(`/o/${org.slug}?error=${encodeURIComponent((err as Error).message)}`, 303);
    }
  });

  app.post("/o/:slug/ldap", control, async (c) => {
    const org = orgOrNotFound(c);
    if (!org || !org.ldap_url) return c.html(notFoundPage(), 404);
    const form = await c.req.parseBody();
    const username = String(form.username ?? "");
    const password = String(form.password ?? "");
    const next = safeNext(String(form.next ?? ""));
    const { ip } = client(c);
    if (!loginLimiter.allow(ip) || !ldapPerUser.allow(`${org.id}:${username.toLowerCase()}`)) {
      return c.redirect(`/o/${org.slug}?error=${encodeURIComponent("Too many attempts. Try again later.")}`, 303);
    }
    try {
      const { email } = await ldapAuthenticate(org, username, password);
      const user = resolveOrgUser(org, email, "ldap");
      store.audit(org.id, user.id, "auth.ldap", username);
      return c.redirect(signIn(c, user, user.enrolled_at === null ? "/setup" : next), 303);
    } catch (err) {
      return c.redirect(`/o/${org.slug}?error=${encodeURIComponent((err as Error).message)}`, 303);
    }
  });

  // --------------------------------------------------------- signed-in pages

  app.get("/setup", control, requireAuth, async (c) => {
    const user = c.get("user")!;
    const a = accountFor(user);
    const subscribe = a.ntfy_subscribe_url ?? "";
    const svg = subscribe ? await QRCode.toString(subscribe.replace(/^https?:\/\//, "ntfy://"), { type: "svg", margin: 1, errorCorrectionLevel: "M" }) : "";
    const code = issueToken(store, user, "device", cfg.magicLinkMs);
    return c.html(
      setupPage({
        user,
        onboardingUrl: a.vault.onboarding_url,
        ntfySubscribeUrl: subscribe,
        ntfyQrSvg: svg,
        testSent: c.req.query("test") === "1",
        hasSmtp: mailer !== null,
        cliCommand: `git clone https://github.com/Rockerran21/baitline.git && cd baitline && npm install --silent && node client/src/cli.ts setup --server ${cfg.controlUrl} --link ${code}`,
      }),
    );
  });

  const sendTest = (back: string) => async (c: Ctx) => {
    await trip(c.get("user")!, "test_alert", "low", c);
    return c.redirect(back, 303);
  };
  app.post("/setup/test", control, requireAuth, sendTest("/setup?test=1"));
  app.post("/dashboard/test", control, requireAuth, sendTest("/dashboard?test=1"));

  app.get("/dashboard", control, requireAuth, (c) => {
    const user = c.get("user")!;
    const members = user.parent_id === null ? store.membersOf(user.id) : [];
    const memberTrips = members.flatMap((m) => store.tripsForUser(m.id).map((t) => ({ ...t, who: m.label || m.email })));
    const trips = [...store.tripsForUser(user.id).map((t) => ({ ...t, who: "" })), ...memberTrips].sort((a, b) => b.created_at - a.created_at);
    return c.html(
      dashboardPage({
        user,
        decoys: store.decoysForUser(user.id),
        trips,
        guard: store.guardEventsForUser(user.id),
        members: orgMemberRows(members),
        org: user.org_id !== null ? (store.org(user.org_id) ?? null) : null,
        testSent: c.req.query("test") === "1",
        notice: c.req.query("notice") ?? undefined,
        error: c.req.query("error") ?? undefined,
      }),
    );
  });

  // family
  app.post("/dashboard/members", control, requireAuth, requireFresh, async (c) => {
    const owner = c.get("user")!;
    if (owner.parent_id !== null || owner.org_id !== null) return c.html(notFoundPage(), 404);
    const form = await c.req.parseBody();
    const label = String(form.label ?? "").trim().slice(0, 40);
    const email = String(form.email ?? "").trim();
    if (!label || !EMAIL_RE.test(email)) return c.redirect("/dashboard?error=member", 303);
    if (store.membersOf(owner.id).length >= 10) return c.redirect("/dashboard?error=members-full", 303);
    if (store.userByEmail(email)) return c.redirect("/dashboard?error=exists", 303);
    const member = createUser(email, { parentId: owner.id, label });
    const dev = await sendLink(member, "invite", INVITE_MS);
    return c.redirect(`/dashboard?notice=${encodeURIComponent(dev ? `Invite link for ${label}: ${dev}` : `Invite sent to ${email}`)}`, 303);
  });
  app.post("/dashboard/members/:id/invite", control, requireAuth, async (c) => {
    const owner = c.get("user")!;
    const m = store.userById(Number(c.req.param("id")));
    if (!m || m.parent_id !== owner.id) return c.html(notFoundPage(), 404);
    const dev = await sendLink(m, "invite", INVITE_MS);
    return c.redirect(`/dashboard?notice=${encodeURIComponent(dev ? `Invite link for ${m.label}: ${dev}` : `Invite sent to ${m.email}`)}`, 303);
  });
  app.post("/dashboard/members/:id/remove", control, requireAuth, requireFresh, (c) => {
    const owner = c.get("user")!;
    const m = store.userById(Number(c.req.param("id")));
    if (!m || m.parent_id !== owner.id) return c.html(notFoundPage(), 404);
    store.deleteUser(m.id);
    return c.redirect(`/dashboard?notice=${encodeURIComponent(`${m.label} removed`)}`, 303);
  });

  // account
  app.get("/account", control, requireAuth, (c) => {
    const u = c.get("user")!;
    return c.html(accountPage({ user: u, passkeys: store.passkeysFor(u.id), codesLeft: store.recoveryCodesLeft(u.id), notice: c.req.query("notice") ?? undefined, error: c.req.query("error") ?? undefined }));
  });
  app.post("/account/passkeys/options", control, requireAuth, async (c) => c.json(await registrationOptions(store, cfg, c.get("user")!)));
  app.post("/account/passkeys/verify", control, requireAuth, async (c) => {
    const u = c.get("user")!;
    const s = c.get("session")!;
    try {
      const body = (await c.req.json()) as { flow: string; name?: string; response: Parameters<typeof verifyRegistration>[4] };
      const pk = await verifyRegistration(store, cfg, u, body.flow, body.response, String(body.name ?? ""));
      store.completeMfa(s.id, Date.now());
      store.audit(u.org_id, u.id, "passkey.added", pk.name);
      return c.json({ ok: true, id: pk.id });
    } catch (err) {
      return c.text((err as Error).message, 400);
    }
  });
  app.post("/account/passkeys/:id/delete", control, requireAuth, requireFresh, (c) => {
    const u = c.get("user")!;
    if (store.deletePasskey(Number(c.req.param("id")), u.id)) store.audit(u.org_id, u.id, "passkey.removed");
    return c.redirect("/account", 303);
  });
  app.post("/account/recovery", control, requireAuth, requireFresh, (c) => {
    const u = c.get("user")!;
    const codes = generateRecoveryCodes(store, u.id);
    store.audit(u.org_id, u.id, "recovery.regenerated");
    return c.html(accountPage({ user: u, passkeys: store.passkeysFor(u.id), codesLeft: codes.length, newCodes: codes }));
  });
  app.post("/account/delete", control, requireAuth, requireFresh, async (c) => {
    const u = c.get("user")!;
    const form = await c.req.parseBody();
    if (String(form.confirm ?? "") !== "DELETE") return c.redirect("/account?error=" + encodeURIComponent("Type DELETE exactly to delete the account."), 303);
    store.audit(u.org_id, u.id, "account.deleted", u.email);
    store.deleteUser(u.id);
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
    return c.redirect("/?deleted=1", 303);
  });

  // organisation
  app.get("/org", control, requireAuth, (c) => {
    const u = c.get("user")!;
    const org = u.org_id !== null ? (store.org(u.org_id) ?? null) : null;
    return c.html(orgPage({ user: u, org, members: org ? orgMemberRows(store.orgMembers(org.id)) : [], controlUrl: cfg.controlUrl, notice: c.req.query("notice") ?? undefined, error: c.req.query("error") ?? undefined }));
  });
  app.post("/org/create", control, requireAuth, requireFresh, async (c) => {
    const u = c.get("user")!;
    if (u.org_id !== null || u.parent_id !== null) return c.redirect("/org?error=" + encodeURIComponent("This account already belongs to a plan."), 303);
    const form = await c.req.parseBody();
    const name = String(form.name ?? "").trim().slice(0, 60);
    if (!name) return c.redirect("/org?error=" + encodeURIComponent("Give the organisation a name."), 303);
    const slug = `${name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "org"}-${randomSlug(3)}`;
    const org = store.createOrg(name, slug);
    store.setOrg(u.id, org.id, "admin", u.email);
    store.audit(org.id, u.id, "org.created", name);
    return c.redirect("/org", 303);
  });
  app.post("/org/members", control, requireAuth, requireOrgAdmin, requireFresh, async (c) => {
    const admin = c.get("user")!;
    const form = await c.req.parseBody();
    const label = String(form.label ?? "").trim().slice(0, 40);
    const email = String(form.email ?? "").trim();
    if (!label || !EMAIL_RE.test(email)) return c.redirect("/org?error=" + encodeURIComponent("A name and a valid work email are needed."), 303);
    if (store.userByEmail(email)) return c.redirect("/org?error=" + encodeURIComponent("That email already has a Baitline account."), 303);
    const m = createUser(email, { orgId: admin.org_id!, role: "member", label });
    store.audit(admin.org_id, admin.id, "member.added", email);
    const dev = await sendLink(m, "invite", INVITE_MS);
    return c.redirect(`/org?notice=${encodeURIComponent(dev ? `Invite link for ${label}: ${dev}` : `Invite sent to ${email}`)}`, 303);
  });
  app.post("/org/members/:id/invite", control, requireAuth, requireOrgAdmin, async (c) => {
    const admin = c.get("user")!;
    const m = store.userById(Number(c.req.param("id")));
    if (!m || m.org_id !== admin.org_id) return c.html(notFoundPage(), 404);
    const dev = await sendLink(m, "invite", INVITE_MS);
    return c.redirect(`/org?notice=${encodeURIComponent(dev ? `Invite link for ${m.label}: ${dev}` : `Invite sent to ${m.email}`)}`, 303);
  });
  app.post("/org/members/:id/remove", control, requireAuth, requireOrgAdmin, requireFresh, (c) => {
    const admin = c.get("user")!;
    const m = store.userById(Number(c.req.param("id")));
    if (!m || m.org_id !== admin.org_id || m.id === admin.id) return c.html(notFoundPage(), 404);
    store.audit(admin.org_id, admin.id, "member.removed", m.email);
    store.deleteUser(m.id);
    return c.redirect(`/org?notice=${encodeURIComponent(`${m.label || m.email} removed`)}`, 303);
  });
  app.get("/org/settings", control, requireAuth, requireOrgAdmin, (c) => {
    const u = c.get("user")!;
    return c.html(orgSettingsPage({ user: u, org: store.org(u.org_id!)!, controlUrl: cfg.controlUrl, notice: c.req.query("notice") ?? undefined }));
  });
  app.post("/org/settings", control, requireAuth, requireOrgAdmin, requireFresh, async (c) => {
    const u = c.get("user")!;
    const org = store.org(u.org_id!)!;
    const form = await c.req.parseBody();
    const str = (k: string) => String(form[k] ?? "").trim() || null;
    const fields = {
      oidc_issuer: str("oidc_issuer"),
      oidc_client_id: str("oidc_client_id"),
      oidc_client_secret: str("oidc_client_secret"),
      oidc_email_domain: str("oidc_email_domain")?.replace(/^@/, "").toLowerCase() ?? null,
      ldap_url: str("ldap_url"),
      ldap_user_dn: str("ldap_user_dn"),
      ldap_email_attr: str("ldap_email_attr") ?? "mail",
      alert_webhook_url: str("alert_webhook_url"),
      alert_email: str("alert_email"),
    };
    try {
      if (fields.oidc_issuer) {
        const issuer = new URL(fields.oidc_issuer);
        if (issuer.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(issuer.hostname)) throw new Error("the issuer must be https");
        if (!fields.oidc_client_id || !fields.oidc_client_secret) throw new Error("single sign-on needs a client ID and secret");
      }
      if (fields.ldap_url) {
        checkLdapUrl(fields.ldap_url);
        if (!fields.ldap_user_dn?.includes("{username}")) throw new Error("the user DN template must contain {username}");
      }
      if (fields.alert_webhook_url && !/^https:\/\//.test(fields.alert_webhook_url) && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(fields.alert_webhook_url)) throw new Error("the webhook must be https");
      if (fields.alert_email && !EMAIL_RE.test(fields.alert_email)) throw new Error("the security mailbox is not a valid email");
    } catch (err) {
      return c.html(orgSettingsPage({ user: u, org: { ...org, ...fields }, controlUrl: cfg.controlUrl, error: (err as Error).message }), 400);
    }
    store.updateOrg(org.id, fields);
    store.audit(org.id, u.id, "org.settings.updated");
    return c.redirect("/org/settings?notice=" + encodeURIComponent("Saved."), 303);
  });
  app.get("/org/audit", control, requireAuth, requireOrgAdmin, (c) => {
    const u = c.get("user")!;
    const org = store.org(u.org_id!)!;
    const actors = new Map(store.orgMembers(org.id).map((m) => [m.id, m.email]));
    return c.html(orgAuditPage({ user: u, org, entries: store.auditFor(org.id), actors }));
  });

  // ------------------------------------------------------------ client API

  /** The desktop client trades a one-time device code for its secrets. This is the only path that returns them. */
  app.post("/api/link", control, async (c) => {
    let body: { code?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid json" }, 400);
    }
    const user = body.code ? redeemToken(store, "device", body.code) : undefined;
    if (!user) return c.json({ error: "that code is invalid or expired; open the setup page for a new one" }, 401);
    return c.json(accountFor(user));
  });

  app.get("/api/status/:token", onControl, (c) => {
    const user = store.userByGuardToken(c.req.param("token") ?? "");
    if (!user) return c.json({ error: "not found" }, 404);
    const trips = store.tripsForUser(user.id).filter((t) => t.kind !== "test_alert");
    return c.json({
      email: user.email,
      enrolled: user.enrolled_at !== null,
      decoys: store.decoysForUser(user.id).map((d) => d.kind),
      high_severity_trips: trips.filter((t) => t.severity === "high").length,
      trips: trips.map((t) => ({ at: t.created_at, kind: t.kind, severity: t.severity, ip: t.ip, ua: t.ua, notified: t.notified === 1 })),
      guard_events: store.guardEventsForUser(user.id).length,
    });
  });

  app.post("/api/guard/:token", onControl, async (c) => {
    const user = store.userByGuardToken(c.req.param("token") ?? "");
    if (!user) return c.json({ error: "not found" }, 404);
    let body: { host?: string; source_app?: string; rule?: string; sample?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid json" }, 400);
    }
    store.addGuardEvent({ user_id: user.id, host: String(body.host ?? "").slice(0, 120), source_app: String(body.source_app ?? "").slice(0, 120), rule: String(body.rule ?? "").slice(0, 80), sample: String(body.sample ?? "").slice(0, 300) });
    return c.json({ ok: true }, 201);
  });

  // ----------------------------------------------------------- decoy vault

  const brand = { brand: cfg.brand, company: cfg.company };

  app.get("/vault/:slug", onDecoy, async (c) => {
    const user = store.userBySlug(c.req.param("slug") ?? "");
    if (!user) return c.html(notFoundPage(), 404);
    const a = accountFor(user);
    const setup = c.req.query("setup") ?? null;
    const validSetup = setup !== null && user.setup_token !== null && setup === user.setup_token;
    const { ip } = client(c);
    if (user.enrolled_at !== null && !ownerGrace(user, ip)) await trip(user, "vault_visit", "low", c);
    return c.html(vaultLoginPage(brand, { slug: user.slug, username: a.vault.username, password: validSetup ? a.vault.password : "", setup: validSetup ? setup : null }));
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
      if (onboarding) store.markEnrolled(user.id, ip, ua);
      else {
        await trip(user, "credential_use", "high", c, { username });
        setCookie(c, FRESH, "1", { path: cookiePath, httpOnly: true, sameSite: "Lax", secure: cfg.publicUrl.startsWith("https://"), maxAge: 120 });
      }
      setCookie(c, COOKIE, cookie.secret, { path: cookiePath, httpOnly: true, sameSite: "Lax", secure: cfg.publicUrl.startsWith("https://"), maxAge: 400 * 24 * 3600 });
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
    const a = accountFor(user);
    const { ip } = client(c);
    const fresh = getCookie(c, FRESH) === "1";
    const welcome = c.req.query("welcome") === "1" && ownerGrace(user, ip);
    if (!welcome && !fresh && !ownerGrace(user, ip)) await trip(user, "cookie_replay", "high", c);
    return c.html(vaultAccountPage(brand, { username: a.vault.username, balance: decoyBalanceUsd(), welcome, setupUrl: welcome ? a.setup_url : null }));
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
