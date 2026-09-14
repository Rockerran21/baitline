import assert from "node:assert/strict";
import { Store } from "../../src/db.ts";
import { loadConfig } from "../../src/config.ts";
import { createApp } from "../../src/app.ts";
import type { AlertPayload, Mailer } from "../../src/alerts.ts";

export const CONTROL = "http://ctrl.test";

export function harness(env: Record<string, string> = {}, mailer: Mailer | null = null, fetchImpl: typeof fetch = fetch) {
  const store = new Store(":memory:");
  const cfg = loadConfig({ PUBLIC_URL: CONTROL, DB_PATH: ":memory:", ...env });
  const alerts: AlertPayload[] = [];
  const app = createApp(
    store,
    cfg,
    async (p) => {
      alerts.push(p);
    },
    mailer,
    fetchImpl,
  );
  return { store, cfg, app, alerts };
}

/** A tiny cookie jar so tests behave like one browser. */
export class Jar {
  cookies = new Map<string, string>();
  absorb(res: Response) {
    for (const sc of res.headers.getSetCookie()) {
      const [pair, ...attrs] = sc.split(";");
      const [name, ...rest] = pair!.split("=");
      const value = rest.join("=");
      const gone = attrs.some((a) => /max-age=0/i.test(a.trim()));
      if (gone || value === "") this.cookies.delete(name!.trim());
      else this.cookies.set(name!.trim(), value);
    }
  }
  header(): Record<string, string> {
    return this.cookies.size ? { cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ") } : {};
  }
}

type App = ReturnType<typeof harness>["app"];

export async function go(app: App, jar: Jar, path: string, init: RequestInit & { headers?: Record<string, string> } = {}): Promise<Response> {
  const res = await app.request(path, { ...init, headers: { ...jar.header(), ...(init.headers ?? {}) } });
  jar.absorb(res);
  return res;
}

export function form(fields: Record<string, string>, extra: Record<string, string> = {}) {
  return { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...extra }, body: new URLSearchParams(fields) };
}

export function json(body: unknown, extra: Record<string, string> = {}) {
  return { method: "POST", headers: { "content-type": "application/json", ...extra }, body: JSON.stringify(body) };
}

/** Pull the dev-mode sign-in link out of a page (no mail server in tests). */
export function linkFrom(html: string): string {
  const m = /\/login\/magic\?t=([A-Za-z0-9_-]+)/.exec(html);
  assert.ok(m, "no sign-in link in page");
  return `/login/magic?t=${m![1]}`;
}

/** Open a sign-in link the way a person does: the GET shows a Continue button, the POST redeems. */
export async function follow(app: App, jar: Jar, link: string, headers: Record<string, string> = {}): Promise<Response> {
  const page = await go(app, jar, link, { headers });
  assert.equal(page.status, 200, "link page renders");
  const t = /name="t" value="([^"]+)"/.exec(await page.text());
  assert.ok(t, "continue form carries the token");
  return go(app, jar, "/login/magic", form({ t: t![1]! }, headers));
}

/** Request a link for an email and follow it. Creates the account on first use. */
export async function signIn(app: App, jar: Jar, email: string): Promise<Response> {
  const page = await go(app, jar, "/login/email", form({ email }));
  assert.equal(page.status, 200);
  const res = await follow(app, jar, linkFrom(await page.text()));
  assert.equal(res.status, 303);
  return res;
}

/** Complete the vault onboarding step for the signed-in user; returns the decoy session cookie value. */
export async function onboard(app: App, jar: Jar, ownerIp: string): Promise<{ cookie: string; loginPath: string }> {
  const setup = await (await go(app, jar, "/setup")).text();
  const m = /href="(?:https?:\/\/[^/"]+)?(\/vault\/[^"?]+)\?setup=([^"]+)"/.exec(setup);
  assert.ok(m, "setup page has the onboarding link");
  const loginPath = m![1]!;
  const page = await (await app.request(`${loginPath}?setup=${m![2]}`)).text();
  const u = /name="username"[^>]*value="([^"]*)"/.exec(page)![1]!;
  const p = /name="password"[^>]*value="([^"]*)"/.exec(page)![1]!;
  const res = await app.request(`${loginPath}/login`, form({ username: u, password: p, setup: m![2]! }, { "x-forwarded-for": ownerIp, "user-agent": "OwnerBrowser" }));
  assert.equal(res.status, 303);
  const c = /sv_session=([^;]+)/.exec(res.headers.get("set-cookie") ?? "");
  assert.ok(c, "decoy cookie set");
  return { cookie: c![1]!, loginPath };
}
