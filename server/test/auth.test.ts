import { test } from "node:test";
import assert from "node:assert/strict";
import { CONTROL, Jar, follow, form, go, harness, json, linkFrom, signIn } from "./helpers/harness.ts";
import { remember } from "../src/auth.ts";
import { SoftAuthenticator } from "./helpers/authenticator.ts";
import { isFresh, readSession, sha256 } from "../src/auth.ts";

const RP_ID = "ctrl.test";

test("magic link: creates the account, signs in once, cannot be replayed, and expires", async () => {
  const { app, store, cfg } = harness();
  const jar = new Jar();
  const page = await go(app, jar, "/login/email", form({ email: "new@example.com" }));
  const link = linkFrom(await page.text());
  assert.equal(store.userByEmail("new@example.com"), undefined, "no account until the link is redeemed");

  // A mail scanner prefetching the link must not use it up or create the account.
  for (let i = 0; i < 3; i++) assert.equal((await app.request(link)).status, 200, "GET is harmless");
  assert.equal(store.userByEmail("new@example.com"), undefined, "still no account from a GET");
  assert.equal(jar.cookies.has("bl_session"), false, "no session from a GET");

  const first = await follow(app, jar, link);
  assert.equal(first.status, 303);
  assert.ok(store.userByEmail("new@example.com"), "account created at redemption");
  assert.equal(first.headers.get("location"), "/setup", "new accounts land on setup");
  assert.ok(jar.cookies.get("bl_session"));

  const replay = await follow(app, new Jar(), link);
  assert.equal(replay.status, 400, "a used link is dead");

  const dash = await go(app, jar, "/dashboard");
  assert.equal(dash.status, 200);
  assert.equal(dash.headers.get("cache-control"), "no-store");

  // Expire the session by clock.
  const loaded = readSession(store, cfg, jar.cookies.get("bl_session"), Date.now() + cfg.sessionMaxMs + 1);
  assert.equal(loaded, null);
  const after = await go(app, jar, "/dashboard");
  assert.equal(after.status, 303, "expired session redirects to sign-in");
});

test("nobody can be enumerated: an unknown address gets the same page, and links are rate limited per address", async () => {
  const { app } = harness();
  const jar = new Jar();
  const texts: string[] = [];
  for (let i = 0; i < 6; i++) texts.push(await (await go(app, jar, "/login/email", form({ email: "same@example.com" }))).text());
  assert.match(texts[0]!, /Check your email/);
  assert.match(texts[5]!, /Check your email/);
  assert.match(texts[4]!, /login\/magic/, "fifth request still gets a link");
  assert.doesNotMatch(texts[5]!, /login\/magic/, "sixth request in the hour issues no link");
});

test("bad email and cross-site POST are refused", async () => {
  const { app } = harness();
  assert.equal((await app.request("/login/email", form({ email: "nope" }))).status, 400);
  const jar = new Jar();
  await signIn(app, jar, "a@example.com");
  const evil = await go(app, jar, "/logout", { method: "POST", headers: { origin: "https://evil.example" } });
  assert.equal(evil.status, 403);
  const ok = await go(app, jar, "/logout", { method: "POST", headers: { origin: CONTROL } });
  assert.equal(ok.status, 303);
  assert.equal(jar.cookies.has("bl_session"), false, "logout clears the cookie");
});

test("passkey: register, then every sign-in needs it; passkey alone signs in; recovery code is the fallback", async () => {
  const { app, store } = harness();
  const jar = new Jar();
  await signIn(app, jar, "pk@example.com");
  const authn = new SoftAuthenticator(RP_ID, CONTROL);

  // Register from the account page.
  const opts = (await (await go(app, jar, "/account/passkeys/options", { method: "POST" })).json()) as { flow: string; options: { challenge: string } };
  const reg = await go(app, jar, "/account/passkeys/verify", json({ flow: opts.flow, name: "MacBook", response: authn.register(opts.options.challenge) }));
  assert.equal(reg.status, 200, await reg.clone().text());
  const user = store.userByEmail("pk@example.com")!;
  assert.equal(store.passkeysFor(user.id).length, 1);

  // Recovery codes need a fresh session; we just signed in, so this works.
  const codesPage = await (await go(app, jar, "/account/recovery", { method: "POST" })).text();
  const codes = [...codesPage.matchAll(/<div>([a-z0-9]{5}-[a-z0-9]{5})<\/div>/g)].map((m) => m[1]!);
  assert.equal(codes.length, 8);

  // New browser: email link alone is not enough now.
  const jar2 = new Jar();
  const res = await signIn(app, jar2, "pk@example.com");
  assert.match(res.headers.get("location")!, /^\/login\/mfa/);
  assert.equal((await go(app, jar2, "/dashboard")).status, 303, "dashboard blocked until second step");
  assert.equal((await go(app, jar2, "/dashboard")).headers.get("location")?.startsWith("/login/mfa"), true);

  // Wrong recovery code is refused; a right one is consumed once.
  const bad = await go(app, jar2, "/login/mfa/recovery", form({ code: "aaaaa-aaaaa" }));
  assert.match(bad.headers.get("location")!, /error=/);
  const good = await go(app, jar2, "/login/mfa/recovery", form({ code: codes[0]! }));
  assert.match(good.headers.get("location")!, /^\/account/);
  assert.equal((await go(app, jar2, "/dashboard")).status, 200);
  assert.equal(store.recoveryCodesLeft(user.id), 7);
  const jar2b = new Jar();
  await signIn(app, jar2b, "pk@example.com");
  const reuse = await go(app, jar2b, "/login/mfa/recovery", form({ code: codes[0]! }));
  assert.match(reuse.headers.get("location")!, /error=/, "a recovery code works once");

  // Third browser: passkey as the second step.
  const jar3 = new Jar();
  await signIn(app, jar3, "pk@example.com");
  const mo = (await (await go(app, jar3, "/login/mfa/options", { method: "POST" })).json()) as { flow: string; options: { challenge: string; allowCredentials: unknown[] } };
  assert.equal(mo.options.allowCredentials.length, 1);
  const mv = await go(app, jar3, "/login/mfa/verify", json({ flow: mo.flow, response: authn.assert(mo.options.challenge) }));
  assert.equal(mv.status, 200, await mv.clone().text());
  assert.equal((await go(app, jar3, "/dashboard")).status, 200);

  // Fourth browser: passkey alone, nothing typed. Requires user verification.
  const jar4 = new Jar();
  const po = (await (await go(app, jar4, "/login/passkey/options", { method: "POST" })).json()) as { flow: string; options: { challenge: string; userVerification: string } };
  assert.equal(po.options.userVerification, "required");
  const noUv = await go(app, jar4, "/login/passkey/verify", json({ flow: po.flow, response: authn.assert(po.options.challenge, false) }));
  assert.equal(noUv.status, 401, "without user verification a passkey is one factor, not two");
  const po2 = (await (await go(app, jar4, "/login/passkey/options", { method: "POST" })).json()) as { flow: string; options: { challenge: string } };
  const pv = await go(app, jar4, "/login/passkey/verify", json({ flow: po2.flow, response: authn.assert(po2.options.challenge) }));
  assert.equal(pv.status, 200, await pv.clone().text());
  assert.equal((await go(app, jar4, "/dashboard")).status, 200);

  // A replayed assertion (same challenge) is rejected: the challenge is single use.
  const replay = await go(app, new Jar(), "/login/passkey/verify", json({ flow: po2.flow, response: authn.assert(po2.options.challenge) }));
  assert.equal(replay.status, 401);

  // Counter went up on the stored credential.
  assert.ok(store.passkeysFor(user.id)[0]!.counter >= 3);
});

test("sensitive actions need a recent sign-in; a stolen session cookie alone cannot do them", async () => {
  const { app, store, cfg } = harness({ FRESH_MS: "1000" });
  const jar = new Jar();
  await signIn(app, jar, "fresh@example.com");
  const user = store.userByEmail("fresh@example.com")!;
  const sid = sha256(jar.cookies.get("bl_session")!);
  // Age the session's authentication.
  store.db.prepare("UPDATE sessions SET authenticated_at = ? WHERE id = ?").run(Date.now() - 5000, sid);
  assert.equal(isFresh(store.session(sid)!, cfg), false);

  const add = await go(app, jar, "/dashboard/members", form({ label: "Mom", email: "mom@example.com" }));
  assert.equal(add.status, 303);
  assert.match(add.headers.get("location")!, /^\/login\/reauth/);
  assert.equal(store.membersOf(user.id).length, 0, "nothing happened");

  const del = await go(app, jar, "/account/delete", form({ confirm: "DELETE" }));
  assert.match(del.headers.get("location")!, /^\/login\/reauth/);
  assert.ok(store.userByEmail("fresh@example.com"), "account still exists");

  // Re-auth by email link while already signed in refreshes the same session instead of creating a new one.
  const sent = await go(app, jar, "/login/reauth/email", form({ next: "/dashboard" }));
  const dev = new URL(sent.headers.get("location")!, CONTROL).searchParams.get("dev")!;
  const before = jar.cookies.get("bl_session");
  await follow(app, jar, new URL(dev).pathname + new URL(dev).search);
  assert.equal(jar.cookies.get("bl_session"), before, "same session");
  assert.equal(isFresh(store.session(sid)!, cfg), true);
  const add2 = await go(app, jar, "/dashboard/members", form({ label: "Mom", email: "mom@example.com" }));
  assert.match(add2.headers.get("location")!, /notice=/);
  assert.equal(store.membersOf(user.id).length, 1);
});

test("a signed-in user opening the home page goes to the dashboard; an unauthenticated one sees sign-in", async () => {
  const { app } = harness();
  const jar = new Jar();
  assert.match(await (await go(app, jar, "/")).text(), /Email me a sign-in link/);
  await signIn(app, jar, "home@example.com");
  assert.equal((await go(app, jar, "/")).headers.get("location"), "/dashboard");
});

test("challenge and pending maps are bounded: expired entries are swept and the oldest evicted past the cap", () => {
  const m = new Map<string, { expiresAt: number }>();
  const now = Date.now();
  for (let i = 0; i < 10; i++) remember(m, `old${i}`, { expiresAt: now - 1 }, 10);
  remember(m, "fresh", { expiresAt: now + 60_000 }, 10);
  assert.equal(m.size, 1, "expired entries swept when full");
  for (let i = 0; i < 12; i++) remember(m, `live${i}`, { expiresAt: now + 60_000 }, 10);
  assert.equal(m.size, 10, "hard cap holds");
  assert.equal(m.has("fresh"), false, "oldest evicted first");
  assert.equal(m.has("live11"), true);
});

test("purge drops expired sessions and dead tokens, keeps live ones", async () => {
  const { app, store } = harness();
  const jar = new Jar();
  await signIn(app, jar, "p@example.com");
  const user = store.userByEmail("p@example.com")!;
  store.db.prepare("INSERT INTO sessions (id, user_id, created_at, last_seen_at, authenticated_at, mfa_done, expires_at) VALUES ('dead', ?, 0, 0, 0, 1, 1)").run(user.id);
  store.putToken("expired", "signin", { userId: user.id }, 1);
  store.putToken("usedlongago", "signin", { userId: user.id }, Date.now() + 60_000);
  store.db.prepare("UPDATE one_time_tokens SET used_at = ? WHERE hash = 'usedlongago'").run(Date.now() - 2 * 86_400_000);
  store.putToken("live", "signin", { userId: user.id }, Date.now() + 60_000);
  const r = store.purge();
  assert.equal(r.sessions, 1);
  assert.equal(r.tokens, 2, "the expired one and the one used two days ago; the one used at sign-in just now is kept for the day");
  assert.ok(store.session(sha256(jar.cookies.get("bl_session")!)), "live session kept");
  assert.equal(store.useToken("live", "signin", Date.now())?.userId, user.id, "live token kept");
});
