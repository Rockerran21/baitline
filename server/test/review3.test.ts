/** Regression tests for the third adversarial pass of 2026-09-15. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../src/db.ts";
import { issueToken, sha256 } from "../src/auth.ts";
import { assertPublicUrl } from "../src/netguard.ts";
import { Jar, follow, form, go, harness, json, linkFrom, signIn } from "./helpers/harness.ts";

test("T1. a next path that a browser would resolve off-site falls back to the dashboard", async () => {
  const { app, store, cfg } = harness();
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const user = store.userByEmail("victim@example.test")!;
  for (const next of ["/\\evil.example", "//evil.example", "/\\\\evil.example/x", "/ /evil", "http://evil.example", "/dashboard\\@evil"]) {
    const token = issueToken(store, user, "signin", cfg.magicLinkMs);
    const res = await go(app, jar, "/login/magic", form({ t: token, next }));
    assert.equal(res.headers.get("location"), "/dashboard", next);
  }
  const token = issueToken(store, user, "signin", cfg.magicLinkMs);
  assert.equal((await go(app, jar, "/login/magic", form({ t: token, next: "/account?notice=hi" }))).headers.get("location"), "/account?notice=hi");
});

test("T2/T3. only the one-time setup token writes the manifest; the device token cannot; paths and kinds are checked", async () => {
  const { app, store } = harness();
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const user = store.userByEmail("victim@example.test")!;
  const legit = [{ path: "/home/victim/Documents/passwords.txt", kind: "passwords_file", sha256: "a".repeat(64) }];
  assert.equal((await app.request(`/api/guard/${user.guard_token}/manifest`, json({ files: [] }))).status, 404, "old device-token route is gone");
  assert.equal((await app.request("/api/manifest/put", json({ token: user.guard_token, files: [] }))).status, 401, "device token is not a manifest token");
  const token = issueToken(store, user, "manifest", 60_000);
  assert.equal((await app.request("/api/manifest/put", json({ token, files: legit }))).status, 201);
  assert.equal((await app.request("/api/manifest/put", json({ token, files: [] }))).status, 401, "single use");
  assert.equal(store.userById(user.id)!.seed_manifest, JSON.stringify(legit));
  // A second setup run keeps what it does not mention and refuses kinds or paths we never plant.
  const again = issueToken(store, user, "manifest", 60_000);
  const more = [
    { path: "/home/victim/Desktop/wallet-recovery-phrase.txt", kind: "wallet_file", sha256: "b".repeat(64) },
    { path: "/home/victim/valuable.txt", kind: "anything", sha256: "c".repeat(64) },
    { path: "relative/passwords.txt", kind: "passwords_file", sha256: "d".repeat(64) },
  ];
  assert.equal((await app.request("/api/manifest/put", json({ token: again, files: more }))).status, 201);
  assert.deepEqual(JSON.parse(store.userById(user.id)!.seed_manifest!), [legit[0], more[0]]);
});

test("T4. the server keeps the manifest until the client confirms cleanup", async () => {
  const { app, store } = harness();
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  const user = store.userByEmail("victim@example.test")!;
  store.setManifest(user.id, JSON.stringify([{ path: "/offline/device/file", kind: "wallet_file", sha256: "b".repeat(64) }]));
  const code = issueToken(store, user, "reset", 60_000);
  const read = await app.request("/api/manifest", json({ code }));
  assert.equal(read.status, 200);
  const { files, done } = (await read.json()) as { files: unknown[]; done: string };
  assert.equal(files.length, 1);
  assert.notEqual(store.userById(user.id)!.seed_manifest, null, "still there if the client crashes now");
  // A fresh code reads the same list again; only the confirmation clears it.
  const code2 = issueToken(store, user, "reset", 60_000);
  assert.equal((await app.request("/api/manifest", json({ code: code2 }))).status, 200);
  assert.equal((await app.request("/api/manifest/done", json({ done: user.guard_token }))).status, 401);
  assert.equal((await app.request("/api/manifest/done", json({ done }))).status, 200);
  assert.equal(store.userById(user.id)!.seed_manifest, null);
  assert.equal((await app.request("/api/manifest/done", json({ done }))).status, 401, "single use");
});

test("T5. the database directory and files are owner-only regardless of umask", { skip: process.platform === "win32" }, () => {
  const root = mkdtempSync(join(tmpdir(), "baitline-db-"));
  const path = join(root, "data", "baitline.db");
  const old = process.umask(0o022);
  try {
    const store = new Store(path);
    store.createUser({ parent_id: null, org_id: null, org_role: null, label: "", email: "a@b.c", ntfy_topic: "t", slug: "s", guard_token: "g", setup_token: null, enroll_ip: null, enroll_ua: null, enrolled_at: null, seed_manifest: null });
    assert.equal(statSync(`${path}-wal`).mode & 0o777, 0o600, "WAL inherits the main file's mode");
    store.close();
  } finally {
    process.umask(old);
  }
  assert.equal(statSync(join(root, "data")).mode & 0o777, 0o700);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test("T6. development mode relaxes scheme and pinning for loopback only", async () => {
  const dev = { schemes: ["https:"], allowLocal: true, resolve: async () => ["93.184.216.34"] };
  await assertPublicUrl("http://localhost:1234/hook", dev);
  await assertPublicUrl("http://127.0.0.1:9/hook", dev);
  await assertPublicUrl("http://[::1]:9/hook", dev);
  await assertPublicUrl("ldap://127.0.0.1:3390/dc=x", { ...dev, schemes: ["ldaps:"] });
  await assert.rejects(assertPublicUrl("ftp://localhost/x", dev), /https/, "loopback still needs the scheme or its plaintext twin");
  await assert.rejects(assertPublicUrl("http://public.example.test/issuer", dev), /https/);
  await assert.rejects(assertPublicUrl("ldap://203.0.113.10/dc=example", { ...dev, schemes: ["ldaps:"] }), /ldaps/);
  await assert.rejects(assertPublicUrl("https://169.254.169.254/latest/meta-data/", dev), /private or internal/);
  await assert.rejects(assertPublicUrl("https://[::ffff:127.0.0.1]/x", dev), /private or internal/);
  assert.equal((await assertPublicUrl("https://public.example.test/issuer", dev)).address, "93.184.216.34", "everything else is resolved and pinned");
});

test("T7. the setup page and its device code need a fresh sign-in", async () => {
  const { app, store } = harness({ FRESH_MS: "1000" });
  const jar = new Jar();
  await signIn(app, jar, "victim@example.test");
  assert.equal((await go(app, jar, "/setup")).status, 200);
  const sid = sha256(jar.cookies.get("bl_session")!);
  store.db.prepare("UPDATE sessions SET authenticated_at = ? WHERE id = ?").run(Date.now() - 10_000, sid);
  const stale = await go(app, jar, "/setup");
  assert.equal(stale.status, 303);
  assert.equal(stale.headers.get("location"), "/login/reauth?next=%2Fsetup");
  assert.equal((await go(app, jar, "/dashboard")).status, 200, "the dashboard itself still works");
});

test("T8. invite resend needs a fresh sign-in and is limited per member", async () => {
  let sent = 0;
  const inbox: string[] = [];
  const mailer = { async send(_to: string, _subject: string, body: string) { sent++; inbox.push(body); } };
  const { app, store } = harness({}, mailer);
  const owner = new Jar();
  await go(app, owner, "/login/email", form({ email: "owner@example.test" }));
  await follow(app, owner, linkFrom(inbox.at(-1)!));
  await go(app, owner, "/dashboard/members", form({ label: "Member", email: "member@example.test" }));
  const member = store.userByEmail("member@example.test")!;
  const before = sent;
  for (let i = 0; i < 10; i++) await go(app, owner, `/dashboard/members/${member.id}/invite`, { method: "POST" });
  assert.equal(sent - before, 5, "five resends an hour per address");
  const sid = sha256(owner.cookies.get("bl_session")!);
  store.db.prepare("UPDATE sessions SET authenticated_at = ? WHERE id = ?").run(Date.now() - 60 * 60_000, sid);
  const stale = await go(app, owner, `/dashboard/members/${member.id}/invite`, { method: "POST" });
  assert.match(stale.headers.get("location")!, /^\/login\/reauth/);
  assert.equal(sent - before, 5);
});
