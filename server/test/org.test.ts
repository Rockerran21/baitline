import { test } from "node:test";
import assert from "node:assert/strict";
import { Jar, follow, go, harness, linkFrom, signIn, form } from "./helpers/harness.ts";
import type { Mailer } from "../src/alerts.ts";

test("create an org, add a member by invite; the member's trip reaches the member, the org webhook and the security mailbox", async () => {
  const posted: Array<{ url: string; body: Record<string, unknown> }> = [];
  const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
    posted.push({ url: String(url), body: JSON.parse(String(init?.body)) as Record<string, unknown> });
    return new Response("ok");
  }) as unknown as typeof fetch;
  const mails: Array<{ to: string; subject: string; text: string }> = [];
  const mailer: Mailer = { send: async (to, subject, text) => void mails.push({ to, subject, text }) };
  const { app, store, alerts } = harness({}, mailer, fakeFetch);

  const admin = new Jar();
  const first = await go(app, admin, "/login/email", form({ email: "admin@acme.test" }));
  assert.equal(mails.length, 1, "with a mailer the link is emailed, not shown");
  assert.doesNotMatch(await first.text(), /login\/magic/);
  await follow(app, admin, linkFrom(mails[0]!.text));

  await go(app, admin, "/org/create", form({ name: "Acme Ltd" }));
  const org = store.org(1)!;
  assert.match(org.slug, /^acme-ltd-/);
  assert.equal(store.userByEmail("admin@acme.test")!.org_role, "admin");

  // Settings form validates and saves; audit records it.
  const bad = await go(app, admin, "/org/settings", form({ ldap_url: "ldaps://ldap.acme.test", ldap_user_dn: "uid=alice,dc=acme" }));
  assert.equal(bad.status, 400);
  assert.match(await bad.text(), /must contain \{username\}/);
  const cred = await go(app, admin, "/org/settings", form({ alert_webhook_url: "https://user:pw@hooks.example/x" }));
  assert.equal(cred.status, 400);
  const saved = await go(app, admin, "/org/settings", form({ alert_webhook_url: "https://hooks.example/siem", alert_email: "security@acme.test", ldap_email_attr: "mail" }));
  assert.equal(saved.status, 303, await saved.clone().text());
  assert.equal(store.org(org.id)!.alert_webhook_url, "https://hooks.example/siem");

  const add = await go(app, admin, "/org/members", form({ label: "Bob's laptop", email: "bob@acme.test" }));
  assert.match(decodeURIComponent(add.headers.get("location")!), /Invite sent/);
  const invite = mails.find((m) => m.to === "bob@acme.test")!;
  assert.match(invite.subject, /added to Baitline/);

  const bob = new Jar();
  const landed = await follow(app, bob, linkFrom(invite.text));
  assert.equal(landed.headers.get("location"), "/setup");
  const bobUser = store.userByEmail("bob@acme.test")!;
  assert.equal(bobUser.org_id, org.id);

  // Bob onboards and then gets robbed.
  const setup = await (await go(app, bob, "/setup")).text();
  const m = /href="(?:https?:\/\/[^/"]+)?(\/vault\/[^"?]+)\?setup=([^"]+)"/.exec(setup)!;
  const page = await (await app.request(`${m[1]}?setup=${m[2]}`)).text();
  const u = /name="username"[^>]*value="([^"]*)"/.exec(page)![1]!;
  const p = /name="password"[^>]*value="([^"]*)"/.exec(page)![1]!;
  const onb = await app.request(`${m[1]}/login`, form({ username: u, password: p, setup: m[2]! }, { "x-forwarded-for": "203.0.113.10" }));
  const cookie = /sv_session=([^;]+)/.exec(onb.headers.get("set-cookie")!)![1]!;
  mails.length = 0;
  await app.request(`${m[1]}/account`, { headers: { cookie: `sv_session=${cookie}`, "x-forwarded-for": "198.51.100.7" } });

  assert.equal(alerts.length, 1, "bob himself is notified through the normal channels");
  assert.equal(alerts[0]!.user.id, bobUser.id);
  assert.equal(posted.length, 1, "org webhook fired");
  assert.equal(posted[0]!.url, "https://hooks.example/siem");
  assert.equal(posted[0]!.body.member, "Bob's laptop");
  assert.equal(posted[0]!.body.org, org.slug);
  assert.equal(posted[0]!.body.kind, "cookie_replay");
  const sec = mails.find((x) => x.to === "security@acme.test")!;
  assert.match(sec.subject, /\[TRIPPED\] Bob's laptop: /);

  // Org page shows bob tripped; audit has the story; a member cannot see admin pages.
  const orgPage = await (await go(app, admin, "/org")).text();
  assert.match(orgPage, /Bob&#39;s laptop/);
  assert.match(orgPage, /TRIPPED \(1\)/);
  const audit = await (await go(app, admin, "/org/audit")).text();
  for (const a of ["org.created", "org.settings.updated", "member.added"]) assert.match(audit, new RegExp(a));
  assert.equal((await go(app, bob, "/org/settings")).status, 404);
  assert.equal((await go(app, bob, "/org/audit")).status, 404);
  assert.equal((await go(app, bob, "/org/members", form({ label: "x", email: "x@acme.test" }))).status, 404);

  // Removing bob removes his decoys and vault.
  const rm = await go(app, admin, `/org/members/${bobUser.id}/remove`, { method: "POST" });
  assert.equal(rm.status, 303);
  assert.equal(store.userByEmail("bob@acme.test"), undefined);
  assert.equal((await app.request(m[1]!)).status, 404);
  assert.ok(store.auditFor(org.id).some((e) => e.action === "member.removed" && e.target === "bob@acme.test"));
  const self = await go(app, admin, `/org/members/${store.userByEmail("admin@acme.test")!.id}/remove`, { method: "POST" });
  assert.equal(self.status, 404, "an admin cannot remove themselves");
});

test("an account in a family plan or already in an org cannot create another org", async () => {
  const { app, store } = harness();
  const owner = new Jar();
  await signIn(app, owner, "owner@example.com");
  await go(app, owner, "/org/create", form({ name: "One" }));
  const again = await go(app, owner, "/org/create", form({ name: "Two" }));
  assert.match(decodeURIComponent(again.headers.get("location")!), /already belongs/);
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM orgs").get()!.n, 1);
});

test("the only admin cannot delete their account while members remain; with none left the org goes too", async () => {
  const { app, store } = harness();
  const admin = new Jar();
  await signIn(app, admin, "boss@acme.test");
  await go(app, admin, "/org/create", form({ name: "Acme" }));
  await go(app, admin, "/org/members", form({ label: "Bob", email: "bob@acme.test" }));
  const refused = await go(app, admin, "/account/delete", form({ confirm: "DELETE" }));
  assert.match(decodeURIComponent(refused.headers.get("location")!), /only admin/);
  assert.ok(store.userByEmail("boss@acme.test"));
  const bob = store.userByEmail("bob@acme.test")!;
  await go(app, admin, `/org/members/${bob.id}/remove`, { method: "POST" });
  const ok = await go(app, admin, "/account/delete", form({ confirm: "DELETE" }));
  assert.equal(ok.headers.get("location"), "/?deleted=1");
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM orgs").get()!.n, 0, "empty org deleted with its last admin");
});
