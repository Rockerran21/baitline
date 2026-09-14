import { test, after, before } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Jar, go, harness, signIn, form } from "./helpers/harness.ts";
import { ldapUserDn } from "../src/ldap.ts";

const SLAPD = ["/opt/homebrew/opt/openldap/libexec/slapd", "/usr/libexec/slapd", "/usr/sbin/slapd"].find((p) => existsSync(p));
const SCHEMA = ["/opt/homebrew/etc/openldap/schema", "/etc/openldap/schema", "/etc/ldap/schema"].find((p) => existsSync(p));
const PORT = 3390;
const URL = `ldap://127.0.0.1:${PORT}`;
const BASE = "dc=example,dc=com";
let slapd: ChildProcess | null = null;

function waitForPort(port: number, tries = 40): Promise<void> {
  return new Promise((resolve, reject) => {
    const attempt = (n: number) => {
      const s = connect(port, "127.0.0.1");
      s.once("connect", () => {
        s.end();
        resolve();
      });
      s.once("error", () => (n > 0 ? setTimeout(() => attempt(n - 1), 100) : reject(new Error("slapd did not start"))));
    };
    attempt(tries);
  });
}

before(async () => {
  if (!SLAPD || !SCHEMA) return;
  const dir = mkdtempSync(join(tmpdir(), "bl-ldap-"));
  mkdirSync(join(dir, "db"));
  writeFileSync(
    join(dir, "slapd.conf"),
    `include ${SCHEMA}/core.schema\ninclude ${SCHEMA}/cosine.schema\ninclude ${SCHEMA}/inetorgperson.schema\npidfile ${dir}/slapd.pid\ndatabase mdb\nsuffix "${BASE}"\nrootdn "cn=admin,${BASE}"\nrootpw adminpw\ndirectory ${dir}/db\n`,
  );
  slapd = spawn(SLAPD, ["-h", URL, "-f", join(dir, "slapd.conf"), "-d", "0"], { stdio: "ignore" });
  await waitForPort(PORT);
  const ldif = `dn: ${BASE}\nobjectClass: dcObject\nobjectClass: organization\ndc: example\no: Example\n\ndn: ou=people,${BASE}\nobjectClass: organizationalUnit\nou: people\n\ndn: uid=alice,ou=people,${BASE}\nobjectClass: inetOrgPerson\nuid: alice\ncn: Alice\nsn: Example\nmail: alice@example.com\nuserPassword: alicepw\n\ndn: uid=nomail,ou=people,${BASE}\nobjectClass: inetOrgPerson\nuid: nomail\ncn: No Mail\nsn: Example\nuserPassword: nomailpw\n`;
  writeFileSync(join(dir, "base.ldif"), ldif);
  execFileSync("ldapadd", ["-x", "-H", URL, "-D", `cn=admin,${BASE}`, "-w", "adminpw", "-f", join(dir, "base.ldif")], { stdio: "ignore" });
});
after(() => {
  slapd?.kill();
});

test("username charset cannot alter the DN; plain ldap:// is only allowed to localhost", () => {
  assert.equal(ldapUserDn("uid={username},ou=people,dc=x", "alice"), "uid=alice,ou=people,dc=x");
  for (const bad of ["alice,ou=admins", "a)(uid=*", "x\\y", "", "a".repeat(65), "bob dn"]) assert.throws(() => ldapUserDn("uid={username},dc=x", bad), /invalid credentials/, bad);
});

test("LDAP sign-in against a real directory: right password signs in and provisions; wrong password, unknown user and no-email all fail the same way", { skip: !SLAPD || !SCHEMA ? "no slapd on this machine" : false }, async () => {
  const { app, store } = harness();
  const admin = new Jar();
  await signIn(app, admin, "admin@example.com");
  await go(app, admin, "/org/create", form({ name: "Example Co" }));
  const org = store.org(1)!;
  store.updateOrg(org.id, { ldap_url: URL, ldap_user_dn: `uid={username},ou=people,${BASE}`, ldap_email_attr: "mail" });

  const page = await (await go(app, new Jar(), `/o/${org.slug}`)).text();
  assert.match(page, /Directory username/);

  const jar = new Jar();
  const ok = await go(app, jar, `/o/${org.slug}/ldap`, form({ username: "alice", password: "alicepw", next: "/dashboard" }));
  assert.equal(ok.status, 303);
  assert.equal(ok.headers.get("location"), "/setup");
  const alice = store.userByEmail("alice@example.com")!;
  assert.equal(alice.org_id, org.id);
  assert.equal((await go(app, jar, "/dashboard")).status, 200);
  assert.ok(store.auditFor(org.id).some((e) => e.action === "auth.ldap" && e.target === "alice"));

  const wrong = await go(app, new Jar(), `/o/${org.slug}/ldap`, form({ username: "alice", password: "nope", next: "/dashboard" }));
  const unknown = await go(app, new Jar(), `/o/${org.slug}/ldap`, form({ username: "nobody", password: "x", next: "/dashboard" }));
  const wrongMsg = decodeURIComponent(wrong.headers.get("location")!);
  const unknownMsg = decodeURIComponent(unknown.headers.get("location")!);
  assert.match(wrongMsg, /invalid credentials/);
  assert.equal(wrongMsg, unknownMsg, "unknown user and wrong password are indistinguishable");

  const nomail = await go(app, new Jar(), `/o/${org.slug}/ldap`, form({ username: "nomail", password: "nomailpw", next: "/dashboard" }));
  assert.match(decodeURIComponent(nomail.headers.get("location")!), /no email address/);
  assert.equal(store.orgMembers(org.id).length, 2, "admin + alice only");

  // Per-user attempt limit.
  let last = "";
  for (let i = 0; i < 6; i++) last = decodeURIComponent((await go(app, new Jar(), `/o/${org.slug}/ldap`, form({ username: "alice", password: "bad", next: "/" }), )).headers.get("location")!);
  assert.match(last, /Too many attempts/);
});
