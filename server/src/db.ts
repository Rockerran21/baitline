import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type DecoyKind = "browser_password" | "session_cookie" | "api_key" | "wallet_file" | "passwords_file";
export type TripKind = "vault_visit" | "login_attempt" | "credential_use" | "cookie_replay" | "api_key_use" | "test_alert";
export type Severity = "low" | "medium" | "high";
export type OrgRole = "admin" | "member";

export interface User {
  id: number;
  /** Family plan: members belong to an owner. Their trips also alert the owner. */
  parent_id: number | null;
  /** Organisation plan: members belong to an org. Their trips also alert the org's channels. */
  org_id: number | null;
  org_role: OrgRole | null;
  /** How the owner or org names this person, e.g. "Mom's laptop". */
  label: string;
  email: string;
  ntfy_topic: string | null;
  /** Device token for the desktop client: post guard events, read status. Cannot read secrets. */
  guard_token: string;
  /** One-time token in the vault onboarding link. Cleared when used. */
  setup_token: string | null;
  slug: string;
  enroll_ip: string | null;
  enroll_ua: string | null;
  enrolled_at: number | null;
  created_at: number;
}

export interface Session {
  id: string;
  user_id: number;
  created_at: number;
  last_seen_at: number;
  /** When the user last proved who they are. Sensitive actions require this to be recent. */
  authenticated_at: number;
  /** 0 while a second factor is still owed. */
  mfa_done: number;
  expires_at: number;
}

export interface Passkey {
  id: number;
  user_id: number;
  credential_id: string;
  public_key: string;
  counter: number;
  transports: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
}

export interface Org {
  id: number;
  name: string;
  slug: string;
  oidc_issuer: string | null;
  oidc_client_id: string | null;
  oidc_client_secret: string | null;
  /** Only sign-ins whose verified email ends with this domain are accepted or provisioned. */
  oidc_email_domain: string | null;
  ldap_url: string | null;
  /** DN template with {username}, e.g. uid={username},ou=people,dc=example,dc=com */
  ldap_user_dn: string | null;
  ldap_email_attr: string;
  alert_webhook_url: string | null;
  alert_email: string | null;
  created_at: number;
}

export interface AuditEntry {
  id: number;
  org_id: number | null;
  actor_id: number | null;
  action: string;
  target: string;
  created_at: number;
}

export interface Decoy {
  id: number;
  user_id: number;
  kind: DecoyKind;
  secret: string;
  meta: string;
  created_at: number;
}

export interface Trip {
  id: number;
  user_id: number;
  kind: TripKind;
  severity: Severity;
  ip: string;
  ua: string;
  path: string;
  details: string;
  notified: number;
  created_at: number;
}

export interface GuardEvent {
  id: number;
  user_id: number;
  host: string;
  source_app: string;
  rule: string;
  sample: string;
  created_at: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS orgs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  oidc_issuer TEXT, oidc_client_id TEXT, oidc_client_secret TEXT, oidc_email_domain TEXT,
  ldap_url TEXT, ldap_user_dn TEXT, ldap_email_attr TEXT NOT NULL DEFAULT 'mail',
  alert_webhook_url TEXT, alert_email TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  org_role TEXT,
  label TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  ntfy_topic TEXT,
  guard_token TEXT NOT NULL UNIQUE,
  setup_token TEXT UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  enroll_ip TEXT, enroll_ua TEXT, enrolled_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, authenticated_at INTEGER NOT NULL,
  mfa_done INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS one_time_tokens (
  hash TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE TABLE IF NOT EXISTS passkeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  hash TEXT NOT NULL UNIQUE,
  used_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER REFERENCES orgs(id) ON DELETE CASCADE,
  actor_id INTEGER,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS decoys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, secret TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS decoys_secret ON decoys(kind, secret);
CREATE TABLE IF NOT EXISTS trips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, severity TEXT NOT NULL, ip TEXT NOT NULL, ua TEXT NOT NULL, path TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}', notified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS trips_user ON trips(user_id, created_at);
CREATE TABLE IF NOT EXISTS guard_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  host TEXT NOT NULL, source_app TEXT NOT NULL, rule TEXT NOT NULL, sample TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`;

type Row = Record<string, unknown>;

export class Store {
  readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA);
  }

  // ---- users

  createUser(u: Omit<User, "id" | "created_at">): User {
    const created_at = Date.now();
    const r = this.db
      .prepare(
        `INSERT INTO users (parent_id, org_id, org_role, label, email, ntfy_topic, guard_token, setup_token, slug, enroll_ip, enroll_ua, enrolled_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(u.parent_id, u.org_id, u.org_role, u.label, u.email, u.ntfy_topic, u.guard_token, u.setup_token, u.slug, u.enroll_ip, u.enroll_ua, u.enrolled_at, created_at);
    return { ...u, id: Number(r.lastInsertRowid), created_at };
  }

  userById(id: number): User | undefined {
    return this.db.prepare("SELECT * FROM users WHERE id = ?").get(id) as User | undefined;
  }
  userBySlug(slug: string): User | undefined {
    return this.db.prepare("SELECT * FROM users WHERE slug = ?").get(slug) as User | undefined;
  }
  userByEmail(email: string): User | undefined {
    return this.db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE").get(email) as User | undefined;
  }
  userByGuardToken(token: string): User | undefined {
    return this.db.prepare("SELECT * FROM users WHERE guard_token = ?").get(token) as User | undefined;
  }
  membersOf(ownerId: number): User[] {
    return this.db.prepare("SELECT * FROM users WHERE parent_id = ? ORDER BY id").all(ownerId) as unknown as User[];
  }
  orgMembers(orgId: number): User[] {
    return this.db.prepare("SELECT * FROM users WHERE org_id = ? ORDER BY org_role, id").all(orgId) as unknown as User[];
  }
  markEnrolled(userId: number, ip: string, ua: string): void {
    this.db.prepare("UPDATE users SET enrolled_at = ?, enroll_ip = ?, enroll_ua = ?, setup_token = NULL WHERE id = ?").run(Date.now(), ip, ua, userId);
  }
  setOrg(userId: number, orgId: number | null, role: OrgRole | null, label?: string): void {
    if (label === undefined) this.db.prepare("UPDATE users SET org_id = ?, org_role = ? WHERE id = ?").run(orgId, role, userId);
    else this.db.prepare("UPDATE users SET org_id = ?, org_role = ?, label = ? WHERE id = ?").run(orgId, role, label, userId);
  }
  deleteUser(id: number): void {
    this.db.prepare("DELETE FROM users WHERE id = ?").run(id);
  }

  // ---- sessions and one-time tokens

  createSession(s: Session): void {
    this.db
      .prepare("INSERT INTO sessions (id, user_id, created_at, last_seen_at, authenticated_at, mfa_done, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(s.id, s.user_id, s.created_at, s.last_seen_at, s.authenticated_at, s.mfa_done, s.expires_at);
  }
  session(id: string): Session | undefined {
    return this.db.prepare("SELECT * FROM sessions WHERE id = ?").get(id) as Session | undefined;
  }
  touchSession(id: string, lastSeen: number, expires: number): void {
    this.db.prepare("UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?").run(lastSeen, expires, id);
  }
  completeMfa(id: string, at: number): void {
    this.db.prepare("UPDATE sessions SET mfa_done = 1, authenticated_at = ? WHERE id = ?").run(at, id);
  }
  deleteSession(id: string): void {
    this.db.prepare("DELETE FROM sessions WHERE id = ?").run(id);
  }
  deleteUserSessions(userId: number): void {
    this.db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
  }

  putToken(hash: string, purpose: string, userId: number, expiresAt: number): void {
    this.db.prepare("INSERT INTO one_time_tokens (hash, purpose, user_id, expires_at) VALUES (?, ?, ?, ?)").run(hash, purpose, userId, expiresAt);
  }
  /** Atomically consume a live token. Returns the user id or undefined. */
  useToken(hash: string, purpose: string, now: number): number | undefined {
    const row = this.db.prepare("SELECT user_id FROM one_time_tokens WHERE hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?").get(hash, purpose, now) as Row | undefined;
    if (!row) return undefined;
    this.db.prepare("UPDATE one_time_tokens SET used_at = ? WHERE hash = ?").run(now, hash);
    return Number(row.user_id);
  }

  // ---- passkeys and recovery codes

  addPasskey(p: Omit<Passkey, "id" | "created_at" | "last_used_at">): Passkey {
    const created_at = Date.now();
    const r = this.db
      .prepare("INSERT INTO passkeys (user_id, credential_id, public_key, counter, transports, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(p.user_id, p.credential_id, p.public_key, p.counter, p.transports, p.name, created_at);
    return { ...p, id: Number(r.lastInsertRowid), created_at, last_used_at: null };
  }
  passkeysFor(userId: number): Passkey[] {
    return this.db.prepare("SELECT * FROM passkeys WHERE user_id = ? ORDER BY id").all(userId) as unknown as Passkey[];
  }
  passkeyByCredentialId(credentialId: string): Passkey | undefined {
    return this.db.prepare("SELECT * FROM passkeys WHERE credential_id = ?").get(credentialId) as Passkey | undefined;
  }
  updatePasskeyCounter(id: number, counter: number): void {
    this.db.prepare("UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?").run(counter, Date.now(), id);
  }
  deletePasskey(id: number, userId: number): boolean {
    return this.db.prepare("DELETE FROM passkeys WHERE id = ? AND user_id = ?").run(id, userId).changes > 0;
  }

  replaceRecoveryCodes(userId: number, hashes: string[]): void {
    this.db.prepare("DELETE FROM recovery_codes WHERE user_id = ?").run(userId);
    const ins = this.db.prepare("INSERT INTO recovery_codes (user_id, hash) VALUES (?, ?)");
    for (const h of hashes) ins.run(userId, h);
  }
  useRecoveryCode(userId: number, hash: string): boolean {
    return this.db.prepare("UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND hash = ? AND used_at IS NULL").run(Date.now(), userId, hash).changes > 0;
  }
  recoveryCodesLeft(userId: number): number {
    return Number((this.db.prepare("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL").get(userId) as Row).n);
  }

  // ---- orgs and audit

  createOrg(name: string, slug: string): Org {
    const created_at = Date.now();
    const r = this.db.prepare("INSERT INTO orgs (name, slug, created_at) VALUES (?, ?, ?)").run(name, slug, created_at);
    return this.org(Number(r.lastInsertRowid))!;
  }
  org(id: number): Org | undefined {
    return this.db.prepare("SELECT * FROM orgs WHERE id = ?").get(id) as Org | undefined;
  }
  orgBySlug(slug: string): Org | undefined {
    return this.db.prepare("SELECT * FROM orgs WHERE slug = ?").get(slug) as Org | undefined;
  }
  updateOrg(id: number, fields: Partial<Omit<Org, "id" | "created_at" | "slug">>): void {
    const keys = Object.keys(fields) as Array<keyof typeof fields>;
    if (!keys.length) return;
    const set = keys.map((k) => `${k} = ?`).join(", ");
    this.db.prepare(`UPDATE orgs SET ${set} WHERE id = ?`).run(...keys.map((k) => fields[k] as string | null), id);
  }
  audit(orgId: number | null, actorId: number | null, action: string, target = ""): void {
    this.db.prepare("INSERT INTO audit_log (org_id, actor_id, action, target, created_at) VALUES (?, ?, ?, ?, ?)").run(orgId, actorId, action, target, Date.now());
  }
  auditFor(orgId: number, limit = 200): AuditEntry[] {
    return this.db.prepare("SELECT * FROM audit_log WHERE org_id = ? ORDER BY id DESC LIMIT ?").all(orgId, limit) as unknown as AuditEntry[];
  }

  // ---- decoys, trips, guard

  addDecoy(userId: number, kind: DecoyKind, secret: string, meta: Record<string, unknown> = {}): Decoy {
    const created_at = Date.now();
    const r = this.db.prepare("INSERT INTO decoys (user_id, kind, secret, meta, created_at) VALUES (?, ?, ?, ?, ?)").run(userId, kind, secret, JSON.stringify(meta), created_at);
    return { id: Number(r.lastInsertRowid), user_id: userId, kind, secret, meta: JSON.stringify(meta), created_at };
  }
  decoysForUser(userId: number): Decoy[] {
    return this.db.prepare("SELECT * FROM decoys WHERE user_id = ? ORDER BY id").all(userId) as unknown as Decoy[];
  }

  addTrip(t: Omit<Trip, "id" | "created_at" | "notified">): Trip {
    const created_at = Date.now();
    const r = this.db
      .prepare("INSERT INTO trips (user_id, kind, severity, ip, ua, path, details, notified, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)")
      .run(t.user_id, t.kind, t.severity, t.ip, t.ua, t.path, t.details, created_at);
    return { ...t, id: Number(r.lastInsertRowid), notified: 0, created_at };
  }
  tripsForUser(userId: number, limit = 200): Trip[] {
    return this.db.prepare("SELECT * FROM trips WHERE user_id = ? ORDER BY created_at DESC LIMIT ?").all(userId, limit) as unknown as Trip[];
  }
  lastTripFrom(userId: number, kind: TripKind, ip: string): Trip | undefined {
    return this.db.prepare("SELECT * FROM trips WHERE user_id = ? AND kind = ? AND ip = ? ORDER BY created_at DESC LIMIT 1").get(userId, kind, ip) as Trip | undefined;
  }
  notifiedSince(userId: number, sinceMs: number): number {
    return Number((this.db.prepare("SELECT COUNT(*) AS n FROM trips WHERE user_id = ? AND notified = 1 AND created_at >= ?").get(userId, sinceMs) as Row).n);
  }
  markNotified(tripId: number): void {
    this.db.prepare("UPDATE trips SET notified = 1 WHERE id = ?").run(tripId);
  }

  addGuardEvent(e: Omit<GuardEvent, "id" | "created_at">): GuardEvent {
    const created_at = Date.now();
    const r = this.db.prepare("INSERT INTO guard_events (user_id, host, source_app, rule, sample, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(e.user_id, e.host, e.source_app, e.rule, e.sample, created_at);
    return { ...e, id: Number(r.lastInsertRowid), created_at };
  }
  guardEventsForUser(userId: number, limit = 100): GuardEvent[] {
    return this.db.prepare("SELECT * FROM guard_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?").all(userId, limit) as unknown as GuardEvent[];
  }

  close(): void {
    this.db.close();
  }
}
