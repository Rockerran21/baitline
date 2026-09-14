import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export type DecoyKind =
  | "browser_password"
  | "session_cookie"
  | "api_key"
  | "wallet_file"
  | "passwords_file";

export type TripKind =
  | "vault_visit"
  | "login_attempt"
  | "credential_use"
  | "cookie_replay"
  | "api_key_use";

export type Severity = "low" | "medium" | "high";

export interface User {
  id: number;
  email: string;
  ntfy_topic: string | null;
  dashboard_token: string;
  setup_token: string | null;
  slug: string;
  enroll_ip: string | null;
  enroll_ua: string | null;
  enrolled_at: number | null;
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
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  ntfy_topic TEXT,
  dashboard_token TEXT NOT NULL UNIQUE,
  setup_token TEXT UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  enroll_ip TEXT,
  enroll_ua TEXT,
  enrolled_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS decoys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,
  secret TEXT NOT NULL,
  meta TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS decoys_secret ON decoys(kind, secret);
CREATE TABLE IF NOT EXISTS trips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  ip TEXT NOT NULL,
  ua TEXT NOT NULL,
  path TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS trips_user ON trips(user_id, created_at);
CREATE TABLE IF NOT EXISTS guard_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  host TEXT NOT NULL,
  source_app TEXT NOT NULL,
  rule TEXT NOT NULL,
  sample TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
`;

export class Store {
  readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA);
  }

  createUser(u: Omit<User, "id" | "created_at">): User {
    const created_at = Date.now();
    const r = this.db
      .prepare(
        `INSERT INTO users (email, ntfy_topic, dashboard_token, setup_token, slug, enroll_ip, enroll_ua, enrolled_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(u.email, u.ntfy_topic, u.dashboard_token, u.setup_token, u.slug, u.enroll_ip, u.enroll_ua, u.enrolled_at, created_at);
    return { ...u, id: Number(r.lastInsertRowid), created_at };
  }

  userBySlug(slug: string): User | undefined {
    return this.db.prepare("SELECT * FROM users WHERE slug = ?").get(slug) as User | undefined;
  }

  userByDashboardToken(token: string): User | undefined {
    return this.db.prepare("SELECT * FROM users WHERE dashboard_token = ?").get(token) as User | undefined;
  }

  userById(id: number): User | undefined {
    return this.db.prepare("SELECT * FROM users WHERE id = ?").get(id) as User | undefined;
  }

  markEnrolled(userId: number, ip: string, ua: string): void {
    this.db
      .prepare("UPDATE users SET enrolled_at = ?, enroll_ip = ?, enroll_ua = ?, setup_token = NULL WHERE id = ?")
      .run(Date.now(), ip, ua, userId);
  }

  addDecoy(userId: number, kind: DecoyKind, secret: string, meta: Record<string, unknown> = {}): Decoy {
    const created_at = Date.now();
    const r = this.db
      .prepare("INSERT INTO decoys (user_id, kind, secret, meta, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(userId, kind, secret, JSON.stringify(meta), created_at);
    return { id: Number(r.lastInsertRowid), user_id: userId, kind, secret, meta: JSON.stringify(meta), created_at };
  }

  decoysForUser(userId: number): Decoy[] {
    return this.db.prepare("SELECT * FROM decoys WHERE user_id = ? ORDER BY id").all(userId) as unknown as Decoy[];
  }

  decoyBySecret(kind: DecoyKind, secret: string): Decoy | undefined {
    return this.db.prepare("SELECT * FROM decoys WHERE kind = ? AND secret = ?").get(kind, secret) as Decoy | undefined;
  }

  addTrip(t: Omit<Trip, "id" | "created_at">): Trip {
    const created_at = Date.now();
    const r = this.db
      .prepare("INSERT INTO trips (user_id, kind, severity, ip, ua, path, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(t.user_id, t.kind, t.severity, t.ip, t.ua, t.path, t.details, created_at);
    return { ...t, id: Number(r.lastInsertRowid), created_at };
  }

  tripsForUser(userId: number, limit = 200): Trip[] {
    return this.db
      .prepare("SELECT * FROM trips WHERE user_id = ? ORDER BY created_at DESC LIMIT ?")
      .all(userId, limit) as unknown as Trip[];
  }

  addGuardEvent(e: Omit<GuardEvent, "id" | "created_at">): GuardEvent {
    const created_at = Date.now();
    const r = this.db
      .prepare("INSERT INTO guard_events (user_id, host, source_app, rule, sample, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(e.user_id, e.host, e.source_app, e.rule, e.sample, created_at);
    return { ...e, id: Number(r.lastInsertRowid), created_at };
  }

  guardEventsForUser(userId: number, limit = 100): GuardEvent[] {
    return this.db
      .prepare("SELECT * FROM guard_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?")
      .all(userId, limit) as unknown as GuardEvent[];
  }

  close(): void {
    this.db.close();
  }
}
