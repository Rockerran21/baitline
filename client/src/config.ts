import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface SeededFile {
  path: string;
  kind: "wallet_file" | "passwords_file" | "env_file";
  /** SHA-256 of the exact content we wrote. Sent to the server once; never kept here. */
  sha256: string;
}

/**
 * What we keep on disk. Deliberately NOT the decoy passwords, cookie, API key or seed
 * phrase, NOT the list of planted files, and no sign-in credential. If a stealer reads
 * this file it learns that Baitline is installed and nothing else: not which files or
 * saved logins are bait, not how to open the dashboard, not how to silence alerts.
 * The device token can only report guard events, read status, and store the manifest.
 */
export interface ClientConfig {
  server: string;
  email: string;
  guard_url: string;
  status_url: string;
  enrolled_at: string;
}

export const CONFIG_DIR = process.env.BAITLINE_HOME ?? join(homedir(), ".baitline");
export const CONFIG_PATH = join(CONFIG_DIR, "config.json");
export const PAUSE_PATH = join(CONFIG_DIR, "guard-pause");
export const GUARD_LOG = join(CONFIG_DIR, "guard.log");

export function loadConfig(): ClientConfig | null {
  if (!existsSync(CONFIG_PATH)) return null;
  return JSON.parse(readFileSync(CONFIG_PATH, "utf8")) as ClientConfig;
}

export function saveConfig(cfg: ClientConfig): void {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

export function requireConfig(): ClientConfig {
  const cfg = loadConfig();
  if (!cfg) {
    console.error(`Not set up yet. Sign in on the server's setup page and run the command it shows you.`);
    process.exit(2);
  }
  return cfg;
}
