import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface SeededFile {
  path: string;
  kind: "wallet_file" | "passwords_file" | "env_file";
}

/**
 * What we keep on disk. Deliberately NOT the decoy passwords, cookie, API key or
 * seed phrase: if a stealer reads this file it must not be able to tell the decoys
 * from real accounts, and it must not learn the dashboard URL. The dashboard token
 * lives in the OS keychain; everything here is either public or a write-only URL.
 */
export interface ClientConfig {
  server: string;
  email: string;
  slug: string;
  guard_url: string;
  seeded: SeededFile[];
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
    console.error(`Not set up yet. Run: baitline setup --server <url>`);
    process.exit(2);
  }
  return cfg;
}
