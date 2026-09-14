import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ClientConfig, SeededFile } from "./config.ts";

const MARK = "meridian";

/**
 * Where infostealers look. Every family that matters (Lumma, Vidar, StealC, RedLine, AMOS)
 * greps Desktop, Documents and Downloads for files named like wallets, seeds and passwords,
 * and most grab any .env they see. We put ours exactly there.
 */
export function plannedFiles(home = homedir()): SeededFile[] {
  return [
    { path: join(home, "Desktop", "wallet-recovery-phrase.txt"), kind: "wallet_file" },
    { path: join(home, "Documents", "passwords.txt"), kind: "passwords_file" },
    { path: join(home, "Documents", "meridian-api", ".env"), kind: "env_file" },
  ];
}

export function renderFile(kind: SeededFile["kind"], cfg: ClientConfig): string {
  switch (kind) {
    case "wallet_file":
      return [
        `Meridian Vault - wallet recovery phrase`,
        `Account: ${cfg.vault.username}`,
        ``,
        cfg.wallet.seed_phrase,
        ``,
        `Restore or check balance: ${cfg.vault.login_url}`,
        `Password: ${cfg.vault.password}`,
        ``,
      ].join("\n");
    case "passwords_file":
      return [
        `passwords (do not share)`,
        ``,
        `Meridian Vault (crypto)`,
        `  url: ${cfg.vault.login_url}`,
        `  user: ${cfg.vault.username}`,
        `  pass: ${cfg.vault.password}`,
        `  api key: ${cfg.api.key}`,
        ``,
      ].join("\n");
    case "env_file":
      return [
        `# Meridian custody API`,
        `MERIDIAN_API_BASE=${cfg.api.base}`,
        `MERIDIAN_API_KEY=${cfg.api.key}`,
        `MERIDIAN_ACCOUNT=${cfg.vault.username}`,
        ``,
      ].join("\n");
  }
}

export interface SeedResult {
  written: SeededFile[];
  skipped: Array<{ path: string; reason: string }>;
}

export function seedFiles(cfg: ClientConfig, files: SeededFile[] = plannedFiles()): SeedResult {
  const written: SeededFile[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];
  for (const f of files) {
    if (existsSync(f.path) && !readFileSync(f.path, "utf8").toLowerCase().includes(MARK)) {
      skipped.push({ path: f.path, reason: "a file with that name already exists and is not ours" });
      continue;
    }
    mkdirSync(dirname(f.path), { recursive: true });
    writeFileSync(f.path, renderFile(f.kind, cfg));
    written.push(f);
  }
  return { written, skipped };
}

export function removeSeeded(files: SeededFile[]): string[] {
  const removed: string[] = [];
  for (const f of files) {
    if (!existsSync(f.path)) continue;
    if (!readFileSync(f.path, "utf8").toLowerCase().includes(MARK)) continue;
    rmSync(f.path);
    removed.push(f.path);
    const dir = dirname(f.path);
    if (f.kind === "env_file") {
      try {
        rmSync(dir, { recursive: false });
      } catch {
        /* not empty; leave it */
      }
    }
  }
  return removed;
}
