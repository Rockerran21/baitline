import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { SeededFile } from "./config.ts";
import type { Account } from "./account.ts";

/** Marker written into every decoy file so we only ever delete or overwrite our own. */
const MARK = "baitline-decoy";

/**
 * Where infostealers look. Every family that matters (Lumma, Vidar, StealC, RedLine, AMOS)
 * greps Desktop, Documents and Downloads for files named like wallets, seeds and passwords,
 * and most grab any .env they see. We put ours exactly there.
 */
export function plannedFiles(home = homedir()): SeededFile[] {
  return [
    { path: join(home, "Desktop", "wallet-recovery-phrase.txt"), kind: "wallet_file" },
    { path: join(home, "Documents", "passwords.txt"), kind: "passwords_file" },
    { path: join(home, "Documents", "vault-api", ".env"), kind: "env_file" },
  ];
}

export function renderFile(kind: SeededFile["kind"], a: Account): string {
  const marker = `# ${MARK} - do not edit`;
  switch (kind) {
    case "wallet_file":
      return [
        `${a.brand} - wallet recovery phrase`,
        `Account: ${a.vault.username}`,
        ``,
        a.wallet.seed_phrase,
        ``,
        `Restore or check balance: ${a.vault.login_url}`,
        `Password: ${a.vault.password}`,
        ``,
        marker,
        ``,
      ].join("\n");
    case "passwords_file":
      return [
        `passwords (do not share)`,
        ``,
        `${a.brand} (crypto)`,
        `  url: ${a.vault.login_url}`,
        `  user: ${a.vault.username}`,
        `  pass: ${a.vault.password}`,
        `  api key: ${a.api.key}`,
        ``,
        marker,
        ``,
      ].join("\n");
    case "env_file":
      return [
        `# ${a.brand} custody API`,
        `VAULT_API_BASE=${a.api.base}`,
        `VAULT_API_KEY=${a.api.key}`,
        `VAULT_ACCOUNT=${a.vault.username}`,
        marker,
        ``,
      ].join("\n");
  }
}

export interface SeedResult {
  written: SeededFile[];
  skipped: Array<{ path: string; reason: string }>;
}

function isOurs(path: string): boolean {
  try {
    return readFileSync(path, "utf8").includes(MARK);
  } catch {
    return false;
  }
}

export function seedFiles(account: Account, files: SeededFile[] = plannedFiles()): SeedResult {
  const written: SeededFile[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];
  for (const f of files) {
    if (existsSync(f.path) && !isOurs(f.path)) {
      skipped.push({ path: f.path, reason: "a file with that name already exists and is not ours" });
      continue;
    }
    mkdirSync(dirname(f.path), { recursive: true });
    writeFileSync(f.path, renderFile(f.kind, account));
    written.push(f);
  }
  return { written, skipped };
}

export function removeSeeded(files: SeededFile[]): string[] {
  const removed: string[] = [];
  for (const f of files) {
    if (!existsSync(f.path) || !isOurs(f.path)) continue;
    rmSync(f.path);
    removed.push(f.path);
    if (f.kind === "env_file") {
      try {
        rmSync(dirname(f.path), { recursive: false });
      } catch {
        /* not empty; leave it */
      }
    }
  }
  return removed;
}
