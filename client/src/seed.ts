import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { SeededFile } from "./config.ts";
import type { Account } from "./account.ts";

/**
 * A decoy file must read exactly like the real thing. There is no marker, comment or
 * name inside it that says otherwise; a stealer-log buyer grepping for a product name
 * would find nothing. We recognise our own files by a hash kept in the local config.
 */
export type Planned = Omit<SeededFile, "sha256">;

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

/**
 * Where infostealers look. Every family that matters (Lumma, Vidar, StealC, RedLine, AMOS)
 * greps Desktop, Documents and Downloads for files named like wallets, seeds and passwords,
 * and most grab any .env they see. We put ours exactly there.
 */
export function plannedFiles(home = homedir()): Planned[] {
  return [
    { path: join(home, "Desktop", "wallet-recovery-phrase.txt"), kind: "wallet_file" },
    { path: join(home, "Documents", "passwords.txt"), kind: "passwords_file" },
    { path: join(home, "Documents", "vault-api", ".env"), kind: "env_file" },
  ];
}

export function renderFile(kind: Planned["kind"], a: Account): string {
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
      ].join("\n");
    case "env_file":
      return [
        `# ${a.brand} custody API`,
        `VAULT_API_BASE=${a.api.base}`,
        `VAULT_API_KEY=${a.api.key}`,
        `VAULT_ACCOUNT=${a.vault.username}`,
        ``,
      ].join("\n");
  }
}

export interface SeedResult {
  written: SeededFile[];
  skipped: Array<{ path: string; reason: string }>;
}

function isOurs(f: SeededFile): boolean {
  try {
    return sha256(readFileSync(f.path, "utf8")) === f.sha256;
  } catch {
    return false;
  }
}

/** Plant the files. Never overwrites a file we did not write (by hash), so a real passwords.txt is safe. */
export function seedFiles(account: Account, files: Planned[] = plannedFiles(), known: SeededFile[] = []): SeedResult {
  const written: SeededFile[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];
  for (const f of files) {
    const prior = known.find((k) => k.path === f.path);
    if (existsSync(f.path) && !(prior && isOurs(prior))) {
      skipped.push({ path: f.path, reason: "a file with that name already exists and is not ours" });
      continue;
    }
    const content = renderFile(f.kind, account);
    mkdirSync(dirname(f.path), { recursive: true });
    writeFileSync(f.path, content);
    written.push({ ...f, sha256: sha256(content) });
  }
  return { written, skipped };
}

/** Remove only files whose content still matches what we wrote. */
export function removeSeeded(files: SeededFile[]): string[] {
  const removed: string[] = [];
  for (const f of files) {
    if (!isOurs(f)) continue;
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
