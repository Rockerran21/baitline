import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { plannedFiles, removeSeeded, seedFiles } from "../src/seed.ts";
import type { ClientConfig } from "../src/config.ts";

const cfg: ClientConfig = {
  server: "http://vault.test",
  email: "v@example.com",
  ntfy_topic: null,
  dashboard_url: "http://vault.test/dashboard/t",
  status_url: "http://vault.test/api/status/t",
  guard_url: "http://vault.test/api/guard/t",
  vault: { onboarding_url: "http://vault.test/vault/s?setup=x", login_url: "http://vault.test/vault/s", username: "sam.kim42", password: "Anchor4821!" },
  api: { base: "http://vault.test/api/v1/s", key: "mvk_live_" + "ab".repeat(20) },
  wallet: { seed_phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident" },
  seeded: [],
  enrolled_at: new Date().toISOString(),
};

test("seeds the three decoy files under the home directory with the secrets inside", () => {
  const home = mkdtempSync(join(tmpdir(), "tw-home-"));
  const files = plannedFiles(home);
  const r = seedFiles(cfg, files);
  assert.equal(r.written.length, 3);
  assert.equal(r.skipped.length, 0);
  const wallet = readFileSync(join(home, "Desktop", "wallet-recovery-phrase.txt"), "utf8");
  assert.match(wallet, /abandon ability/);
  assert.match(wallet, /Anchor4821!/);
  const env = readFileSync(join(home, "Documents", "meridian-api", ".env"), "utf8");
  assert.match(env, /MERIDIAN_API_KEY=mvk_live_/);
  const pw = readFileSync(join(home, "Documents", "passwords.txt"), "utf8");
  assert.match(pw, /sam\.kim42/);

  const removed = removeSeeded(files);
  assert.equal(removed.length, 3);
  for (const f of files) assert.equal(existsSync(f.path), false);
});

test("never overwrites or deletes a file that is not ours", () => {
  const home = mkdtempSync(join(tmpdir(), "tw-home-"));
  mkdirSync(join(home, "Documents"), { recursive: true });
  const real = join(home, "Documents", "passwords.txt");
  writeFileSync(real, "my actual notes");
  const files = plannedFiles(home);
  const r = seedFiles(cfg, files);
  assert.equal(r.written.length, 2);
  assert.equal(r.skipped.length, 1);
  assert.equal(readFileSync(real, "utf8"), "my actual notes");
  removeSeeded(files);
  assert.equal(readFileSync(real, "utf8"), "my actual notes");
});
