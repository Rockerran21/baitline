import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { plannedFiles, removeSeeded, seedFiles } from "../src/seed.ts";
import type { Account } from "../src/account.ts";

const account: Account = {
  email: "v@example.com",
  brand: "Meridian Vault",
  company: "Meridian Custody Ltd.",
  ntfy_topic: "bl-abc",
  ntfy_subscribe_url: "https://ntfy.sh/bl-abc",
  setup_url: "http://ctrl.test/setup",
  status_url: "http://ctrl.test/api/status/g",
  guard_url: "http://ctrl.test/api/guard/g",
  enrolled: false,
  vault: { onboarding_url: "http://vault.test/vault/s?setup=x", login_url: "http://vault.test/vault/s", username: "sam.kim42", password: "Anchor4821!" },
  api: { base: "http://vault.test/api/v1/s", key: "mvk_live_" + "ab".repeat(20) },
  wallet: { seed_phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident" },
  manifest_token: "m",
};

test("seeds the three decoy files under the home directory with the secrets inside and nothing that names the product", () => {
  const home = mkdtempSync(join(tmpdir(), "tw-home-"));
  const files = plannedFiles(home);
  const r = seedFiles(account, files);
  assert.equal(r.written.length, 3);
  assert.equal(r.skipped.length, 0);
  for (const f of r.written) {
    const text = readFileSync(f.path, "utf8");
    assert.doesNotMatch(text, /baitline|decoy|do not edit/i, `${f.path} must not identify itself`);
    assert.match(f.sha256, /^[0-9a-f]{64}$/);
  }
  const wallet = readFileSync(join(home, "Desktop", "wallet-recovery-phrase.txt"), "utf8");
  assert.match(wallet, /abandon ability/);
  assert.match(wallet, /Anchor4821!/);
  const env = readFileSync(join(home, "Documents", "vault-api", ".env"), "utf8");
  assert.match(env, /VAULT_API_KEY=mvk_live_/);
  const pw = readFileSync(join(home, "Documents", "passwords.txt"), "utf8");
  assert.match(pw, /sam\.kim42/);

  const removed = removeSeeded(r.written, files);
  assert.equal(removed.length, 3);
  for (const f of files) assert.equal(existsSync(f.path), false);
});

test("re-seeding over our own files works; a file the user edited is left alone", () => {
  const home = mkdtempSync(join(tmpdir(), "tw-home-"));
  const first = seedFiles(account, plannedFiles(home));
  const again = seedFiles(account, plannedFiles(home), first.written);
  assert.equal(again.written.length, 3, "our own files can be refreshed");
  writeFileSync(first.written[0]!.path, "user changed this");
  assert.deepEqual(removeSeeded(first.written, plannedFiles(home)).length, 2, "the edited file is not deleted");
  assert.equal(readFileSync(first.written[0]!.path, "utf8"), "user changed this");
});

test("never overwrites or deletes a file that is not ours", () => {
  const home = mkdtempSync(join(tmpdir(), "tw-home-"));
  mkdirSync(join(home, "Documents"), { recursive: true });
  const real = join(home, "Documents", "passwords.txt");
  writeFileSync(real, "my actual notes");
  const files = plannedFiles(home);
  const r = seedFiles(account, files);
  assert.equal(r.written.length, 2);
  assert.equal(r.skipped.length, 1);
  assert.equal(readFileSync(real, "utf8"), "my actual notes");
  removeSeeded([...r.written, { path: real, kind: "passwords_file", sha256: "0".repeat(64) }], files);
  assert.equal(readFileSync(real, "utf8"), "my actual notes");
});
