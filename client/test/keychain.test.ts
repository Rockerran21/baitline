import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Force the file fallback path (deterministic across CI and headless machines).
process.env.BAITLINE_HOME = mkdtempSync(join(tmpdir(), "bl-kc-"));
process.env.BAITLINE_TOKEN_STORE = "file";

const { setDashboardToken, getDashboardToken, clearDashboardToken } = await import("../src/keychain.ts");

test("dashboard token round-trips through the file fallback with 0600 perms", async () => {
  const where = setDashboardToken("v@example.com", "secret-token-123");
  assert.equal(where, "file");
  const file = join(process.env.BAITLINE_HOME!, "dashboard.token");
  assert.ok(existsSync(file));
  const { statSync } = await import("node:fs");
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(getDashboardToken("v@example.com"), "secret-token-123");
  clearDashboardToken("v@example.com");
  assert.equal(getDashboardToken("v@example.com"), null);
});

test("missing token reads as null", () => {
  assert.equal(getDashboardToken("nobody@example.com"), null);
});
