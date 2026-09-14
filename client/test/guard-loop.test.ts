import { test } from "node:test";
import assert from "node:assert/strict";
import { nextDelay } from "../src/guard.ts";
import { renderPlist } from "../src/autostart.ts";

test("guard polls fast for a while after a block, then settles back", () => {
  const blockedAt = 1_000_000;
  const hotUntil = blockedAt + 10_000;
  assert.equal(nextDelay(hotUntil, blockedAt + 1, 400, 75), 75, "right after a block");
  assert.equal(nextDelay(hotUntil, blockedAt + 9_999, 400, 75), 75, "still inside the hot window");
  assert.equal(nextDelay(hotUntil, blockedAt + 10_000, 400, 75), 400, "back to normal after the window");
  assert.equal(nextDelay(0, blockedAt, 400, 75), 400, "never blocked");
});

test("launch agent definition runs the guard quietly, at login, and restarts it", () => {
  const plist = renderPlist("/opt/homebrew/bin/node", "/Users/x/baitline/client/src/cli.ts", "/Users/x/.baitline");
  assert.match(plist, /<string>com\.baitline\.guard<\/string>/);
  assert.match(plist, /<string>\/opt\/homebrew\/bin\/node<\/string>\s*<string>\/Users\/x\/baitline\/client\/src\/cli\.ts<\/string>\s*<string>guard<\/string>\s*<string>--quiet<\/string>/);
  assert.match(plist, /<key>RunAtLoad<\/key><true\/>/);
  assert.match(plist, /<key>KeepAlive<\/key><true\/>/);
  assert.match(plist, /guard\.err/);
});

test("paths with XML-special characters are escaped in the agent definition", () => {
  const plist = renderPlist("/n", "/Users/a&b/<cli>.ts", "/l");
  assert.match(plist, /\/Users\/a&amp;b\/&lt;cli&gt;\.ts/);
  assert.doesNotMatch(plist, /<cli>/);
});
