import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { CONFIG_DIR, GUARD_LOG, PAUSE_PATH, loadConfig } from "./config.ts";
import { analyze, type Verdict } from "./patterns.ts";
import { frontmostApp, machineName, notify, platform, readClipboard, writeClipboard } from "./platform.ts";

export interface GuardOptions {
  intervalMs?: number;
  dryRun?: boolean;
  quiet?: boolean;
}

export function blockedText(v: Verdict): string {
  return [
    `⚠️ Baitline blocked a suspicious command that a web page put on your clipboard.`,
    `A web page tried to make you run it. Do not paste it into Run, Terminal or PowerShell.`,
    `Reason: ${v.why}`,
    `If you really meant to run it: baitline guard pause 2m`,
  ].join("\n");
}

export function isPaused(now = Date.now()): boolean {
  if (!existsSync(PAUSE_PATH)) return false;
  const until = Number(readFileSync(PAUSE_PATH, "utf8").trim());
  return Number.isFinite(until) && until > now;
}

export function pauseFor(ms: number): number {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  const until = Date.now() + ms;
  writeFileSync(PAUSE_PATH, String(until));
  return until;
}

export function parseDuration(s: string): number {
  const m = /^(\d+)\s*(s|m|h)?$/i.exec(s.trim());
  if (!m) throw new Error(`bad duration "${s}" (use e.g. 90s, 2m, 1h)`);
  const n = Number(m[1]);
  const unit = (m[2] ?? "m").toLowerCase();
  return n * (unit === "s" ? 1000 : unit === "m" ? 60_000 : 3_600_000);
}

async function report(v: Verdict, app: string, sample: string): Promise<void> {
  const cfg = loadConfig();
  if (!cfg) return;
  try {
    await fetch(cfg.guard_url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ host: machineName(), source_app: app, rule: v.rule, sample }),
    });
  } catch {
    /* offline; the local log still has it */
  }
}

/** One tick of the guard. Exported so the loop is testable without a real clipboard. */
export interface Blocked extends Verdict {
  app: string;
}

/**
 * One tick of the guard. Exported so the loop is testable without a real clipboard.
 * Order matters: wipe the clipboard first, because that is the protective action and it
 * must not wait on anything slow. Finding out which app was in front is cosmetic.
 */
export function handleClipboard(
  text: string,
  deps: { write: (t: string) => void; app: () => string; notify: (title: string, body: string) => void; paused: () => boolean; dryRun: boolean },
): Blocked | null {
  const v = analyze(text);
  if (!v) return null;
  if (deps.paused()) return null;
  if (!deps.dryRun) deps.write(blockedText(v));
  const app = deps.app();
  deps.notify("Baitline blocked a command", `${app} copied a command that looks like a ClickFix attack (${v.rule}). It was removed from your clipboard.`);
  return { ...v, app };
}

export function runGuard(opts: GuardOptions = {}): void {
  const interval = opts.intervalMs ?? (platform === "win32" ? 800 : 400);
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  let last = readClipboard();
  let lastBlocked = "";
  if (!opts.quiet) {
    console.log(`baitline guard running (${platform}, every ${interval}ms${opts.dryRun ? ", dry run" : ""}). Ctrl+C to stop.`);
  }
  setInterval(() => {
    const text = readClipboard();
    if (text === last || text === lastBlocked) return;
    last = text;
    const v = handleClipboard(text, {
      write: (t) => {
        lastBlocked = t;
        writeClipboard(t);
      },
      app: frontmostApp,
      notify,
      paused: isPaused,
      dryRun: opts.dryRun ?? false,
    });
    if (!v) return;
    const sample = text.replace(/\s+/g, " ").slice(0, 300);
    const line = `${new Date().toISOString()} BLOCKED rule=${v.rule} app=${JSON.stringify(v.app)} sample=${JSON.stringify(sample)}\n`;
    appendFileSync(GUARD_LOG, line);
    if (!opts.quiet) process.stdout.write(line);
    void report(v, v.app, sample);
  }, interval).unref?.();
  // Keep the process alive.
  setInterval(() => {}, 1 << 30);
}
