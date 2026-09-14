import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CONFIG_DIR, GUARD_LOG, PAUSE_PATH, loadConfig } from "./config.ts";
import { analyze, type Verdict } from "./patterns.ts";
import { clipboardAvailable, frontmostApp, machineName, notify, platform, readClipboard, writeClipboard } from "./platform.ts";

export const PID_PATH = join(CONFIG_DIR, "guard.pid");

/** Normal cadence. Fast enough that a paste after reading the fake CAPTCHA is caught. */
const BASE_MS = platform === "win32" ? 800 : 400;
/** After a block, the page may rewrite the clipboard again. Watch it closely for a while. */
const HOT_MS = 75;
const HOT_FOR_MS = 10_000;

export interface GuardOptions {
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

/** Delay until the next clipboard check. Pure, so the hot-mode logic is testable. */
export function nextDelay(hotUntil: number, now: number, base = BASE_MS, hot = HOT_MS): number {
  return now < hotUntil ? hot : base;
}

/** Is a guard already running? Reads the pid file and probes the process. */
export function runningGuardPid(): number | null {
  if (!existsSync(PID_PATH)) return null;
  const pid = Number(readFileSync(PID_PATH, "utf8").trim());
  if (!Number.isInteger(pid) || pid <= 0) return null;
  try {
    process.kill(pid, 0);
    return pid;
  } catch {
    return null;
  }
}

async function report(v: Verdict, app: string, sample: string): Promise<void> {
  const cfg = loadConfig();
  if (!cfg?.guard_url) return;
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

/**
 * One tick of the guard, minus the reporting. Exported so it is testable without a real
 * clipboard. Nothing in here may block: the wipe is the protective action and the next
 * check must come 75 ms later.
 */
export function handleClipboard(text: string, deps: { write: (t: string) => void; paused: () => boolean; dryRun: boolean }): Verdict | null {
  const v = analyze(text);
  if (!v) return null;
  if (deps.paused()) return null;
  if (!deps.dryRun) deps.write(blockedText(v));
  return v;
}

/** Everything that happens after a wipe. Slow and fallible, so it runs detached from the loop. */
async function afterBlock(v: Verdict, text: string, quiet: boolean): Promise<void> {
  const app = await frontmostApp();
  notify("Baitline blocked a command", `${app} copied a command that looks like a ClickFix attack (${v.rule}). It was removed from your clipboard.`);
  const sample = text.replace(/\s+/g, " ").slice(0, 300);
  const line = `${new Date().toISOString()} BLOCKED rule=${v.rule} app=${JSON.stringify(app)} sample=${JSON.stringify(sample)}\n`;
  appendFileSync(GUARD_LOG, line);
  if (!quiet) process.stdout.write(line);
  await report(v, app, sample);
}

export function runGuard(opts: GuardOptions = {}): void {
  if (!clipboardAvailable()) {
    console.error(`Cannot read the clipboard on this system, so the guard would protect nothing. Not starting.`);
    if (platform === "linux") console.error(`Install wl-clipboard (Wayland) or xclip (X11) and try again.`);
    process.exit(3);
  }
  const other = runningGuardPid();
  if (other !== null && other !== process.pid) {
    console.error(`A guard is already running (pid ${other}).`);
    process.exit(1);
  }
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(PID_PATH, String(process.pid));
  const cleanup = () => {
    try {
      rmSync(PID_PATH, { force: true });
    } catch {
      /* already gone */
    }
  };
  process.on("exit", cleanup);
  for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => process.exit(0));

  let last = readClipboard();
  let lastBlocked = "";
  let hotUntil = 0;
  if (!opts.quiet) console.log(`baitline guard running (${platform}, every ${BASE_MS}ms${opts.dryRun ? ", dry run" : ""}). Ctrl+C to stop.`);

  const tick = () => {
    const text = readClipboard();
    if (text !== last && text !== lastBlocked) {
      last = text;
      const v = handleClipboard(text, {
        write: (t) => {
          lastBlocked = t;
          writeClipboard(t);
        },
        paused: isPaused,
        dryRun: opts.dryRun ?? false,
      });
      if (v) {
        hotUntil = Date.now() + HOT_FOR_MS;
        void afterBlock(v, text, opts.quiet ?? false).catch(() => {});
      }
    }
    setTimeout(tick, nextDelay(hotUntil, Date.now()));
  };
  tick();
}
