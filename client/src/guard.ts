import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG_DIR, PAUSE_PATH } from "./config.ts";

/**
 * The guard itself is the Rust binary in ../guard. This module only knows where it is,
 * whether it is running, and how to pause it. The files are shared: same directory,
 * same names on both sides.
 */

export const PID_PATH = join(CONFIG_DIR, "guard.pid");

export function guardBinary(): string {
  const fromEnv = process.env.BAITLINE_GUARD_BIN;
  if (fromEnv) return fromEnv;
  const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  return join(repo, "guard", "target", "release", process.platform === "win32" ? "baitline-guard.exe" : "baitline-guard");
}

export function requireGuardBinary(): string {
  const bin = guardBinary();
  if (!existsSync(bin)) {
    throw new Error(`The guard binary is not built. Run:  cargo build --release --manifest-path guard/Cargo.toml\n(or set BAITLINE_GUARD_BIN to a built binary)`);
  }
  return bin;
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

/** Run the guard in the foreground, passing signals through. Returns its exit code. */
export function runGuardForeground(args: string[]): number {
  const r = spawnSync(requireGuardBinary(), args, { stdio: "inherit" });
  return r.status ?? 1;
}

export function check(text: string): { blocked: boolean; output: string } {
  try {
    return { blocked: false, output: execFileSync(requireGuardBinary(), ["check", text], { encoding: "utf8" }) };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; message: string };
    if (e.status === 1) return { blocked: true, output: e.stdout ?? "" };
    throw err;
  }
}
