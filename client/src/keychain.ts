import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CONFIG_DIR } from "./config.ts";

/**
 * The dashboard token is the one real secret on the client: it reads all your trips.
 * Keep it out of the plain config file. Use the OS secret store where we can, and fall
 * back to a 0600 file so the tool still works headless (servers, Linux without a keyring).
 */

const SERVICE = "baitline";

/** Set BAITLINE_TOKEN_STORE=file to skip the OS keychain (tests, headless boxes). */
function useKeychain(): boolean {
  return process.platform === "darwin" && process.env.BAITLINE_TOKEN_STORE !== "file";
}
const FALLBACK = join(CONFIG_DIR, "dashboard.token");

function mac(args: string[], input?: string): string {
  return execFileSync("security", args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "ignore"], timeout: 5000 });
}

export function setDashboardToken(account: string, token: string): "keychain" | "file" {
  if (useKeychain()) {
    try {
      mac(["add-generic-password", "-a", account, "-s", SERVICE, "-w", token, "-U"]);
      return "keychain";
    } catch {
      /* fall through */
    }
  }
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(FALLBACK, token, { mode: 0o600 });
  chmodSync(FALLBACK, 0o600);
  return "file";
}

export function getDashboardToken(account: string): string | null {
  if (useKeychain()) {
    try {
      return mac(["find-generic-password", "-a", account, "-s", SERVICE, "-w"]).trim();
    } catch {
      /* fall through */
    }
  }
  if (existsSync(FALLBACK)) return readFileSync(FALLBACK, "utf8").trim();
  return null;
}

export function clearDashboardToken(account: string): void {
  if (useKeychain()) {
    try {
      mac(["delete-generic-password", "-a", account, "-s", SERVICE]);
    } catch {
      /* not there */
    }
  }
  if (existsSync(FALLBACK)) rmSync(FALLBACK);
}
