import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CONFIG_DIR } from "./config.ts";
import { platform } from "./platform.ts";

/**
 * Prevention only counts if the guard is running. On macOS we register a launchd
 * agent: starts at login, restarts if it dies. Other platforms are not wired yet
 * because I cannot verify them here, and unverified startup code in a security
 * tool is worse than an honest message.
 */

const LABEL = "com.baitline.guard";

function plistPath(): string {
  return join(homedir(), "Library", "LaunchAgents", `${LABEL}.plist`);
}

function xml(s: string): string {
  return s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

/** Pure, so the generated agent definition is testable. */
export function renderPlist(nodePath: string, cliPath: string, logDir: string): string {
  const args = [nodePath, cliPath, "guard", "--quiet"].map((a) => `    <string>${xml(a)}</string>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>${xml(join(logDir, "guard.err"))}</string>
</dict>
</plist>
`;
}

function cliPath(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "cli.ts");
}

function launchctl(args: string[]): void {
  execFileSync("launchctl", args, { stdio: ["ignore", "ignore", "pipe"], timeout: 10_000 });
}

export function installAutostart(): string {
  if (platform !== "darwin") {
    throw new Error(`Autostart is only wired up for macOS so far. On ${platform}, run "baitline guard" in a terminal you keep open, or add that command to your login items.`);
  }
  const p = plistPath();
  mkdirSync(dirname(p), { recursive: true });
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(p, renderPlist(process.execPath, cliPath(), CONFIG_DIR), { mode: 0o644 });
  const domain = `gui/${userInfo().uid}`;
  try {
    launchctl(["bootout", `${domain}/${LABEL}`]);
  } catch {
    /* was not loaded */
  }
  launchctl(["bootstrap", domain, p]);
  return p;
}

export function uninstallAutostart(): boolean {
  if (platform !== "darwin") return false;
  const p = plistPath();
  try {
    launchctl(["bootout", `gui/${userInfo().uid}/${LABEL}`]);
  } catch {
    /* was not loaded */
  }
  if (!existsSync(p)) return false;
  rmSync(p);
  return true;
}
