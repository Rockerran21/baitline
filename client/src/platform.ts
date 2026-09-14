import { execFile, execFileSync } from "node:child_process";
import { hostname } from "node:os";

export const platform: "darwin" | "win32" | "linux" = process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";

function run(cmd: string, args: string[], input?: string, timeout = 5000): string {
  return execFileSync(cmd, args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "ignore"], timeout, maxBuffer: 4 * 1024 * 1024 });
}

function readRaw(): string {
  switch (platform) {
    case "darwin":
      return run("pbpaste", []);
    case "win32":
      return run("powershell", ["-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"]);
    case "linux":
      try {
        return run("wl-paste", ["--no-newline"]);
      } catch {
        return run("xclip", ["-selection", "clipboard", "-o"]);
      }
  }
}

export function readClipboard(): string {
  try {
    return readRaw();
  } catch {
    return "";
  }
}

/**
 * Prove the clipboard can be read before promising protection. A guard that cannot
 * see the clipboard is worse than no guard: the user believes they are covered.
 */
export function clipboardAvailable(): boolean {
  try {
    readRaw();
    return true;
  } catch {
    return false;
  }
}

export function writeClipboard(text: string): void {
  try {
    switch (platform) {
      case "darwin":
        run("pbcopy", [], text);
        return;
      case "win32":
        run("powershell", ["-NoProfile", "-NonInteractive", "-Command", "$input | Set-Clipboard"], text);
        return;
      case "linux":
        try {
          run("wl-copy", [], text);
        } catch {
          run("xclip", ["-selection", "clipboard"], text);
        }
        return;
    }
  } catch {
    /* the notification and the log still fire */
  }
}

/**
 * Name of the frontmost app, macOS only. Cosmetic: used in the alert text and dashboard.
 * Asynchronous on purpose. Under launchd there is no Automation permission and this call
 * hangs until its timeout; it must never sit between the guard and the next clipboard check.
 */
export function frontmostApp(): Promise<string> {
  if (platform !== "darwin") return Promise.resolve("unknown");
  return new Promise((resolve) => {
    execFile(
      "osascript",
      ["-e", 'tell application "System Events" to get name of first application process whose frontmost is true'],
      { timeout: 1500 },
      (err, out) => resolve(err ? "unknown" : out.trim() || "unknown"),
    );
  });
}

export function notify(title: string, body: string): void {
  const safeTitle = title.replaceAll('"', "'");
  const safeBody = body.replaceAll('"', "'").slice(0, 240);
  try {
    switch (platform) {
      case "darwin":
        execFile("osascript", ["-e", `display notification "${safeBody}" with title "${safeTitle}" sound name "Basso"`]);
        return;
      case "win32":
        execFile("powershell", [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          `Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true; $n.ShowBalloonTip(15000, "${safeTitle}", "${safeBody}", [System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -Seconds 16; $n.Dispose()`,
        ]);
        return;
      case "linux":
        execFile("notify-send", ["-u", "critical", safeTitle, safeBody]);
        return;
    }
  } catch {
    /* no notification backend */
  }
}

export function openUrl(url: string): void {
  try {
    switch (platform) {
      case "darwin":
        execFile("open", [url]);
        return;
      case "win32":
        execFile("cmd", ["/c", "start", "", url]);
        return;
      case "linux":
        execFile("xdg-open", [url]);
        return;
    }
  } catch {
    /* the caller prints the URL as a fallback */
  }
}

export function machineName(): string {
  return hostname();
}
