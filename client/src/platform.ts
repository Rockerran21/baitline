import { execFile, execFileSync } from "node:child_process";
import { hostname } from "node:os";

export const platform: "darwin" | "win32" | "linux" = process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";

function run(cmd: string, args: string[], input?: string, timeout = 5000): string {
  return execFileSync(cmd, args, { input, encoding: "utf8", stdio: ["pipe", "pipe", "ignore"], timeout, maxBuffer: 4 * 1024 * 1024 });
}

export function readClipboard(): string {
  try {
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
  } catch {
    return "";
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
    /* clipboard write failed; the notification still fires */
  }
}

/** Best effort name of the frontmost application. Used for the alert text and dashboard only. */
export function frontmostApp(): string {
  try {
    switch (platform) {
      case "darwin":
        return run("osascript", ["-e", 'tell application "System Events" to get name of first application process whose frontmost is true'], undefined, 1500).trim();
      case "win32":
        return run("powershell", [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Add-Type 'using System;using System.Runtime.InteropServices;public class W{[DllImport(\"user32.dll\")]public static extern IntPtr GetForegroundWindow();[DllImport(\"user32.dll\")]public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);}'; $h=[W]::GetForegroundWindow(); $p=0; [void][W]::GetWindowThreadProcessId($h,[ref]$p); (Get-Process -Id $p).ProcessName",
        ], undefined, 2500).trim();
      case "linux":
        return run("xdotool", ["getactivewindow", "getwindowname"], undefined, 1500).trim();
    }
  } catch {
    return "unknown";
  }
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
    /* printed to the terminal as a fallback by the caller */
  }
}

export function machineName(): string {
  return hostname();
}
