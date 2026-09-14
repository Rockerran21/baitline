import { execFile } from "node:child_process";

export const platform: "darwin" | "win32" | "linux" = process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux";

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

