#!/usr/bin/env node
import { CONFIG_PATH, GUARD_LOG, loadConfig, requireConfig, saveConfig } from "./config.ts";
import { clearDashboardToken, getDashboardToken } from "./keychain.ts";
import { setup } from "./setup.ts";
import { pauseFor, parseDuration, runGuard, runningGuardPid } from "./guard.ts";
import { installAutostart, uninstallAutostart } from "./autostart.ts";
import { analyze } from "./patterns.ts";
import { openUrl } from "./platform.ts";
import { plannedFiles, removeSeeded } from "./seed.ts";

const HELP = `baitline — decoys that alert you when your computer is robbed, and a guard for your clipboard

Setup:
  baitline setup --server <url>                 create an account (asks for your email)
  baitline setup --server <url> --email <you@example.com>
  baitline setup --server <url> --link <your dashboard URL>   attach this machine to a web sign-up

Run:
  baitline guard install         start the clipboard guard at every login (macOS)
  baitline guard                 run the guard in this terminal instead
  baitline guard pause <2m>      let a legitimate installer through for a while
  baitline guard uninstall
  baitline status                what is planted, what has tripped, is the guard running
  baitline dashboard             open your dashboard
  baitline check "<text>"        test the detector on a string
  baitline reset                 remove the decoy files and forget this machine's setup
  baitline help
`;

function flag(args: string[], name: string): string | null {
  const i = args.indexOf(name);
  if (i === -1) return null;
  const v = args[i + 1];
  return v === undefined || v.startsWith("--") ? "" : v;
}

function dashboardUrl(): string | null {
  const cfg = loadConfig();
  if (!cfg) return null;
  const token = getDashboardToken(cfg.email);
  return token ? `${cfg.server}/dashboard/${token}` : null;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case "setup": {
      const server = flag(args, "--server");
      if (!server) {
        console.error(HELP);
        return 2;
      }
      const existing = loadConfig();
      if (existing && !args.includes("--force")) {
        console.error(`Already set up as ${existing.email} (${CONFIG_PATH}). Use --force to start over, or 'baitline reset' first.`);
        return 1;
      }
      await setup({
        server,
        email: flag(args, "--email"),
        link: flag(args, "--link"),
        noBrowser: args.includes("--no-browser"),
        interactive: process.stdin.isTTY === true && !args.includes("--no-input"),
      });
      return 0;
    }
    case "guard": {
      if (args[0] === "pause") {
        const until = pauseFor(parseDuration(args[1] ?? "2m"));
        console.log(`guard paused until ${new Date(until).toLocaleTimeString()}`);
        return 0;
      }
      if (args[0] === "install") {
        const p = installAutostart();
        console.log(`guard installed as a login agent (${p}). It is running now and will start at every login.`);
        return 0;
      }
      if (args[0] === "uninstall") {
        console.log(uninstallAutostart() ? "guard login agent removed" : "no login agent was installed");
        return 0;
      }
      runGuard({ dryRun: args.includes("--dry-run"), quiet: args.includes("--quiet") });
      return -1;
    }
    case "check": {
      const v = analyze(args.join(" "));
      if (v) {
        console.log(`BLOCK  rule=${v.rule}\n       ${v.why}`);
        return 1;
      }
      console.log("clean");
      return 0;
    }
    case "status": {
      const cfg = requireConfig();
      console.log(`set up: ${cfg.email} at ${cfg.enrolled_at}`);
      console.log(`server: ${cfg.server}`);
      console.log(`decoy files:`);
      for (const f of cfg.seeded) console.log(`  ${f.path}`);
      if (!cfg.seeded.length) console.log(`  (none recorded)`);
      const pid = runningGuardPid();
      console.log(pid ? `guard: running (pid ${pid})` : `guard: NOT running. Start it with 'baitline guard install'.`);
      console.log(`guard log: ${GUARD_LOG}`);
      const token = getDashboardToken(cfg.email);
      if (!token) {
        console.log(`no dashboard token found; run 'baitline setup --force' to relink.`);
        return 0;
      }
      try {
        const res = await fetch(`${cfg.server}/api/status/${token}`);
        const s = (await res.json()) as { enrolled: boolean; high_severity_trips: number; guard_events: number; trips: Array<{ at: number; kind: string; severity: string; ip: string }> };
        console.log(`server: browser decoy ${s.enrolled ? "planted" : "NOT planted yet (open the setup link)"}, ${s.high_severity_trips} high-severity trips, ${s.guard_events} blocked pastes`);
        for (const t of s.trips.slice(0, 10)) console.log(`  ${new Date(t.at).toISOString()} ${t.severity.padEnd(6)} ${t.kind.padEnd(15)} ${t.ip}`);
      } catch (err) {
        console.log(`server unreachable: ${(err as Error).message}`);
      }
      console.log(`dashboard: ${cfg.server}/dashboard/${token}`);
      return 0;
    }
    case "dashboard": {
      requireConfig();
      const url = dashboardUrl();
      if (!url) {
        console.error(`no dashboard token found; run 'baitline setup --force' to relink.`);
        return 1;
      }
      console.log(url);
      openUrl(url);
      return 0;
    }
    case "reset": {
      const cfg = loadConfig();
      if (!cfg) {
        console.log("nothing to reset");
        return 0;
      }
      const removed = removeSeeded(cfg.seeded.length ? cfg.seeded : plannedFiles());
      for (const p of removed) console.log(`removed ${p}`);
      clearDashboardToken(cfg.email);
      const { rmSync } = await import("node:fs");
      rmSync(CONFIG_PATH, { force: true });
      console.log(`forgot ${cfg.email}. Your decoys on the server still exist; the dashboard link still works if you saved it.`);
      return 0;
    }
    case "help":
    case "--help":
    case "-h":
    case undefined:
      console.log(HELP);
      return 0;
    default:
      console.error(`unknown command: ${cmd}\n\n${HELP}`);
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    if (code >= 0) process.exit(code);
  },
  (err) => {
    console.error((err as Error).message);
    process.exit(1);
  },
);
