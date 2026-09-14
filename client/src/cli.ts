#!/usr/bin/env node
import { rmSync } from "node:fs";
import { CONFIG_PATH, GUARD_LOG, loadConfig, requireConfig } from "./config.ts";
import { setup } from "./setup.ts";
import { check, pauseFor, parseDuration, runGuardForeground, runningGuardPid } from "./guard.ts";
import { installAutostart, uninstallAutostart } from "./autostart.ts";
import { openUrl } from "./platform.ts";
import { removeSeeded } from "./seed.ts";

const HELP = `baitline — decoys that alert you when your computer is robbed, and a guard for your clipboard

Setup:
  Sign in on the server, open Setup, and run the command shown there. It looks like:
  baitline setup --server <url> --link <one-time device code>

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

async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case "setup": {
      const server = flag(args, "--server");
      const link = flag(args, "--link");
      if (!server || !link) {
        console.error(HELP);
        return 2;
      }
      const existing = loadConfig();
      if (existing && !args.includes("--force")) {
        console.error(`Already set up as ${existing.email} (${CONFIG_PATH}). Use --force to start over, or 'baitline reset' first.`);
        return 1;
      }
      await setup({ server, link, noBrowser: args.includes("--no-browser") });
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
      return runGuardForeground(args);
    }
    case "check": {
      const r = check(args.join(" "));
      process.stdout.write(r.output);
      return r.blocked ? 1 : 0;
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
      try {
        const res = await fetch(cfg.status_url);
        const s = (await res.json()) as { enrolled: boolean; high_severity_trips: number; guard_events: number; trips: Array<{ at: number; kind: string; severity: string; ip: string }> };
        console.log(`server: browser decoy ${s.enrolled ? "planted" : "NOT planted yet (open the setup link)"}, ${s.high_severity_trips} high-severity trips, ${s.guard_events} blocked pastes`);
        for (const t of s.trips.slice(0, 10)) console.log(`  ${new Date(t.at).toISOString()} ${t.severity.padEnd(6)} ${t.kind.padEnd(15)} ${t.ip}`);
      } catch (err) {
        console.log(`server unreachable: ${(err as Error).message}`);
      }
      console.log(`dashboard: ${cfg.server}/dashboard`);
      return 0;
    }
    case "dashboard": {
      const cfg = requireConfig();
      const url = `${cfg.server}/dashboard`;
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
      const removed = removeSeeded(cfg.seeded.filter((f) => typeof f.sha256 === "string"));
      for (const p of removed) console.log(`removed ${p}`);
      rmSync(CONFIG_PATH, { force: true });
      console.log(`forgot ${cfg.email}. Your account on the server still exists; sign in there to manage it.`);
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
