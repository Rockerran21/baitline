#!/usr/bin/env node
import { CONFIG_PATH, GUARD_LOG, loadConfig, requireConfig, saveConfig } from "./config.ts";
import { enroll } from "./enroll.ts";
import { pauseFor, parseDuration, runGuard } from "./guard.ts";
import { analyze } from "./patterns.ts";
import { openUrl } from "./platform.ts";
import { plannedFiles, removeSeeded, seedFiles } from "./seed.ts";

const HELP = `baitline — decoys that phone you when your computer is robbed, and a guard for your clipboard

Usage:
  baitline enroll --server <url> --email <you@example.com> [--ntfy <topic>] [--no-browser]
  baitline seed                 re-plant decoy files (after a cleanup or on a new machine)
  baitline unseed               remove the decoy files this tool created
  baitline guard [--dry-run] [--interval <ms>] [--quiet]
  baitline guard pause <2m|90s|1h>
  baitline check "<text>"       test the ClickFix detector on a string
  baitline status
  baitline dashboard            open your dashboard in the browser
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
    case "enroll": {
      const server = flag(args, "--server");
      const email = flag(args, "--email");
      if (!server || !email) {
        console.error(HELP);
        return 2;
      }
      const existing = loadConfig();
      if (existing && !args.includes("--force")) {
        console.error(`Already enrolled as ${existing.email} (${CONFIG_PATH}). Use --force to enroll again with fresh decoys.`);
        return 1;
      }
      await enroll({ server, email, ntfyTopic: flag(args, "--ntfy") || null, noBrowser: args.includes("--no-browser") });
      return 0;
    }
    case "seed": {
      const cfg = requireConfig();
      const r = seedFiles(cfg, plannedFiles());
      cfg.seeded = [...cfg.seeded.filter((s) => !r.written.some((w) => w.path === s.path)), ...r.written];
      saveConfig(cfg);
      for (const f of r.written) console.log(`planted ${f.path}`);
      for (const s of r.skipped) console.log(`skipped ${s.path}: ${s.reason}`);
      return 0;
    }
    case "unseed": {
      const cfg = requireConfig();
      const removed = removeSeeded(cfg.seeded.length ? cfg.seeded : plannedFiles());
      cfg.seeded = [];
      saveConfig(cfg);
      for (const p of removed) console.log(`removed ${p}`);
      if (!removed.length) console.log("nothing to remove");
      return 0;
    }
    case "guard": {
      if (args[0] === "pause") {
        const until = pauseFor(parseDuration(args[1] ?? "2m"));
        console.log(`guard paused until ${new Date(until).toLocaleTimeString()}`);
        return 0;
      }
      const iv = flag(args, "--interval");
      runGuard({ dryRun: args.includes("--dry-run"), quiet: args.includes("--quiet"), intervalMs: iv ? Number(iv) : undefined });
      return -1; // keeps running
    }
    case "check": {
      const text = args.join(" ");
      const v = analyze(text);
      if (v) {
        console.log(`BLOCK  rule=${v.rule}\n       ${v.why}`);
        return 1;
      }
      console.log("clean");
      return 0;
    }
    case "status": {
      const cfg = requireConfig();
      console.log(`enrolled: ${cfg.email} at ${cfg.enrolled_at}`);
      console.log(`server:   ${cfg.server}`);
      console.log(`decoy files: ${cfg.seeded.length ? "" : "(none recorded)"}`);
      for (const f of cfg.seeded) console.log(`  ${f.path}`);
      console.log(`guard log:  ${GUARD_LOG}`);
      try {
        const res = await fetch(cfg.status_url);
        const s = (await res.json()) as { enrolled: boolean; high_severity_trips: number; guard_events: number; trips: Array<{ at: number; kind: string; severity: string; ip: string }> };
        console.log(`server says: browser decoy ${s.enrolled ? "planted" : "NOT planted yet (open the onboarding link)"}, ${s.high_severity_trips} high-severity trips, ${s.guard_events} blocked pastes`);
        for (const t of s.trips.slice(0, 10)) console.log(`  ${new Date(t.at).toISOString()} ${t.severity.padEnd(6)} ${t.kind.padEnd(15)} ${t.ip}`);
      } catch (err) {
        console.log(`server unreachable: ${(err as Error).message}`);
      }
      console.log(`dashboard: ${cfg.dashboard_url}`);
      return 0;
    }
    case "dashboard": {
      const cfg = requireConfig();
      console.log(cfg.dashboard_url);
      openUrl(cfg.dashboard_url);
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
