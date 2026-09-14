import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import type { Account } from "./account.ts";
import { saveConfig, type ClientConfig } from "./config.ts";
import { setDashboardToken } from "./keychain.ts";
import { openUrl } from "./platform.ts";
import { seedFiles } from "./seed.ts";

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export interface SetupOptions {
  server: string;
  email: string | null;
  /** A dashboard URL or bare token from a web sign-up, to attach this machine to that account. */
  link: string | null;
  noBrowser: boolean;
  interactive: boolean;
}

async function ask(question: string): Promise<string> {
  const rl = createInterface({ input: stdin, output: stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

function tokenFromLink(link: string): string {
  const m = /\/(?:setup|dashboard)\/([^/?#]+)/.exec(link);
  return (m?.[1] ?? link).trim();
}

async function fetchAccount(opts: SetupOptions): Promise<Account> {
  const server = opts.server.replace(/\/+$/, "");
  if (opts.link) {
    const token = tokenFromLink(opts.link);
    const res = await fetch(`${server}/api/me/${encodeURIComponent(token)}`);
    if (!res.ok) throw new Error(`could not find that account (HTTP ${res.status}). Check the link.`);
    return (await res.json()) as Account;
  }
  let email = opts.email;
  if (!email && opts.interactive) email = await ask("Your email (for alerts): ");
  if (!email || !EMAIL_RE.test(email)) throw new Error("a valid --email is required (or use --link with your dashboard URL)");
  const res = await fetch(`${server}/api/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) throw new Error(`enroll failed: HTTP ${res.status} ${await res.text()}`);
  return (await res.json()) as Account;
}

export async function setup(opts: SetupOptions): Promise<ClientConfig> {
  const account = await fetchAccount(opts);

  const seeded = seedFiles(account);
  const store = setDashboardToken(account.email, tokenFromLink(account.dashboard_url));
  const cfg: ClientConfig = {
    server: opts.server.replace(/\/+$/, ""),
    email: account.email,
    slug: new URL(account.vault.login_url).pathname.split("/").pop() ?? "",
    guard_url: account.guard_url,
    seeded: seeded.written,
    enrolled_at: new Date().toISOString(),
  };
  saveConfig(cfg);

  console.log(`\nBaitline is set up for ${account.email}.`);
  console.log(`Decoy files planted:`);
  for (const f of seeded.written) console.log(`  ${f.path}`);
  for (const s of seeded.skipped) console.log(`  skipped ${s.path}: ${s.reason}`);
  console.log(`Dashboard token stored in ${store === "keychain" ? "your login keychain" : "a protected file"}.`);

  if (!account.enrolled && account.vault.onboarding_url) {
    console.log(`\nOne thing left, and it takes ten seconds:`);
    console.log(`  1. A browser tab will open to a fake vault login (already filled in).`);
    console.log(`  2. Click Sign in.`);
    console.log(`  3. When the browser asks to save the password, click Save. That saved password is the trap.`);
    console.log(`\n  ${account.vault.onboarding_url}`);
    if (!opts.noBrowser) openUrl(account.vault.onboarding_url);
  } else if (account.enrolled) {
    console.log(`\nThe browser decoy is already planted for this account.`);
  }

  if (account.ntfy_subscribe_url) {
    console.log(`\nPhone alerts: install the "ntfy" app, then open this and tap Subscribe:`);
    console.log(`  ${account.ntfy_subscribe_url}`);
  }
  console.log(`\nFull setup page (QR code, test alert): ${account.setup_url}`);
  console.log(`Then start the guard:  baitline guard`);
  return cfg;
}
