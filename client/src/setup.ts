import type { Account } from "./account.ts";
import { saveConfig, type ClientConfig } from "./config.ts";
import { openUrl } from "./platform.ts";
import { seedFiles } from "./seed.ts";

export interface SetupOptions {
  server: string;
  /** The one-time device code from the setup page. */
  link: string;
  noBrowser: boolean;
}

export async function setup(opts: SetupOptions): Promise<ClientConfig> {
  const server = opts.server.replace(/\/+$/, "");
  const res = await fetch(`${server}/api/link`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code: opts.link.trim() }),
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `link failed: HTTP ${res.status}`);
  }
  const account = (await res.json()) as Account;

  const seeded = seedFiles(account);
  // The list of what was planted goes to the server, where only a fresh one-time reset code can read it back.
  // The write uses a token that never touches the disk, so the device token on disk cannot change the list.
  const m = await fetch(`${server}/api/manifest/put`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: account.manifest_token, files: seeded.written }) });
  if (!m.ok) throw new Error(`could not store the file manifest on the server (HTTP ${m.status}); nothing was left on this machine that lists the files`);
  const cfg: ClientConfig = {
    server,
    email: account.email,
    guard_url: account.guard_url,
    status_url: account.status_url,
    enrolled_at: new Date().toISOString(),
  };
  saveConfig(cfg);

  console.log(`\nBaitline is set up for ${account.email}.`);
  console.log(`Decoy files planted:`);
  for (const f of seeded.written) console.log(`  ${f.path}`);
  for (const s of seeded.skipped) console.log(`  skipped ${s.path}: ${s.reason}`);

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
  console.log(`\nNow start the guard so it runs at every login:  baitline guard install`);
  return cfg;
}
