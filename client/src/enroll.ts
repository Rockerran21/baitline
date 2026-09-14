import { saveConfig, type ClientConfig } from "./config.ts";
import { openUrl } from "./platform.ts";
import { seedFiles } from "./seed.ts";

export interface EnrollOptions {
  server: string;
  email: string;
  ntfyTopic: string | null;
  noBrowser: boolean;
}

export async function enroll(opts: EnrollOptions): Promise<ClientConfig> {
  const server = opts.server.replace(/\/+$/, "");
  const res = await fetch(`${server}/api/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: opts.email, ntfy_topic: opts.ntfyTopic ?? undefined }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`enroll failed: HTTP ${res.status} ${text}`);
  }
  const data = (await res.json()) as Omit<ClientConfig, "server" | "email" | "ntfy_topic" | "seeded" | "enrolled_at">;
  const cfg: ClientConfig = {
    server,
    email: opts.email,
    ntfy_topic: opts.ntfyTopic,
    ...data,
    seeded: [],
    enrolled_at: new Date().toISOString(),
  };

  const seeded = seedFiles(cfg);
  cfg.seeded = seeded.written;
  saveConfig(cfg);

  console.log(`Enrolled ${opts.email} against ${server}`);
  console.log(`Decoy files planted:`);
  for (const f of seeded.written) console.log(`  ${f.path}`);
  for (const s of seeded.skipped) console.log(`  skipped ${s.path}: ${s.reason}`);
  console.log(``);
  console.log(`Last step: sign in to the decoy vault once so your browser saves the password.`);
  console.log(`  ${cfg.vault.onboarding_url}`);
  console.log(`When the browser offers to save the password, click Save. Then close the tab and never go back.`);
  if (opts.ntfyTopic) {
    console.log(``);
    console.log(`Push alerts: install the ntfy app on your phone and subscribe to topic "${opts.ntfyTopic}".`);
  }
  console.log(``);
  console.log(`Dashboard: ${cfg.dashboard_url}`);
  if (!opts.noBrowser) openUrl(cfg.vault.onboarding_url);
  return cfg;
}
