import { serve } from "@hono/node-server";
import { loadConfig } from "./config.ts";
import { Store } from "./db.ts";
import { consoleNotifier, createMailer, emailNotifier, fanout, ntfyNotifier } from "./alerts.ts";
import { createApp } from "./app.ts";

const cfg = loadConfig();
const store = new Store(cfg.dbPath);
const mailer = createMailer(cfg);
const notify = fanout([consoleNotifier(), ntfyNotifier(cfg), emailNotifier(mailer)]);
const app = createApp(store, cfg, notify, mailer);

serve({ fetch: app.fetch, port: cfg.port }, (info) => {
  console.log(`baitline server listening on http://localhost:${info.port}`);
  console.log(`decoy vault: ${cfg.publicUrl}  control plane: ${cfg.controlUrl}  brand: ${cfg.brand}`);
  console.log(`sign up at ${cfg.controlUrl}/`);
  console.log(`alerts: console${cfg.smtpUrl ? ", email" : ""}, ntfy via ${cfg.ntfyBase}`);
});
