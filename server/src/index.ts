import { serve } from "@hono/node-server";
import { loadConfig } from "./config.ts";
import { Store } from "./db.ts";
import { consoleNotifier, emailNotifier, fanout, ntfyNotifier, webhookNotifier } from "./alerts.ts";
import { createApp } from "./app.ts";

const cfg = loadConfig();
const store = new Store(cfg.dbPath);
const notify = fanout([consoleNotifier(), ntfyNotifier(cfg), webhookNotifier(cfg), emailNotifier(cfg)]);
const app = createApp(store, cfg, notify);

serve({ fetch: app.fetch, port: cfg.port }, (info) => {
  console.log(`baitline server listening on http://localhost:${info.port} (public: ${cfg.publicUrl})`);
  console.log(`alerts: console${cfg.alertWebhookUrl ? ", webhook" : ""}${cfg.smtpUrl ? ", email" : ""}, ntfy via ${cfg.ntfyBase}`);
});
