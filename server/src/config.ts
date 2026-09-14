export interface Config {
  port: number;
  publicUrl: string;
  dbPath: string;
  ntfyBase: string;
  alertWebhookUrl: string | null;
  smtpUrl: string | null;
  alertFrom: string;
  onboardingGraceMs: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const port = Number(env.PORT ?? 8787);
  return {
    port,
    publicUrl: (env.PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/+$/, ""),
    dbPath: env.DB_PATH ?? "data/baitline.db",
    ntfyBase: (env.NTFY_BASE ?? "https://ntfy.sh").replace(/\/+$/, ""),
    alertWebhookUrl: env.ALERT_WEBHOOK_URL ?? null,
    smtpUrl: env.SMTP_URL ?? null,
    alertFrom: env.ALERT_FROM ?? "Baitline <baitline@localhost>",
    onboardingGraceMs: Number(env.ONBOARDING_GRACE_MS ?? 15 * 60 * 1000),
  };
}
