export interface Config {
  port: number;
  /** Where the decoy vault lives. Decoy URLs are built from it. */
  publicUrl: string;
  /** Where setup, dashboard and the client API live. Same as publicUrl in dev; a different host in production. */
  controlUrl: string;
  dbPath: string;
  ntfyBase: string;
  smtpUrl: string | null;
  alertFrom: string;
  onboardingGraceMs: number;
  /** What the decoy site calls itself. Change this in production; the default is in a public repo. */
  brand: string;
  company: string;
  keyPrefix: string;
  /** Same (kind, ip) within this window is recorded but not re-notified. */
  alertDedupeMs: number;
  /** Max notifications per user per hour. Trips are still recorded past this. */
  alertHourlyCap: number;
  enrollPerHourPerIp: number;
}

function strip(u: string): string {
  return u.replace(/\/+$/, "");
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const port = Number(env.PORT ?? 8787);
  const publicUrl = strip(env.PUBLIC_URL ?? `http://localhost:${port}`);
  return {
    port,
    publicUrl,
    controlUrl: strip(env.CONTROL_URL ?? publicUrl),
    dbPath: env.DB_PATH ?? "data/baitline.db",
    ntfyBase: strip(env.NTFY_BASE ?? "https://ntfy.sh"),
    smtpUrl: env.SMTP_URL ?? null,
    alertFrom: env.ALERT_FROM ?? "Baitline <baitline@localhost>",
    onboardingGraceMs: Number(env.ONBOARDING_GRACE_MS ?? 15 * 60 * 1000),
    brand: env.DECOY_BRAND ?? "Meridian Vault",
    company: env.DECOY_COMPANY ?? "Meridian Custody Ltd.",
    keyPrefix: env.DECOY_KEY_PREFIX ?? "mvk_live_",
    alertDedupeMs: Number(env.ALERT_DEDUPE_MS ?? 10 * 60 * 1000),
    alertHourlyCap: Number(env.ALERT_HOURLY_CAP ?? 6),
    enrollPerHourPerIp: Number(env.ENROLL_PER_HOUR_PER_IP ?? 5),
  };
}
