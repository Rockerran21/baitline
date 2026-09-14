export interface Config {
  port: number;
  /** Where the decoy vault lives. Decoy URLs are built from it. */
  publicUrl: string;
  /** Where sign-in, setup, dashboard and the client API live. A different host in production. */
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
  alertDedupeMs: number;
  alertHourlyCap: number;
  enrollPerHourPerIp: number;
  /** Sign-in sessions. Short on purpose: the admin's laptop can be robbed too. */
  sessionIdleMs: number;
  sessionMaxMs: number;
  /** Sensitive actions need a sign-in more recent than this. */
  freshMs: number;
  magicLinkMs: number;
  /** WebAuthn relying party, derived from controlUrl. */
  rpId: string;
  rpOrigin: string;
  rpName: string;
}

function strip(u: string): string {
  return u.replace(/\/+$/, "");
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const port = Number(env.PORT ?? 8787);
  const publicUrl = strip(env.PUBLIC_URL ?? `http://localhost:${port}`);
  const controlUrl = strip(env.CONTROL_URL ?? publicUrl);
  const control = new URL(controlUrl);
  return {
    port,
    publicUrl,
    controlUrl,
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
    sessionIdleMs: Number(env.SESSION_IDLE_MS ?? 60 * 60 * 1000),
    sessionMaxMs: Number(env.SESSION_MAX_MS ?? 12 * 60 * 60 * 1000),
    freshMs: Number(env.FRESH_MS ?? 10 * 60 * 1000),
    magicLinkMs: Number(env.MAGIC_LINK_MS ?? 15 * 60 * 1000),
    rpId: control.hostname,
    rpOrigin: control.origin,
    rpName: "Baitline",
  };
}
