import nodemailer from "nodemailer";
import type { Config } from "./config.ts";
import type { Org, Severity, Trip, TripKind, User } from "./db.ts";

export interface AlertPayload {
  /** Who receives this alert. For a member's trip this is sent once to the member and once to the owner. */
  user: User;
  trip: Trip;
  dashboardUrl: string;
  /** Set when the trip belongs to a family member: how the owner named them. */
  label?: string;
}

const KIND_TEXT: Record<TripKind, string> = {
  vault_visit: "Someone opened your decoy vault page",
  login_attempt: "Someone tried to log in to your decoy vault",
  credential_use: "Your decoy password was USED to log in",
  cookie_replay: "Your decoy session cookie was REPLAYED",
  api_key_use: "Your decoy API key was USED",
  test_alert: "Test alert. Your phone is wired up correctly",
};

/** ASCII only: this string also travels in HTTP headers (ntfy), which reject non-Latin-1 characters. */
export function alertTitle(trip: Trip, label?: string): string {
  const sev = trip.severity === "high" ? "[TRIPPED] " : trip.severity === "medium" ? "[Probe] " : "[Info] ";
  const who = label ? `${label.replace(/[^\x20-\x7E]/g, "?").slice(0, 40)}: ` : "";
  return `${sev}${who}${KIND_TEXT[trip.kind]}`;
}

export function alertBody(p: AlertPayload): string {
  const when = new Date(p.trip.created_at).toISOString();
  const lines = [
    `${p.label ? `${p.label}: ` : ""}${KIND_TEXT[p.trip.kind]}.`,
    ``,
    `When: ${when}`,
    `From IP: ${p.trip.ip}`,
    `Client: ${p.trip.ua || "(none)"}`,
    ``,
  ];
  if (p.trip.kind === "test_alert") {
    return `This is a test. If you can read this on your phone, real alerts will reach you the same way.\n\nDashboard: ${p.dashboardUrl}`;
  }
  if (p.trip.severity === "high") {
    lines.push(
      `This decoy only exists on your computer. Somebody copied it off your machine and is using it now.`,
      `Treat the device it was planted on as compromised. Reset from a different, clean device.`,
      ``,
    );
  }
  lines.push(`Details and reset checklist: ${p.dashboardUrl}`);
  return lines.join("\n");
}

export type Notifier = (p: AlertPayload) => Promise<void>;

function priorityFor(sev: Severity): string {
  return sev === "high" ? "urgent" : sev === "medium" ? "high" : "default";
}

export function ntfyNotifier(cfg: Config, fetchImpl: typeof fetch = fetch): Notifier {
  return async (p) => {
    if (!p.user.ntfy_topic) return;
    const url = `${cfg.ntfyBase}/${encodeURIComponent(p.user.ntfy_topic)}`;
    await fetchImpl(url, {
      method: "POST",
      headers: {
        Title: alertTitle(p.trip, p.label),
        Priority: priorityFor(p.trip.severity),
        Tags: p.trip.severity === "high" ? "rotating_light" : "warning",
        Click: p.dashboardUrl,
      },
      body: alertBody(p),
    });
  };
}

export interface Mailer {
  send(to: string, subject: string, text: string): Promise<void>;
}

export function createMailer(cfg: Config): Mailer | null {
  if (!cfg.smtpUrl) return null;
  const transport = nodemailer.createTransport(cfg.smtpUrl);
  return {
    async send(to, subject, text) {
      await transport.sendMail({ from: cfg.alertFrom, to, subject, text });
    },
  };
}

export function emailNotifier(mailer: Mailer | null): Notifier {
  if (!mailer) return async () => {};
  return async (p) => {
    await mailer.send(p.user.email, alertTitle(p.trip, p.label), alertBody(p));
  };
}

export function consoleNotifier(): Notifier {
  return async (p) => {
    console.log(`[alert] user=${p.user.id} ${p.trip.severity} ${p.trip.kind} ip=${p.trip.ip}`);
  };
}

/** Fan out to every channel; one channel failing must not stop the others. */
export function fanout(notifiers: Notifier[]): Notifier {
  return async (p) => {
    const results = await Promise.allSettled(notifiers.map((n) => n(p)));
    for (const r of results) {
      if (r.status === "rejected") console.error("[alert] channel failed:", r.reason);
    }
  };
}

/**
 * Organisation channels. For a security team an alert that is not in their SIEM or
 * chat does not exist, so the org tier gets a JSON webhook and a shared mailbox.
 */
export function orgChannels(org: Org, mailer: Mailer | null, fetchImpl: typeof fetch = fetch): Notifier[] {
  const out: Notifier[] = [];
  if (org.alert_webhook_url) {
    const url = org.alert_webhook_url;
    out.push(async (p) => {
      await fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          title: alertTitle(p.trip, p.label),
          text: alertBody(p),
          org: org.slug,
          member: p.label ?? p.user.email,
          severity: p.trip.severity,
          kind: p.trip.kind,
          ip: p.trip.ip,
          ua: p.trip.ua,
          at: new Date(p.trip.created_at).toISOString(),
        }),
      });
    });
  }
  if (org.alert_email && mailer) {
    const to = org.alert_email;
    out.push(async (p) => {
      await mailer.send(to, alertTitle(p.trip, p.label), alertBody(p));
    });
  }
  return out;
}
