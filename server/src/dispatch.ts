import type { Config } from "./config.ts";
import type { Store, Trip, User } from "./db.ts";
import { orgChannels, type Mailer, type Notifier } from "./alerts.ts";

/**
 * Who hears about a trip: the person on their own channels, a family owner with the
 * member's name, an organisation once on its channels. Shared by the live path and the
 * retry sweep, so a failed delivery is re-attempted the same way it was first tried.
 * Returns whether any channel accepted the alert.
 */
export async function dispatch(store: Store, cfg: Config, notify: Notifier, mailer: Mailer | null, fetchImpl: typeof fetch, user: User, trip: Trip): Promise<boolean> {
  const dashboardUrl = `${cfg.controlUrl}/dashboard`;
  const label = user.label || user.email;
  const jobs: Promise<boolean>[] = [notify({ user, trip, dashboardUrl })];
  const owner = user.parent_id !== null ? store.userById(user.parent_id) : undefined;
  if (owner) jobs.push(notify({ user: owner, trip, dashboardUrl, label }));
  const org = user.org_id !== null ? store.org(user.org_id) : undefined;
  if (org) {
    for (const ch of orgChannels(org, cfg, mailer, fetchImpl)) jobs.push(ch({ user, trip, dashboardUrl, label }));
  }
  const results = await Promise.allSettled(jobs);
  let delivered = false;
  for (const r of results) {
    if (r.status === "rejected") console.error("[alert] delivery failed:", r.reason);
    else if (r.value) delivered = true;
  }
  store.recordDelivery(trip.id, delivered);
  return delivered;
}

/** Re-attempt trips whose notification was never accepted. Run periodically. */
export async function retryUndelivered(store: Store, cfg: Config, notify: Notifier, mailer: Mailer | null, fetchImpl: typeof fetch = fetch): Promise<number> {
  let delivered = 0;
  for (const trip of store.undelivered(cfg.notifyMaxAttempts)) {
    const user = store.userById(trip.user_id);
    if (!user) continue;
    if (await dispatch(store, cfg, notify, mailer, fetchImpl, user, trip)) delivered++;
  }
  return delivered;
}
