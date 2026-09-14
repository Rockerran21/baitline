import type { Config } from "./config.ts";
import type { Delivery, Store, Trip, User } from "./db.ts";
import { DELIVERY_TIMEOUT_MS, orgChannels, type Mailer, type Notifier } from "./alerts.ts";

/**
 * Every trip fans out to destinations: the person, a family owner, an organisation's
 * webhook and mailbox. Each destination has its own outbox row with its own attempts,
 * so one success never hides another's failure, and the retry sweep re-attempts only
 * what has not been accepted. No attempt may outlive its deadline.
 */

interface Destination {
  key: string;
  run: () => Promise<boolean>;
}

function withDeadline<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timed out after ${ms} ms`)), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      },
    );
  });
}

function destinations(store: Store, cfg: Config, notify: Notifier, mailer: Mailer | null, fetchImpl: typeof fetch, user: User, trip: Trip): Destination[] {
  const dashboardUrl = `${cfg.controlUrl}/dashboard`;
  const label = user.label || user.email;
  const out: Destination[] = [{ key: `self:${user.id}`, run: () => notify({ user, trip, dashboardUrl }) }];
  const owner = user.parent_id !== null ? store.userById(user.parent_id) : undefined;
  if (owner) out.push({ key: `owner:${owner.id}`, run: () => notify({ user: owner, trip, dashboardUrl, label }) });
  const org = user.org_id !== null ? store.org(user.org_id) : undefined;
  if (org) {
    const channels = orgChannels(org, cfg, mailer, fetchImpl);
    channels.forEach((ch, i) => out.push({ key: `org:${org.id}:${i === 0 && org.alert_webhook_url ? "webhook" : "email"}`, run: () => ch({ user, trip, dashboardUrl, label }) }));
  }
  return out;
}

async function attempt(store: Store, row: Delivery, d: Destination): Promise<boolean> {
  try {
    const ok = await withDeadline(d.run(), DELIVERY_TIMEOUT_MS + 1_000);
    store.recordDeliveryResult(row.id, ok, ok ? "" : "channel declined");
    return ok;
  } catch (err) {
    const msg = (err as Error).message ?? String(err);
    console.error(`[alert] ${d.key} failed:`, msg);
    store.recordDeliveryResult(row.id, false, msg);
    return false;
  }
}

/** First attempt on every destination. Returns whether any accepted. */
export async function dispatch(store: Store, cfg: Config, notify: Notifier, mailer: Mailer | null, fetchImpl: typeof fetch, user: User, trip: Trip): Promise<boolean> {
  const ds = destinations(store, cfg, notify, mailer, fetchImpl, user, trip);
  const results = await Promise.all(ds.map((d) => attempt(store, store.addDelivery(trip.id, d.key), d)));
  return results.some(Boolean);
}

/** Re-attempt every destination that has not accepted its copy. One at a time, so a slow target cannot hold the queue. */
export async function retryUndelivered(store: Store, cfg: Config, notify: Notifier, mailer: Mailer | null, fetchImpl: typeof fetch = fetch): Promise<number> {
  let delivered = 0;
  for (const row of store.pendingDeliveries(cfg.notifyMaxAttempts)) {
    const trip = store.trip(row.trip_id);
    const user = trip ? store.userById(trip.user_id) : undefined;
    if (!trip || !user) continue;
    const d = destinations(store, cfg, notify, mailer, fetchImpl, user, trip).find((x) => x.key === row.destination);
    if (!d) {
      store.recordDeliveryResult(row.id, false, "destination no longer configured");
      continue;
    }
    if (await attempt(store, row, d)) delivered++;
  }
  return delivered;
}
