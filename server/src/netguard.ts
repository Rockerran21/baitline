import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { Agent, type Dispatcher } from "undici";
import { isPrivateIp, parseIp } from "./ipaddr.ts";

/**
 * Organisation admins can point the server at URLs of their choosing: a webhook, an
 * OpenID issuer, a directory. Every one of those is an outbound request made by this
 * server, so none may reach inside the network it runs on.
 *
 * Two rules. Addresses are classified as bytes, so no textual form of a private
 * address (IPv4-mapped IPv6, hex groups, NAT64) slips past. And the address that was
 * checked is the address that gets connected to: the hostname is resolved once, and the
 * connection is pinned to that result while TLS still verifies the original name.
 */

export type Resolver = (host: string) => Promise<string[]>;

let defaultResolve: Resolver = async (host) => (await lookup(host, { all: true })).map((a) => a.address);

/** Tests replace DNS so fixture hostnames get the full public check without a network. */
export function setDefaultResolver(r: Resolver): void {
  defaultResolve = r;
}

function isLocalName(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost");
}

/** Only the machine itself: what a developer's test IdP or LDAP server runs on. */
function isLoopback(host: string): boolean {
  if (isLocalName(host)) return true;
  const ip = parseIp(host);
  return ip !== null && ((ip.length === 4 && ip[0] === 127) || (ip.length === 16 && ip.slice(0, 15).every((b) => b === 0) && ip[15] === 1));
}

/** The plaintext twin of a required scheme, permitted only for loopback in development. */
const INSECURE: Record<string, string> = { "https:": "http:", "ldaps:": "ldap:" };

export interface UrlPolicy {
  schemes: string[];
  /** Development escape hatch: loopback hosts may use the plaintext scheme and are not pinned. Every other host gets the full check. */
  allowLocal: boolean;
  resolve?: Resolver;
}

export interface CheckedUrl {
  url: URL;
  hostname: string;
  /** The single address every connection for this URL must use. Absent in development mode. */
  address: string | null;
}

/** Throws with a message safe to show an admin. */
export async function assertPublicUrl(raw: string, policy: UrlPolicy): Promise<CheckedUrl> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("that is not a valid URL");
  }
  if (url.username || url.password) throw new Error("URLs with a username or password are not allowed");
  if (url.hash) throw new Error("URLs with a fragment are not allowed");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (policy.allowLocal && isLoopback(hostname)) {
    if (!policy.schemes.some((s) => s === url.protocol || INSECURE[s] === url.protocol)) throw new Error(`the URL must use ${policy.schemes.map((s) => s.replace(":", "://")).join(" or ")}`);
    return { url, hostname, address: null };
  }
  if (!policy.schemes.includes(url.protocol)) throw new Error(`the URL must use ${policy.schemes.map((s) => s.replace(":", "://")).join(" or ")}`);
  if (isLocalName(hostname)) throw new Error("the URL must not point at this server");
  const literal = parseIp(hostname);
  if (literal) {
    if (isPrivateIp(literal)) throw new Error("the URL must point at a public address, not a private or internal one");
    return { url, hostname, address: hostname };
  }
  const addrs = await (policy.resolve ?? defaultResolve)(hostname).catch(() => [] as string[]);
  if (!addrs.length) throw new Error("that hostname does not resolve");
  for (const a of addrs) {
    const p = parseIp(a);
    if (!p || isPrivateIp(p)) throw new Error("the URL must point at a public address, not a private or internal one");
  }
  return { url, hostname, address: addrs[0]! };
}

/** An HTTP dispatcher whose every connection goes to the pinned address, whatever DNS says later. */
export function pinnedDispatcher(address: string): Dispatcher {
  const family = isIP(address) === 6 ? 6 : 4;
  return new Agent({
    connect: {
      lookup: (_host, _opts, cb) => cb(null, [{ address, family }]),
      timeout: 8_000,
    },
  });
}

/**
 * fetch() for admin-supplied URLs: validated, pinned, no redirects, with a deadline.
 * In development mode it is a plain fetch so local fakes work.
 */
export async function guardedFetch(raw: string, init: RequestInit, policy: UrlPolicy, fetchImpl: typeof fetch = fetch, timeoutMs = 8_000): Promise<Response> {
  const checked = await assertPublicUrl(raw, policy);
  const base: RequestInit = { ...init, redirect: "error", signal: init.signal ?? AbortSignal.timeout(timeoutMs) };
  if (!checked.address) return fetchImpl(checked.url, base);
  const dispatcher = pinnedDispatcher(checked.address);
  try {
    return await fetchImpl(checked.url, { ...base, dispatcher } as unknown as RequestInit);
  } finally {
    void dispatcher.close();
  }
}
