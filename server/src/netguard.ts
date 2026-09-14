import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

/**
 * Organisation admins can point the server at URLs of their choosing: a webhook, an
 * OpenID issuer, a directory. Every one of those is an outbound request made by this
 * server, so none of them may reach inside the network it runs on.
 */

export type Resolver = (host: string) => Promise<string[]>;

const defaultResolve: Resolver = async (host) => (await lookup(host, { all: true })).map((a) => a.address);

function isPrivate(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number) as [number, number];
    return (
      a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224
    );
  }
  const v6 = ip.toLowerCase();
  if (v6.startsWith("::ffff:")) return isPrivate(v6.slice(7));
  return v6 === "::" || v6 === "::1" || v6.startsWith("fc") || v6.startsWith("fd") || v6.startsWith("fe8") || v6.startsWith("fe9") || v6.startsWith("fea") || v6.startsWith("feb") || v6.startsWith("ff");
}

function isLocalName(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

export interface UrlPolicy {
  /** Allowed schemes, e.g. ["https:"] or ["ldaps:"]. */
  schemes: string[];
  /** Development escape hatch: syntax checks only, so localhost test services work. Never on in production. */
  allowLocal: boolean;
  resolve?: Resolver;
}

/**
 * Throws with a message safe to show an admin. Resolves the hostname and rejects any
 * address that is loopback, private, link-local, multicast, or unspecified.
 */
export async function assertPublicUrl(raw: string, policy: UrlPolicy): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("that is not a valid URL");
  }
  if (url.username || url.password) throw new Error("URLs with a username or password are not allowed");
  if (url.hash) throw new Error("URLs with a fragment are not allowed");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (policy.allowLocal) return url;
  if (!policy.schemes.includes(url.protocol)) throw new Error(`the URL must use ${policy.schemes.map((s) => s.replace(":", "://")).join(" or ")}`);
  if (isLocalName(host)) throw new Error("the URL must not point at this server");
  const addrs = isIP(host) ? [host] : await (policy.resolve ?? defaultResolve)(host).catch(() => [] as string[]);
  if (!addrs.length) throw new Error("that hostname does not resolve");
  if (addrs.some(isPrivate)) throw new Error("the URL must point at a public address, not a private or internal one");
  return url;
}
