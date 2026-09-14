/**
 * Classify an IP address literal by parsing it to bytes. Text tricks such as
 * IPv4-mapped IPv6 (`::ffff:7f00:1` is 127.0.0.1) or hex groups are all reduced to
 * the same 16-byte form before any range is checked.
 */

export function parseIp(text: string): Uint8Array | null {
  const s = text.trim().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  return s.includes(":") ? parseV6(s) : parseV4(s);
}

function parseV4(s: string): Uint8Array | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i]!;
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

function parseV6(s: string): Uint8Array | null {
  // Embedded dotted quad at the end: ::ffff:192.0.2.1
  let tail: Uint8Array | null = null;
  let body = s;
  const lastColon = s.lastIndexOf(":");
  if (s.slice(lastColon + 1).includes(".")) {
    tail = parseV4(s.slice(lastColon + 1));
    if (!tail) return null;
    body = s.slice(0, lastColon + 1) + "0:0";
  }
  const halves = body.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string) => (part === "" ? [] : part.split(":"));
  const head = groups(halves[0]!);
  const rest = halves.length === 2 ? groups(halves[1]!) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  if (head.length + rest.length > (halves.length === 2 ? 7 : 8)) return null;
  const words: number[] = [];
  for (const g of head) words.push(parseGroup(g));
  if (halves.length === 2) for (let i = head.length + rest.length; i < 8; i++) words.push(0);
  for (const g of rest) words.push(parseGroup(g));
  if (words.some((w) => Number.isNaN(w))) return null;
  const out = new Uint8Array(16);
  words.forEach((w, i) => {
    out[i * 2] = w >> 8;
    out[i * 2 + 1] = w & 0xff;
  });
  if (tail) out.set(tail, 12);
  return out;
}

function parseGroup(g: string): number {
  if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return Number.NaN;
  return parseInt(g, 16);
}

/** Loopback, private, link-local, unique-local, multicast, unspecified, CGNAT, documentation ranges. */
export function isPrivateIp(addr: Uint8Array): boolean {
  if (addr.length === 16) {
    const mapped = addr.slice(0, 10).every((b) => b === 0) && addr[10] === 0xff && addr[11] === 0xff;
    if (mapped) return isPrivateIp(addr.slice(12));
    const compat = addr.slice(0, 12).every((b) => b === 0) && !(addr[12] === 0 && addr[13] === 0 && addr[14] === 0 && (addr[15] === 0 || addr[15] === 1));
    if (compat) return isPrivateIp(addr.slice(12)); // ::a.b.c.d deprecated form
    // NAT64 well-known prefix 64:ff9b::/96 embeds an IPv4 address too.
    if (addr[0] === 0 && addr[1] === 0x64 && addr[2] === 0xff && addr[3] === 0x9b && addr.slice(4, 12).every((b) => b === 0)) return isPrivateIp(addr.slice(12));
    if (addr.every((b) => b === 0)) return true; // ::
    if (addr.slice(0, 15).every((b) => b === 0) && addr[15] === 1) return true; // ::1
    const b0 = addr[0]!;
    const b1 = addr[1]!;
    if ((b0 & 0xfe) === 0xfc) return true; // fc00::/7 unique local
    if (b0 === 0xfe && (b1 & 0xc0) === 0x80) return true; // fe80::/10 link local
    if (b0 === 0xff) return true; // multicast
    if (b0 === 0x20 && b1 === 0x01 && addr[2] === 0x0d && addr[3] === 0xb8) return true; // 2001:db8::/32 documentation
    return false;
  }
  const [a, b] = [addr[0]!, addr[1]!];
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && addr[2] === 0) ||
    (a === 192 && b === 0 && addr[2] === 2) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && addr[2] === 100) ||
    (a === 203 && b === 0 && addr[2] === 113) ||
    a >= 224
  );
}

export function isPrivateText(text: string): boolean {
  const p = parseIp(text);
  return p === null ? true : isPrivateIp(p);
}
