import { Client } from "ldapts";
import type { Org } from "./db.ts";

/**
 * Directory sign-in by binding as the user. The password exists only in memory for the
 * duration of the bind and is never logged or stored. Direct LDAP is weaker than an
 * identity provider because Baitline handles the directory password at all; it is here
 * because customers ask for it, with the sharpest edges filed off:
 *   - TLS (ldaps://) is mandatory except against localhost, for tests.
 *   - The username charset is restricted so it can never change the meaning of the DN.
 *   - Every failure looks the same to the caller.
 */

const USERNAME = /^[A-Za-z0-9._@-]{1,64}$/;

export function ldapUserDn(template: string, username: string): string {
  if (!USERNAME.test(username)) throw new Error("invalid credentials");
  return template.replace("{username}", username);
}

function isLocal(url: string): boolean {
  const h = new URL(url).hostname;
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

export function checkLdapUrl(url: string): void {
  const u = new URL(url);
  if (u.protocol === "ldaps:") return;
  if (u.protocol === "ldap:" && isLocal(url)) return;
  throw new Error("LDAP must use ldaps:// (plain ldap:// is only allowed to localhost)");
}

export async function ldapAuthenticate(org: Org, username: string, password: string): Promise<{ email: string }> {
  if (!org.ldap_url || !org.ldap_user_dn) throw new Error("LDAP is not configured for this organisation");
  if (!password) throw new Error("invalid credentials");
  checkLdapUrl(org.ldap_url);
  const dn = ldapUserDn(org.ldap_user_dn, username);
  const client = new Client({ url: org.ldap_url, timeout: 5000, connectTimeout: 5000 });
  try {
    await client.bind(dn, password);
    const { searchEntries } = await client.search(dn, { scope: "base", attributes: [org.ldap_email_attr] });
    const raw = searchEntries[0]?.[org.ldap_email_attr];
    const email = (Array.isArray(raw) ? raw[0] : raw)?.toString().trim() ?? "";
    if (!email) throw new Error("the directory has no email address for this account");
    return { email };
  } catch (err) {
    const msg = (err as Error).message;
    // Only our own, safe messages pass through. Everything from the directory is collapsed.
    throw new Error(msg.startsWith("the directory") ? msg : "invalid credentials");
  } finally {
    await client.unbind().catch(() => {});
  }
}
