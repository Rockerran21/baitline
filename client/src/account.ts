/** What the server hands the desktop client once, in exchange for a device code. The
 *  secrets are used to seed files and never written to the client config. */
export interface Account {
  email: string;
  brand: string;
  company: string;
  ntfy_topic: string | null;
  ntfy_subscribe_url: string | null;
  setup_url: string;
  status_url: string;
  guard_url: string;
  enrolled: boolean;
  vault: { onboarding_url: string | null; login_url: string; username: string; password: string };
  api: { base: string; key: string };
  wallet: { seed_phrase: string };
}
