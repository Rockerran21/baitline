# Baitline

Decoy secrets that phone you when an infostealer takes them, plus a clipboard guard that stops the way most people get infected.

Infostealers took about 1.8 billion credentials from roughly 5.8 million machines in 2025. The stolen passwords and session cookies get sold in logs and used months later, and the person whose laptop it was usually finds out when an account empties. Baitline flips that around. It plants fake credentials on your machine in exactly the places stealers look. Nobody legitimate will ever use them, so the first time anyone does, you get a push notification within seconds, with the attacker's IP and a reset checklist.

The second half, the clipboard guard, watches for the ClickFix trick: a fake CAPTCHA page that silently copies a command to your clipboard and tells you to paste it into Run or Terminal. ClickFix was over half of all malware loader activity in 2025. The guard recognises the command shape, wipes it from the clipboard, and tells you what just happened.

## What gets planted

| Decoy | Where | What trips it |
|---|---|---|
| Saved browser password for "Meridian Vault" | Your browser's password store | Anyone logging in to the vault with it |
| Session cookie for the vault | Your browser's cookie jar | Anyone presenting that cookie |
| `.env` with an API key | `~/Documents/vault-api/.env` | Any API request using the key |
| Wallet recovery phrase file | `~/Desktop/wallet-recovery-phrase.txt` | Contains the vault login, so using it trips the vault |
| Plain-text passwords file | `~/Documents/passwords.txt` | Same |

The vault is a plausible crypto custody site. Stealer-log buyers sort by domain and go for exchanges first.

## Quick start

Requirements: Node 24 or newer.

```sh
npm install
npm test

# start the server (dev: decoy vault and control plane share one host, sign-in links print to the log)
npm run dev
```

Open http://localhost:8787, type your email, and follow the sign-in link. There is no password and there never will be. The setup page then:

1. Links to the decoy vault with the login pre-filled. Sign in once, click Save when the browser offers to remember the password. That saved password is the bait.
2. Shows a QR code for the free ntfy phone app so alerts reach you, with a "send a test alert" button.
3. Shows the one-line command for the optional desktop guard, with a one-time device code in it.
4. Points you at adding a passkey.

### Desktop guard (optional, adds file decoys and blocks ClickFix)

Run the command from the setup page. It looks like this:

```sh
node client/src/cli.ts setup --server http://localhost:8787 --link <one-time code>
node client/src/cli.ts guard install   # macOS: runs at every login, restarts if it dies
```

Other commands: `guard` (run in a terminal instead), `status`, `dashboard`, `check "<text>"`, `guard pause 2m`, `guard uninstall`, `reset`.

## Signing in

- **Email link.** The default, and the way accounts are created. One use, fifteen minutes.
- **Passkey.** Add one on the account page. From then on every sign-in is two steps: your link, company sign-in, or directory password first, then the passkey. A passkey that verified you (Face ID, fingerprint, PIN) also signs you in on its own with nothing typed.
- **Recovery codes.** Eight single-use codes for the day the phone is gone. Shown once.
- **Sessions are short** and the things that change your protection (adding people, settings, deleting) require a sign-in from the last ten minutes, so a stolen session cookie alone is not enough.

## Organisations

Any account can create an organisation and becomes its admin. Members are added by invite, or provisioned automatically the first time they sign in through the company's identity provider. Each member gets their own decoys. When a member's decoy trips, the member is alerted, and so is the organisation on its own channels: a JSON webhook for a SIEM or chat tool and a security mailbox. Admin actions and sign-ins are in an audit log.

Sign-in options for an organisation, configured by an admin:

| Method | Works with | Notes |
|---|---|---|
| **OpenID Connect** | Google Workspace, Microsoft Entra, Okta, Keycloak, anything certified | Authorization code with PKCE, state and nonce. Optionally restrict to one email domain. Register the callback URL shown on the settings page. |
| **LDAP** | Any directory that allows a user bind | Binds as the user; the password is checked and forgotten, never stored. TLS is mandatory except to localhost. The username is restricted to characters that cannot alter the DN. Prefer OpenID if your directory has an identity provider in front of it. |

Both are tested here against a local OpenLDAP and a local OpenID provider. Google and Microsoft need a registered application; that live check is on the roadmap.

## What makes it hard to bypass

- **Split hosts.** In production the decoy vault and the control plane run on different hostnames (`PUBLIC_URL` vs `CONTROL_URL`). Someone who lands on the vault cannot discover the sign-up, dashboard, or that Baitline exists at all. Every control route 404s on the decoy host and vice versa.
- **No secrets on disk, and no sign-in on disk.** The desktop client trades a one-time device code for its secrets, uses them to plant files, and keeps only a device token that can report guard events and read status. A stealer that reads `~/.baitline/config.json` cannot tell the bait from real accounts, cannot open the dashboard, and cannot silence the alerts.
- **No bearer links.** The dashboard is behind a real sign-in with short sessions and a second factor, not a URL in your browser history that a stealer would also take.
- **Rebrandable decoys.** The vault brand and API-key prefix are server config, not hardcoded, so a real deployment is not the published default and cannot be blocklisted by string.
- **Alert throttling.** Repeat hits from the same IP are de-duplicated and capped per hour, so an attacker who finds a vault URL cannot bury you in a notification flood. Every trip is still recorded.
- **Deobfuscating clipboard guard.** Before matching, the guard strips zero-width characters, unifies fancy quotes, removes caret and backtick escapes, and collapses the `"p"+"owershell"` string-split trick, so the usual ClickFix evasions do not get past it. It also flags any "press Win+R and paste" instruction paired with a shell command.

## How the server decides

## How the server decides something is a trip

- The vault URL contains a random slug. Nothing links to it. Any visit after onboarding from an IP other than the owner's is at least a low-severity event.
- Correct decoy password: high. Decoy cookie presented: high. Decoy API key used: high.
- Wrong password on the vault: medium probe.
- The owner's own IP is ignored for 15 minutes after onboarding so the setup itself never alerts.

Alerts go to the console, ntfy, and optional email. See `server/.env.example`.

## Layout

```
server/   Hono + SQLite. Decoy vault, decoy API, dashboard, alert fan-out.
client/   Zero-dependency CLI. Enrolment, decoy files, clipboard guard.
```

Both run TypeScript directly on Node. No build step.

## Honest limits

- This detects theft. It does not prevent it, except for the ClickFix path the guard blocks.
- If your browser's built-in password manager is off, the saved-password decoy is not planted. The cookie and file decoys still are. Planting into 1Password and Bitwarden vaults is the next item on the list.
- The clipboard guard polls the clipboard. On Windows that spawns PowerShell roughly once a second, which is fine for a prototype and wrong for a product. The product version is a small native agent with a clipboard listener and a check of the foreground window at paste time.
- Nothing here stops voice-clone scams or investment fraud. Different problem, deliberately out of scope.
- The guard's `curl | sh` rule will also catch legitimate installers. That is by design, since macOS ClickFix uses the same shape. Pause the guard for those.

## Roadmap

Held to the same bar as the code: real gain, and verifiable before it ships.

1. **Prove it with a live sample.** Deploy behind a real decoy domain, enroll a throwaway Windows VM, run a current Lumma or Vidar sample, record the phone buzzing. This is the launch demo and it needs a VM and samples you control.
2. **Windows and Linux guard autostart**, and the Win+R registry hardening Microsoft recommends. Both are small; both are waiting on a Windows machine to verify on.
3. **Native guard agents** (Swift, then C# or Rust) with real paste-target detection.
4. **OAuth consent and device-code warnings**, as a browser extension, once the core is proven.
5. **Live check of Google Workspace and Microsoft Entra sign-in** with registered applications. The generic OpenID path is tested; the two providers are not yet.
6. **SAML and SCIM** when an enterprise customer needs them. TOTP codes as a weaker fallback to passkeys if customers ask.

Dropped: decoys inside 1Password and Bitwarden (those vaults are encrypted at rest, so a stealer never sees the decoy) and per-user decoy email addresses for breach feeds (a delayed second signal adds little when the first one fires in seconds).
