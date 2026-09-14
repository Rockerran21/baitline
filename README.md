# Baitline

**Know within seconds when your computer has been robbed. Stop the most common way it happens.**

Baitline plants fake credentials on your devices in exactly the places infostealer malware looks. Nobody legitimate ever uses them, so the first time anyone does, you get a push notification with the attacker's IP and a reset checklist. Alongside it runs a clipboard guard that wipes the "paste this command to verify you are human" attacks before you can paste them.

Self-hosted. Passwordless. Built for one person, a family, or a whole company behind single sign-on.

---

## The problem

Infostealers took about 1.8 billion credentials from roughly 5.8 million machines in 2025. The stolen passwords and session cookies are sold in bulk and used weeks or months later, and the person whose laptop it was usually finds out when an account empties. Session cookies walk straight past two-factor authentication, because to the website the session is already signed in.

The most common way those stealers get installed is ClickFix: a fake CAPTCHA page silently copies a command to your clipboard and tells you to press Win+R and paste. It was more than half of all malware loader activity in 2025.

Antivirus tries to recognise the malware. Breach-monitoring services tell you months later. Nothing on the market tells you *the day it happens* and stops the paste.

## How it works

```
   your laptop                                   Baitline server
   ┌─────────────────────────────┐               ┌──────────────────────────────┐
   │ browser password store      │               │ decoy vault  (custody.example)│
   │   ↳ decoy login for a fake  │   stealer     │   plausible crypto custody    │
   │     crypto custody site     │ ───────────►  │   site; any sign-in, cookie   │
   │ browser cookie jar          │  takes them   │   or API call = alert         │
   │   ↳ decoy session cookie    │               ├──────────────────────────────┤
   │ ~/Desktop, ~/Documents      │               │ control plane (app.example)   │
   │   ↳ wallet seed, passwords, │               │   sign-in, dashboard, orgs,   │
   │     .env with an API key    │               │   alert routing, audit log    │
   ├─────────────────────────────┤               └──────────────┬───────────────┘
   │ clipboard guard             │                              │
   │   wipes ClickFix payloads   │                 push / email / webhook
   └─────────────────────────────┘                              ▼
                                                     your phone, your SIEM
```

1. **Plant.** Sign in once to a convincing decoy site so your browser saves the password and cookie. The optional desktop guard drops decoy files where stealers grep.
2. **Wait.** Nothing runs, nothing scans. The decoys cost zero CPU.
3. **Alert.** The moment a stolen decoy is used anywhere in the world, the server sees it and tells you: what, when, from where, and exactly what to reset.
4. **Prevent.** The clipboard guard recognises ClickFix command shapes, wipes them before you can paste, and tells you what just happened.

## Features

**Detection**
- Five decoys per person: browser password, session cookie, API key in a `.env`, a wallet recovery phrase file, a plain-text passwords file
- Alerts within seconds by phone push (ntfy), email, or webhook, with severity, IP, client, and a reset checklist
- De-duplicated and rate-capped so an attacker cannot turn your phone into a siren
- Test alert button so you know the phone is wired up before you need it

**Prevention**
- Clipboard guard for macOS, Windows, and Linux that blocks ClickFix, FileFix, and TerminalFix payloads
- Deobfuscation before matching: zero-width characters, caret and backtick escapes, string-split tricks, fancy quotes
- Hot mode after a block: rechecks every 75 ms for ten seconds, so a page that rewrites the clipboard is wiped again
- Runs at login on macOS and restarts if it dies

**Identity**
- No passwords, ever. Sign in by one-time email link, passkey, or your company's identity provider
- Passkeys as a second factor, or as a complete sign-in on their own when the authenticator verified you
- Recovery codes for a lost phone
- Short sessions, and a fresh sign-in required for anything that changes your protection

**Family plan**
- Add up to ten people from your dashboard. Each gets their own decoys and an emailed invite
- When theirs trips, you get the alert too, with their name on it

**Organisations**
- Single sign-on through OpenID Connect: Google Workspace, Microsoft Entra, Okta, Keycloak, or any certified provider
- Directory sign-in through LDAP, bind-as-user, TLS required
- Members provisioned automatically on first sign-in, optionally restricted to your email domain
- Every member's trip also goes to your security channel: a JSON webhook for your SIEM or chat, and a shared mailbox
- Audit log of admin actions, sign-ins, provisioning, and passkey changes

## Get started

Requirements: Node 24 or newer.

```sh
git clone https://github.com/Rockerran21/baitline.git
cd baitline
npm install
npm test
npm run dev
```

Open http://localhost:8787, enter your email, and follow the sign-in link. In development there is no mail server, so the link is printed to the terminal.

The setup page walks you through the rest:

1. **Plant the decoy password.** Click through to the decoy vault, press Sign in, and click Save when your browser offers to remember the password. That saved password is the bait.
2. **Get alerts on your phone.** Scan the QR code with the free ntfy app and tap Subscribe. Press "Send a test alert."
3. **Install the desktop guard** (optional). Copy the one-line command shown, which includes a one-time device code, and run it in a terminal.
4. **Add a passkey** on the account page.

### Desktop guard

The setup page shows the exact command. It looks like this:

```sh
node client/src/cli.ts setup --server https://app.example --link <one-time device code>
node client/src/cli.ts guard install      # macOS: starts at every login, restarts if it dies
```

| Command | What it does |
|---|---|
| `guard install` / `guard uninstall` | Register or remove the login agent (macOS) |
| `guard` | Run the guard in the current terminal instead |
| `guard pause 2m` | Let a legitimate `curl \| sh` installer through for a while |
| `status` | What is planted, what has tripped, whether the guard is running |
| `check "<text>"` | Try the detector on a string |
| `dashboard` | Open your dashboard |
| `reset` | Remove the decoy files and forget this machine's setup |

## Deploy to production

Copy `server/.env.example` and set at least these:

| Variable | Set it to |
|---|---|
| `PUBLIC_URL` | The decoy vault, on its own domain. Pick something a stealer-log buyer would want to open, such as a custody or exchange name. |
| `CONTROL_URL` | The control plane, on a **different** domain. Sign-in, dashboard, and the client API live here. Passkeys bind to this hostname. |
| `DECOY_BRAND`, `DECOY_COMPANY`, `DECOY_KEY_PREFIX` | Your own decoy identity. The defaults are in this public repository and could be blocklisted. |
| `SMTP_URL` | A mail transport. Required for sign-in links, invites, and email alerts. |
| `NTFY_BASE` | Your own ntfy server if you do not want to use the public one. |
| `DB_PATH` | Where the SQLite database lives. Back it up. |

Put both hostnames behind TLS. The server sets HSTS and secure cookies when `CONTROL_URL` is `https`.

Then run:

```sh
npm --workspace server start
```

Why two domains: the decoy vault must look like a real custody site and nothing else. Every control-plane route returns 404 on the vault host, and the vault returns 404 on the control host. Someone who lands on the vault cannot discover the sign-in page, the dashboard, or that Baitline exists.

## For organisations

Any signed-in account can create an organisation from the **Organisation** page and becomes its admin. The organisation gets a sign-in page for your team at `https://app.example/o/<your-org>`.

| Method | Works with | How it is built |
|---|---|---|
| **OpenID Connect** | Google Workspace, Microsoft Entra, Okta, Keycloak, and any certified provider | Authorization code flow with PKCE, state, and nonce. Register a web application with your provider using the callback URL shown on the settings page. Optionally restrict to one email domain. |
| **LDAP** | Any directory that allows a user bind | Binds as the user. The password is checked and forgotten, never stored. TLS is mandatory except to localhost. The username is restricted to characters that cannot alter the DN. Wrong password and unknown user produce the same message. Five attempts per user per hour. |

Prefer OpenID Connect when your directory has an identity provider in front of it. Direct LDAP means the employee's directory password passes through Baitline at all, which is the pattern this product exists to fight. It is offered because customers ask for it, with the sharpest edges filed off.

Members can be added by invite from the admin page, or provisioned automatically the first time they sign in through your identity provider. Each member gets their own decoys and their own setup page. When any member's decoy trips, the member is alerted on their own channels, and the organisation is alerted once on its channels, with the member's name.

The audit log records organisation creation, settings changes, members added and removed, identity-provider sign-ins, provisioning, passkey changes, and recovery-code use.

## Security model

Baitline assumes the machine it protects will be compromised. That shapes every decision.

- **Nothing on the client can betray the decoys.** The desktop client trades a one-time device code for its secrets, uses them to plant files, and keeps only a device token that can report guard events and read status. A stealer that reads the client's config cannot tell the bait from real accounts, cannot open the dashboard, and cannot silence the alerts.
- **No bearer links.** The dashboard is behind a real sign-in, not a URL in your browser history that a stealer would take along with everything else.
- **No passwords stored.** Sign-in is by email link, passkey, or identity provider. There is no password table to leak.
- **Sessions are short** and hashed at rest: one hour idle, twelve hours absolute. Adding people, changing settings, and deleting require a sign-in from the last ten minutes, so a stolen session cookie alone cannot change your protection.
- **Passkeys are the second factor.** They are phishing-resistant and bound to the control-plane origin. Passkey-only sign-in requires user verification, so a passkey without Face ID, fingerprint, or PIN is one factor, not two.
- **Cross-site requests are refused** on every state-changing route by origin check, on top of same-site cookies.
- **Alerts are throttled, never dropped.** Repeat hits from the same address inside ten minutes are recorded but not re-sent, and notifications are capped per hour. Every trip is stored.
- **The decoy site never names the product.** Not in its pages, its headers, or its 404s.

### What Baitline does not do

- It does not detect malware. It detects the *use* of what malware steals, which is why it catches stealers written last week.
- It does not prevent theft, except through the ClickFix path the guard blocks.
- It does not protect against voice-clone scams, investment fraud, or anything that persuades you to send money yourself.
- If your browser's built-in password manager is off, the saved-password decoy is not planted. The cookie and file decoys still are. Decoys inside 1Password or Bitwarden are deliberately not attempted: those vaults are encrypted at rest, so a stealer never sees them.
- The guard's `curl | sh` rule also catches legitimate installers, because macOS ClickFix uses the same shape. Pause the guard for those.
- The guard polls the clipboard. On Windows that spawns PowerShell about once a second. A native agent is on the roadmap.

## Architecture

```
server/     Hono on Node with the built-in SQLite driver. One process, one database file.
            Decoy vault and API, passwordless sign-in, passkeys, OpenID Connect, LDAP,
            organisations, family plan, alert routing, audit log, dashboard.
client/     Zero-dependency command-line tool. Device linking, decoy files,
            clipboard guard, macOS login agent.
```

TypeScript runs directly on Node with no build step. Server dependencies are Hono, the certified `openid-client`, `@simplewebauthn/server`, `ldapts`, `nodemailer`, and `qrcode`. The client has none.

Alerts fan out to the console, ntfy, and email for people; to a webhook and a shared mailbox for organisations. Every channel is independent, and one failing does not stop the others.

## Development and testing

```sh
npm test          # all suites
npm run typecheck
```

The suites cover the full product, not just units:

- **Decoys and trips.** Onboarding is silent; cookie replay, password use, and API key use fire high-severity alerts; probes are lower; throttling and the hourly cap hold; split hosts hide the product.
- **Sign-in.** Magic links are single use and expire; addresses cannot be enumerated; cross-site posts are refused; sessions expire; sensitive actions demand a fresh sign-in.
- **Passkeys.** Registration, second-factor assertion, passkey-only sign-in, user-verification requirement, challenge replay rejection, counter updates, and recovery codes, driven by a software authenticator in the test helpers.
- **OpenID Connect.** A complete code flow with PKCE, state, and nonce against an in-process OpenID provider, including domain restriction, unverified emails, forged state, and account hijack attempts.
- **LDAP.** Against a real OpenLDAP server that the suite starts itself: correct bind, wrong password, unknown user, missing email, and the attempt limit. Skipped automatically if `slapd` is not installed.
- **Organisations.** Creation, invites, settings validation, webhook and mailbox delivery, admin-only pages, audit entries, member removal.
- **Clipboard guard.** Twenty-four known malicious shapes including obfuscated ones, seventeen benign strings that must not trigger, hot mode timing, and the login agent definition.

Every change to the guard loop has also been exercised live on macOS under launchd, with payloads set 200 ms apart.

## Roadmap

Held to one standard: a real gain, verified before it ships.

1. **Live proof with a current stealer sample** in a disposable Windows VM behind a real decoy domain. This is the launch demonstration.
2. **Windows and Linux guard autostart**, and the Win+R registry hardening Microsoft recommends. Waiting on a Windows machine to verify against.
3. **Native guard agents** with real paste-target detection.
4. **Live verification of Google Workspace and Microsoft Entra sign-in** with registered applications. The generic OpenID path is tested; the two providers are not yet.
5. **OAuth consent and device-code phishing warnings** as a browser extension, once the core is proven.
6. **SAML and SCIM** when an enterprise customer needs them. TOTP as a weaker fallback to passkeys if customers ask.

## Status

Baitline is in active development. The product works end to end and every claim above is covered by an automated test or a recorded live run, but it has not yet been run against a live infostealer sample, and it has not been through an external security review. Treat it as pre-release until both have happened.

No license has been chosen yet. All rights reserved until one is.
