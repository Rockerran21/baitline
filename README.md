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

# start the server (dev: decoy vault and control plane share one host)
npm run dev
```

Open http://localhost:8787 and enter your email. That creates your account and takes you to a setup page that:

1. Links to the decoy vault with the login pre-filled. Sign in once, click Save when the browser offers to remember the password. That saved password is the bait.
2. Shows a QR code for the free ntfy phone app so alerts reach you.
3. Has a "Send a test alert" button so you can confirm your phone is wired up.
4. Gives you the one-line command for the optional desktop guard.

No account, no install, nothing to configure. The browser decoys are planted just by finishing step 1.

### Desktop guard (optional, adds file decoys and blocks ClickFix)

```sh
node client/src/cli.ts setup --server http://localhost:8787 --email you@example.com
# or attach to an account you made in the browser:
node client/src/cli.ts setup --server http://localhost:8787 --link "<your dashboard URL>"

node client/src/cli.ts guard install   # macOS: runs at every login, restarts if it dies
node client/src/cli.ts guard           # or run it in a terminal you keep open
```

Other commands: `status` (also tells you whether the guard is running), `dashboard`, `check "<text>"`, `guard pause 2m`, `guard uninstall`, `reset`.

## Family plan

From the dashboard an owner can add up to ten people ("Mom's laptop", "Dad's PC"). Each gets their own decoys and their own setup link to open on their computer. When a member's decoy trips, the member is alerted and so is the owner, with the member's name on the alert. Deleting the owner deletes every member.

## Account hygiene

- **Lost link recovery.** When the operator configures email, the home page offers "Lost your dashboard link?". The reply is identical whether or not the address has an account, only owners are ever emailed, and it is limited to three attempts an hour per address.
- **Delete account.** One form, type DELETE, and the account, its decoys, every event and every family member are gone.

## Prevention, not just detection

The decoys tell you after the fact. The guard is the part that stops the infection in the first place, so it is held to a higher bar:

- **It wipes first, asks questions later.** The clipboard is overwritten before anything slow runs.
- **It watches closely after a block.** A ClickFix page can rewrite the clipboard again while you are still on it. For ten seconds after a block the guard checks every 75 ms instead of every 400 ms.
- **It refuses to run blind.** If the clipboard cannot be read on this system, the guard exits with an error instead of sitting there giving you false confidence.
- **It survives reboots.** `guard install` registers a login agent on macOS that starts at login and is restarted if it dies. `status` reports whether it is actually running. Windows and Linux autostart are not wired yet because I could not verify them, and unverified startup code in a security tool is worse than an honest message.

## What makes it hard to bypass

- **Split hosts.** In production the decoy vault and the control plane run on different hostnames (`PUBLIC_URL` vs `CONTROL_URL`). Someone who lands on the vault cannot discover the sign-up, dashboard, or that Baitline exists at all. Every control route 404s on the decoy host and vice versa.
- **No secrets on disk.** The desktop client never writes the decoy password, cookie, API key, or seed phrase to its config. A stealer that reads `~/.baitline/config.json` sees only public URLs and a write-only guard token, so it cannot tell the bait from real accounts or silence the alerts.
- **Dashboard token in the keychain.** The one token that can read your trips lives in the macOS login keychain (or a 0600 file on other systems), not in the config file.
- **Write-only guard token.** The token the guard uses to report blocked pastes cannot read anything. Stealing it gains nothing.
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

Dropped: decoys inside 1Password and Bitwarden (those vaults are encrypted at rest, so a stealer never sees the decoy) and per-user decoy email addresses for breach feeds (a delayed second signal adds little when the first one fires in seconds).
