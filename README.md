# Baitline

Decoy secrets that phone you when an infostealer takes them, plus a clipboard guard that stops the way most people get infected.

Infostealers took about 1.8 billion credentials from roughly 5.8 million machines in 2025. The stolen passwords and session cookies get sold in logs and used months later, and the person whose laptop it was usually finds out when an account empties. Baitline flips that around. It plants fake credentials on your machine in exactly the places stealers look. Nobody legitimate will ever use them, so the first time anyone does, you get a push notification within seconds, with the attacker's IP and a reset checklist.

The second half, the clipboard guard, watches for the ClickFix trick: a fake CAPTCHA page that silently copies a command to your clipboard and tells you to paste it into Run or Terminal. ClickFix was over half of all malware loader activity in 2025. The guard recognises the command shape, wipes it from the clipboard, and tells you what just happened.

## What gets planted

| Decoy | Where | What trips it |
|---|---|---|
| Saved browser password for "Meridian Vault" | Your browser's password store | Anyone logging in to the vault with it |
| Session cookie for the vault | Your browser's cookie jar | Anyone presenting that cookie |
| `.env` with an API key | `~/Documents/meridian-api/.env` | Any API request using the key |
| Wallet recovery phrase file | `~/Desktop/wallet-recovery-phrase.txt` | Contains the vault login, so using it trips the vault |
| Plain-text passwords file | `~/Documents/passwords.txt` | Same |

The vault is a plausible crypto custody site. Stealer-log buyers sort by domain and go for exchanges first.

## Quick start

Requirements: Node 24 or newer.

```sh
npm install
npm test

# terminal 1: the decoy server
npm run dev

# terminal 2: enroll this machine
node client/src/cli.ts enroll --server http://localhost:8787 --email you@example.com --ntfy some-long-random-topic
```

Enrolment plants the files and opens the vault login page with the decoy credentials filled in. Click Sign in, then click Save when the browser offers to remember the password. Close the tab. That is the whole setup.

Install the ntfy app on your phone and subscribe to the topic you chose. Alerts arrive there.

Start the clipboard guard and leave it running:

```sh
node client/src/cli.ts guard
```

Other commands:

```sh
node client/src/cli.ts status            # what is planted, what has tripped
node client/src/cli.ts dashboard         # open the web dashboard
node client/src/cli.ts check "<text>"    # try the detector on a string
node client/src/cli.ts guard pause 2m    # let a legitimate curl | sh installer through
node client/src/cli.ts unseed            # remove the decoy files
```

## Prove it works

The claim that matters is "a real stealer takes the bait and you get the alert." Do this before showing anyone:

1. Deploy the server somewhere reachable with a real domain as `PUBLIC_URL`.
2. Build a throwaway Windows VM with Chrome. Enrol it, complete the browser step.
3. Snapshot the VM.
4. Run a current infostealer sample from a malware zoo (MalwareBazaar tags: lumma, vidar, stealc, redline) inside the VM with no network egress except to the internet the sample needs.
5. Watch for the trip. The log validators most buyers use will hit the vault or the cookie within hours of the log going up for sale. Some panels validate at exfil time, which trips immediately.
6. Restore the snapshot. Never run samples on a machine you care about.

Record a screen capture of the phone buzzing. That is the product demo.

## How the server decides something is a trip

- The vault URL contains a random slug. Nothing links to it. Any visit after onboarding from an IP other than the owner's is at least a low-severity event.
- Correct decoy password: high. Decoy cookie presented: high. Decoy API key used: high.
- Wrong password on the vault: medium probe.
- The owner's own IP is ignored for 15 minutes after onboarding so the setup itself never alerts.

Alerts go to the console, ntfy, an optional webhook and optional email. See `server/.env.example`.

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

1. Native guard agents (Swift on macOS, C# or Rust on Windows) with real paste-target detection.
2. Decoys inside 1Password and Bitwarden via their CLIs.
3. A unique decoy email address per user so the stealer log surfaces in breach feeds as a second signal.
4. Warnings on OAuth consent screens and device-code pages with risky scopes.
5. Family plan: one dashboard, several machines, alerts to the person who handles tech for the family.
