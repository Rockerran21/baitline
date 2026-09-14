import type { Decoy, GuardEvent, Trip, User } from "./db.ts";

export function esc(s: unknown): string {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export interface Brand {
  brand: string;
  company: string;
}

// ---------------------------------------------------------------------------
// Decoy vault. Must look like a real custody product and nothing else.
// ---------------------------------------------------------------------------

const VAULT_CSS = `
  :root{color-scheme:light}
  body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#0b1220;color:#e8edf5}
  .wrap{max-width:420px;margin:8vh auto;padding:32px;background:#121a2b;border:1px solid #1f2a40;border-radius:12px}
  h1{font-size:20px;margin:0 0 4px;letter-spacing:.3px}
  .sub{color:#8a97ad;font-size:13px;margin-bottom:24px}
  label{display:block;font-size:13px;color:#b7c1d3;margin:14px 0 6px}
  input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #2a3650;background:#0b1220;color:#e8edf5;font-size:15px}
  button{width:100%;margin-top:22px;padding:11px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-weight:600;font-size:15px;cursor:pointer}
  .err{background:#3a1520;border:1px solid #7a2a3a;color:#ffb4c0;padding:10px 12px;border-radius:8px;font-size:13px;margin-top:12px}
  .foot{color:#5f6b82;font-size:12px;margin-top:22px;text-align:center}
  table{width:100%;border-collapse:collapse;margin-top:14px}
  td,th{padding:8px 4px;border-bottom:1px solid #1f2a40;text-align:left;font-size:14px}
  .bal{font-size:28px;font-weight:700;margin:10px 0}
  .ok{background:#0f2d1e;border:1px solid #1e5a3a;color:#9ee6b8;padding:12px;border-radius:8px;font-size:14px}
`;

export function vaultLoginPage(b: Brand, opts: { slug: string; username: string; password: string; setup: string | null; error?: string }): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(b.brand)} — Sign in</title><style>${VAULT_CSS}</style></head><body>
<div class="wrap">
  <h1>${esc(b.brand)}</h1>
  <div class="sub">Digital asset custody</div>
  <form method="post" action="/vault/${esc(opts.slug)}/login" autocomplete="on">
    ${opts.setup ? `<input type="hidden" name="setup" value="${esc(opts.setup)}">` : ""}
    <label for="u">Email or username</label>
    <input id="u" name="username" autocomplete="username" value="${esc(opts.username)}" required>
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" value="${esc(opts.password)}" required>
    <button type="submit">Sign in</button>
    ${opts.error ? `<div class="err">${esc(opts.error)}</div>` : ""}
  </form>
  <div class="foot">© ${esc(b.company)}</div>
</div></body></html>`;
}

export function vaultAccountPage(b: Brand, opts: { username: string; balance: string; welcome: boolean; setupUrl: string | null }): string {
  const welcome = opts.welcome
    ? `<div class="ok"><b>Done.</b> Your browser should have offered to save this password. Say yes.
       You never need to open this page again.${opts.setupUrl ? ` <a href="${esc(opts.setupUrl)}" style="color:#9ee6b8">Back to setup.</a>` : ""}</div>`
    : "";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(b.brand)} — Portfolio</title><style>${VAULT_CSS}</style></head><body>
<div class="wrap">
  <h1>${esc(b.brand)}</h1>
  <div class="sub">Signed in as ${esc(opts.username)}</div>
  ${welcome}
  <div class="bal">${esc(opts.balance)}</div>
  <table>
    <tr><th>Asset</th><th>Amount</th><th>Status</th></tr>
    <tr><td>BTC</td><td>0.8412</td><td>Cold storage</td></tr>
    <tr><td>ETH</td><td>14.207</td><td>Cold storage</td></tr>
    <tr><td>USDC</td><td>12,500.00</td><td>Available</td></tr>
  </table>
  <button type="button" onclick="alert('Withdrawals require a 24h security hold. A confirmation email has been sent.')">Withdraw</button>
  <div class="foot">© ${esc(b.company)}</div>
</div></body></html>`;
}

export function notFoundPage(): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>404 Not Found</title></head>
<body style="font-family:sans-serif;padding:40px"><h1>404 Not Found</h1><p>The requested resource could not be found.</p></body></html>`;
}

// ---------------------------------------------------------------------------
// Control plane: landing, setup, dashboard.
// ---------------------------------------------------------------------------

const APP_CSS = `
  body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7f9;color:#111}
  .wrap{max-width:760px;margin:32px auto;padding:0 20px}
  h1{font-size:24px;margin:0}
  h2{font-size:16px;margin:26px 0 8px}
  .card{background:#fff;border:1px solid #e3e6eb;border-radius:10px;padding:18px 20px;margin-top:12px}
  .badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:13px;font-weight:600}
  .quiet{background:#e7f7ee;color:#116b3a}.tripped{background:#fde8e8;color:#9b1c1c}.pending{background:#fff4d6;color:#8a5a00}
  table{width:100%;border-collapse:collapse}
  td,th{padding:8px 6px;border-bottom:1px solid #eceff3;text-align:left;font-size:14px;vertical-align:top}
  .high{color:#b91c1c;font-weight:700}.medium{color:#b45309;font-weight:600}.low{color:#6b7280}
  code,pre{background:#f0f2f5;padding:1px 5px;border-radius:4px;font-size:13px}
  pre{padding:10px 12px;overflow:auto}
  ol li,ul li{margin:6px 0}
  .muted{color:#6b7280;font-size:13px}
  .btn{display:inline-block;padding:10px 16px;border-radius:8px;background:#111;color:#fff;text-decoration:none;font-weight:600;border:0;cursor:pointer;font-size:15px}
  .btn.secondary{background:#e9ecf1;color:#111}
  .step{display:flex;gap:14px;align-items:flex-start}
  .num{flex:0 0 28px;height:28px;border-radius:50%;background:#111;color:#fff;text-align:center;line-height:28px;font-weight:700}
  .num.done{background:#116b3a}
  input[type=email]{padding:10px 12px;border:1px solid #cfd4dc;border-radius:8px;font-size:15px;width:100%;box-sizing:border-box;margin:8px 0 12px}
  .qr{width:180px;height:180px}
  .row{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
`;

function shell(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${APP_CSS}</style></head><body><div class="wrap">${body}</div></body></html>`;
}

export function landingPage(opts: { error?: string }): string {
  return shell(
    "Baitline",
    `<h1>Baitline</h1>
  <p>Plant fake passwords on your computer. If malware ever steals them and someone tries to use them, your phone buzzes within seconds.</p>
  <div class="card">
    <form method="post" action="/enroll">
      <label for="e"><b>Your email</b> <span class="muted">(used for alerts and to find your dashboard again)</span></label>
      <input id="e" name="email" type="email" required placeholder="you@example.com" autocomplete="email">
      <button class="btn" type="submit">Set up my decoys</button>
      ${opts.error ? `<p class="high">${esc(opts.error)}</p>` : ""}
    </form>
  </div>
  <p class="muted">Setup takes about two minutes and installs nothing. The optional desktop guard adds file decoys and blocks fake CAPTCHA "paste this command" attacks.</p>`,
  );
}

export interface SetupView {
  user: User;
  dashboardUrl: string;
  onboardingUrl: string | null;
  ntfySubscribeUrl: string;
  ntfyQrSvg: string;
  testSent: boolean;
  hasSmtp: boolean;
  cliInstall: string;
}

export function setupPage(v: SetupView): string {
  const done = v.user.enrolled_at !== null;
  return shell(
    "Baitline setup",
    `<h1>Set up Baitline</h1>
  <div class="muted">${esc(v.user.email)}</div>

  <div class="card"><div class="step"><div class="num ${done ? "done" : ""}">1</div><div>
    <b>Plant the decoy password in your browser</b>
    <p>Click below, then press <b>Sign in</b>. The login is filled in for you. When your browser offers to save the password, click <b>Save</b>. That saved password is the bait.</p>
    ${
      done
        ? `<span class="badge quiet">Done. The decoy login and cookie are planted in this browser.</span>`
        : `<a class="btn" href="${esc(v.onboardingUrl ?? "#")}">Open the decoy vault and sign in</a>
           <p class="muted">Do it once in each browser you use. If the save prompt does not appear, check that the browser's password manager is turned on.</p>`
    }
  </div></div></div>

  <div class="card"><div class="step"><div class="num">2</div><div>
    <b>Get alerts on your phone</b>
    <p>Install the free <b>ntfy</b> app (App Store or Google Play), then scan this code or open the link on your phone and tap Subscribe.</p>
    <div class="row">
      <div class="qr">${v.ntfyQrSvg}</div>
      <div><code>${esc(v.ntfySubscribeUrl)}</code>
      ${v.hasSmtp ? `<p class="muted">Alerts are also emailed to ${esc(v.user.email)}.</p>` : ""}
      <form method="post" action="/setup/${esc(v.user.dashboard_token)}/test" style="margin-top:10px"><button class="btn secondary" type="submit">Send a test alert</button></form>
      ${v.testSent ? `<p class="badge quiet">Test sent. Check your phone.</p>` : ""}
      </div>
    </div>
  </div></div></div>

  <div class="card"><div class="step"><div class="num">3</div><div>
    <b>Optional: install the desktop guard</b>
    <p>Adds decoy files where malware looks and blocks the fake CAPTCHA "paste this command" trick. One command in a terminal:</p>
    <pre>${esc(v.cliInstall)}</pre>
    <p class="muted">Needs Node 24 or newer. It will ask for your email and then run the guard in the background.</p>
  </div></div></div>

  <div class="card"><div class="step"><div class="num">4</div><div>
    <b>Bookmark your dashboard</b>
    <p><a href="${esc(v.dashboardUrl)}">${esc(v.dashboardUrl)}</a></p>
    <p class="muted">This link is your login. Keep it in a password manager or bookmarks, not in a note on the desktop.</p>
  </div></div></div>`,
  );
}

const RESET_LINKS: Array<[string, string]> = [
  ["Google: sign out of all devices", "https://myaccount.google.com/device-activity"],
  ["Google: revoke third-party app access", "https://myaccount.google.com/permissions"],
  ["Microsoft: sign out everywhere", "https://account.microsoft.com/security"],
  ["Microsoft: revoke app consent", "https://account.live.com/consent/Manage"],
  ["Apple: review devices", "https://account.apple.com/account/manage"],
  ["Facebook: log out of all sessions", "https://www.facebook.com/settings?tab=security"],
  ["Instagram: login activity", "https://www.instagram.com/session/login_activity/"],
  ["Amazon: secure your account", "https://www.amazon.com/gp/css/account/info/view.html"],
  ["Steam: deauthorize all devices", "https://store.steampowered.com/account/authorizeddevices"],
  ["Discord: change password (logs out all sessions)", "https://discord.com/channels/@me"],
  ["Coinbase: sign out of all devices", "https://www.coinbase.com/settings/security"],
];

export function dashboardPage(opts: { user: User; decoys: Decoy[]; trips: Trip[]; guard: GuardEvent[]; setupUrl: string; testSent: boolean }): string {
  const { user, decoys, trips, guard } = opts;
  const real = trips.filter((t) => t.kind !== "test_alert");
  const high = real.filter((t) => t.severity === "high").length;
  const status = !user.enrolled_at
    ? `<span class="badge pending">Setup not finished</span> <a href="${esc(opts.setupUrl)}">Finish setup</a>`
    : high > 0
      ? `<span class="badge tripped">TRIPPED: ${high} high-severity event${high === 1 ? "" : "s"}</span>`
      : `<span class="badge quiet">Quiet. Nothing has touched your decoys.</span>`;

  const tripRows = trips.length
    ? trips
        .map(
          (t) => `<tr><td>${esc(new Date(t.created_at).toISOString())}</td>
        <td class="${t.severity}">${esc(t.severity)}</td><td>${esc(t.kind)}${t.notified ? "" : ' <span class="muted">(not notified: throttled)</span>'}</td><td><code>${esc(t.ip)}</code></td>
        <td class="muted">${esc(t.ua).slice(0, 80)}</td></tr>`,
        )
        .join("")
    : `<tr><td colspan="5" class="muted">No events.</td></tr>`;

  const guardRows = guard.length
    ? guard
        .map(
          (g) => `<tr><td>${esc(new Date(g.created_at).toISOString())}</td><td>${esc(g.host)}</td>
        <td>${esc(g.source_app)}</td><td><code>${esc(g.rule)}</code></td><td class="muted"><code>${esc(g.sample).slice(0, 90)}</code></td></tr>`,
        )
        .join("")
    : `<tr><td colspan="5" class="muted">No blocked pastes yet.</td></tr>`;

  const decoyRows = decoys.map((d) => `<tr><td><code>${esc(d.kind)}</code></td><td class="muted">${esc(describeDecoy(d))}</td></tr>`).join("");
  const checklist = RESET_LINKS.map(([t, u]) => `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(t)}</a></li>`).join("");

  return shell(
    "Baitline",
    `<h1>Baitline</h1>
  <div class="muted">${esc(user.email)}</div>
  <div class="card">${status}
    <form method="post" action="/dashboard/${esc(user.dashboard_token)}/test" style="display:inline;margin-left:12px"><button class="btn secondary" type="submit">Send test alert</button></form>
    ${opts.testSent ? `<span class="badge quiet">Test sent</span>` : ""}
  </div>

  <h2>Events</h2>
  <div class="card"><table><tr><th>When (UTC)</th><th>Severity</th><th>What</th><th>From</th><th>Client</th></tr>${tripRows}</table></div>

  ${
    high > 0
      ? `<h2>Do this now, from a device that is not the one the decoys were planted on</h2>
  <div class="card"><ol>
    <li>Disconnect the affected computer from the internet. Do not log in to anything from it.</li>
    <li>From your phone or a clean machine, sign out of all sessions and change passwords, most valuable first:</li>
    <ul>${checklist}</ul>
    <li>Revoke every third-party app you do not recognize (links above for Google and Microsoft).</li>
    <li>Call your bank. Tell them your computer was compromised on the date above.</li>
    <li>Wipe and reinstall the affected computer. Antivirus cleanup is not enough against modern stealers.</li>
    <li>Set up Baitline again on the fresh install to plant new decoys.</li>
  </ol></div>`
      : ""
  }

  <h2>Blocked pastes (clipboard guard)</h2>
  <div class="card"><table><tr><th>When (UTC)</th><th>Host</th><th>Source app</th><th>Rule</th><th>Sample</th></tr>${guardRows}</table></div>

  <h2>Decoys planted</h2>
  <div class="card"><table>${decoyRows}</table><p class="muted"><a href="${esc(opts.setupUrl)}">Setup page</a> (add another browser, re-scan the phone code)</p></div>`,
  );
}

function describeDecoy(d: Decoy): string {
  const meta = JSON.parse(d.meta || "{}") as Record<string, unknown>;
  switch (d.kind) {
    case "browser_password":
      return `Saved login for the decoy vault as ${String(meta.username ?? "")}`;
    case "session_cookie":
      return "Long-lived session cookie for the vault";
    case "api_key":
      return "API key in a .env file (desktop guard)";
    case "wallet_file":
      return "Wallet recovery phrase file (desktop guard)";
    case "passwords_file":
      return "Plain-text passwords file (desktop guard)";
  }
}
