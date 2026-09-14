import type { AuditEntry, Decoy, GuardEvent, Org, Passkey, Trip, User } from "./db.ts";

export function esc(s: unknown): string {
  return String(s).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
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
// Control plane
// ---------------------------------------------------------------------------

const APP_CSS = `
  body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7f9;color:#111}
  .wrap{max-width:780px;margin:32px auto;padding:0 20px}
  h1{font-size:24px;margin:0}
  h2{font-size:16px;margin:26px 0 8px}
  nav{display:flex;gap:16px;margin:10px 0 4px;font-size:14px}
  nav a{color:#374151}
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
  input,select{padding:10px 12px;border:1px solid #cfd4dc;border-radius:8px;font-size:15px;box-sizing:border-box}
  input.wide{width:100%;margin:8px 0 12px}
  .qr{width:180px;height:180px}
  .row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
  .err{color:#b91c1c;font-weight:600}
  .codes{font-family:ui-monospace,Menlo,monospace;font-size:16px;columns:2}
`;

const PASSKEY_JS = `
function bl_json(r){return r.json()}
async function bl_pkCreate(name){
  if(!window.PublicKeyCredential||!PublicKeyCredential.parseCreationOptionsFromJSON){alert('This browser cannot create passkeys.');return}
  const o=await fetch('/account/passkeys/options',{method:'POST'}).then(bl_json);
  const cred=await navigator.credentials.create({publicKey:PublicKeyCredential.parseCreationOptionsFromJSON(o.options)});
  const r=await fetch('/account/passkeys/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({flow:o.flow,name:name,response:cred.toJSON()})});
  if(!r.ok){alert('Could not add the passkey: '+(await r.text()));return}
  location.reload();
}
async function bl_pkSignIn(optUrl,verifyUrl){
  if(!window.PublicKeyCredential||!PublicKeyCredential.parseRequestOptionsFromJSON){alert('This browser cannot use passkeys.');return}
  const o=await fetch(optUrl,{method:'POST'}).then(bl_json);
  const cred=await navigator.credentials.get({publicKey:PublicKeyCredential.parseRequestOptionsFromJSON(o.options)});
  const r=await fetch(verifyUrl,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({flow:o.flow,response:cred.toJSON()})});
  if(!r.ok){alert('Sign-in failed: '+(await r.text()));return}
  location.href=(await r.json()).next;
}
`;

function shell(title: string, body: string, opts: { nav?: User | null; script?: boolean } = {}): string {
  const nav = opts.nav
    ? `<nav><a href="/dashboard">Dashboard</a><a href="/setup">Setup</a><a href="/account">Account</a><a href="/org">Organisation</a>
       <form method="post" action="/logout" style="display:inline"><button class="btn secondary" style="padding:2px 10px;font-size:13px" type="submit">Sign out</button></form></nav>`
    : "";
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${APP_CSS}</style>${opts.script ? `<script>${PASSKEY_JS}</script>` : ""}</head>
<body><div class="wrap">${nav}${body}</div></body></html>`;
}

// ---- sign-in

export function landingPage(opts: { error?: string; notice?: string; sent?: boolean; devLink?: string }): string {
  return shell(
    "Baitline",
    `<h1>Baitline</h1>
  <p>Plant fake passwords on your computer. If malware ever steals them and someone tries to use them, your phone buzzes within seconds.</p>
  ${opts.notice ? `<div class="card"><span class="badge quiet">${esc(opts.notice)}</span></div>` : ""}
  ${
    opts.sent
      ? `<div class="card"><b>Check your email.</b> If that address is yours, a sign-in link is on its way. It works once and expires in 15 minutes.
         ${opts.devLink ? `<p class="muted">Development mode, no mail server configured. Your link: <a href="${esc(opts.devLink)}">${esc(opts.devLink)}</a></p>` : ""}</div>`
      : `<div class="card">
      <form method="post" action="/login/email">
        <label for="e"><b>Your email</b></label>
        <input class="wide" id="e" name="email" type="email" required placeholder="you@example.com" autocomplete="email webauthn">
        <button class="btn" type="submit">Email me a sign-in link</button>
        ${opts.error ? `<p class="err">${esc(opts.error)}</p>` : ""}
      </form>
      <p class="muted" style="margin-top:14px">New here? The same link creates your account. No password, ever.</p>
      <p><button class="btn secondary" type="button" onclick="bl_pkSignIn('/login/passkey/options','/login/passkey/verify')">Sign in with a passkey</button></p>
      <p class="muted">Company account? Use your organisation's sign-in page: <code>/o/&lt;your-org&gt;</code></p>
    </div>`
  }`,
    { script: true },
  );
}

export function magicContinuePage(token: string, next: string): string {
  return shell(
    "Continue to Baitline",
    `<h1>Almost there</h1>
  <div class="card">
    <p>Press the button to finish signing in. This extra step keeps email link scanners from using up your link before you do.</p>
    <form method="post" action="/login/magic"><input type="hidden" name="t" value="${esc(token)}"><input type="hidden" name="next" value="${esc(next)}">
    <button class="btn" type="submit">Continue</button></form>
  </div>`,
  );
}

export function mfaPage(opts: { error?: string }): string {
  return shell(
    "Second step",
    `<h1>One more step</h1>
  <div class="card">
    <p>This account has a passkey. Use it to finish signing in.</p>
    <p><button class="btn" type="button" onclick="bl_pkSignIn('/login/mfa/options','/login/mfa/verify')">Use my passkey</button></p>
    <form method="post" action="/login/mfa/recovery" class="row" style="margin-top:14px">
      <span class="muted">Lost it? Enter a recovery code:</span>
      <input name="code" placeholder="xxxxx-xxxxx" autocomplete="one-time-code">
      <button class="btn secondary" type="submit">Use code</button>
    </form>
    ${opts.error ? `<p class="err">${esc(opts.error)}</p>` : ""}
    <form method="post" action="/logout" style="margin-top:14px"><button class="btn secondary" type="submit">Cancel</button></form>
  </div>`,
    { script: true },
  );
}

export function reauthPage(opts: { next: string; hasPasskey: boolean; sent?: boolean; devLink?: string; error?: string }): string {
  return shell(
    "Confirm it is you",
    `<h1>Confirm it is you</h1>
  <div class="card">
    <p>That action changes your protection, so we need a fresh sign-in.</p>
    ${opts.hasPasskey ? `<p><button class="btn" type="button" onclick="bl_pkSignIn('/login/mfa/options','/login/reauth/verify?next=${encodeURIComponent(opts.next)}')">Use my passkey</button></p>` : ""}
    ${
      opts.sent
        ? `<p><b>Check your email</b> for a link. ${opts.devLink ? `<span class="muted">Development mode: <a href="${esc(opts.devLink)}">${esc(opts.devLink)}</a></span>` : ""}</p>`
        : `<form method="post" action="/login/reauth/email"><input type="hidden" name="next" value="${esc(opts.next)}"><button class="btn secondary" type="submit">Email me a link instead</button></form>`
    }
    ${opts.error ? `<p class="err">${esc(opts.error)}</p>` : ""}
  </div>`,
    { script: true },
  );
}

export function orgLoginPage(org: Org, opts: { error?: string; next: string }): string {
  return shell(
    `Sign in to ${org.name}`,
    `<h1>${esc(org.name)}</h1>
  <div class="card">
    ${org.oidc_issuer ? `<p><a class="btn" href="/o/${esc(org.slug)}/oidc/start?next=${encodeURIComponent(opts.next)}">Sign in with your company account</a></p>` : ""}
    ${
      org.ldap_url
        ? `<form method="post" action="/o/${esc(org.slug)}/ldap">
        <input type="hidden" name="next" value="${esc(opts.next)}">
        <label><b>Directory username</b></label><input class="wide" name="username" autocomplete="username" required>
        <label><b>Directory password</b></label><input class="wide" name="password" type="password" autocomplete="current-password" required>
        <button class="btn" type="submit">Sign in</button>
        <p class="muted">Your password is checked against your company directory and never stored.</p></form>`
        : ""
    }
    ${!org.oidc_issuer && !org.ldap_url ? `<p class="muted">This organisation has not set up sign-in yet. Ask an administrator.</p>` : ""}
    ${opts.error ? `<p class="err">${esc(opts.error)}</p>` : ""}
  </div>`,
  );
}

// ---- signed-in pages

export interface SetupView {
  user: User;
  onboardingUrl: string | null;
  ntfySubscribeUrl: string;
  ntfyQrSvg: string;
  testSent: boolean;
  hasSmtp: boolean;
  cliCommand: string;
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
    <p>Install the free <b>ntfy</b> app, then scan this code or open the link on your phone and tap Subscribe.</p>
    <div class="row">
      <div class="qr">${v.ntfyQrSvg}</div>
      <div><code>${esc(v.ntfySubscribeUrl)}</code>
      ${v.hasSmtp ? `<p class="muted">Alerts are also emailed to ${esc(v.user.email)}.</p>` : ""}
      <form method="post" action="/setup/test" style="margin-top:10px"><button class="btn secondary" type="submit">Send a test alert</button></form>
      ${v.testSent ? `<p class="badge quiet">Test sent. Check your phone.</p>` : ""}
      </div>
    </div>
  </div></div></div>

  <div class="card"><div class="step"><div class="num">3</div><div>
    <b>Optional: install the desktop guard</b>
    <p>Adds decoy files where malware looks and blocks the fake CAPTCHA "paste this command" trick. Run this in a terminal on this computer. The code in it works once and expires in 15 minutes.</p>
    <pre>${esc(v.cliCommand)}</pre>
  </div></div></div>

  <div class="card"><div class="step"><div class="num">4</div><div>
    <b>Add a passkey</b>
    <p>Sign-in links alone are fine. A passkey makes it two steps, and lets you sign in with nothing typed. <a href="/account">Add one on your account page.</a></p>
  </div></div></div>`,
    { nav: v.user },
  );
}

export interface MemberRow {
  id: number;
  label: string;
  email: string;
  enrolled: boolean;
  high: number;
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

export function dashboardPage(opts: {
  user: User;
  decoys: Decoy[];
  trips: Array<Trip & { who: string }>;
  guard: GuardEvent[];
  members: MemberRow[];
  org: Org | null;
  testSent: boolean;
  notice?: string;
  error?: string;
}): string {
  const { user, decoys, trips, guard, members } = opts;
  const real = trips.filter((t) => t.kind !== "test_alert");
  const high = real.filter((t) => t.severity === "high").length;
  const status = !user.enrolled_at
    ? `<span class="badge pending">Setup not finished</span> <a href="/setup">Finish setup</a>`
    : high > 0
      ? `<span class="badge tripped">TRIPPED: ${high} high-severity event${high === 1 ? "" : "s"}</span>`
      : `<span class="badge quiet">Quiet. Nothing has touched your decoys.</span>`;

  const tripRows = trips.length
    ? trips
        .map(
          (t) => `<tr><td>${esc(new Date(t.created_at).toISOString())}</td><td>${esc(t.who || "you")}</td>
        <td class="${t.severity}">${esc(t.severity)}</td><td>${esc(t.kind)}${t.notified ? "" : ' <span class="muted">(not notified: throttled)</span>'}</td><td><code>${esc(t.ip)}</code></td>
        <td class="muted">${esc(t.ua).slice(0, 80)}</td></tr>`,
        )
        .join("")
    : `<tr><td colspan="6" class="muted">No events.</td></tr>`;

  const guardRows = guard.length
    ? guard.map((g) => `<tr><td>${esc(new Date(g.created_at).toISOString())}</td><td>${esc(g.host)}</td><td>${esc(g.source_app)}</td><td><code>${esc(g.rule)}</code></td><td class="muted"><code>${esc(g.sample).slice(0, 90)}</code></td></tr>`).join("")
    : `<tr><td colspan="5" class="muted">No blocked pastes yet.</td></tr>`;

  const memberRows = members
    .map(
      (m) => `<tr><td><b>${esc(m.label)}</b><br><span class="muted">${esc(m.email)}</span></td>
      <td>${m.high > 0 ? `<span class="badge tripped">TRIPPED (${m.high})</span>` : m.enrolled ? `<span class="badge quiet">Quiet</span>` : `<span class="badge pending">Setup not finished</span>`}</td>
      <td class="row"><form method="post" action="/dashboard/members/${m.id}/invite"><button class="btn secondary" type="submit">Resend invite</button></form>
      <form method="post" action="/dashboard/members/${m.id}/remove"><button class="btn secondary" type="submit">Remove</button></form></td></tr>`,
    )
    .join("");

  const decoyRows = decoys.map((d) => `<tr><td><code>${esc(d.kind)}</code></td><td class="muted">${esc(describeDecoy(d))}</td></tr>`).join("");
  const checklist = RESET_LINKS.map(([t, u]) => `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(t)}</a></li>`).join("");
  const errorText: Record<string, string> = {
    member: "A name and a valid email are needed to add someone.",
    "members-full": "A family plan holds up to 10 people.",
    exists: "That email already has a Baitline account.",
  };

  return shell(
    "Baitline",
    `<h1>Baitline</h1>
  <div class="muted">${esc(user.email)}${opts.org ? ` · ${esc(opts.org.name)}` : ""}</div>
  <div class="card">${status}
    <form method="post" action="/dashboard/test" style="display:inline;margin-left:12px"><button class="btn secondary" type="submit">Send test alert</button></form>
    ${opts.testSent ? `<span class="badge quiet">Test sent</span>` : ""}
    ${opts.notice ? `<span class="badge quiet">${esc(opts.notice)}</span>` : ""}
    ${opts.error && errorText[opts.error] ? `<p class="err">${esc(errorText[opts.error])}</p>` : ""}
  </div>

  <h2>Events</h2>
  <div class="card"><table><tr><th>When (UTC)</th><th>Who</th><th>Severity</th><th>What</th><th>From</th><th>Client</th></tr>${tripRows}</table></div>

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

  ${
    user.parent_id === null && user.org_id === null
      ? `<h2>Family</h2>
  <div class="card">
    <p class="muted">Add the people you look after. Each gets their own decoys and an emailed invite. If theirs trip, you get the alert too, with their name on it.</p>
    <table>${memberRows || `<tr><td class="muted">Nobody added yet.</td></tr>`}</table>
    <form method="post" action="/dashboard/members" class="row" style="margin-top:12px">
      <input name="label" placeholder="Mom's laptop" maxlength="40" required>
      <input name="email" type="email" placeholder="their email" required>
      <button class="btn secondary" type="submit">Add and invite</button>
    </form>
  </div>`
      : user.parent_id !== null
        ? `<div class="card muted">This account is part of a family plan. The owner also receives your alerts.</div>`
        : ""
  }

  <h2>Blocked pastes (clipboard guard)</h2>
  <div class="card"><table><tr><th>When (UTC)</th><th>Host</th><th>Source app</th><th>Rule</th><th>Sample</th></tr>${guardRows}</table></div>

  <h2>Decoys planted</h2>
  <div class="card"><table>${decoyRows}</table><p class="muted"><a href="/setup">Setup page</a> (add another browser, re-scan the phone code, get the desktop command)</p></div>`,
    { nav: user },
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

export function accountPage(opts: { user: User; passkeys: Passkey[]; codesLeft: number; newCodes?: string[]; notice?: string; error?: string }): string {
  const rows = opts.passkeys.length
    ? opts.passkeys
        .map(
          (p) => `<tr><td>${esc(p.name)}</td><td class="muted">added ${esc(new Date(p.created_at).toISOString().slice(0, 10))}${p.last_used_at ? `, last used ${esc(new Date(p.last_used_at).toISOString().slice(0, 10))}` : ""}</td>
      <td><form method="post" action="/account/passkeys/${p.id}/delete"><button class="btn secondary" type="submit">Remove</button></form></td></tr>`,
        )
        .join("")
    : `<tr><td class="muted" colspan="3">No passkeys yet. Sign-in is by email link only.</td></tr>`;
  return shell(
    "Account",
    `<h1>Account</h1>
  <div class="muted">${esc(opts.user.email)}</div>
  ${opts.notice ? `<div class="card"><span class="badge quiet">${esc(opts.notice)}</span></div>` : ""}
  ${opts.error ? `<div class="card"><span class="err">${esc(opts.error)}</span></div>` : ""}

  <h2>Passkeys</h2>
  <div class="card">
    <p class="muted">With a passkey, every sign-in needs two things: your email link or company sign-in, then the passkey. You can also sign in with the passkey alone.</p>
    <table>${rows}</table>
    <div class="row" style="margin-top:12px"><input id="pkname" placeholder="This device's name" maxlength="40"><button class="btn" type="button" onclick="bl_pkCreate(document.getElementById('pkname').value)">Add a passkey</button></div>
  </div>

  <h2>Recovery codes</h2>
  <div class="card">
    ${
      opts.newCodes
        ? `<p><b>Save these now.</b> Each works once. They will not be shown again.</p><div class="codes">${opts.newCodes.map((c) => `<div>${esc(c)}</div>`).join("")}</div>`
        : `<p class="muted">${opts.codesLeft} unused code${opts.codesLeft === 1 ? "" : "s"}. Use one instead of the passkey if you lose it.</p>`
    }
    <form method="post" action="/account/recovery" style="margin-top:10px"><button class="btn secondary" type="submit">${opts.codesLeft ? "Replace all codes" : "Generate codes"}</button></form>
  </div>

  <h2>Delete account</h2>
  <div class="card"><form method="post" action="/account/delete" class="row">
    <span class="muted">Removes your decoys, every event, and ${opts.user.parent_id === null ? "every family member" : "this member"}. Decoy files on your computer stay until you run <code>baitline reset</code>. Type DELETE to confirm.</span>
    <input name="confirm" placeholder="DELETE" style="width:120px">
    <button class="btn secondary" type="submit">Delete</button>
  </form></div>`,
    { nav: opts.user, script: true },
  );
}

// ---- organisation

export function orgPage(opts: { user: User; org: Org | null; members: MemberRow[]; controlUrl: string; notice?: string; error?: string }): string {
  const { user, org } = opts;
  if (!org) {
    return shell(
      "Organisation",
      `<h1>Organisation</h1>
    <div class="card">
      <p>Protect a team. Members sign in with your company's identity provider or directory, each gets their own decoys, and every trip also goes to your security channel.</p>
      <form method="post" action="/org/create" class="row"><input name="name" placeholder="Acme Ltd" maxlength="60" required><button class="btn" type="submit">Create organisation</button></form>
      ${opts.error ? `<p class="err">${esc(opts.error)}</p>` : ""}
    </div>`,
      { nav: user },
    );
  }
  const admin = user.org_role === "admin";
  const rows = opts.members
    .map(
      (m) => `<tr><td><b>${esc(m.label)}</b><br><span class="muted">${esc(m.email)}</span></td>
      <td>${m.high > 0 ? `<span class="badge tripped">TRIPPED (${m.high})</span>` : m.enrolled ? `<span class="badge quiet">Quiet</span>` : `<span class="badge pending">Setup not finished</span>`}</td>
      ${admin && m.id !== user.id ? `<td class="row"><form method="post" action="/org/members/${m.id}/invite"><button class="btn secondary" type="submit">Resend invite</button></form><form method="post" action="/org/members/${m.id}/remove"><button class="btn secondary" type="submit">Remove</button></form></td>` : "<td></td>"}</tr>`,
    )
    .join("");
  return shell(
    org.name,
    `<h1>${esc(org.name)}</h1>
  <div class="muted">Sign-in page for your team: <code>${esc(opts.controlUrl)}/o/${esc(org.slug)}</code></div>
  ${opts.notice ? `<div class="card"><span class="badge quiet">${esc(opts.notice)}</span></div>` : ""}
  ${opts.error ? `<div class="card"><span class="err">${esc(opts.error)}</span></div>` : ""}
  <h2>Members</h2>
  <div class="card"><table>${rows}</table>
  ${
    admin
      ? `<form method="post" action="/org/members" class="row" style="margin-top:12px">
      <input name="label" placeholder="Name or laptop" maxlength="40" required><input name="email" type="email" placeholder="work email" required>
      <button class="btn secondary" type="submit">Add and invite</button></form>
    <p class="muted">Anyone who signs in through your identity provider with an allowed email domain is added automatically.</p>`
      : ""
  }
  </div>
  ${admin ? `<p><a class="btn secondary" href="/org/settings">Sign-in and alert settings</a> <a class="btn secondary" href="/org/audit">Audit log</a></p>` : ""}`,
    { nav: user },
  );
}

export function orgSettingsPage(opts: { user: User; org: Org; controlUrl: string; notice?: string; error?: string }): string {
  const o = opts.org;
  const v = (x: string | null) => esc(x ?? "");
  return shell(
    "Organisation settings",
    `<h1>${esc(o.name)}: settings</h1>
  ${opts.notice ? `<div class="card"><span class="badge quiet">${esc(opts.notice)}</span></div>` : ""}
  ${opts.error ? `<div class="card"><span class="err">${esc(opts.error)}</span></div>` : ""}
  <form method="post" action="/org/settings">
  <h2>Single sign-on (OpenID Connect)</h2>
  <div class="card">
    <p class="muted">Works with Google Workspace, Microsoft Entra, Okta, Keycloak and any OpenID provider. Register a web application with your provider and give it this redirect URL:<br><code>${esc(opts.controlUrl)}/o/${esc(o.slug)}/oidc/callback</code></p>
    <label>Issuer URL</label><input class="wide" name="oidc_issuer" value="${v(o.oidc_issuer)}" placeholder="https://accounts.google.com or https://login.microsoftonline.com/<tenant>/v2.0">
    <label>Client ID</label><input class="wide" name="oidc_client_id" value="${v(o.oidc_client_id)}">
    <label>Client secret</label><input class="wide" name="oidc_client_secret" type="password" value="${v(o.oidc_client_secret)}" autocomplete="off">
    <label>Only allow emails ending in</label><input class="wide" name="oidc_email_domain" value="${v(o.oidc_email_domain)}" placeholder="acme.com">
  </div>
  <h2>Directory sign-in (LDAP)</h2>
  <div class="card">
    <p class="muted">Prefer single sign-on above if your directory has an identity provider in front of it. Direct LDAP means the user's directory password passes through Baitline. It is checked and forgotten, never stored. TLS is required.</p>
    <label>Server URL</label><input class="wide" name="ldap_url" value="${v(o.ldap_url)}" placeholder="ldaps://ldap.acme.com">
    <label>User DN template</label><input class="wide" name="ldap_user_dn" value="${v(o.ldap_user_dn)}" placeholder="uid={username},ou=people,dc=acme,dc=com">
    <label>Email attribute</label><input class="wide" name="ldap_email_attr" value="${esc(o.ldap_email_attr)}">
  </div>
  <h2>Where alerts go</h2>
  <div class="card">
    <label>Webhook URL (JSON POST, for your SIEM or chat)</label><input class="wide" name="alert_webhook_url" value="${v(o.alert_webhook_url)}" placeholder="https://hooks.example/...">
    <label>Security mailbox</label><input class="wide" name="alert_email" type="email" value="${v(o.alert_email)}" placeholder="security@acme.com">
  </div>
  <p><button class="btn" type="submit">Save</button> <a class="btn secondary" href="/org">Back</a></p>
  </form>`,
    { nav: opts.user },
  );
}

export function orgAuditPage(opts: { user: User; org: Org; entries: AuditEntry[]; actors: Map<number, string> }): string {
  const rows = opts.entries.length
    ? opts.entries.map((e) => `<tr><td>${esc(new Date(e.created_at).toISOString())}</td><td>${esc(e.actor_id !== null ? (opts.actors.get(e.actor_id) ?? `#${e.actor_id}`) : "system")}</td><td><code>${esc(e.action)}</code></td><td class="muted">${esc(e.target)}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">Nothing yet.</td></tr>`;
  return shell(
    "Audit log",
    `<h1>${esc(opts.org.name)}: audit log</h1>
  <div class="card"><table><tr><th>When (UTC)</th><th>Who</th><th>Action</th><th>Target</th></tr>${rows}</table></div>
  <p><a class="btn secondary" href="/org">Back</a></p>`,
    { nav: opts.user },
  );
}
