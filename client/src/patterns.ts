/**
 * ClickFix / FileFix / TerminalFix detection.
 *
 * Every rule here is meant to be high confidence: it should match what a fake CAPTCHA
 * page copies to the clipboard and almost never match what a person copies on purpose.
 * The one grey area is `curl | sh` installers, which is also exactly what macOS ClickFix
 * uses, so it stays in and the user can `baitline guard pause` for a legitimate install.
 */

export interface Rule {
  id: string;
  why: string;
  test: (text: string) => boolean;
}

const PS = String.raw`\b(?:powershell|pwsh)(?:\.exe)?\b`;

function re(src: string, flags = "i"): (t: string) => boolean {
  const r = new RegExp(src, flags);
  return (t) => r.test(t);
}

function all(...fns: Array<(t: string) => boolean>): (t: string) => boolean {
  return (t) => fns.every((f) => f(t));
}

const SHELLY = re(String.raw`\b(?:powershell|pwsh|mshta|cmd|curl|wget|iex|bash|zsh|\bsh\b|osascript|certutil|bitsadmin|rundll32|regsvr32|wscript|cscript|msiexec|python3?)\b`);

export const RULES: Rule[] = [
  {
    id: "clickfix-marker",
    why: "Text mentions a CAPTCHA or 'not a robot' check next to a shell command. That is the ClickFix lure verbatim.",
    test: all(re(String.raw`(?:not a robot|verification (?:id|code|step)|ray id|cloudflare|captcha|human verification)`), SHELLY),
  },
  {
    id: "powershell-hidden",
    why: "PowerShell asked to run with a hidden window. Nothing legitimate needs you to paste that.",
    test: re(String.raw`${PS}[^\n]*\s-(?:w|win|windowstyle)\s*h(?:idden)?\b`),
  },
  {
    id: "powershell-encoded",
    why: "PowerShell running a base64-encoded command. Encoding exists here only to hide what it does.",
    test: re(String.raw`${PS}[^\n]*\s-(?:e|ec|en|enc|encodedcommand)\s+["']?[A-Za-z0-9+/=]{20,}`),
  },
  {
    id: "powershell-bypass",
    why: "PowerShell told to bypass the execution policy.",
    test: re(String.raw`${PS}[^\n]*\s-(?:ep|ex|exec|executionpolicy)\s+bypass\b`),
  },
  {
    id: "powershell-download-exec",
    why: "Downloads code from the internet and executes it in memory.",
    test: all(
      re(String.raw`\b(?:iex|invoke-expression)\b`),
      re(String.raw`(?:downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod|net\.webclient|start-bitstransfer|\[uri\]|http[s]?://)`),
    ),
  },
  {
    id: "mshta-remote",
    why: "mshta launching a remote or inline script. A classic malware loader.",
    test: re(String.raw`\bmshta(?:\.exe)?\s+["']?(?:https?:|javascript:|vbscript:|\\\\|[A-Za-z]:\\)`),
  },
  {
    id: "msiexec-remote",
    why: "Windows Installer pulling a package straight from a URL, silently.",
    test: re(String.raw`\bmsiexec(?:\.exe)?\b[^\n]*/(?:i|package|q[nb]?)\s*["']?https?://`),
  },
  {
    id: "curl-pipe-shell",
    why: "Downloads a script and pipes it straight into a shell.",
    test: re(String.raw`\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b`),
  },
  {
    id: "shell-c-curl",
    why: "Runs a shell on whatever a download returns.",
    test: re(String.raw`\b(?:ba|z|da)?sh\s+-c\s+["']?\$\((?:curl|wget)\b`),
  },
  {
    id: "base64-decode-shell",
    why: "Decodes hidden base64 and executes it.",
    test: (t) =>
      re(String.raw`base64\s+(?:-d|--decode|-D)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`)(t) ||
      re(String.raw`echo\s+["']?[A-Za-z0-9+/=]{40,}["']?\s*\|\s*base64`)(t),
  },
  {
    id: "certutil-urlcache",
    why: "certutil abused as a downloader.",
    test: re(String.raw`\bcertutil(?:\.exe)?\b[^\n]*-urlcache`),
  },
  {
    id: "bitsadmin-transfer",
    why: "bitsadmin abused as a downloader.",
    test: re(String.raw`\bbitsadmin(?:\.exe)?\s+/transfer\b`),
  },
  {
    id: "cmd-chained-loader",
    why: "cmd.exe chaining into a known loader binary.",
    test: re(String.raw`\bcmd(?:\.exe)?\s+/[ckCK]\s+[^\n]*\b(?:powershell|pwsh|mshta|curl|certutil|bitsadmin|rundll32|regsvr32|wscript|cscript)\b`),
  },
  {
    id: "regsvr32-remote",
    why: "regsvr32 loading a remote scriptlet (Squiblydoo).",
    test: re(String.raw`\bregsvr32(?:\.exe)?\b[^\n]*/i:https?:`),
  },
  {
    id: "rundll32-remote",
    why: "rundll32 executing remote or scripted content.",
    test: re(String.raw`\brundll32(?:\.exe)?\b[^\n]*(?:https?:|javascript:|\\\\)`),
  },
  {
    id: "osascript-shell",
    why: "AppleScript being used to run a shell command or download.",
    test: re(String.raw`\bosascript\b[^\n]*(?:do shell script|curl|wget|http[s]?://)`),
  },
  {
    id: "filefix-path-comment",
    why: "A command disguised as a file path (FileFix). Pasting this into the Explorer address bar runs it.",
    test: re(String.raw`\b(?:powershell|pwsh|cmd|mshta|wscript|cscript)\b[^\n]*#\s*[A-Za-z]:\\`),
  },
  {
    id: "python-inline-loader",
    why: "Inline Python fetching and executing remote code.",
    test: re(String.raw`\bpython3?(?:\.exe)?\s+-c\s+["'][^\n]*\b(?:urllib|urlopen|requests\.get|exec\(|socket\.|subprocess)\b`),
  },
];

export interface Verdict {
  rule: string;
  why: string;
}

export const MAX_ANALYZED_CHARS = 20_000;

/** Returns the first matching rule, or null when the clipboard looks harmless. */
export function analyze(text: string): Verdict | null {
  if (!text || text.length > MAX_ANALYZED_CHARS) return null;
  const t = normalize(text);
  for (const rule of RULES) {
    if (rule.test(t)) return { rule: rule.id, why: rule.why };
  }
  return null;
}

/** Strip characters attackers use to hide commands from eyes and from naive regexes. */
export function normalize(text: string): string {
  return text
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g, "")
    .replace(/[\u00A0\u2000-\u200A\u3000]/g, " ")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2018\u2019]/g, "'");
}
