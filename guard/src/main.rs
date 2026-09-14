//! baitline-guard: wipes ClickFix payloads from the clipboard before they can be pasted.
//!
//! Loop design, in priority order: the wipe must never wait on anything; the idle cost
//! must be nothing a laptop notices; and after a block the page may rewrite the
//! clipboard, so we watch closely for a while.

mod clipboard;
mod notify;
mod paths;
mod rules;

use clipboard::{Clipboard, Native};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const BASE: Duration = Duration::from_millis(250);
#[cfg(not(target_os = "linux"))]
const BASE: Duration = Duration::from_millis(100);
const HOT: Duration = Duration::from_millis(25);
const HOT_FOR: Duration = Duration::from_secs(10);

const HELP: &str = "baitline-guard: clipboard guard against ClickFix

  baitline-guard [--dry-run] [--quiet]   run (this is what the login agent does)
  baitline-guard check \"<text>\"          try the detector on a string
  baitline-guard pause <2m|90s|1h>       let a legitimate installer through for a while
";

fn blocked_text(v: &rules::Verdict) -> String {
    format!(
        "⚠️ Baitline blocked a suspicious command that a web page put on your clipboard.\n\
         A web page tried to make you run it. Do not paste it into Run, Terminal or PowerShell.\n\
         Reason: {}\n\
         If you really meant to run it: baitline guard pause 2m",
        v.why
    )
}

fn run(dry_run: bool, quiet: bool) -> ! {
    let mut cb = match Native::open() {
        Ok(cb) => cb,
        Err(e) => {
            eprintln!("Cannot read the clipboard on this system, so the guard would protect nothing. Not starting. ({e})");
            process::exit(3);
        }
    };
    let dir = paths::config_dir();
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(paths::pid_path(), process::id().to_string());
    if !quiet {
        println!("baitline-guard running (check every {}ms, {}ms for 10s after a block{}). Ctrl+C to stop.", BASE.as_millis(), HOT.as_millis(), if dry_run { ", dry run" } else { "" });
    }

    let mut last = cb.token();
    let mut last_blocked: Option<String> = None;
    let mut hot_until: Option<Instant> = None;

    loop {
        let hot = hot_until.map(|t| Instant::now() < t).unwrap_or(false);
        thread::sleep(if hot { HOT } else { BASE });
        let token = cb.token();
        if token == last {
            continue;
        }
        last = token;
        let text = cb.read_text();
        if text.is_empty() || last_blocked.as_deref() == Some(text.as_str()) {
            continue;
        }
        let Some(v) = rules::analyze(&text) else { continue };
        if paths::is_paused() {
            continue;
        }
        if !dry_run {
            let msg = blocked_text(&v);
            cb.write_text(&msg);
            last = cb.token();
            last_blocked = Some(msg);
        }
        hot_until = Some(Instant::now() + HOT_FOR);

        // Everything below is reporting. The wipe is done.
        let app = cb.frontmost_app();
        let sample: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect();
        let line = format!("{} BLOCKED rule={} app={:?} sample={:?}\n", timestamp(), v.rule, app, sample);
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(paths::log_path()) {
            let _ = f.write_all(line.as_bytes());
        }
        if !quiet {
            print!("{line}");
        }
        notify::notify("Baitline blocked a command", &format!("{app} copied a command that looks like a ClickFix attack ({}). It was removed from your clipboard.", v.rule));
        notify::report(v.rule, app, sample);
    }
}

fn timestamp() -> String {
    // ISO-8601 UTC without pulling in a date crate.
    let ms = paths::now_ms();
    let secs = (ms / 1000) as i64;
    let millis = (ms % 1000) as u32;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", sod / 3600, (sod % 3600) / 60, sod % 60)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") => {
            let text = args[1..].join(" ");
            match rules::analyze(&text) {
                Some(v) => {
                    println!("BLOCK  rule={}\n       {}", v.rule, v.why);
                    process::exit(1);
                }
                None => println!("clean"),
            }
        }
        Some("pause") => {
            let Some(ms) = paths::parse_duration(args.get(1).map(String::as_str).unwrap_or("2m")) else {
                eprintln!("bad duration (use e.g. 90s, 2m, 1h)");
                process::exit(2);
            };
            match paths::pause_for(ms) {
                Ok(until) => println!("guard paused for {}s (until epoch ms {until})", ms / 1000),
                Err(e) => {
                    eprintln!("could not write pause file: {e}");
                    process::exit(1);
                }
            }
        }
        Some("help") | Some("--help") | Some("-h") => print!("{HELP}"),
        Some(a) if !a.starts_with("--") => {
            eprintln!("unknown command: {a}\n\n{HELP}");
            process::exit(2);
        }
        _ => run(args.iter().any(|a| a == "--dry-run"), args.iter().any(|a| a == "--quiet")),
    }
}
