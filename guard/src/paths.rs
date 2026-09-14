//! Files shared with the Node setup tool: same directory, same names, so `baitline status`
//! and `baitline guard pause` keep working against this binary.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

pub fn config_dir() -> PathBuf {
    if let Ok(p) = env::var("BAITLINE_HOME") {
        return PathBuf::from(p);
    }
    let home = env::var("HOME").or_else(|_| env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".baitline")
}

pub fn pid_path() -> PathBuf {
    config_dir().join("guard.pid")
}
pub fn pause_path() -> PathBuf {
    config_dir().join("guard-pause")
}
pub fn log_path() -> PathBuf {
    config_dir().join("guard.log")
}

pub fn is_paused() -> bool {
    fs::read_to_string(pause_path())
        .ok()
        .and_then(|s| s.trim().parse::<u128>().ok())
        .map(|until| until > now_ms())
        .unwrap_or(false)
}

pub fn pause_for(ms: u128) -> std::io::Result<u128> {
    fs::create_dir_all(config_dir())?;
    let until = now_ms() + ms;
    fs::write(pause_path(), until.to_string())?;
    Ok(until)
}

/// "90s", "2m", "1h", or a bare number of minutes.
pub fn parse_duration(s: &str) -> Option<u128> {
    let s = s.trim();
    let (num, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&s[..s.len() - 1], c.to_ascii_lowercase()),
        _ => (s, 'm'),
    };
    let n: u128 = num.trim().parse().ok()?;
    Some(n * match unit {
        's' => 1_000,
        'm' => 60_000,
        'h' => 3_600_000,
        _ => return None,
    })
}

/// The guard's write-only report URL from the setup tool's config, if this machine is linked.
pub fn guard_url() -> Option<String> {
    let raw = fs::read_to_string(config_dir().join("config.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("guard_url")?.as_str().map(str::to_owned)
}

pub fn hostname() -> String {
    env::var("HOSTNAME")
        .ok()
        .or_else(|| env::var("COMPUTERNAME").ok())
        .or_else(|| std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()))
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s"), Some(90_000));
        assert_eq!(parse_duration("2m"), Some(120_000));
        assert_eq!(parse_duration("1h"), Some(3_600_000));
        assert_eq!(parse_duration("5"), Some(300_000));
        assert_eq!(parse_duration("soon"), None);
    }
}
