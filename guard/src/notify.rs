//! User-facing signals on a block. These spawn a process, which is fine: blocks are rare
//! events, and the wipe has already happened by the time any of this runs.

use std::process::Command;

pub fn notify(title: &str, body: &str) {
    let title = title.replace('"', "'");
    let body: String = body.replace('"', "'").chars().take(240).collect();
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("osascript")
            .args(["-e", &format!("display notification \"{body}\" with title \"{title}\" sound name \"Basso\"")])
            .spawn();
    }
    #[cfg(windows)]
    {
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true; $n.ShowBalloonTip(15000, \"{title}\", \"{body}\", [System.Windows.Forms.ToolTipIcon]::Warning); Start-Sleep -Seconds 16; $n.Dispose()"
        );
        let _ = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("notify-send").args(["-u", "critical", &title, &body]).spawn();
    }
}

/// Tell the server, if this machine is linked. Runs on its own thread; never blocks the loop.
pub fn report(rule: &'static str, app: String, sample: String) {
    let Some(url) = crate::paths::guard_url() else { return };
    let host = crate::paths::hostname();
    std::thread::spawn(move || {
        let body = serde_json::json!({ "host": host, "source_app": app, "rule": rule, "sample": sample }).to_string();
        let _ = ureq::post(&url).header("Content-Type", "application/json").send(&body);
    });
}
