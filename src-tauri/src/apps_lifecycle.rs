//! Best-effort quit of foreground user applications before a protected session.
//!
//! Closing apps is an OPSEC control, not a network guarantee. OnionGate never
//! force-kills itself, the shell used to launch it, or core OS UI processes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuitAppsResult {
    pub requested: usize,
    pub detail: String,
    pub closed: Vec<String>,
    pub skipped: Vec<String>,
}

fn protected_names() -> Vec<&'static str> {
    vec![
        "OnionGate",
        "tor-socks-gui",
        "oniongate",
        "oniongate_helper",
        "oniongate-helper",
        "Finder",
        "Dock",
        "SystemUIServer",
        "WindowServer",
        "loginwindow",
        "kernel_task",
        "launchd",
        "cfprefsd",
        "System Settings",
        "System Preferences",
        "Control Center",
        "NotificationCenter",
        "Spotlight",
        "Cursor",
        "Code",
        "Terminal",
        "iTerm2",
        "Warp",
        "Alacritty",
        "kitty",
        "ghostty",
        "systemd",
        "init",
        "kthreadd",
        "explorer",
        "dwm",
        "csrss",
        "lsass",
        "services",
        "wininit",
        "smss",
        "System",
        "Registry",
        "mDNSResponder",
        "configd",
        "syslogd",
        "securityd",
        "coreaudiod",
        "UserEventAgent",
    ]
}

pub(crate) fn is_protected_process(name: &str, pid: u32) -> bool {
    if pid <= 1 || pid == std::process::id() {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    if lower == "kernel" || lower.starts_with("pid ") {
        return true;
    }
    if lower.starts_with("oniongate") || lower.starts_with("tor-socks-gui") {
        return true;
    }
    if lower == "cursor" || lower.starts_with("cursor ") {
        return true;
    }
    if lower == "code" || lower.starts_with("code helper") {
        return true;
    }
    protected_names()
        .iter()
        .any(|protected| lower == protected.to_ascii_lowercase())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearnetKillResult {
    pub killed: Vec<KilledProcess>,
    pub skipped: Vec<KilledProcess>,
    pub failed: Vec<KilledProcess>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KilledProcess {
    pub process: String,
    pub pid: u32,
}

/// Terminate processes that currently have clearnet sockets. Only PIDs from
/// the live census are accepted; protected and OnionGate transport PIDs are
/// skipped. Destinations are never logged.
pub async fn kill_clearnet_processes() -> Result<ClearnetKillResult, String> {
    let targets = crate::egress_watch::current().clearnet_processes;
    if targets.is_empty() {
        return Ok(ClearnetKillResult {
            killed: vec![],
            skipped: vec![],
            failed: vec![],
            detail: "No processes currently have sockets classified as not through Tor"
                .into(),
        });
    }

    let mut killed = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();

    for target in targets {
        let item = KilledProcess {
            process: target.process.clone(),
            pid: target.pid,
        };
        if !target.killable {
            skipped.push(item);
            continue;
        }
        match terminate_pid(target.pid).await {
            Ok(()) => killed.push(item),
            Err(_) => failed.push(item),
        }
    }

    crate::logs::append(format!(
        "Clearnet process kill: {} terminated, {} skipped, {} failed",
        killed.len(),
        skipped.len(),
        failed.len()
    ));

    let detail = match (killed.len(), skipped.len(), failed.len()) {
        (0, skipped_n, 0) if skipped_n > 0 => {
            format!(
                "Left {skipped_n} protected process(es) running; nothing was killed"
            )
        }
        (killed_n, skipped_n, failed_n) => {
            let mut parts = vec![format!("Terminated {killed_n} process(es) not through Tor")];
            if skipped_n > 0 {
                parts.push(format!("left {skipped_n} protected"));
            }
            if failed_n > 0 {
                parts.push(format!("{failed_n} could not be killed"));
            }
            parts.join("; ")
        }
    };

    Ok(ClearnetKillResult {
        killed,
        skipped,
        failed,
        detail,
    })
}

async fn terminate_pid(pid: u32) -> Result<(), String> {
    if pid <= 1 || pid == std::process::id() {
        return Err("refusing to kill a protected pid".into());
    }

    #[cfg(unix)]
    {
        terminate_pid_unix(pid).await
    }
    #[cfg(target_os = "windows")]
    {
        terminate_pid_windows(pid).await
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = pid;
        Err("Killing processes is not supported on this OS".into())
    }
}

#[cfg(unix)]
async fn terminate_pid_unix(pid: u32) -> Result<(), String> {
    let raw = pid as i32;
    let term = unsafe { libc::kill(raw, libc::SIGTERM) };
    if term != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(err.to_string());
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let still = unsafe { libc::kill(raw, 0) };
    if still == 0 {
        let kill = unsafe { libc::kill(raw, libc::SIGKILL) };
        if kill != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err.to_string());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn terminate_pid_windows(pid: u32) -> Result<(), String> {
    let pid_s = pid.to_string();
    let status = tokio::process::Command::new("taskkill")
        .args(["/PID", &pid_s, "/T"])
        .status()
        .await
        .map_err(|e| e.to_string())?;
    if status.success() {
        return Ok(());
    }
    let forced = tokio::process::Command::new("taskkill")
        .args(["/PID", &pid_s, "/T", "/F"])
        .status()
        .await
        .map_err(|e| e.to_string())?;
    if forced.success() {
        Ok(())
    } else {
        Err(format!("taskkill failed for pid {pid}"))
    }
}

/// Quit foreground user applications. Never touches OnionGate or core OS UI.
pub async fn quit_user_applications() -> Result<QuitAppsResult, String> {
    #[cfg(target_os = "macos")]
    {
        return quit_macos().await;
    }
    #[cfg(target_os = "linux")]
    {
        return quit_linux().await;
    }
    #[cfg(target_os = "windows")]
    {
        return quit_windows().await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Closing applications is not supported on this OS".into())
    }
}

#[cfg(target_os = "macos")]
async fn quit_macos() -> Result<QuitAppsResult, String> {
    let skip = protected_names()
        .into_iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        r#"
set closedNames to {{}}
set skippedNames to {{}}
set protect to {{{skip}}}
tell application "System Events"
    set procs to name of every process whose background only is false
end tell
repeat with procName in procs
    set n to procName as text
    if n is in protect then
        set end of skippedNames to n
    else
        try
            tell application n to quit
            set end of closedNames to n
        on error
            set end of skippedNames to n
        end try
    end if
end repeat
set AppleScript's text item delimiters to linefeed
return (closedNames as text) & "|||" & (skippedNames as text)
"#
    );
    let output = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .await
        .map_err(|e| format!("osascript failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Could not quit applications: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut parts = text.trim().splitn(2, "|||");
    let closed = split_names(parts.next().unwrap_or(""));
    let skipped = split_names(parts.next().unwrap_or(""));
    let requested = closed.len();
    crate::logs::append(format!(
        "Quit {requested} foreground app(s) before connect; skipped {}",
        skipped.len()
    ));
    Ok(QuitAppsResult {
        requested,
        detail: if requested == 0 {
            "No foreground apps needed quitting (or all were protected)".into()
        } else {
            format!("Asked {requested} application(s) to quit")
        },
        closed,
        skipped,
    })
}

#[cfg(target_os = "linux")]
async fn quit_linux() -> Result<QuitAppsResult, String> {
    // Best-effort: SIGTERM graphical windows via wmctrl when available; otherwise
    // only report that the user must close apps manually.
    if which::which("wmctrl").is_err() {
        return Ok(QuitAppsResult {
            requested: 0,
            detail: "Install wmctrl to auto-close apps, or close identity-linked apps manually"
                .into(),
            closed: vec![],
            skipped: protected_names().into_iter().map(str::to_string).collect(),
        });
    }
    let output = tokio::process::Command::new("wmctrl")
        .args(["-l"])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    let mut closed = Vec::new();
    let protect = protected_names();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Some(id) = line.split_whitespace().next() else {
            continue;
        };
        let title = line.split_whitespace().skip(3).collect::<Vec<_>>().join(" ");
        if protect.iter().any(|p| title.contains(p)) {
            continue;
        }
        let _ = tokio::process::Command::new("wmctrl")
            .args(["-ic", id])
            .status()
            .await;
        if !title.is_empty() {
            closed.push(title);
        }
    }
    let requested = closed.len();
    Ok(QuitAppsResult {
        requested,
        detail: format!("Asked {requested} window(s) to close via wmctrl"),
        closed,
        skipped: vec![],
    })
}

#[cfg(target_os = "windows")]
async fn quit_windows() -> Result<QuitAppsResult, String> {
    // Close visible top-level apps except protected names / OnionGate.
    let protect = protected_names().join("','");
    let script = format!(
        r#"
$protect = @('{protect}')
$closed = New-Object System.Collections.Generic.List[string]
Get-Process | Where-Object {{ $_.MainWindowHandle -ne 0 }} | ForEach-Object {{
  if ($protect -contains $_.ProcessName -or $protect -contains $_.MainWindowTitle) {{ return }}
  if ($_.ProcessName -match 'OnionGate|tor-socks|Cursor|Code|powershell|WindowsTerminal|cmd') {{ return }}
  try {{
    $_.CloseMainWindow() | Out-Null
    $closed.Add($_.ProcessName) | Out-Null
  }} catch {{}}
}}
$closed -join "`n"
"#
    );
    let output = tokio::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "Could not quit applications: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let closed = split_names(&String::from_utf8_lossy(&output.stdout));
    let requested = closed.len();
    Ok(QuitAppsResult {
        requested,
        detail: format!("Asked {requested} application(s) to close"),
        closed,
        skipped: vec![],
    })
}

fn split_names(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oniongate_and_os_shells_are_protected() {
        assert!(is_protected_process("OnionGate", 42));
        assert!(is_protected_process("oniongate_helper", 42));
        assert!(is_protected_process("Cursor Helper", 42));
        assert!(is_protected_process("Finder", 42));
        assert!(is_protected_process("kernel", 42));
        assert!(is_protected_process("pid 88", 88));
        assert!(is_protected_process("Slack", 1));
        assert!(is_protected_process("anything", std::process::id()));
    }

    #[test]
    fn user_apps_are_killable() {
        assert!(!is_protected_process("Slack", 4242));
        assert!(!is_protected_process("Google Chrome", 4242));
        assert!(!is_protected_process("Discord", 4242));
    }
}
