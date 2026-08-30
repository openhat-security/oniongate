//! Best-effort quit of foreground user applications before a protected session.
//!
//! Closing apps is an OPSEC control, not a network guarantee. OnionGate never
//! force-kills itself, the shell used to launch it, or core OS UI processes.

use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::fs;
use std::path::{Component, Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command as StdCommand;
use std::sync::{LazyLock, Mutex};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use crate::win_console::HideConsole;

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
        "oniongate-cli",
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

/// Whether this pid/path may be stopped by OnionGate, including via the
/// privileged helper. Root VPN daemons under `/Applications` are allowed;
/// Apple/system paths and OnionGate itself are not.
pub(crate) fn may_kill_target(pid: u32, path: &str, name: &str) -> Result<(), String> {
    if pid <= 1 || pid == std::process::id() {
        return Err("refusing to kill a protected pid".into());
    }
    if path.is_empty() {
        #[cfg(windows)]
        {
            if pid > 4 {
                return Ok(());
            }
        }
        return Err("could not resolve the executable for that pid".into());
    }
    if crate::egress_watch::is_system_executable(path) {
        return Err("refusing to kill a system executable".into());
    }
    if is_protected_process(name, pid) {
        return Err("refusing to kill a protected process".into());
    }
    Ok(())
}

fn name_from_path(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Called by the privileged helper (already root). Resolves the live
/// executable; never takes a path or command from the client.
pub(crate) fn helper_terminate_pid(pid: u32) -> Result<String, String> {
    let path = crate::egress_watch::pid_executable_path(pid).unwrap_or_default();
    let name = name_from_path(&path);
    may_kill_target(pid, &path, &name)?;
    helper_signal_stop(pid)?;
    Ok(format!("stopped {name} (pid {pid})"))
}

/// Called by the privileged helper. Unloads launchd jobs that exec this
/// application bundle, then stops every process whose binary lives in it.
pub(crate) fn helper_stop_application(pid: u32) -> Result<String, String> {
    let path = crate::egress_watch::pid_executable_path(pid).unwrap_or_default();
    let name = name_from_path(&path);
    may_kill_target(pid, &path, &name)?;
    #[cfg(not(target_os = "macos"))]
    {
        helper_signal_stop(pid)?;
        return Ok(format!("stopped {name} (pid {pid})"));
    }
    #[cfg(target_os = "macos")]
    {
        let root = application_bundle(&path).unwrap_or(path);
        let mut notes = Vec::new();
        for job in launchd_jobs_for_root(&root) {
            if bootout_launchd_job(&job) {
                notes.push(format!("unloaded {}", job.label));
            }
        }
        let mut stopped = 0usize;
        for _ in 0..2 {
            for sibling in pids_under_prefix(&root) {
                let sp = crate::egress_watch::pid_executable_path(sibling).unwrap_or_default();
                let sn = name_from_path(&sp);
                if may_kill_target(sibling, &sp, &sn).is_err() {
                    continue;
                }
                if helper_signal_stop(sibling).is_ok() {
                    stopped += 1;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        if notes.is_empty() {
            Ok(format!("stopped {stopped} process(es) under {root}"))
        } else {
            Ok(format!(
                "stopped {stopped} process(es) under {root}; {}",
                notes.join(", ")
            ))
        }
    }
}

fn application_bundle(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let idx = normalized.find(".app/")?;
    Some(format!("{}.app", &normalized[..idx]))
}

fn bundle_token(root: &str) -> Option<String> {
    let stem = Path::new(root).file_stem()?.to_string_lossy();
    let compact: String = stem
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (compact.len() >= 6).then_some(compact)
}

fn job_belongs_to_root(xml: &str, label: &str, root: &str) -> bool {
    let needle = root.trim_end_matches('/');
    if !needle.is_empty() && xml.contains(needle) {
        return true;
    }
    match bundle_token(root) {
        Some(token) => label.to_ascii_lowercase().contains(&token),
        None => false,
    }
}

fn safe_app_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
}

fn safe_launchd_label(label: &str) -> bool {
    let label = label.trim();
    !label.is_empty()
        && label.len() <= 128
        && !label.to_ascii_lowercase().starts_with("com.apple.")
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn plist_label(xml: &str) -> Option<String> {
    let key = xml.find("<key>Label</key>")?;
    let rest = &xml[key + "<key>Label</key>".len()..];
    let start = rest.find("<string>")? + "<string>".len();
    let end = rest[start..].find("</string>")?;
    let label = rest[start..start + end].trim();
    safe_launchd_label(label).then(|| label.to_string())
}

#[cfg(target_os = "macos")]
struct LaunchdJob {
    label: String,
}

#[cfg(target_os = "macos")]
fn launchd_plist_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/Library/LaunchAgents"),
    ];
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join("Library/LaunchAgents"));
    }
    dirs
}

#[cfg(target_os = "macos")]
fn read_plist_xml(path: &Path) -> Option<String> {
    if let Ok(text) = fs::read_to_string(path) {
        if text.contains("<key>Label</key>") {
            return Some(text);
        }
    }
    let output = StdCommand::new("/usr/bin/plutil")
        .args(["-convert", "xml1", "-o", "-"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(target_os = "macos")]
fn launchd_jobs_for_root(root: &str) -> Vec<LaunchdJob> {
    let needle = root.trim_end_matches('/');
    let mut jobs: Vec<LaunchdJob> = Vec::new();
    for dir in launchd_plist_dirs() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("plist") {
                continue;
            }
            let Some(xml) = read_plist_xml(&path) else {
                continue;
            };
            let Some(label) = plist_label(&xml) else {
                continue;
            };
            if !job_belongs_to_root(&xml, &label, needle) {
                continue;
            }
            if jobs.iter().any(|job| job.label == label) {
                continue;
            }
            jobs.push(LaunchdJob { label });
            if jobs.len() >= 16 {
                return jobs;
            }
        }
    }
    if let Ok(output) = StdCommand::new("/bin/launchctl").arg("list").output() {
        for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
            let Some(label) = line.split_whitespace().nth(2) else {
                continue;
            };
            if !safe_launchd_label(label) || !job_belongs_to_root("", label, needle) {
                continue;
            }
            if jobs.iter().any(|job| job.label == label) {
                continue;
            }
            jobs.push(LaunchdJob {
                label: label.to_string(),
            });
            if jobs.len() >= 16 {
                break;
            }
        }
    }
    jobs
}

#[cfg(target_os = "macos")]
fn bootout_launchd_job(job: &LaunchdJob) -> bool {
    if !safe_launchd_label(&job.label) {
        return false;
    }
    let uid = unsafe { libc::getuid() };
    let specs = [
        format!("system/{}", job.label),
        format!("gui/{uid}/{}", job.label),
    ];
    let mut ok = false;
    for spec in specs {
        let status = StdCommand::new("/bin/launchctl")
            .args(["bootout", &spec])
            .status();
        if status.map(|s| s.success()).unwrap_or(false) {
            ok = true;
        }
    }
    ok
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn pids_under_prefix(prefix: &str) -> Vec<u32> {
    let prefix = prefix.trim_end_matches('/');
    let Ok(output) = StdCommand::new("ps").args(["-axo", "pid="]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .filter(|&pid| {
            crate::egress_watch::pid_executable_path(pid)
                .is_some_and(|path| path == prefix || path.starts_with(&format!("{prefix}/")))
        })
        .collect()
}

fn helper_signal_stop(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        let raw = pid as i32;
        let term = unsafe { libc::kill(raw, libc::SIGTERM) };
        if term != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("SIGTERM: {err}"));
            }
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        if unsafe { libc::kill(raw, 0) } != 0 {
            return Ok(());
        }
        let kill = unsafe { libc::kill(raw, libc::SIGKILL) };
        if kill != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("SIGKILL: {err}"));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        if unsafe { libc::kill(raw, 0) } == 0 {
            return Err(format!("pid {pid} still running after SIGKILL"));
        }
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let pid_s = pid.to_string();
        let status = std::process::Command::new("taskkill.exe")
            .args(["/PID", &pid_s, "/T", "/F"])
            .hide_console()
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("taskkill failed for pid {pid}"))
        }
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = pid;
        Err("Killing processes is not supported on this OS".into())
    }
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
            detail: "No processes currently have sockets classified as not through Tor".into(),
        });
    }

    let mut killed = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    let mut seen_bundles = HashSet::new();

    for target in targets {
        let item = KilledProcess {
            process: target.process.clone(),
            pid: target.pid,
        };
        if !target.killable {
            skipped.push(item);
            continue;
        }
        let path = crate::egress_watch::pid_executable_path(target.pid).unwrap_or_default();
        if let Some(bundle) = application_bundle(&path) {
            if !seen_bundles.insert(bundle) {
                continue;
            }
        }
        match stop_target_logged(target.pid, &target.process).await {
            attempt if attempt.ok => {
                remember_closed_app(&target.process, reopen_source(&target));
                killed.push(item);
            }
            _ => failed.push(item),
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
            format!("Left {skipped_n} protected process(es) running; nothing was killed")
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessKillResult {
    pub process: String,
    pub pid: u32,
    pub ok: bool,
    pub detail: String,
    pub log: String,
}

struct KillAttempt {
    ok: bool,
    detail: String,
    lines: Vec<String>,
}

/// Terminate one process from the live Not through Tor census. Caller-supplied
/// PIDs that are not in that census, or that are protected, are refused.
pub async fn kill_clearnet_process(pid: u32) -> Result<ProcessKillResult, String> {
    let watch = crate::egress_watch::current();
    let Some(target) = watch
        .clearnet_processes
        .iter()
        .find(|process| process.pid == pid)
        .cloned()
    else {
        return Ok(ProcessKillResult {
            process: String::new(),
            pid,
            ok: false,
            detail: "That process is not in the current Not through Tor list".into(),
            log: format!("pid {pid} is not in the live Not through Tor census\n"),
        });
    };
    if !target.killable {
        let reason = if target.system {
            "system process"
        } else {
            "protected process"
        };
        return Ok(ProcessKillResult {
            process: target.process.clone(),
            pid,
            ok: false,
            detail: format!(
                "{} (pid {pid}) is a {reason} and will not be killed",
                target.process
            ),
            log: format!(
                "refusing to stop {} (pid {pid}): {reason}\n",
                target.process
            ),
        });
    }

    let attempt = stop_target_logged(target.pid, &target.process).await;
    if attempt.ok {
        remember_closed_app(&target.process, reopen_source(&target));
    }
    crate::logs::append(format!(
        "Clearnet process kill: {} pid {} — {}",
        target.process, target.pid, attempt.detail
    ));
    Ok(ProcessKillResult {
        process: target.process,
        pid: target.pid,
        ok: attempt.ok,
        detail: attempt.detail,
        log: join_log(&attempt.lines),
    })
}

async fn stop_target_logged(pid: u32, name: &str) -> KillAttempt {
    let path = crate::egress_watch::pid_executable_path(pid).unwrap_or_default();
    if let Some(bundle) = application_bundle(&path) {
        return stop_bundle_logged(pid, name, &bundle).await;
    }
    terminate_pid_logged(pid, name).await
}

async fn stop_bundle_logged(pid: u32, name: &str, bundle: &str) -> KillAttempt {
    let mut lines = vec![format!(
        "Stopping {name} (pid {pid}) and keeping {} from relaunching",
        Path::new(bundle)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| bundle.to_string())
    )];
    if let Err(e) = may_kill_target(
        pid,
        &crate::egress_watch::pid_executable_path(pid).unwrap_or_default(),
        name,
    ) {
        lines.push(e.clone());
        return KillAttempt {
            ok: false,
            detail: e,
            lines,
        };
    }

    let helper_ok = if crate::helper::client::available() {
        lines.push("asking oniongate-helper to unload launch jobs and stop the app".into());
        let helper = tokio::task::spawn_blocking(move || {
            crate::helper::client::request(&crate::helper::HelperRequest::StopApplication { pid })
        })
        .await;
        match helper {
            Ok(Ok(resp)) if resp.ok => {
                lines.push(format!("helper: {}", resp.message));
                true
            }
            Ok(Ok(resp)) => {
                lines.push(format!("helper: {}", resp.message));
                false
            }
            Ok(Err(e)) => {
                lines.push(format!("helper: {e}"));
                false
            }
            Err(e) => {
                lines.push(format!("helper: {e}"));
                false
            }
        }
    } else {
        lines.push("privileged helper is not installed".into());
        false
    };

    if !helper_ok {
        quit_gui_bundle(bundle, &mut lines).await;
        #[cfg(target_os = "macos")]
        {
            elevated_stop_bundle(pid, bundle, &mut lines).await;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let attempt = terminate_pid_logged(pid, name).await;
            lines.extend(attempt.lines);
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let leftover = pids_under_prefix(bundle);
        if leftover.is_empty() {
            lines.push(format!("{bundle} is not running"));
            return KillAttempt {
                ok: true,
                detail: format!("Stopped {name} and prevented relaunch"),
                lines,
            };
        }
        lines.push(format!(
            "{} process(es) still in the bundle; stopping leftovers",
            leftover.len()
        ));
        if helper_ok {
            let retry_pid = leftover[0];
            let helper = tokio::task::spawn_blocking(move || {
                crate::helper::client::request(&crate::helper::HelperRequest::StopApplication {
                    pid: retry_pid,
                })
            })
            .await;
            match helper {
                Ok(Ok(resp)) => lines.push(format!("helper retry: {}", resp.message)),
                Ok(Err(e)) => lines.push(format!("helper retry: {e}")),
                Err(e) => lines.push(format!("helper retry: {e}")),
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let still = pids_under_prefix(bundle);
        if still.is_empty() {
            lines.push(format!("{bundle} stayed down"));
            KillAttempt {
                ok: true,
                detail: format!("Stopped {name} and prevented relaunch"),
                lines,
            }
        } else {
            lines.push(format!(
                "{} process(es) came back; open the app again if you want it running",
                still.len()
            ));
            KillAttempt {
                ok: false,
                detail: format!("{name} relaunched after stop"),
                lines,
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        KillAttempt {
            ok: true,
            detail: format!("Stopped {name}"),
            lines,
        }
    }
}

async fn quit_gui_bundle(bundle: &str, lines: &mut Vec<String>) {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (bundle, lines);
    }
    #[cfg(target_os = "macos")]
    {
        let Some(name) = Path::new(bundle)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
        else {
            return;
        };
        if !safe_app_name(&name) {
            return;
        }
        lines.push(format!("asking {name} to quit"));
        let script = format!("tell application \"{name}\" to quit");
        match tokio::process::Command::new("osascript")
            .args(["-e", &script])
            .output()
            .await
        {
            Ok(output) => {
                append_command_output(lines, &format!("osascript quit {name}"), &output);
            }
            Err(e) => lines.push(format!("osascript quit {name}: {e}")),
        }
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    }
}

#[cfg(target_os = "macos")]
async fn elevated_stop_bundle(pid: u32, bundle: &str, lines: &mut Vec<String>) {
    let mut jobs = launchd_jobs_for_root(bundle);
    jobs.truncate(16);
    let mut pids = pids_under_prefix(bundle);
    if !pids.contains(&pid) {
        pids.push(pid);
    }
    pids.truncate(32);
    if jobs.is_empty() && pids.is_empty() {
        return;
    }
    for job in &jobs {
        lines.push(format!("will unload launch job {}", job.label));
    }
    let uid = unsafe { libc::getuid() };
    let mut script = String::new();
    for job in &jobs {
        if !safe_launchd_label(&job.label) {
            continue;
        }
        script.push_str(&format!(
            "/bin/launchctl bootout system/{} 2>/dev/null || true; \
             /bin/launchctl bootout gui/{uid}/{} 2>/dev/null || true; ",
            job.label, job.label
        ));
    }
    for sibling in &pids {
        script.push_str(&format!("/bin/kill -TERM {sibling} 2>/dev/null || true; "));
    }
    script.push_str("sleep 0.5; ");
    for sibling in &pids {
        script.push_str(&format!("/bin/kill -KILL {sibling} 2>/dev/null || true; "));
    }
    script.push_str("echo STOPPED");
    let prompt = "OnionGate needs administrator access to stop a VPN/app that keeps relaunching.";
    lines.push("$ administrator launchctl bootout + kill".into());
    let result =
        tokio::task::spawn_blocking(move || crate::elevate::run_shell_captured(&script, prompt))
            .await;
    match result {
        Ok(Ok(out)) => {
            for line in out.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    lines.push(line.to_string());
                }
            }
        }
        Ok(Err(e)) => lines.push(e),
        Err(e) => lines.push(e.to_string()),
    }
}

async fn terminate_pid_logged(pid: u32, name: &str) -> KillAttempt {
    let label = if name.is_empty() {
        format!("pid {pid}")
    } else {
        format!("{name} (pid {pid})")
    };
    let mut lines = vec![format!("Stopping {label}")];

    if pid <= 1 || pid == std::process::id() {
        lines.push("refusing to kill a protected pid".into());
        return KillAttempt {
            ok: false,
            detail: "refusing to kill a protected pid".into(),
            lines,
        };
    }

    #[cfg(unix)]
    {
        return terminate_pid_unix_logged(pid, lines).await;
    }
    #[cfg(target_os = "windows")]
    {
        return terminate_pid_windows_logged(pid, lines).await;
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        lines.push("Killing processes is not supported on this OS".into());
        KillAttempt {
            ok: false,
            detail: "Killing processes is not supported on this OS".into(),
            lines,
        }
    }
}

fn join_log(lines: &[String]) -> String {
    let mut log = lines.join("\n");
    if !log.ends_with('\n') {
        log.push('\n');
    }
    log
}

fn is_permission_error(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    text.contains("operation not permitted")
        || text.contains("permission denied")
        || text.contains("access is denied")
        || text.contains("not permitted")
}

fn output_is_permission_denied(output: &std::process::Output) -> bool {
    is_permission_error(&String::from_utf8_lossy(&output.stdout))
        || is_permission_error(&String::from_utf8_lossy(&output.stderr))
}

async fn escalate_terminate(pid: u32, lines: &mut Vec<String>) -> bool {
    let path = crate::egress_watch::pid_executable_path(pid).unwrap_or_default();
    let name = name_from_path(&path);
    if let Err(e) = may_kill_target(pid, &path, &name) {
        lines.push(e);
        return false;
    }
    lines.push("process is owned by another user; requesting administrator access".into());

    if crate::helper::client::available() {
        lines.push("asking oniongate-helper to stop it".into());
        let helper = tokio::task::spawn_blocking(move || {
            crate::helper::client::request(&crate::helper::HelperRequest::TerminatePid { pid })
        })
        .await;
        match helper {
            Ok(Ok(resp)) => {
                lines.push(format!("helper: {}", resp.message));
                if resp.ok {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    #[cfg(unix)]
                    {
                        if !pid_still_running(pid) {
                            return true;
                        }
                        lines.push("helper reported success but the pid is still running".into());
                    }
                    #[cfg(not(unix))]
                    {
                        return true;
                    }
                }
            }
            Ok(Err(e)) => lines.push(format!("helper: {e}")),
            Err(e) => lines.push(format!("helper: {e}")),
        }
    } else {
        lines.push("privileged helper is not installed".into());
    }

    #[cfg(unix)]
    {
        elevated_unix_kill(pid, lines).await
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
async fn elevated_unix_kill(pid: u32, lines: &mut Vec<String>) -> bool {
    let script = format!(
        "/bin/kill -TERM {pid}; echo TERM_EXIT:$?; \
         sleep 0.5; \
         if /bin/kill -0 {pid} 2>/dev/null; then \
           echo STILL_RUNNING; \
           /bin/kill -KILL {pid}; echo KILL_EXIT:$?; \
           sleep 0.15; \
         fi; \
         if /bin/kill -0 {pid} 2>/dev/null; then echo STILL_ALIVE; exit 1; fi; \
         echo EXITED"
    );
    let prompt = "OnionGate needs administrator access to stop a process that is not using Tor.";
    lines.push(format!("$ administrator /bin/kill {pid}"));
    let result =
        tokio::task::spawn_blocking(move || crate::elevate::run_shell_captured(&script, prompt))
            .await;
    match result {
        Ok(Ok(out)) => {
            for line in out.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    lines.push(line.to_string());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            !pid_still_running(pid)
        }
        Ok(Err(e)) => {
            lines.push(e);
            false
        }
        Err(e) => {
            lines.push(e.to_string());
            false
        }
    }
}

fn append_command_output(lines: &mut Vec<String>, command: &str, output: &std::process::Output) {
    let status = output
        .status
        .code()
        .map(|code| format!("exit {code}"))
        .unwrap_or_else(|| "no exit code".into());
    lines.push(format!("$ {command}  ({status})"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stdout.lines().chain(stderr.lines()) {
        let line = line.trim_end();
        if !line.is_empty() {
            lines.push(line.to_string());
        }
    }
}

async fn run_command(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("{program}: {e}"))
}

#[cfg(unix)]
fn pid_still_running(pid: u32) -> bool {
    let raw = pid as i32;
    let rc = unsafe { libc::kill(raw, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(unix)]
async fn snapshot_pid(pid: u32, lines: &mut Vec<String>) {
    let pid_s = pid.to_string();
    match run_command("ps", &["-p", &pid_s, "-o", "pid=,stat=,comm="]).await {
        Ok(output) => {
            append_command_output(lines, &format!("ps -p {pid} -o pid=,stat=,comm="), &output)
        }
        Err(e) => lines.push(e),
    }
}

#[cfg(unix)]
async fn terminate_pid_unix_logged(pid: u32, mut lines: Vec<String>) -> KillAttempt {
    let pid_s = pid.to_string();
    snapshot_pid(pid, &mut lines).await;

    let term = match run_command("/bin/kill", &["-TERM", &pid_s]).await {
        Ok(output) => {
            append_command_output(&mut lines, &format!("/bin/kill -TERM {pid}"), &output);
            if output.status.success() {
                true
            } else if String::from_utf8_lossy(&output.stderr).contains("No such process") {
                lines.push("process already gone".into());
                return KillAttempt {
                    ok: true,
                    detail: format!("pid {pid} was already gone"),
                    lines,
                };
            } else if output_is_permission_denied(&output) {
                if escalate_terminate(pid, &mut lines).await {
                    snapshot_pid(pid, &mut lines).await;
                    lines.push("process exited after administrator stop".into());
                    return KillAttempt {
                        ok: true,
                        detail: format!("Terminated pid {pid} with administrator access"),
                        lines,
                    };
                }
                return KillAttempt {
                    ok: false,
                    detail: format!("Could not terminate pid {pid} (administrator stop failed)"),
                    lines,
                };
            } else {
                false
            }
        }
        Err(e) => {
            lines.push(format!("/bin/kill -TERM: {e}"));
            false
        }
    };
    if !term {
        let raw = pid as i32;
        let rc = unsafe { libc::kill(raw, libc::SIGTERM) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                lines.push("process already gone".into());
                return KillAttempt {
                    ok: true,
                    detail: format!("pid {pid} was already gone"),
                    lines,
                };
            }
            lines.push(format!("SIGTERM failed: {err}"));
            if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
                if escalate_terminate(pid, &mut lines).await {
                    snapshot_pid(pid, &mut lines).await;
                    lines.push("process exited after administrator stop".into());
                    return KillAttempt {
                        ok: true,
                        detail: format!("Terminated pid {pid} with administrator access"),
                        lines,
                    };
                }
            }
            return KillAttempt {
                ok: false,
                detail: err.to_string(),
                lines,
            };
        }
        lines.push("sent SIGTERM via libc after /bin/kill failed".into());
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    if !pid_still_running(pid) {
        snapshot_pid(pid, &mut lines).await;
        lines.push("process exited after SIGTERM".into());
        return KillAttempt {
            ok: true,
            detail: format!("Terminated pid {pid}"),
            lines,
        };
    }

    lines.push("still running; sending SIGKILL".into());
    match run_command("/bin/kill", &["-KILL", &pid_s]).await {
        Ok(output) => {
            append_command_output(&mut lines, &format!("/bin/kill -KILL {pid}"), &output);
            if output_is_permission_denied(&output) {
                if escalate_terminate(pid, &mut lines).await {
                    snapshot_pid(pid, &mut lines).await;
                    lines.push("process exited after administrator stop".into());
                    return KillAttempt {
                        ok: true,
                        detail: format!("Terminated pid {pid} with administrator access"),
                        lines,
                    };
                }
            }
        }
        Err(e) => lines.push(format!("/bin/kill -KILL: {e}")),
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    snapshot_pid(pid, &mut lines).await;
    if pid_still_running(pid) {
        lines.push("process still running after SIGKILL".into());
        KillAttempt {
            ok: false,
            detail: format!("Could not terminate pid {pid}"),
            lines,
        }
    } else {
        lines.push("process exited after SIGKILL".into());
        KillAttempt {
            ok: true,
            detail: format!("Terminated pid {pid}"),
            lines,
        }
    }
}

#[cfg(target_os = "windows")]
async fn terminate_pid_windows_logged(pid: u32, mut lines: Vec<String>) -> KillAttempt {
    let pid_s = pid.to_string();
    match run_command("taskkill.exe", &["/PID", &pid_s, "/T"]).await {
        Ok(output) => {
            append_command_output(&mut lines, &format!("taskkill /PID {pid} /T"), &output);
            if output.status.success() {
                return KillAttempt {
                    ok: true,
                    detail: format!("Terminated pid {pid}"),
                    lines,
                };
            }
        }
        Err(e) => lines.push(e),
    }
    lines.push("still running; forcing taskkill".into());
    match run_command("taskkill.exe", &["/PID", &pid_s, "/T", "/F"]).await {
        Ok(output) => {
            append_command_output(&mut lines, &format!("taskkill /PID {pid} /T /F"), &output);
            if output.status.success() {
                return KillAttempt {
                    ok: true,
                    detail: format!("Terminated pid {pid}"),
                    lines,
                };
            }
            if output_is_permission_denied(&output) && escalate_terminate(pid, &mut lines).await {
                return KillAttempt {
                    ok: true,
                    detail: format!("Terminated pid {pid} with administrator access"),
                    lines,
                };
            }
            KillAttempt {
                ok: false,
                detail: format!("taskkill failed for pid {pid}"),
                lines,
            }
        }
        Err(e) => {
            lines.push(e.clone());
            KillAttempt {
                ok: false,
                detail: e,
                lines,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Memory-only reopen ledger
// ---------------------------------------------------------------------------

/// An application OnionGate closed, remembered only well enough to launch it
/// again.
///
/// There is deliberately no field for arguments, environment, or a command
/// line, and no constructor that could accept one: full process command lines
/// must never enter storage or a report, so the type is unable to hold one.
/// The ledger this lives in is memory-only — never settings, SQLite, logs, or
/// an export — and is dropped on teardown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReopenableApp {
    /// Display name, e.g. `Slack`.
    pub label: String,
    /// Application bundle root, e.g. `/Applications/Slack.app`.
    pub path: String,
}

const MAX_LEDGER: usize = 64;

/// Roots a reopenable application may live under. Anything else is refused
/// rather than launched.
const REOPEN_ROOTS: [&str; 2] = ["/Applications", "/System/Applications"];

static REOPEN_LEDGER: LazyLock<Mutex<Vec<ReopenableApp>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Strip an executable path down to its `.app` bundle root. This is also what
/// drops any arguments that came attached to the path: everything after the
/// bundle boundary goes away.
fn bundle_root(path: &str) -> Option<String> {
    let path = path.trim().trim_end_matches('/');
    if path.is_empty() {
        return None;
    }
    if let Some(bundle) = application_bundle(path) {
        return Some(bundle);
    }
    let normalized = path.replace('\\', "/");
    normalized.ends_with(".app").then_some(normalized)
}

/// A bundle path never carries an argument. Anything that looks like one means
/// we were handed a command line, which must not be recorded at all.
fn carries_arguments(path: &str) -> bool {
    path.split_ascii_whitespace()
        .any(|token| token.starts_with('-'))
}

/// Lexical policy for a reopen target, applied both when recording and when
/// launching: absolute, no traversal, an app bundle, under an allowed root.
fn reopen_path_policy(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("it has no path on disk".into());
    }
    if path.chars().any(char::is_control) {
        return Err("its path is not a plain filesystem path".into());
    }
    if carries_arguments(path) {
        return Err("its path looks like a command line rather than a bundle".into());
    }
    let candidate = Path::new(path);
    if !candidate.is_absolute() {
        return Err("its path is not absolute".into());
    }
    if candidate
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("its path walks up out of its own directory".into());
    }
    if candidate.extension().and_then(|ext| ext.to_str()) != Some("app") {
        return Err("it is not an application bundle".into());
    }
    if !REOPEN_ROOTS.iter().any(|root| candidate.starts_with(root)) {
        return Err("it does not live in /Applications or /System/Applications".into());
    }
    Ok(())
}

/// On-disk half of the check. A symlink is refused outright rather than
/// followed: it is the cheapest way to point a launch somewhere else.
fn reopen_target_on_disk(target: &Path) -> Result<(), String> {
    let meta =
        std::fs::symlink_metadata(target).map_err(|_| "it is no longer on disk".to_string())?;
    if meta.file_type().is_symlink() {
        return Err("it is a symlink, and OnionGate will not follow one to launch an app".into());
    }
    if !meta.is_dir() {
        return Err("it is not an application bundle".into());
    }
    Ok(())
}

/// Full validation. The resolved path is re-checked against the policy so a
/// symlinked parent directory cannot land the launch outside the allowed roots.
fn validate_reopen_target(path: &str) -> Result<PathBuf, String> {
    reopen_path_policy(path)?;
    let target = PathBuf::from(path);
    reopen_target_on_disk(&target)?;
    let resolved =
        std::fs::canonicalize(&target).map_err(|_| "it is no longer on disk".to_string())?;
    reopen_path_policy(&resolved.to_string_lossy())?;
    Ok(resolved)
}

fn reopen_entry(label: &str, path: &str) -> Option<ReopenableApp> {
    let bundle = bundle_root(path)?;
    reopen_path_policy(&bundle).ok()?;
    let label = match label.trim() {
        "" => Path::new(&bundle)
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())?,
        name => name.to_string(),
    };
    Some(ReopenableApp {
        label,
        path: bundle,
    })
}

/// De-duplicate by bundle path so closing the same app twice — once as a GUI
/// quit, once as a clearnet kill — yields one entry.
fn push_unique(ledger: &mut Vec<ReopenableApp>, entry: ReopenableApp) -> bool {
    if ledger.len() >= MAX_LEDGER || ledger.iter().any(|item| item.path == entry.path) {
        return false;
    }
    ledger.push(entry);
    true
}

/// Record an application OnionGate just closed. Callers pass a display label
/// and an executable or bundle path only; anything else is dropped on the floor.
pub(crate) fn remember_closed_app(label: &str, path: &str) {
    let Some(entry) = reopen_entry(label, path) else {
        return;
    };
    if let Ok(mut ledger) = REOPEN_LEDGER.lock() {
        push_unique(&mut ledger, entry);
    }
}

/// Current ledger contents. Empty when nothing is reopenable.
pub fn reopenable_apps() -> Vec<ReopenableApp> {
    REOPEN_LEDGER
        .lock()
        .map(|ledger| ledger.clone())
        .unwrap_or_default()
}

/// Drop the ledger. Called on teardown so a later session can never relaunch
/// something a previous one closed.
pub fn clear_reopen_ledger() {
    if let Ok(mut ledger) = REOPEN_LEDGER.lock() {
        ledger.clear();
    }
}

fn forget_closed_app(path: &str) {
    if let Ok(mut ledger) = REOPEN_LEDGER.lock() {
        ledger.retain(|item| item.path != path);
    }
}

/// The bundle location the census already resolved, falling back to the
/// executable path.
fn reopen_source(target: &crate::egress_watch::ClearnetProcess) -> &str {
    if target.location.is_empty() {
        &target.path
    } else {
        &target.location
    }
}

fn phase_label(phase: crate::session::SessionPhase) -> &'static str {
    match phase {
        crate::session::SessionPhase::Disconnected => "disconnected",
        crate::session::SessionPhase::Connecting => "still connecting",
        crate::session::SessionPhase::Protected => "protected",
        crate::session::SessionPhase::Degraded => "degraded",
        crate::session::SessionPhase::Recovering => "recovering",
    }
}

/// Fail closed. Putting an app back on the network while the route is
/// unverified is exactly the leak this feature must not cause, so every
/// uncertain state refuses.
fn reopen_gate(
    phase: crate::session::SessionPhase,
    tun_mode: bool,
    tun_live: bool,
) -> Result<(), String> {
    if !tun_mode {
        return Err(
            "Reopening apps needs TUN mode. In Proxy mode a relaunched app is not \
                    forced through Tor, so nothing was launched."
                .into(),
        );
    }
    if !tun_live {
        return Err(
            "Reopening apps needs a live TUN interface. Connect first, then reopen; \
                    nothing was launched."
                .into(),
        );
    }
    if phase != crate::session::SessionPhase::Protected {
        return Err(format!(
            "Reopening apps needs a verified Protected session. OnionGate is {}, \
             so nothing was launched.",
            phase_label(phase)
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn running_as_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

#[cfg(not(unix))]
pub(crate) fn running_as_root() -> bool {
    false
}

/// Launch a validated bundle in the caller's own GUI session. `open` hands the
/// request to the console user's launch services; the caller has already
/// refused to do this from a privileged process.
async fn launch_app_bundle(bundle: &Path) -> Result<(), String> {
    let output = tokio::process::Command::new("/usr/bin/open")
        .arg("-a")
        .arg(bundle)
        .output()
        .await
        .map_err(|e| format!("it could not be launched: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if detail.is_empty() {
        "the system refused to launch it".into()
    } else {
        detail
    })
}

fn reopen_summary(reopened: &[String], skipped: &[String]) -> String {
    let mut parts = Vec::new();
    if reopened.is_empty() {
        parts.push("Reopened nothing".to_string());
    } else {
        parts.push(format!(
            "Reopened {} app(s) through Tor: {}",
            reopened.len(),
            reopened.join(", ")
        ));
    }
    if !skipped.is_empty() {
        parts.push(format!("skipped {}: {}", skipped.len(), skipped.join("; ")));
    }
    parts.join(". ")
}

/// Relaunch the ledger's applications, as the console user, only while the
/// route is verified live.
pub async fn reopen_closed_apps() -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("Reopening closed applications is only supported on macOS.".into());
    }
    let settings = crate::settings::load();
    reopen_gate(
        crate::session::load().phase,
        settings.connection_mode == "tun",
        crate::tun::process_seems_running(),
    )?;
    // A GUI app launched from a privileged context would run as root for the
    // rest of its life. Refuse rather than drop privileges by hand.
    if running_as_root() {
        return Err(
            "Refusing to relaunch an application from a privileged process. Restart OnionGate \
             as your own user and try again."
                .into(),
        );
    }

    let targets = reopenable_apps();
    if targets.is_empty() {
        return Ok("No closed applications to reopen.".into());
    }

    let mut reopened = Vec::new();
    let mut skipped = Vec::new();
    for target in targets {
        let outcome = match validate_reopen_target(&target.path) {
            Ok(resolved) => launch_app_bundle(&resolved).await,
            Err(reason) => Err(reason),
        };
        match outcome {
            Ok(()) => {
                forget_closed_app(&target.path);
                reopened.push(target.label);
            }
            Err(reason) => skipped.push(format!("{} — {reason}", target.label)),
        }
    }

    // Counts only: the ledger's contents are memory-only and stay out of logs.
    crate::logs::append(format!(
        "Reopen closed apps: {} launched, {} skipped",
        reopened.len(),
        skipped.len()
    ));
    Ok(reopen_summary(&reopened, &skipped))
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
    // Each closed row is `name<tab>bundle path`. The path is what makes the app
    // reopenable later; it is never joined with arguments of any kind.
    let script = format!(
        r#"
set closedRows to {{}}
set skippedNames to {{}}
set protect to {{{skip}}}
tell application "System Events"
    set procRows to {{}}
    repeat with p in (every process whose background only is false)
        set procName to name of p
        set procPath to ""
        try
            set procPath to POSIX path of (application file of p)
        end try
        set end of procRows to {{procName, procPath}}
    end repeat
end tell
repeat with row in procRows
    set n to (item 1 of row) as text
    set pth to (item 2 of row) as text
    if n is in protect then
        set end of skippedNames to n
    else
        try
            tell application n to quit
            set end of closedRows to (n & tab & pth)
        on error
            set end of skippedNames to n
        end try
    end if
end repeat
set AppleScript's text item delimiters to linefeed
return (closedRows as text) & "|||" & (skippedNames as text)
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
    let rows = split_closed_rows(parts.next().unwrap_or(""));
    let skipped = split_names(parts.next().unwrap_or(""));
    for (name, path) in &rows {
        remember_closed_app(name, path);
    }
    let closed: Vec<String> = rows.into_iter().map(|(name, _)| name).collect();
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
        let title = line
            .split_whitespace()
            .skip(3)
            .collect::<Vec<_>>()
            .join(" ");
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
        .hide_console()
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

/// Parse `name<tab>bundle path` rows. A row without a tab is a bare name, which
/// keeps the older single-column output working.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn split_closed_rows(raw: &str) -> Vec<(String, String)> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| match line.split_once('\t') {
            Some((name, path)) => (name.trim().to_string(), path.trim().to_string()),
            None => (line.to_string(), String::new()),
        })
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

    #[test]
    fn vpn_daemons_in_applications_may_be_killed() {
        assert!(may_kill_target(
            529,
            "/Applications/ExpressVPN.app/Contents/MacOS/expressvpn-daemon",
            "expressvpn-daemon",
        )
        .is_ok());
        assert!(may_kill_target(88, "/usr/libexec/apsd", "apsd",).is_err());
        assert!(
            may_kill_target(1, "/Applications/Slack.app/Contents/MacOS/Slack", "Slack").is_err()
        );
        assert!(is_permission_error("kill: 529: Operation not permitted"));
    }

    #[test]
    fn application_bundle_from_nested_macos_binary() {
        assert_eq!(
            application_bundle("/Applications/ExpressVPN.app/Contents/MacOS/expressvpn-daemon")
                .as_deref(),
            Some("/Applications/ExpressVPN.app")
        );
        assert_eq!(application_bundle("/usr/libexec/apsd"), None);
        assert_eq!(
            application_bundle("/Applications/Slack.app/Contents/MacOS/Slack").as_deref(),
            Some("/Applications/Slack.app")
        );
    }

    #[test]
    fn launchd_label_rejects_apple_and_shell_metacharacters() {
        assert!(safe_launchd_label("com.expressvpn.expressvpnd"));
        assert!(!safe_launchd_label("com.apple.apsd"));
        assert!(!safe_launchd_label("com.foo; rm -rf"));
        assert!(!safe_launchd_label(""));
    }

    #[test]
    fn plist_label_reads_first_label_string() {
        let xml = concat!(
            "<key>Label</key>\n",
            "<string>com.expressvpn.expressvpnd</string>\n"
        );
        assert_eq!(
            plist_label(xml).as_deref(),
            Some("com.expressvpn.expressvpnd")
        );
        assert_eq!(
            plist_label("<key>Label</key><string>com.apple.apsd</string>"),
            None
        );
    }

    #[test]
    fn expressvpn_jobs_match_bundle_path_or_label() {
        assert_eq!(
            bundle_token("/Applications/ExpressVPN.app").as_deref(),
            Some("expressvpn")
        );
        assert!(job_belongs_to_root(
            "",
            "com.expressvpn.helper",
            "/Applications/ExpressVPN.app"
        ));
        assert!(!job_belongs_to_root(
            "",
            "com.apple.apsd",
            "/Applications/ExpressVPN.app"
        ));
        assert!(job_belongs_to_root(
            "/Applications/ExpressVPN.app/Contents/MacOS/expressvpn-daemon",
            "com.expressvpn.expressvpnd",
            "/Applications/ExpressVPN.app"
        ));
        assert_eq!(bundle_token("/Applications/Slack.app"), None);
    }

    #[test]
    fn join_log_ends_with_newline() {
        assert_eq!(
            join_log(&["Stopping Slack (pid 9)".into()]),
            "Stopping Slack (pid 9)\n"
        );
    }

    #[test]
    fn ledger_records_only_a_label_and_a_bundle_path() {
        let entry = reopen_entry(
            "Slack",
            "/Applications/Slack.app/Contents/MacOS/Slack --user-data-dir=/tmp/profile \
             --auth-token=s3cr3t",
        )
        .expect("bundle entry");
        assert_eq!(entry.label, "Slack");
        assert_eq!(entry.path, "/Applications/Slack.app");

        // The serialized shape is the ledger's whole contract with the UI: two
        // string fields, and no room for argv, environment, or a command line.
        let json = serde_json::to_value(&entry).unwrap();
        let object = json.as_object().expect("object");
        assert_eq!(object.len(), 2);
        assert!(object.contains_key("label"));
        assert!(object.contains_key("path"));
        let raw = serde_json::to_string(&entry).unwrap();
        assert!(!raw.contains("s3cr3t"));
        assert!(!raw.contains("--"));
        assert!(!raw.contains("profile"));
    }

    #[test]
    fn ledger_refuses_paths_that_are_really_command_lines() {
        // A trailing argument that itself ends in `.app` must not be mistaken
        // for the bundle to remember.
        assert_eq!(
            reopen_entry(
                "Real",
                "/Applications/Real.app --secret=/Applications/Fake.app"
            ),
            None
        );
        assert_eq!(
            reopen_entry("Foo", "/usr/bin/foo --dir=/tmp/evil.app"),
            None
        );
        assert_eq!(reopen_entry("Nothing", ""), None);
        // A plain daemon with no bundle is not reopenable.
        assert_eq!(reopen_entry("apsd", "/usr/libexec/apsd"), None);
    }

    #[test]
    fn ledger_names_an_app_from_its_bundle_when_the_label_is_empty() {
        let entry = reopen_entry(
            "",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        )
        .expect("bundle entry");
        assert_eq!(entry.label, "Google Chrome");
        assert_eq!(entry.path, "/Applications/Google Chrome.app");
        // A trailing slash (AppleScript's `POSIX path of`) still resolves.
        let entry = reopen_entry("Mail", "/System/Applications/Mail.app/").expect("bundle entry");
        assert_eq!(entry.path, "/System/Applications/Mail.app");
    }

    #[test]
    fn ledger_dedupes_by_bundle() {
        let mut ledger = Vec::new();
        let slack = reopen_entry("Slack", "/Applications/Slack.app/Contents/MacOS/Slack").unwrap();
        // Same app closed twice: once as a GUI quit, once as a clearnet kill.
        let again = reopen_entry("Slack", "/Applications/Slack.app").unwrap();
        assert!(push_unique(&mut ledger, slack));
        assert!(!push_unique(&mut ledger, again));
        assert_eq!(ledger.len(), 1);

        let other = reopen_entry("Discord", "/Applications/Discord.app").unwrap();
        assert!(push_unique(&mut ledger, other));
        assert_eq!(ledger.len(), 2);
    }

    /// Exercises the real process-wide ledger. No other test touches it, so the
    /// parallel test runner cannot interleave here.
    #[test]
    fn ledger_is_memory_only_and_clears_on_teardown() {
        clear_reopen_ledger();
        assert!(reopenable_apps().is_empty());
        remember_closed_app(
            "Slack",
            "/Applications/Slack.app/Contents/MacOS/Slack --token=abc",
        );
        remember_closed_app("Slack", "/Applications/Slack.app");
        assert_eq!(reopenable_apps().len(), 1);
        assert_eq!(reopenable_apps()[0].path, "/Applications/Slack.app");
        remember_closed_app("apsd", "/usr/libexec/apsd");
        assert_eq!(reopenable_apps().len(), 1);
        clear_reopen_ledger();
        assert!(reopenable_apps().is_empty());
    }

    #[test]
    fn reopen_refuses_unless_protected_over_live_tun() {
        use crate::session::SessionPhase;

        assert!(reopen_gate(SessionPhase::Protected, true, true).is_ok());

        // Proxy mode: a relaunched app would not be forced through Tor.
        let err = reopen_gate(SessionPhase::Protected, false, true).expect_err("proxy mode");
        assert!(err.contains("TUN mode"));

        // TUN configured but sing-box is not up.
        let err = reopen_gate(SessionPhase::Protected, true, false).expect_err("tun down");
        assert!(err.contains("live TUN"));

        // Every non-Protected phase refuses, including the ones that look close.
        for phase in [
            SessionPhase::Disconnected,
            SessionPhase::Connecting,
            SessionPhase::Degraded,
            SessionPhase::Recovering,
        ] {
            let err = reopen_gate(phase, true, true).expect_err("unverified phase");
            assert!(err.contains("verified Protected"), "{err}");
            assert!(err.contains("nothing was launched"), "{err}");
        }
    }

    #[test]
    fn reopen_refuses_relative_traversing_and_out_of_tree_paths() {
        assert!(reopen_path_policy("/Applications/Slack.app").is_ok());
        assert!(reopen_path_policy("/System/Applications/Mail.app").is_ok());

        let err = reopen_path_policy("Applications/Slack.app").expect_err("relative");
        assert!(err.contains("not absolute"));

        let err = reopen_path_policy("/Applications/../Users/me/Evil.app").expect_err("traversal");
        assert!(err.contains("walks up"));

        let err = reopen_path_policy("/Users/me/Downloads/Evil.app").expect_err("outside");
        assert!(err.contains("/Applications"));

        let err = reopen_path_policy("/tmp/Evil.app").expect_err("outside");
        assert!(err.contains("/Applications"));

        let err = reopen_path_policy("/Applications/Slack.app/Contents/MacOS/Slack")
            .expect_err("not a bundle");
        assert!(err.contains("not an application bundle"));

        let err = reopen_path_policy("/Applications/Slack\n.app").expect_err("control char");
        assert!(err.contains("plain filesystem path"));
    }

    #[cfg(unix)]
    #[test]
    fn reopen_refuses_a_symlinked_bundle() {
        let root =
            std::env::temp_dir().join(format!("oniongate-reopen-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let real = root.join("Real.app");
        std::fs::create_dir_all(&real).expect("temp bundle");
        let link = root.join("Linked.app");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        assert!(reopen_target_on_disk(&real).is_ok());
        let err = reopen_target_on_disk(&link).expect_err("symlink");
        assert!(err.contains("symlink"), "{err}");

        // A plain file is not a bundle either.
        let file = root.join("Fake.app");
        std::fs::write(&file, b"not a bundle").expect("temp file");
        let err = reopen_target_on_disk(&file).expect_err("file");
        assert!(err.contains("not an application bundle"), "{err}");

        let err = reopen_target_on_disk(&root.join("Gone.app")).expect_err("missing");
        assert!(err.contains("no longer on disk"), "{err}");

        // Full validation refuses the temp tree outright: it is out of tree.
        let err = validate_reopen_target(&link.to_string_lossy()).expect_err("out of tree");
        assert!(err.contains("/Applications"), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reopen_summary_names_what_was_skipped_and_why() {
        assert_eq!(
            reopen_summary(&["Slack".into()], &[]),
            "Reopened 1 app(s) through Tor: Slack"
        );
        let summary = reopen_summary(
            &["Slack".into()],
            &["Evil — it is a symlink, and OnionGate will not follow one to launch an app".into()],
        );
        assert!(summary.contains("Reopened 1 app(s) through Tor: Slack"));
        assert!(summary.contains("skipped 1"));
        assert!(summary.contains("it is a symlink"));
        assert_eq!(
            reopen_summary(&[], &["Evil — it is not an application bundle".into()]),
            "Reopened nothing. skipped 1: Evil — it is not an application bundle"
        );
    }

    #[test]
    fn closed_rows_split_name_from_bundle_path() {
        let rows = split_closed_rows("Slack\t/Applications/Slack.app/\nDiscord\t\nNotes");
        assert_eq!(
            rows,
            vec![
                ("Slack".to_string(), "/Applications/Slack.app/".to_string()),
                ("Discord".to_string(), String::new()),
                ("Notes".to_string(), String::new()),
            ]
        );
    }
}
