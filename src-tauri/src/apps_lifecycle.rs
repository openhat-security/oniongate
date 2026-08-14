//! Best-effort quit of foreground user applications before a protected session.
//!
//! Closing apps is an OPSEC control, not a network guarantee. OnionGate never
//! force-kills itself, the shell used to launch it, or core OS UI processes.

use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::fs;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command as StdCommand;

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
            attempt if attempt.ok => killed.push(item),
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
}
