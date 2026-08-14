//! Fail-closed guard for explicitly selected applications.
//!
//! A full application firewall requires platform entitlements. Until that
//! boundary exists, Session Guard suspends selected processes with SIGSTOP if
//! their TUN-to-Tor route disappears, then resumes only the PIDs it suspended.

use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

static SUSPENDED: LazyLock<Mutex<HashSet<u32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn pids_for(app: &crate::settings::AppIdentity) -> Vec<u32> {
    let output = if !app.executable_path.is_empty() {
        Command::new("pgrep")
            .args(["-f", &app.executable_path])
            .output()
    } else {
        Command::new("pgrep")
            .args(["-x", &app.process_name])
            .output()
    };
    output
        .ok()
        .filter(|result| result.status.success())
        .map(|result| {
            String::from_utf8_lossy(&result.stdout)
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .filter(|pid| *pid != std::process::id())
                .collect()
        })
        .unwrap_or_default()
}

fn signal(pid: u32, name: &str) -> bool {
    Command::new("kill")
        .args([name, &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn suspend_selected() {
    let settings = crate::settings::load();
    if !settings.session_guard || settings.route_apps.is_empty() {
        release_all();
        return;
    }
    let mut suspended = match SUSPENDED.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    for app in &settings.route_apps {
        for pid in pids_for(app) {
            if !suspended.contains(&pid) && signal(pid, "-STOP") {
                suspended.insert(pid);
                crate::logs::append(format!(
                    "Session Guard suspended {} (pid {pid}) after Tor route loss",
                    app.label
                ));
            }
        }
    }
}

pub fn release_all() {
    let Ok(mut suspended) = SUSPENDED.lock() else {
        return;
    };
    for pid in suspended.drain() {
        let _ = signal(pid, "-CONT");
    }
}

pub fn start_monitor() {
    tauri::async_runtime::spawn(async {
        loop {
            let settings = crate::settings::load();
            let session_active =
                crate::session::load().phase != crate::session::SessionPhase::Disconnected;
            if settings.session_guard && settings.split_tunnel && session_active {
                let protected =
                    crate::tor::socks_reachable() && crate::tun::process_seems_running();
                if protected {
                    release_all();
                } else {
                    suspend_selected();
                }
            } else {
                release_all();
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}
