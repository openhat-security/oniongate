//! Full session teardown so Disconnect / quit leave no lingering network state.

use std::sync::Mutex;
use std::time::Duration;

use tokio::process::Child;
use tokio::sync::Mutex as AsyncMutex;

use crate::firewall;
use crate::logs;
use crate::proxy::{self, SavedProxyState};
use crate::snowflake;
use crate::tor::{self, CONTROL_PORT, DNS_PORT, SOCKS_PORT};
use crate::tun;

async fn wait_ports_clear(timeout_ms: u64) -> bool {
    let steps = (timeout_ms / 150).max(1);
    for _ in 0..steps {
        if !tor::socks_reachable() && !tor::control_reachable() && !tor::dns_reachable() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    !tor::socks_reachable() && !tor::control_reachable()
}

async fn cleanup_orphan_pts() {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use tokio::process::Command;
        for name in [
            "lyrebird",
            "obfs4proxy",
            "conjure-client",
            "snowflake-client",
        ] {
            let _ = Command::new("pkill")
                .args(["-x", name])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }
    }
    #[cfg(target_os = "windows")]
    {
        use tokio::process::Command;
        for name in [
            "lyrebird.exe",
            "obfs4proxy.exe",
            "conjure-client.exe",
            "snowflake-client.exe",
        ] {
            let _ = Command::new("taskkill.exe")
                .args(["/IM", name, "/F"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }
    }
}

/// Tear down everything the app may have started for a session.
pub async fn teardown_session(
    managed_tor: &AsyncMutex<Option<Child>>,
    managed_singbox: &AsyncMutex<Option<Child>>,
    managed_snowflake: &AsyncMutex<Option<Child>>,
    saved_proxy: &Mutex<SavedProxyState>,
) -> Result<String, String> {
    let _ = crate::session::set_phase(crate::session::SessionPhase::Recovering, None);
    let mut parts = Vec::new();
    let mut errors = Vec::new();

    // 0) Lock clearnet BEFORE releasing Session Guard or dropping TUN — same
    //    posture as a VPN that blocks traffic while reconnecting/disconnecting.
    match firewall::arm_for_transition().await {
        Ok(msg) => {
            logs::append(&msg);
            parts.push(msg);
        }
        Err(e) => {
            logs::append(format!("Network lock before teardown failed: {e}"));
            errors.push(format!(
                "Could not lock the network before teardown ({e}); continuing carefully"
            ));
        }
    }

    // Suspended apps stay frozen until the lock is up, then we release them onto
    // a blocked network rather than onto a live clearnet path.
    crate::session_guard::release_all();

    // 1) TUN / sing-box (elevated stop if still running as root)
    {
        let mut sb = managed_singbox.lock().await;
        match tun::stop(&mut sb).await {
            Ok(msg) => {
                logs::append(&msg);
                parts.push(msg);
            }
            Err(e) => {
                logs::append(format!("TUN stop error: {e}"));
                errors.push(format!("TUN: {e}"));
            }
        }
        if tun::process_seems_running() {
            errors.push("sing-box still running after stop".into());
        }
    }

    // 2) Kill switch — always clear if we left a marker
    let firewall_status = firewall::status();
    if firewall_status.active || firewall_status.marker_active {
        match firewall::disable_kill_switch().await {
            Ok(msg) => {
                logs::append(&msg);
                parts.push(msg);
            }
            Err(e) => {
                logs::append(format!("Kill switch disable failed: {e}"));
                errors.push(format!(
                    "Kill switch may still be active (approve admin to clear): {e}"
                ));
            }
        }
    }

    // 3) System SOCKS — always restore on disconnect
    {
        let mut saved = saved_proxy
            .lock()
            .map_err(|_| "State lock poisoned".to_string())?;
        if saved.platform.is_empty() {
            if let Some(original) = crate::session::load().original_proxy {
                *saved = original;
            }
        }
        match proxy::disable(&mut saved) {
            Ok(msg) => {
                logs::append(&msg);
                parts.push(msg);
            }
            Err(e) => {
                logs::append(format!("Proxy restore failed: {e}"));
                errors.push(format!("Proxy: {e}"));
            }
        }
    }

    // 4) Snowflake volunteer
    {
        let mut sf = managed_snowflake.lock().await;
        match snowflake::stop(&mut sf).await {
            Ok(msg) if msg.to_ascii_lowercase().contains("stopped") => {
                logs::append(&msg);
                parts.push(msg);
            }
            _ => {}
        }
    }

    // 5) Temporary onion sites (destroy before the control port closes).
    //    Permanent sites live in torrc and are meant to survive this.
    crate::onion_service::stop_all_temporary().await;

    // 6) Tor
    {
        let mut tor_child = managed_tor.lock().await;
        match tor::stop_tor(&mut tor_child).await {
            Ok(msg) => {
                logs::append(&msg);
                parts.push(msg);
            }
            Err(e) => {
                logs::append(format!("Tor stop error: {e}"));
                errors.push(format!("Tor: {e}"));
            }
        }
    }

    // 7) Orphaned PT clients
    cleanup_orphan_pts().await;

    // 8) Ports released?
    if !wait_ports_clear(3000).await {
        let linger = format!(
            "Ports still busy (SOCKS {SOCKS_PORT}={} CTRL {CONTROL_PORT}={} DNS {DNS_PORT}={})",
            tor::socks_reachable(),
            tor::control_reachable(),
            tor::dns_reachable()
        );
        logs::append(&linger);
        errors.push(linger);
    }

    // 9) Clear the transition lock last — only after Tor/TUN/proxy are gone so
    //    nothing can race onto clearnet during teardown.
    match firewall::disarm_after_transition().await {
        Ok(msg) => {
            logs::append(&msg);
            parts.push(msg);
        }
        Err(e) => {
            logs::append(format!("Network lock clear failed: {e}"));
            errors.push(format!(
                "Network lock may still be active (approve admin to clear): {e}"
            ));
        }
    }

    if errors.is_empty() {
        crate::session::clear()?;
        let summary = if parts.is_empty() {
            "Already clean — nothing to stop".into()
        } else {
            format!("Disconnected and cleaned up. {}", parts.join(" · "))
        };
        logs::append(&summary);
        Ok(summary)
    } else {
        let _ = crate::session::set_phase(
            crate::session::SessionPhase::Degraded,
            Some(errors.join("; ")),
        );
        Err(format!(
            "Cleanup finished with leftovers: {}. Done: {}",
            errors.join("; "),
            parts.join(" · ")
        ))
    }
}

/// Best-effort sync wrapper for process exit.
pub fn teardown_session_blocking(
    managed_tor: &AsyncMutex<Option<Child>>,
    managed_singbox: &AsyncMutex<Option<Child>>,
    managed_snowflake: &AsyncMutex<Option<Child>>,
    saved_proxy: &Mutex<SavedProxyState>,
) {
    let _ = tauri::async_runtime::block_on(teardown_session(
        managed_tor,
        managed_singbox,
        managed_snowflake,
        saved_proxy,
    ));
}
