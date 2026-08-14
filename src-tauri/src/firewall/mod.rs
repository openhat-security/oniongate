use serde::{Deserialize, Serialize};

pub mod strict;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub supported: bool,
    pub active: bool,
    pub verified_live: bool,
    pub marker_active: bool,
    pub strict_deny_live: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLockStatus {
    pub supported: bool,
    pub active: bool,
    pub verified_live: bool,
    pub marker_active: bool,
    pub detail: String,
}

pub fn status() -> FirewallStatus {
    #[cfg(target_os = "macos")]
    {
        return macos::status();
    }
    #[cfg(target_os = "linux")]
    {
        return linux::status();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::status();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        FirewallStatus {
            supported: false,
            active: false,
            verified_live: false,
            marker_active: false,
            strict_deny_live: false,
            detail: "Kill switch not supported on this OS".into(),
        }
    }
}

pub fn network_lock_status() -> NetworkLockStatus {
    #[cfg(target_os = "macos")]
    {
        return macos::network_lock_status();
    }
    #[cfg(target_os = "linux")]
    {
        return linux::network_lock_status();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::network_lock_status();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        NetworkLockStatus {
            supported: false,
            active: false,
            verified_live: false,
            marker_active: false,
            detail: "Network lock not supported on this OS".into(),
        }
    }
}

/// Steady-state kill switch: UDP/QUIC + IPv6, or the macOS default-deny NIC lock
/// when `strict_tcp_lock` is on.
pub async fn enable_kill_switch() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return macos::enable().await;
    }
    #[cfg(target_os = "linux")]
    {
        return linux::enable().await;
    }
    #[cfg(target_os = "windows")]
    {
        return windows::enable().await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Kill switch not supported on this OS".into())
    }
}

pub async fn disable_kill_switch() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return macos::disable().await;
    }
    #[cfg(target_os = "linux")]
    {
        return linux::disable().await;
    }
    #[cfg(target_os = "windows")]
    {
        return windows::disable().await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Kill switch not supported on this OS".into())
    }
}

/// Transition lock used while connecting, reconnecting, or tearing down.
/// Blocks clearnet UDP/QUIC and IPv6 on every platform; on Windows also blocks
/// clearnet TCP except the Tor binary so guards can still be reached.
pub async fn enable_network_lock() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return macos::enable_network_lock().await;
    }
    #[cfg(target_os = "linux")]
    {
        return linux::enable_network_lock().await;
    }
    #[cfg(target_os = "windows")]
    {
        return windows::enable_network_lock().await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Network lock not supported on this OS".into())
    }
}

pub async fn disable_network_lock() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return macos::disable_network_lock().await;
    }
    #[cfg(target_os = "linux")]
    {
        return linux::disable_network_lock().await;
    }
    #[cfg(target_os = "windows")]
    {
        return windows::disable_network_lock().await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Network lock not supported on this OS".into())
    }
}

/// Arm the transition lock and journal it. Fail closed: a requested lock that
/// cannot be applied is an error, not a silent continue onto clearnet.
pub async fn arm_for_transition() -> Result<String, String> {
    crate::session::expect_network_lock(true)?;
    match enable_network_lock().await {
        Ok(msg) => {
            crate::logs::append(&msg);
            Ok(msg)
        }
        Err(e) => {
            crate::logs::append(format!("Network lock failed: {e}"));
            let _ =
                crate::session::set_phase(crate::session::SessionPhase::Degraded, Some(e.clone()));
            Err(format!(
                "Could not lock the network before changing protection ({e}). \
                 Refusing to continue so traffic cannot leak during the transition."
            ))
        }
    }
}

/// Drop the transition lock after Protected steady-state rules are in place, or
/// after a clean disconnect. Always clears the journal expectation.
pub async fn disarm_after_transition() -> Result<String, String> {
    let status = network_lock_status();
    if !status.active && !status.marker_active && !crate::helper::client::available() {
        let _ = crate::session::expect_network_lock(false);
        return Ok("Network lock already clear".into());
    }
    match disable_network_lock().await {
        Ok(msg) => {
            let _ = crate::session::expect_network_lock(false);
            crate::logs::append(&msg);
            Ok(msg)
        }
        Err(e) => {
            crate::logs::append(format!("Network lock disable failed: {e}"));
            Err(e)
        }
    }
}

/// Reload the NIC lock when live Tor endpoints change; harvest pflog denies.
pub fn start_strict_watchdog() {
    std::thread::spawn(|| {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return,
        };
        rt.block_on(async {
            let mut last: Vec<String> = Vec::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                let settings = crate::settings::load();
                if !settings.strict_tcp_lock {
                    continue;
                }
                let phase = crate::session::load().phase;
                if phase != crate::session::SessionPhase::Protected
                    && phase != crate::session::SessionPhase::Connecting
                    && phase != crate::session::SessionPhase::Degraded
                {
                    continue;
                }
                #[cfg(target_os = "macos")]
                {
                    if let Ok(denies) = macos::harvest_denies().await {
                        let allow = crate::tor::endpoints::last_good_allowlist();
                        crate::deny_log::ingest(&denies, &allow);
                    }
                    let fw = macos::status();
                    if settings.strict_tcp_lock
                        && phase == crate::session::SessionPhase::Protected
                        && !fw.strict_deny_live
                    {
                        match enable_kill_switch().await {
                            Ok(_) => {}
                            Err(e) => {
                                crate::logs::append(format!(
                                    "NIC lock watchdog: live default-deny missing ({e})"
                                ));
                                let _ = crate::session::set_phase(
                                    crate::session::SessionPhase::Degraded,
                                    Some(
                                        "NIC lock is on but live pf default-deny is missing".into(),
                                    ),
                                );
                            }
                        }
                    }
                    if let Ok(next) = crate::tor::endpoints::current_allowlist(&settings).await {
                        let as_str: Vec<String> = next.iter().map(ToString::to_string).collect();
                        if as_str != last && !as_str.is_empty() {
                            last = as_str;
                            let _ = enable_kill_switch().await;
                        }
                    }
                }
            }
        });
    });
}
