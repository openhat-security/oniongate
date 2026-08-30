//! Shared protected-session bring-up used by the GUI and the CLI.
//!
//! Do not grow a second connect sequence. [`bring_up`] is the only path that
//! may report Protected.

use std::sync::Mutex;

use tokio::process::Child;
use tokio::sync::Mutex as AsyncMutex;

use crate::proxy::{self, SavedProxyState};
use crate::settings;
use crate::tor;

pub async fn bring_up(
    managed_tor: &AsyncMutex<Option<Child>>,
    managed_singbox: &AsyncMutex<Option<Child>>,
    saved_proxy: &Mutex<SavedProxyState>,
) -> Result<String, String> {
    let settings = settings::load();
    if settings.strict_tcp_lock {
        if let Some(reason) = tor::endpoints::strategy_blocks_strict_lock(&settings) {
            return Err(reason.into());
        }
        let vpn = crate::vpn_detect::detect();
        if vpn.active {
            return Err(format!("NIC lock refuses a competing VPN ({})", vpn.detail));
        }
        if cfg!(not(target_os = "macos")) {
            return Err("The default-deny NIC lock is macOS-only".into());
        }
    }
    crate::session::begin_connect()?;
    let filter = crate::ne_filter::status();
    crate::session::expect_connection_filter(settings.connection_filter && filter.installed)?;
    // Fail closed during the whole bootstrap/TUN/proxy bring-up window — same
    // idea as a VPN that blocks traffic while reconnecting.
    let lock_msg = crate::firewall::arm_for_transition().await?;
    crate::session::expect_transports(
        tor::pt::transports_from_bridge_lines(&settings.bridge_lines)
            .into_iter()
            .map(|transport| transport.as_str().to_string())
            .collect(),
    )?;
    let msg = {
        let mut guard = managed_tor.lock().await;
        let started = if settings.smart_connect {
            let result = tor::smart_connect(&mut guard).await;
            result.map(|r| r.message)
        } else {
            let m = tor::start_tor(&mut guard).await;
            if m.is_ok() {
                let strat = if settings.bridges_enabled {
                    "bridges"
                } else {
                    "direct"
                };
                let _ = crate::db::start_session(strat, &settings.connection_mode);
            }
            m
        };
        match started {
            Ok(message) => message,
            Err(e) => {
                // Keep the lock on failure so clearnet does not reopen while the
                // user is still in a Connecting/Degraded journal state. They can
                // Disconnect / Emergency Restore to clear it.
                let _ = crate::session::set_phase(
                    crate::session::SessionPhase::Degraded,
                    Some(e.clone()),
                );
                return Err(e);
            }
        }
    };
    crate::logs::append(&msg);

    let mut parts = vec![lock_msg, msg];

    if settings.connection_mode == "tun" {
        crate::session::expect_tun(true)?;
        let mut sb = managed_singbox.lock().await;
        match crate::tun::start(&mut sb).await {
            Ok(tmsg) => {
                crate::logs::append(&tmsg);
                parts.push(tmsg);
            }
            Err(e) => {
                crate::logs::append(format!("TUN start failed: {e}"));
                // Fail closed: do not report a successful "connect" in TUN mode.
                let _ = settings::update(|s| s.connection_mode = "proxy".into());
                let _ = crate::tun::stop(&mut sb).await;
                let _ = crate::session::set_phase(
                    crate::session::SessionPhase::Degraded,
                    Some(e.clone()),
                );
                return Err(format!(
                    "Tor is up, but TUN was not started ({e}). Switched back to Proxy mode. \
                     Network stays locked until you disconnect."
                ));
            }
        }
        if settings.kill_switch {
            crate::session::expect_firewall(true)?;
            match crate::firewall::enable_kill_switch().await {
                Ok(kmsg) => {
                    crate::logs::append(&kmsg);
                    parts.push(kmsg);
                }
                Err(e) => {
                    crate::logs::append(format!("Required kill switch failed: {e}"));
                    let _ = crate::session::set_phase(
                        crate::session::SessionPhase::Degraded,
                        Some(e.clone()),
                    );
                    return Err(format!(
                        "Tor and TUN are up, but the requested kill switch was not verified ({e}). \
                         The session is degraded; retry the kill switch or disconnect."
                    ));
                }
            }
        }
        // Steady-state containment is TUN (+ optional KS). Drop the transition lock.
        match crate::firewall::disarm_after_transition().await {
            Ok(msg) => parts.push(msg),
            Err(e) => {
                crate::logs::append(format!("Network lock release failed: {e}"));
                parts.push(format!(
                    "Protected, but the transition lock could not be cleared ({e})"
                ));
            }
        }
        finish_protected()?;
        return Ok(parts.join(". "));
    }

    let result = maybe_auto_enable_proxy(saved_proxy, parts.join(". ")).await;
    let result = match result {
        Ok(message) if settings.kill_switch => {
            crate::session::expect_firewall(true)?;
            match crate::firewall::enable_kill_switch().await {
                Ok(kill_switch) => Ok(format!("{message}. {kill_switch}")),
                Err(error) => Err(format!(
                    "Tor started, but the requested kill switch was not verified ({error})"
                )),
            }
        }
        other => other,
    };
    match &result {
        Ok(message) => match crate::firewall::disarm_after_transition().await {
            Ok(unlocked) => {
                finish_protected()?;
                Ok(format!("{message}. {unlocked}"))
            }
            Err(e) => {
                finish_protected()?;
                Ok(format!(
                    "{message}. Protected, but the transition lock could not be cleared ({e})"
                ))
            }
        },
        Err(error) => {
            let _ = crate::session::set_phase(
                crate::session::SessionPhase::Degraded,
                Some(error.clone()),
            );
            Err(error.clone())
        }
    }
}

pub fn finish_protected() -> Result<(), String> {
    let settings = settings::load();
    if settings.strict_tcp_lock {
        let fw = crate::firewall::status();
        if !fw.strict_deny_live {
            return crate::session::set_phase(
                crate::session::SessionPhase::Degraded,
                Some("NIC lock is on but live pf default-deny was not verified".into()),
            );
        }
        if !settings.strict_tcp_exceptions.is_empty() {
            return crate::session::set_phase(
                crate::session::SessionPhase::Degraded,
                Some("NIC lock has destination exceptions (machine-wide leak)".into()),
            );
        }
    }
    if settings.connection_mode == "proxy" && !settings.strict_tcp_lock {
        let bypassers = crate::detect::uncontained_proxy_bypassers();
        if !bypassers.is_empty() {
            let names = bypassers
                .iter()
                .map(|app| app.title.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return crate::session::set_phase(
                crate::session::SessionPhase::Degraded,
                Some(format!(
                    "Proxy mode cannot contain {names}. Quit them, apply Apps helpers, or use TUN / NIC lock"
                )),
            );
        }
    }
    let filter = crate::ne_filter::status();
    if let Err(e) = crate::ne_filter::protect_gate(
        filter.installed,
        filter.running,
        filter.unseen_bypass,
        settings.connection_filter,
    ) {
        return crate::session::set_phase(crate::session::SessionPhase::Degraded, Some(e));
    }
    crate::session::set_phase(crate::session::SessionPhase::Protected, None)
}

async fn maybe_auto_enable_proxy(
    saved_proxy: &Mutex<SavedProxyState>,
    msg: String,
) -> Result<String, String> {
    let settings = settings::load();
    // System proxy mode cannot work without OS SOCKS. The toggle only opts
    // other modes into also applying SOCKS; a false value must not skip proxy mode.
    let must_enable = settings.connection_mode == "proxy" || settings.auto_enable_proxy;
    if !must_enable {
        return Ok(msg);
    }
    if !tor::socks_reachable() {
        return Err(format!(
            "{msg}. System SOCKS was not applied: Tor's local SOCKS listener is not reachable"
        ));
    }
    let mut saved = saved_proxy
        .lock()
        .map_err(|_| "State lock poisoned".to_string())?;
    if crate::session::load().original_proxy.is_none() {
        let snapshot = proxy::capture()?;
        crate::session::record_proxy_before(snapshot.clone())?;
        *saved = snapshot;
    }
    match proxy::enable(&mut saved) {
        Ok(pmsg) => {
            crate::logs::append(&pmsg);
            Ok(format!("{msg}. {pmsg}"))
        }
        Err(e) => {
            crate::logs::append(format!("Auto-enable proxy failed: {e}"));
            Err(format!(
                "{msg}. Requested system proxy was not enabled: {e}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::detect::ProxyBypassApp;

    #[test]
    fn bypass_reason_lists_running_apps() {
        let apps = [
            ProxyBypassApp {
                id: "chrome".into(),
                title: "Google Chrome".into(),
            },
            ProxyBypassApp {
                id: "slack".into(),
                title: "Slack".into(),
            },
        ];
        let names = apps
            .iter()
            .map(|app| app.title.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let reason = format!(
            "Proxy mode cannot contain {names}. Quit them, apply Apps helpers, or use TUN / NIC lock"
        );
        assert!(reason.contains("Google Chrome"));
        assert!(reason.contains("Slack"));
        assert!(reason.contains("TUN"));
    }
}
