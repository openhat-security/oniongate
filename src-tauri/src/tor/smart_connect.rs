//! Smart Connect: bootstrap Tor using the user's current settings.
//! Bridges are configured only on the Bridges tab — this path never fetches,
//! races, or changes bridge preferences.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Child;

use crate::settings;

use super::control;
use super::process;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartConnectResult {
    pub message: String,
    pub strategy: String,
    pub reason: String,
    pub attempts: Vec<String>,
    pub network_key: String,
    pub bootstrap_progress: u32,
}

/// Best-effort network fingerprint (default gateway).
pub fn network_key() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if let Some(gw) = line.trim().strip_prefix("gateway:") {
                    return format!("gw:{}", gw.trim());
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(via) = text.split_whitespace().nth(2) {
                return format!("gw:{via}");
            }
        }
    }
    "unknown".into()
}

async fn wait_bootstrap(timeout_secs: u64) -> Result<u32, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut last = 0u32;
    while tokio::time::Instant::now() < deadline {
        if let Ok(p) = control::bootstrap_progress().await {
            last = p;
            if p >= 100 {
                return Ok(p);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if last >= 100 {
        Ok(last)
    } else {
        Err(format!(
            "Tor bootstrap timed out at {last}% (check network, or configure bridges on the Bridges tab if Tor is blocked)"
        ))
    }
}

async fn try_strategy(
    managed: &mut Option<Child>,
    strategy: &str,
    timeout_secs: u64,
) -> Result<u32, String> {
    let next = settings::update(|s| {
        s.last_connect_strategy = strategy.into();
        match strategy {
            "direct" => s.bridges_enabled = false,
            "builtin:snowflake" => {
                s.bridges_enabled = true;
                s.bridge_source = "builtin:snowflake".into();
            }
            _ => s.bridges_enabled = !s.bridge_lines.is_empty(),
        }
    })?;
    if next.strict_tcp_lock {
        crate::firewall::enable_network_lock()
            .await
            .map_err(|e| format!("NIC lock could not follow {strategy}: {e}"))?;
    }
    process::restart_managed(managed).await?;
    wait_bootstrap(timeout_secs).await
}

/// Try direct Tor, user-configured bridges, then the bundled Snowflake
/// transport. No bridge lines are fetched from third-party collectors.
pub async fn smart_connect(managed: &mut Option<Child>) -> Result<SmartConnectResult, String> {
    let original = settings::load();
    let key = network_key();
    let mut candidates = vec![("direct", 25, "Direct Tor bootstrapped successfully")];
    if !original.bridge_lines.is_empty() {
        candidates.push((
            "bridges",
            55,
            "Direct Tor timed out; configured BridgeDB lines succeeded",
        ));
    }
    candidates.push((
        "builtin:snowflake",
        75,
        "Direct/configured routes timed out; bundled Snowflake succeeded",
    ));

    let mut attempts = Vec::new();
    let mut selected = None;
    for (strategy, timeout_secs, reason) in candidates {
        if original.strict_tcp_lock {
            let mut probe = original.clone();
            probe.last_connect_strategy = strategy.to_string();
            if strategy == "builtin:snowflake" {
                probe.bridge_source = "builtin:snowflake".into();
                probe.bridges_enabled = true;
            }
            if let Some(why) = super::endpoints::strategy_blocks_strict_lock(&probe) {
                attempts.push(format!("{strategy}: skipped ({why})"));
                crate::logs::append(format!("Smart Connect skipped {strategy}: {why}"));
                continue;
            }
        }
        crate::logs::append(format!(
            "Smart Connect: network={key} trying={strategy} timeout={timeout_secs}s"
        ));
        match try_strategy(managed, strategy, timeout_secs).await {
            Ok(progress) => {
                attempts.push(format!("{strategy}: success ({progress}%)"));
                selected = Some((strategy.to_string(), reason.to_string(), progress));
                break;
            }
            Err(error) => {
                attempts.push(format!("{strategy}: {error}"));
                crate::logs::append(format!("Smart Connect {strategy} failed: {error}"));
                let _ = process::stop_tor(managed).await;
            }
        }
    }

    let Some((strategy, reason, progress)) = selected else {
        settings::save(&original)?;
        return Err(format!(
            "All Smart Connect strategies failed: {}",
            attempts.join(" | ")
        ));
    };

    let current = settings::update(|s| {
        s.last_connect_strategy = strategy.clone();
        s.last_network_key = key.clone();
        s.last_connect_reason = reason.clone();
    })?;
    let _ = crate::db::start_session(&strategy, &current.connection_mode);

    Ok(SmartConnectResult {
        message: format!("Connected via {strategy} (bootstrap {progress}%)"),
        strategy,
        reason,
        attempts,
        network_key: key,
        bootstrap_progress: progress,
    })
}
