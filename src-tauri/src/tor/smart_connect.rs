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

/// Settings changes a Smart Connect attempt makes before restarting Tor. Pure
/// so the skip checks below see exactly what [`try_strategy`] will run.
fn apply_strategy(s: &mut settings::AppSettings, strategy: &str) {
    s.last_connect_strategy = strategy.into();
    match strategy {
        "direct" => s.bridges_enabled = false,
        "builtin:snowflake" => {
            s.bridges_enabled = true;
            s.bridge_source = "builtin:snowflake".into();
        }
        _ => s.bridges_enabled = !s.bridge_lines.is_empty(),
    }
}

/// Why Smart Connect should not try `strategy` at all, if anything.
///
/// - Under the macOS NIC lock, transports without a small IP allowlist are
///   refused ([`super::endpoints::strategy_blocks_strict_lock`]).
/// - Under any UDP-blocking lock (the transition lock Smart Connect always
///   runs inside, or the kill switch), Snowflake and meek can't resolve DNS or
///   send UDP, so trying them only burns the 75 s timeout
///   ([`super::endpoints::strategy_blocks_udp_lock`]).
fn skip_reason(
    original: &settings::AppSettings,
    strategy: &str,
    udp_lock_active: bool,
) -> Option<&'static str> {
    let mut probe = original.clone();
    apply_strategy(&mut probe, strategy);
    if original.strict_tcp_lock {
        if let Some(why) = super::endpoints::strategy_blocks_strict_lock(&probe) {
            return Some(why);
        }
    }
    super::endpoints::strategy_blocks_udp_lock(&probe, udp_lock_active)
}

/// Final error when every strategy failed or was skipped. Says plainly when
/// the lock is the reason Snowflake/meek were not tried.
fn all_failed_message(attempts: &[String], skipped_for_udp_lock: bool) -> String {
    let mut msg = format!(
        "All Smart Connect strategies failed: {}",
        attempts.join(" | ")
    );
    if skipped_for_udp_lock {
        msg.push_str(
            ". Snowflake/meek were skipped because the network lock blocks clearnet UDP \
             and DNS while connecting. Add obfs4 or vanilla bridges on the Bridges tab",
        );
    }
    msg
}

async fn try_strategy(
    managed: &mut Option<Child>,
    strategy: &str,
    timeout_secs: u64,
) -> Result<u32, String> {
    let next = settings::update(|s| apply_strategy(s, strategy))?;
    if next.strict_tcp_lock {
        crate::firewall::enable_network_lock()
            .await
            .map_err(|e| format!("NIC lock could not follow {strategy}: {e}"))?;
    }
    process::restart_managed(managed).await?;
    wait_bootstrap(timeout_secs).await
}

/// Strategies in the order Smart Connect tries them, with timeouts and the
/// reason recorded on success.
fn candidates(original: &settings::AppSettings) -> Vec<(&'static str, u64, &'static str)> {
    let mut out = vec![("direct", 25, "Direct Tor bootstrapped successfully")];
    if !original.bridge_lines.is_empty() {
        out.push((
            "bridges",
            55,
            "Direct Tor timed out; configured BridgeDB lines succeeded",
        ));
    }
    out.push((
        "builtin:snowflake",
        75,
        "Direct/configured routes timed out; bundled Snowflake succeeded",
    ));
    out
}

/// Try direct Tor, user-configured bridges, then the bundled Snowflake
/// transport. No bridge lines are fetched from third-party collectors.
pub async fn smart_connect(managed: &mut Option<Child>) -> Result<SmartConnectResult, String> {
    let original = settings::load();
    let key = network_key();
    let candidates = candidates(&original);

    // bring_up arms the transition lock before calling us, and the kill switch
    // may already be on for a reconnect. Read it live so a lock that failed to
    // arm (or was cleared) doesn't hide a strategy that would work.
    let udp_locked = crate::firewall::udp_lock_active();
    let mut attempts = Vec::new();
    let mut selected = None;
    let mut skipped_for_udp_lock = false;
    for (strategy, timeout_secs, reason) in candidates {
        if let Some(why) = skip_reason(&original, strategy, udp_locked) {
            if why == super::endpoints::SNOWFLAKE_UDP_LOCK_REASON
                || why == super::endpoints::MEEK_UDP_LOCK_REASON
            {
                skipped_for_udp_lock = true;
            }
            attempts.push(format!("{strategy}: skipped ({why})"));
            crate::logs::append(format!("Smart Connect skipped {strategy}: {why}"));
            continue;
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
        return Err(all_failed_message(&attempts, skipped_for_udp_lock));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::AppSettings;
    use crate::tor::endpoints::{MEEK_UDP_LOCK_REASON, SNOWFLAKE_UDP_LOCK_REASON};

    const OBFS4: &str = "Bridge obfs4 198.51.100.30:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";

    /// What the Censored Network preset leaves behind.
    fn censored_preset() -> AppSettings {
        let mut s = AppSettings::default();
        s.smart_connect = true;
        s.bridges_enabled = true;
        s.bridge_source = "builtin:snowflake".into();
        s.last_connect_strategy = "builtin:snowflake".into();
        s
    }

    /// The strategies Smart Connect would actually start Tor with.
    fn tried(original: &AppSettings, udp_lock_active: bool) -> Vec<&'static str> {
        candidates(original)
            .into_iter()
            .filter(|(strategy, _, _)| skip_reason(original, strategy, udp_lock_active).is_none())
            .map(|(strategy, _, _)| strategy)
            .collect()
    }

    #[test]
    fn candidates_try_direct_then_bridges_then_snowflake() {
        let mut s = AppSettings::default();
        let order: Vec<_> = candidates(&s).into_iter().map(|c| c.0).collect();
        assert_eq!(order, vec!["direct", "builtin:snowflake"]);
        s.bridge_lines = vec![OBFS4.into()];
        let order: Vec<_> = candidates(&s).into_iter().map(|c| c.0).collect();
        assert_eq!(order, vec!["direct", "bridges", "builtin:snowflake"]);
    }

    #[test]
    fn apply_strategy_matches_what_try_strategy_saves() {
        let mut s = censored_preset();
        apply_strategy(&mut s, "direct");
        assert!(!s.bridges_enabled);
        assert_eq!(s.last_connect_strategy, "direct");

        let mut s = AppSettings::default();
        apply_strategy(&mut s, "builtin:snowflake");
        assert!(s.bridges_enabled);
        assert_eq!(s.bridge_source, "builtin:snowflake");
        assert_eq!(s.last_connect_strategy, "builtin:snowflake");

        let mut s = AppSettings::default();
        apply_strategy(&mut s, "bridges");
        assert!(!s.bridges_enabled, "no lines, nothing to enable");
        s.bridge_lines = vec![OBFS4.into()];
        apply_strategy(&mut s, "bridges");
        assert!(s.bridges_enabled);
    }

    #[test]
    fn snowflake_is_skipped_under_udp_lock() {
        assert_eq!(
            skip_reason(&AppSettings::default(), "builtin:snowflake", true),
            Some(SNOWFLAKE_UDP_LOCK_REASON)
        );
    }

    #[test]
    fn snowflake_is_tried_without_udp_lock() {
        assert_eq!(
            skip_reason(&AppSettings::default(), "builtin:snowflake", false),
            None
        );
    }

    #[test]
    fn direct_is_never_skipped_for_the_udp_lock() {
        assert_eq!(skip_reason(&censored_preset(), "direct", true), None);
        assert_eq!(skip_reason(&AppSettings::default(), "direct", true), None);
    }

    #[test]
    fn censored_preset_under_udp_lock_tries_direct_only() {
        assert_eq!(tried(&censored_preset(), true), vec!["direct"]);
    }

    #[test]
    fn censored_preset_without_udp_lock_still_falls_back_to_snowflake() {
        assert_eq!(
            tried(&censored_preset(), false),
            vec!["direct", "builtin:snowflake"]
        );
    }

    #[test]
    fn saved_obfs4_bridges_are_still_tried_under_udp_lock() {
        let mut s = AppSettings::default();
        s.bridge_source = "custom".into();
        s.bridge_lines = vec![OBFS4.into()];
        assert_eq!(tried(&s, true), vec!["direct", "bridges"]);
        assert_eq!(
            tried(&s, false),
            vec!["direct", "bridges", "builtin:snowflake"]
        );
    }

    #[test]
    fn saved_snowflake_bridges_are_skipped_under_udp_lock() {
        let mut s = AppSettings::default();
        s.bridge_source = "transport:snowflake".into();
        s.bridge_lines = crate::tor::bridges::bundled_defaults("snowflake");
        assert_eq!(
            skip_reason(&s, "bridges", true),
            Some(SNOWFLAKE_UDP_LOCK_REASON)
        );
        assert_eq!(tried(&s, true), vec!["direct"]);
    }

    #[test]
    fn saved_meek_bridges_are_skipped_under_udp_lock() {
        let mut s = AppSettings::default();
        s.bridge_source = "transport:meek".into();
        s.bridge_lines = crate::tor::bridges::bundled_defaults("meek");
        assert_eq!(skip_reason(&s, "bridges", true), Some(MEEK_UDP_LOCK_REASON));
        assert_eq!(skip_reason(&s, "bridges", false), None);
    }

    #[test]
    fn strict_lock_still_skips_snowflake_without_udp_lock() {
        let mut s = AppSettings::default();
        s.strict_tcp_lock = true;
        assert!(skip_reason(&s, "builtin:snowflake", false).is_some());
        assert_ne!(
            skip_reason(&s, "builtin:snowflake", false),
            Some(SNOWFLAKE_UDP_LOCK_REASON),
            "strict refusal keeps its NIC-lock wording"
        );
        assert_eq!(skip_reason(&s, "direct", false), None);
    }

    #[test]
    fn skip_reason_does_not_mutate_saved_settings() {
        let s = censored_preset();
        let before = serde_json::to_string(&s).unwrap();
        let _ = skip_reason(&s, "direct", true);
        let _ = skip_reason(&s, "builtin:snowflake", true);
        assert_eq!(serde_json::to_string(&s).unwrap(), before);
    }

    #[test]
    fn all_failed_message_explains_udp_lock_skip() {
        let attempts = vec![
            "direct: Tor bootstrap timed out at 5%".to_string(),
            format!("builtin:snowflake: skipped ({SNOWFLAKE_UDP_LOCK_REASON})"),
        ];
        let msg = all_failed_message(&attempts, true);
        assert!(msg.starts_with("All Smart Connect strategies failed: direct:"));
        assert!(msg.contains("skipped because the network lock blocks clearnet UDP"));
        assert!(msg.contains("obfs4"));
    }

    #[test]
    fn all_failed_message_is_unchanged_without_udp_skip() {
        let attempts = vec![
            "direct: timed out".to_string(),
            "builtin:snowflake: timed out".to_string(),
        ];
        assert_eq!(
            all_failed_message(&attempts, false),
            "All Smart Connect strategies failed: direct: timed out | builtin:snowflake: timed out"
        );
    }
}
