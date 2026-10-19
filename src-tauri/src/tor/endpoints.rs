//! Tor transport allowlist for the macOS NIC lock.
//!
//! Addresses stay memory-only and are never written to logs.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};

use crate::settings::AppSettings;

use super::bridges::describe_bridge;
use super::control;
use super::process::ensure_data_dir;

/// Directory authorities shipped with current Tor (IPv4 + IPv6). Used only to
/// close the bootstrap window before live OR connections exist.
const DIRAITH_IPS: &[&str] = &[
    "128.31.0.39",
    "217.196.147.77",
    "2a02:16a8:662:2203::1",
    "45.66.35.11",
    "131.188.40.189",
    "2001:638:a000:4140::ffff:189",
    "193.23.244.244",
    "2001:678:558:1000::244",
    "171.25.193.9",
    "2001:67c:289c::9",
    "199.58.81.140",
    "204.13.164.118",
    "2620:13:4000::1",
    "216.218.219.41",
];

static LAST_GOOD: OnceLock<Mutex<Vec<IpAddr>>> = OnceLock::new();

fn last_good() -> &'static Mutex<Vec<IpAddr>> {
    LAST_GOOD.get_or_init(|| Mutex::new(Vec::new()))
}

fn remember(ips: &[IpAddr]) {
    if ips.is_empty() {
        return;
    }
    if let Ok(mut guard) = last_good().lock() {
        *guard = ips.to_vec();
    }
}

pub fn last_good_allowlist() -> Vec<IpAddr> {
    last_good().lock().map(|g| g.clone()).unwrap_or_default()
}

pub fn strategy_blocks_strict_lock(settings: &AppSettings) -> Option<&'static str> {
    let hay = format!(
        "{} {} {}",
        settings.last_connect_strategy,
        settings.bridge_source,
        settings.bridge_lines.join(" ")
    )
    .to_ascii_lowercase();
    if hay.contains("snowflake") {
        return Some("Snowflake has no small IP allowlist; the NIC lock cannot be used");
    }
    if hay.contains("meek") {
        return Some("meek has no small IP allowlist; the NIC lock cannot be used");
    }
    if hay.contains("webtunnel") {
        for line in &settings.bridge_lines {
            let info = describe_bridge(line);
            if info.transport.to_ascii_lowercase().contains("webtunnel") {
                if let Some(ep) = &info.endpoint {
                    if crate::firewall::strict::parse_ip(host_from_endpoint(ep).unwrap_or(ep))
                        .is_err()
                    {
                        return Some(
                            "hostname-fronted WebTunnel cannot be a small IP allowlist; the NIC lock cannot be used",
                        );
                    }
                }
            }
        }
    }
    None
}

/// Why Snowflake can't run under a UDP-blocking lock. Shared by Smart Connect
/// (skip) and the explicit-start paths (refuse).
pub const SNOWFLAKE_UDP_LOCK_REASON: &str = "Snowflake needs clearnet DNS and WebRTC/UDP, \
and the network lock drops all clearnet UDP";
/// Why meek can't run under a UDP-blocking lock.
pub const MEEK_UDP_LOCK_REASON: &str =
    "meek needs clearnet DNS for its front domain, and the network lock drops all clearnet UDP";

/// Does this attempt need a transport that can't bootstrap while outbound
/// UDP is dropped?
///
/// The transition lock (`firewall::arm_for_transition`) and the UDP kill
/// switch drop every clearnet UDP packet, DNS included, on Linux, macOS and
/// Windows. Tor itself only dials relay IPs over TCP, so direct Tor, vanilla
/// and obfs4 bridges still work. Snowflake's client has to resolve its broker
/// and front domains and then speak WebRTC over UDP; meek has to resolve its
/// front domain. Both stall at ~10% with `write: operation not permitted`.
///
/// `udp_lock_active` is passed in rather than read here so callers decide
/// whether the lock *is* live (Smart Connect) or *will be* armed (bring-up),
/// and so this stays testable without nftables or pf.
///
/// Looks only at the bridge lines Tor will actually load
/// ([`super::process::active_bridge_lines`]), so a `direct` attempt with
/// leftover Snowflake settings is not blocked.
pub fn strategy_blocks_udp_lock(
    settings: &AppSettings,
    udp_lock_active: bool,
) -> Option<&'static str> {
    if !udp_lock_active {
        return None;
    }
    let lines = super::process::active_bridge_lines(settings);
    let transports = super::pt::transports_from_bridge_lines(&lines);
    if transports.contains(&super::pt::Transport::Snowflake) {
        return Some(SNOWFLAKE_UDP_LOCK_REASON);
    }
    if transports.contains(&super::pt::Transport::Meek) {
        return Some(MEEK_UDP_LOCK_REASON);
    }
    None
}

fn host_from_endpoint(endpoint: &str) -> Option<&str> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split_once(']').map(|(h, _)| h);
    }
    endpoint.split(':').next()
}

pub fn ip_from_endpoint(endpoint: &str) -> Option<IpAddr> {
    let host = host_from_endpoint(endpoint)?;
    crate::firewall::strict::parse_ip(host).ok()
}

pub fn bridge_ips(settings: &AppSettings) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in &settings.bridge_lines {
        let info = describe_bridge(line);
        if let Some(ep) = &info.endpoint {
            if let Some(ip) = ip_from_endpoint(ep) {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

pub fn dirauth_ips() -> Vec<IpAddr> {
    DIRAITH_IPS.iter().filter_map(|s| s.parse().ok()).collect()
}

pub fn cached_guard_ips() -> Vec<IpAddr> {
    let Ok(dir) = ensure_data_dir() else {
        return Vec::new();
    };
    let path = dir.join("tor-data").join("state");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_state_guard_ips(&text)
}

fn parse_state_guard_ips(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("guard") && !lower.contains("entryguard") {
            continue;
        }
        for token in line.split_whitespace() {
            let candidate = token
                .trim_matches(|c: char| c == '"' || c == ',')
                .split('=')
                .last()
                .unwrap_or(token);
            let host = if let Ok(addr) = candidate.parse::<SocketAddr>() {
                addr.ip()
            } else if let Some(ip) = ip_from_endpoint(candidate) {
                ip
            } else {
                continue;
            };
            if crate::firewall::strict::parse_ip(&host.to_string()).is_ok() && !out.contains(&host)
            {
                out.push(host);
            }
        }
    }
    out
}

/// Allowlist used *before* Tor's first packet: bridges, else dirauths + cached guards.
pub fn bootstrap_allowlist(settings: &AppSettings) -> Result<Vec<IpAddr>, String> {
    if let Some(reason) = strategy_blocks_strict_lock(settings) {
        return Err(reason.into());
    }
    // Only pin the lock to configured bridges when this attempt actually uses
    // them. Smart Connect's "direct" try used to inherit leftover bridge IPs
    // and then time out against a lock that blocked every directory authority.
    let using_bridges = settings.bridges_enabled
        && !settings.bridge_lines.is_empty()
        && settings.last_connect_strategy != "direct";
    let mut ips = if using_bridges {
        bridge_ips(settings)
    } else {
        Vec::new()
    };
    if ips.is_empty() {
        ips.extend(dirauth_ips());
        for ip in cached_guard_ips() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips.truncate(crate::firewall::strict::MAX_ENDPOINTS);
    if ips.is_empty() {
        return Err("could not build a Tor endpoint allowlist before connecting".into());
    }
    remember(&ips);
    Ok(ips)
}

pub fn parse_orconn_status(raw: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in raw.lines() {
        let t = line
            .trim()
            .strip_prefix("250+orconn-status=")
            .or_else(|| line.trim().strip_prefix("250-orconn-status="))
            .unwrap_or(line.trim());
        if t == "." || t.starts_with("250 ") || t.is_empty() {
            continue;
        }
        if !t.to_ascii_uppercase().contains("CONNECTED") {
            continue;
        }
        if let Some(id) = t.split_whitespace().next() {
            let id = id.trim_start_matches('$').split('~').next().unwrap_or(id);
            if id.len() >= 16 {
                ids.push(id.to_string());
            }
        }
    }
    ids
}

pub fn parse_ns_router_ip(raw: &str) -> Option<IpAddr> {
    for line in raw.lines() {
        for token in line.split_whitespace() {
            let token = token.trim_start_matches("250+").trim_start_matches("250-");
            if let Ok(ip) = crate::firewall::strict::parse_ip(token) {
                return Some(ip);
            }
        }
    }
    None
}

/// Live OR connection IPs from the control port. Empty if Tor is not up yet.
pub async fn live_transport_ips() -> Vec<IpAddr> {
    let Ok(reply) = control::run_authenticated(&["GETINFO orconn-status"]).await else {
        return Vec::new();
    };
    let ids = parse_orconn_status(&reply.raw);
    let mut ips = Vec::new();
    for id in ids {
        let cmd = format!("GETINFO ns/id/{id}");
        if let Ok(ns) = control::run_authenticated(&[cmd.as_str()]).await {
            if let Some(ip) = parse_ns_router_ip(&ns.raw) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    if !ips.is_empty() {
        remember(&ips);
    }
    ips
}

/// Prefer live guards; otherwise last good; otherwise bootstrap set.
pub async fn current_allowlist(settings: &AppSettings) -> Result<Vec<IpAddr>, String> {
    if let Some(reason) = strategy_blocks_strict_lock(settings) {
        return Err(reason.into());
    }
    let live = live_transport_ips().await;
    if !live.is_empty() {
        return Ok(live);
    }
    let last = last_good_allowlist();
    if !last.is_empty() {
        return Ok(last);
    }
    bootstrap_allowlist(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orconn_parser_reads_connected_fingerprints() {
        let raw = "250+orconn-status=\n$ABCDEFFEDCBAABCDEFFEDCBAABCDEFFEDCBAABCD~moria CONNECTED\n.\n250 OK\n";
        let ids = parse_orconn_status(raw);
        assert_eq!(ids, vec!["ABCDEFFEDCBAABCDEFFEDCBAABCDEFFEDCBAABCD"]);
    }

    #[test]
    fn ns_parser_reads_router_ip() {
        let raw = "250+ns/id/ABC=\nr moria1 ABCDEF PUB 2024-01-01 00:00:00 128.31.0.39 9131 9132\n.\n250 OK\n";
        assert_eq!(parse_ns_router_ip(raw).unwrap().to_string(), "128.31.0.39");
    }

    #[test]
    fn snowflake_is_refused() {
        let mut s = AppSettings::default();
        s.last_connect_strategy = "builtin:snowflake".into();
        assert!(strategy_blocks_strict_lock(&s).is_some());
    }

    const OBFS4: &str = "Bridge obfs4 198.51.100.30:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
    const VANILLA: &str = "Bridge 198.51.100.20:443 0123456789ABCDEF0123456789ABCDEF01234567";

    fn with_lines(strategy: &str, lines: Vec<String>) -> AppSettings {
        let mut s = AppSettings::default();
        s.bridges_enabled = true;
        s.bridge_source = "custom".into();
        s.last_connect_strategy = strategy.into();
        s.bridge_lines = lines;
        s
    }

    fn smart_snowflake() -> AppSettings {
        let mut s = AppSettings::default();
        s.bridges_enabled = true;
        s.bridge_source = "builtin:snowflake".into();
        s.last_connect_strategy = "builtin:snowflake".into();
        s
    }

    #[test]
    fn snowflake_is_refused_under_udp_lock() {
        assert_eq!(
            strategy_blocks_udp_lock(&smart_snowflake(), true),
            Some(SNOWFLAKE_UDP_LOCK_REASON)
        );
    }

    #[test]
    fn snowflake_is_allowed_without_udp_lock() {
        assert_eq!(strategy_blocks_udp_lock(&smart_snowflake(), false), None);
    }

    #[test]
    fn saved_snowflake_bridge_lines_are_refused_under_udp_lock() {
        let s = with_lines(
            "bridges",
            crate::tor::bridges::bundled_defaults("snowflake"),
        );
        assert_eq!(
            strategy_blocks_udp_lock(&s, true),
            Some(SNOWFLAKE_UDP_LOCK_REASON)
        );
        assert_eq!(strategy_blocks_udp_lock(&s, false), None);
    }

    #[test]
    fn meek_is_refused_under_udp_lock() {
        let s = with_lines("bridges", crate::tor::bridges::bundled_defaults("meek"));
        assert_eq!(
            strategy_blocks_udp_lock(&s, true),
            Some(MEEK_UDP_LOCK_REASON)
        );
    }

    #[test]
    fn meek_is_allowed_without_udp_lock() {
        let s = with_lines("bridges", crate::tor::bridges::bundled_defaults("meek"));
        assert_eq!(strategy_blocks_udp_lock(&s, false), None);
    }

    #[test]
    fn meek_token_spelled_meek_is_refused_too() {
        let s = with_lines(
            "bridges",
            vec![
                "Bridge meek 192.0.2.20:80 url=https://example.invalid/ front=www.example.com"
                    .into(),
            ],
        );
        assert_eq!(
            strategy_blocks_udp_lock(&s, true),
            Some(MEEK_UDP_LOCK_REASON)
        );
    }

    #[test]
    fn mixed_lines_with_one_snowflake_are_refused() {
        // Tor launches every transport in the torrc, so one Snowflake line is
        // enough to need UDP.
        let mut lines = vec![OBFS4.to_string()];
        lines.extend(crate::tor::bridges::bundled_defaults("snowflake"));
        let s = with_lines("bridges", lines);
        assert_eq!(
            strategy_blocks_udp_lock(&s, true),
            Some(SNOWFLAKE_UDP_LOCK_REASON)
        );
    }

    #[test]
    fn snowflake_wins_over_meek_when_both_are_loaded() {
        let mut lines = crate::tor::bridges::bundled_defaults("meek");
        lines.extend(crate::tor::bridges::bundled_defaults("snowflake"));
        let s = with_lines("bridges", lines);
        assert_eq!(
            strategy_blocks_udp_lock(&s, true),
            Some(SNOWFLAKE_UDP_LOCK_REASON)
        );
    }

    #[test]
    fn tcp_only_transports_are_allowed_under_udp_lock() {
        for line in [OBFS4, VANILLA] {
            let s = with_lines("bridges", vec![line.to_string()]);
            assert_eq!(strategy_blocks_udp_lock(&s, true), None, "{line}");
        }
    }

    #[test]
    fn direct_with_leftover_snowflake_source_is_allowed_under_udp_lock() {
        // Censored Network preset leaves bridge_source=builtin:snowflake, but
        // Smart Connect's direct try turns bridges off. That try must not be
        // blocked by the leftover setting.
        let mut s = smart_snowflake();
        s.last_connect_strategy = "direct".into();
        s.bridges_enabled = false;
        assert_eq!(strategy_blocks_udp_lock(&s, true), None);
    }

    #[test]
    fn disabled_bridges_with_snowflake_lines_are_allowed_under_udp_lock() {
        let mut s = with_lines(
            "bridges",
            crate::tor::bridges::bundled_defaults("snowflake"),
        );
        s.bridges_enabled = false;
        assert_eq!(strategy_blocks_udp_lock(&s, true), None);
    }

    #[test]
    fn builtin_snowflake_strategy_overrides_saved_obfs4_lines() {
        // process::write_managed_torrc swaps in bundled Snowflake for this
        // strategy, so the check has to as well.
        let s = with_lines("builtin:snowflake", vec![OBFS4.to_string()]);
        assert_eq!(
            strategy_blocks_udp_lock(&s, true),
            Some(SNOWFLAKE_UDP_LOCK_REASON)
        );
    }

    #[test]
    fn default_settings_are_allowed_under_udp_lock() {
        assert_eq!(
            strategy_blocks_udp_lock(&AppSettings::default(), true),
            None
        );
        assert_eq!(
            strategy_blocks_udp_lock(&AppSettings::default(), false),
            None
        );
    }

    #[test]
    fn strict_lock_refusal_is_unchanged_for_snowflake_and_meek() {
        let mut meek = AppSettings::default();
        meek.bridge_lines = crate::tor::bridges::bundled_defaults("meek");
        assert!(strategy_blocks_strict_lock(&meek).is_some());
        assert!(strategy_blocks_strict_lock(&smart_snowflake()).is_some());
        assert!(strategy_blocks_strict_lock(&AppSettings::default()).is_none());
    }

    #[test]
    fn udp_lock_reasons_name_the_cause() {
        for reason in [SNOWFLAKE_UDP_LOCK_REASON, MEEK_UDP_LOCK_REASON] {
            assert!(reason.contains("DNS"), "{reason}");
            assert!(reason.contains("network lock"), "{reason}");
        }
        assert!(SNOWFLAKE_UDP_LOCK_REASON.contains("UDP"));
    }

    #[test]
    fn vanilla_bridge_ip_is_collected() {
        let mut s = AppSettings::default();
        s.bridge_lines = vec!["Bridge 198.51.100.20:443 FINGERPRINT".into()];
        assert_eq!(bridge_ips(&s)[0].to_string(), "198.51.100.20");
    }

    #[test]
    fn direct_bootstrap_allowlist_ignores_unused_bridge_lines() {
        let mut s = AppSettings::default();
        s.bridges_enabled = false;
        s.last_connect_strategy = "direct".into();
        s.bridge_lines = vec!["Bridge 198.51.100.20:443 FINGERPRINT".into()];
        let ips = bootstrap_allowlist(&s).unwrap();
        assert!(
            !ips.iter().any(|ip| ip.to_string() == "198.51.100.20"),
            "direct must pin directory authorities, not leftover bridges"
        );
        assert!(ips.iter().any(|ip| ip.to_string() == "128.31.0.39"));
    }

    #[test]
    fn bridges_bootstrap_allowlist_uses_bridge_ips() {
        let mut s = AppSettings::default();
        s.bridges_enabled = true;
        s.last_connect_strategy = "bridges".into();
        s.bridge_lines = vec!["Bridge 198.51.100.20:443 FINGERPRINT".into()];
        let ips = bootstrap_allowlist(&s).unwrap();
        assert_eq!(ips[0].to_string(), "198.51.100.20");
    }

    #[test]
    fn state_guard_lines_yield_ips() {
        let text = "Guard in=default rsa_id=ABC address=198.51.100.8:9001 listed=1\n";
        assert_eq!(parse_state_guard_ips(text)[0].to_string(), "198.51.100.8");
    }
}
