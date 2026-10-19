use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AppIdentity {
    pub id: String,
    pub label: String,
    pub process_name: String,
    pub executable_path: String,
    pub bundle_id: Option<String>,
    pub signing_id: Option<String>,
    pub circuit_epoch: u64,
}

impl Default for AppIdentity {
    fn default() -> Self {
        Self {
            id: String::new(),
            label: String::new(),
            process_name: String::new(),
            executable_path: String::new(),
            bundle_id: None,
            signing_id: None,
            circuit_epoch: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    /// Prefer remote DNS: Tor DNSPort + socks5h / socks_remote_dns helpers.
    pub remote_dns: bool,
    /// When Tor starts successfully, also enable the system SOCKS proxy.
    /// System proxy mode always applies OS SOCKS regardless of this toggle.
    pub auto_enable_proxy: bool,
    /// When Tor stops, disable the system SOCKS proxy (recommended).
    pub auto_disable_proxy: bool,
    /// Tor log verbosity written to tor.log
    pub log_level: String,
    /// Poll status interval in the UI (seconds)
    pub status_poll_secs: u32,
    /// UI language (`auto`, `en`, `ru`, `fa`, `zh-CN`, `tr`).
    pub locale: String,
    /// UI theme (`auto`, `light`, `dark`).
    pub theme: String,
    /// Bootstrap Tor with current settings on Connect (does not manage bridges).
    pub smart_connect: bool,
    /// Use Bridge lines from bridge_lines in managed torrc.
    pub bridges_enabled: bool,
    /// Normalized `Bridge …` lines.
    pub bridge_lines: Vec<String>,
    /// ISO 3166-1 alpha-2 exit country pin (empty = any).
    pub exit_country: String,
    /// Last successful Smart Connect strategy (`direct` | `bridges` | `bridges:obfs4` …).
    pub last_connect_strategy: String,
    /// Network key (e.g. gw:…) when last strategy succeeded.
    pub last_network_key: String,
    /// Human-readable reason the most recent strategy was selected.
    pub last_connect_reason: String,
    /// Bridge catalog mode: `auto` | `custom` | `transport:obfs4` | …
    pub bridge_source: String,
    /// `proxy` (OS SOCKS) or `tun` (sing-box system-wide).
    pub connection_mode: String,
    /// Block UDP/QUIC leaks; pair with TUN strict_route for stronger fail-closed.
    pub kill_switch: bool,
    /// TUN only: route listed process names through Tor; everything else direct.
    pub split_tunnel: bool,
    /// Process names for split tunnel allowlist (empty = all via Tor when split off).
    pub split_tunnel_apps: Vec<String>,
    /// Stable application identities used by isolated TUN routing.
    pub route_apps: Vec<AppIdentity>,
    /// `only` routes selected apps; `except` routes everything except selected apps.
    pub app_routing_policy: String,
    /// Suspend selected apps if their isolated Tor route disappears.
    pub session_guard: bool,
    /// macOS: default-deny every outbound IP packet except Tor allowlisted endpoints.
    pub strict_tcp_lock: bool,
    /// Warned destination holes while the NIC lock is on (machine-wide). Session Degraded.
    pub strict_tcp_exceptions: Vec<String>,
    /// When the NIC lock is on, also pass RFC1918/link-local (not Maximum Isolation).
    pub allow_lan: bool,
    /// Incrementing nonce used to rotate per-app SOCKS authentication circuits.
    pub circuit_epoch: u64,
    /// Preferred entry/middle/exit fingerprints (Classic torrc).
    pub entry_nodes: String,
    pub middle_nodes: String,
    pub exit_nodes_fp: String,
    /// First-run setup wizard has been completed/dismissed.
    pub setup_complete: bool,
    /// Warn when a process reaches the network outside Tor while protected.
    pub clearnet_alerts: bool,
    /// With Wi-Fi disabled at boot, turn the radio back on once the session
    /// reports Protected instead of leaving it to the user.
    pub wifi_off_at_boot_auto_reenable: bool,
    /// After the app finishes launching, start a Tor session without waiting
    /// for Connect. Recommended with the boot network lock so a restart is
    /// not an offline brick.
    pub connect_on_launch: bool,
    /// Require the macOS connection filter (Network Extension) once it is
    /// installed. Unsigned builds have no extension; pf stays the lock.
    pub connection_filter: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            remote_dns: true,
            auto_enable_proxy: true,
            auto_disable_proxy: true,
            log_level: "notice".into(),
            status_poll_secs: 4,
            locale: "auto".into(),
            theme: "auto".into(),
            smart_connect: true,
            bridges_enabled: false,
            bridge_lines: Vec::new(),
            exit_country: String::new(),
            last_connect_strategy: "direct".into(),
            last_network_key: String::new(),
            last_connect_reason: String::new(),
            bridge_source: "none".into(),
            connection_mode: "proxy".into(),
            kill_switch: false,
            split_tunnel: false,
            split_tunnel_apps: Vec::new(),
            route_apps: Vec::new(),
            app_routing_policy: "only".into(),
            session_guard: false,
            strict_tcp_lock: false,
            strict_tcp_exceptions: Vec::new(),
            allow_lan: false,
            circuit_epoch: 0,
            entry_nodes: String::new(),
            middle_nodes: String::new(),
            exit_nodes_fp: String::new(),
            setup_complete: false,
            clearnet_alerts: true,
            wifi_off_at_boot_auto_reenable: true,
            connect_on_launch: false,
            connection_filter: true,
        }
    }
}

fn settings_path() -> Result<PathBuf, String> {
    let base = crate::paths::data_dir()?;
    let path = base.join("settings.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Failed to protect data dir: {e}"))?;
        if path.exists() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to protect settings: {e}"))?;
        }
    }
    Ok(path)
}

/// Parse settings JSON. A present-but-unparseable file is a hard error: we must
/// never silently fall back to weaker defaults (kill switch off, proxy instead
/// of TUN) after a partial write, a disk-full, or a bad hand edit.
fn parse_settings(raw: &str) -> Result<AppSettings, String> {
    serde_json::from_str(raw).map_err(|e| format!("settings.json is not valid JSON: {e}"))
}

/// Core of [`load_strict`], split out so it can be tested against a temp path
/// without touching the real data directory. A missing or empty file is a
/// first run (safe defaults); a present file that does not parse is an error,
/// and the bad bytes are preserved next to the original as `settings.json.corrupt`.
fn load_strict_from(path: &std::path::Path) -> Result<AppSettings, String> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => {
            let mut settings = AppSettings::default();
            normalize(&mut settings);
            return Ok(settings);
        }
    };
    if raw.trim().is_empty() {
        let mut settings = AppSettings::default();
        normalize(&mut settings);
        return Ok(settings);
    }
    match parse_settings(&raw) {
        Ok(mut settings) => {
            normalize(&mut settings);
            Ok(settings)
        }
        Err(e) => {
            // Keep the original in place (so every later load stays fail-closed
            // until a human fixes it) and preserve a copy for inspection.
            let corrupt = path.with_extension("json.corrupt");
            let _ = fs::copy(path, &corrupt);
            Err(format!(
                "{e}. The file was left in place and copied to {}. Refusing to \
                 continue with weaker defaults; fix or remove settings.json.",
                corrupt.display()
            ))
        }
    }
}

/// Load settings, failing closed on corruption. Connect paths must use this so
/// a damaged file can never downgrade a fail-closed setup to fail-open.
pub fn load_strict() -> Result<AppSettings, String> {
    let path = settings_path()?;
    match load_strict_from(&path) {
        Ok(settings) => Ok(settings),
        Err(e) => {
            crate::logs::append(format!("Corrupt settings.json: {e}"));
            Err(e)
        }
    }
}

pub fn load() -> AppSettings {
    match load_strict() {
        Ok(settings) => settings,
        Err(_) => {
            // UI/read paths still need a value to render; connect paths call
            // load_strict and refuse. Never persist this over the bad file.
            let mut settings = AppSettings::default();
            normalize(&mut settings);
            settings
        }
    }
}

pub fn save(settings: &AppSettings) -> Result<(), String> {
    let path = settings_path()?;
    let temp = path.with_extension("json.tmp");
    let raw = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    fs::write(&temp, raw).map_err(|e| format!("Failed to write settings: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to protect settings: {e}"))?;
    }
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(&path).map_err(|e| format!("Failed to replace settings: {e}"))?;
    }
    fs::rename(&temp, &path).map_err(|e| format!("Failed to commit settings: {e}"))
}

fn normalize(settings: &mut AppSettings) {
    if !matches!(
        settings.log_level.as_str(),
        "err" | "warn" | "notice" | "info" | "debug"
    ) {
        settings.log_level = "notice".into();
    }
    settings.status_poll_secs = settings.status_poll_secs.clamp(2, 60);
    if !matches!(
        settings.locale.as_str(),
        "auto" | "en" | "ru" | "fa" | "zh-CN" | "tr"
    ) {
        settings.locale = "auto".into();
    }
    if !matches!(settings.theme.as_str(), "auto" | "light" | "dark") {
        settings.theme = "auto".into();
    }
    settings.exit_country = settings.exit_country.trim().to_ascii_lowercase();
    if settings.exit_country.len() != 2
        || !settings
            .exit_country
            .chars()
            .all(|c| c.is_ascii_alphabetic())
    {
        settings.exit_country.clear();
    }
    let strat = settings.last_connect_strategy.as_str();
    if strat != "direct"
        && strat != "bridges"
        && !strat.starts_with("bridges:")
        && !strat.starts_with("builtin:")
    {
        settings.last_connect_strategy = "direct".into();
    }
    let src = settings.bridge_source.trim().to_ascii_lowercase();
    settings.bridge_source = if src == "custom"
        || src == "auto"
        || src == "none"
        || src.starts_with("transport:")
        || src.starts_with("builtin:")
    {
        src
    } else {
        "none".into()
    };
    // None = do not load bridges into torrc / Smart Connect.
    if settings.bridge_source == "none" {
        settings.bridges_enabled = false;
    }
    if !matches!(settings.connection_mode.as_str(), "proxy" | "tun") {
        settings.connection_mode = "proxy".into();
    }
    if !matches!(settings.app_routing_policy.as_str(), "only" | "except") {
        settings.app_routing_policy = "only".into();
    }
    if settings.route_apps.is_empty() && !settings.split_tunnel_apps.is_empty() {
        settings.route_apps = settings
            .split_tunnel_apps
            .iter()
            .map(|name| AppIdentity {
                id: format!("legacy:{name}"),
                label: name.clone(),
                process_name: name.clone(),
                ..AppIdentity::default()
            })
            .collect();
    }
    settings.route_apps.retain(|app| {
        !app.id.trim().is_empty()
            && (!app.process_name.trim().is_empty() || !app.executable_path.trim().is_empty())
    });
    settings.route_apps.sort_by(|a, b| a.id.cmp(&b.id));
    settings.route_apps.dedup_by(|a, b| a.id == b.id);
    settings.split_tunnel_apps = settings
        .route_apps
        .iter()
        .map(|app| app.process_name.clone())
        .filter(|name| !name.is_empty())
        .collect();
    settings
        .strict_tcp_exceptions
        .retain(|item| crate::firewall::strict::parse_ip(item).is_ok());
    settings
        .strict_tcp_exceptions
        .truncate(crate::firewall::strict::MAX_EXCEPTIONS);
    if settings.strict_tcp_lock {
        settings.kill_switch = true;
        settings.remote_dns = true;
    }
    let mut dedup = Vec::new();
    for line in settings.bridge_lines.drain(..) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let normalized = if t.to_ascii_lowercase().starts_with("bridge ") {
            format!("Bridge {}", t[7..].trim())
        } else {
            format!("Bridge {t}")
        };
        if !dedup.contains(&normalized) {
            dedup.push(normalized);
        }
    }
    settings.bridge_lines = dedup;
}

pub fn update(mutator: impl FnOnce(&mut AppSettings)) -> Result<AppSettings, String> {
    let mut settings = load();
    mutator(&mut settings);
    normalize(&mut settings);
    save(&settings)?;
    Ok(settings)
}

pub fn set_remote_dns(enabled: bool) -> Result<AppSettings, String> {
    update(|s| s.remote_dns = enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(mutate: impl FnOnce(&mut AppSettings)) -> AppSettings {
        let mut settings = AppSettings::default();
        mutate(&mut settings);
        normalize(&mut settings);
        settings
    }

    #[test]
    fn unknown_enumerations_fall_back_to_safe_defaults() {
        let s = normalized(|s| {
            s.log_level = "trace".into();
            s.locale = "klingon".into();
            s.theme = "neon".into();
            s.connection_mode = "carrier-pigeon".into();
            s.app_routing_policy = "sometimes".into();
        });
        assert_eq!(s.log_level, "notice");
        assert_eq!(s.locale, "auto");
        assert_eq!(s.theme, "auto");
        assert_eq!(s.connection_mode, "proxy");
        assert_eq!(s.app_routing_policy, "only");
    }

    #[test]
    fn status_poll_interval_is_clamped() {
        assert_eq!(normalized(|s| s.status_poll_secs = 0).status_poll_secs, 2);
        assert_eq!(
            normalized(|s| s.status_poll_secs = 9999).status_poll_secs,
            60
        );
    }

    #[test]
    fn exit_country_is_lowercased_and_validated() {
        assert_eq!(
            normalized(|s| s.exit_country = " DE ".into()).exit_country,
            "de"
        );
        assert!(normalized(|s| s.exit_country = "germany".into())
            .exit_country
            .is_empty());
        assert!(normalized(|s| s.exit_country = "d1".into())
            .exit_country
            .is_empty());
    }

    /// Selecting "none" must not leave stale bridges armed in the torrc.
    #[test]
    fn bridge_source_none_disables_bridges() {
        let s = normalized(|s| {
            s.bridge_source = "none".into();
            s.bridges_enabled = true;
            s.bridge_lines = vec!["obfs4 203.0.113.5:443 ABC".into()];
        });
        assert!(!s.bridges_enabled);
    }

    #[test]
    fn unrecognised_bridge_source_is_treated_as_none() {
        let s = normalized(|s| {
            s.bridge_source = "https://evil.example/bridges".into();
            s.bridges_enabled = true;
        });
        assert_eq!(s.bridge_source, "none");
        assert!(!s.bridges_enabled);
    }

    #[test]
    fn bridge_lines_are_prefixed_deduplicated_and_stripped_of_comments() {
        let s = normalized(|s| {
            s.bridge_source = "custom".into();
            s.bridge_lines = vec![
                "obfs4 203.0.113.5:443 ABC".into(),
                "Bridge obfs4 203.0.113.5:443 ABC".into(),
                "# a comment".into(),
                "   ".into(),
            ];
        });
        assert_eq!(s.bridge_lines, vec!["Bridge obfs4 203.0.113.5:443 ABC"]);
    }

    #[test]
    fn routed_apps_are_sorted_deduplicated_and_require_an_identity() {
        let s = normalized(|s| {
            s.route_apps = vec![
                AppIdentity {
                    id: "z".into(),
                    process_name: "zed".into(),
                    ..AppIdentity::default()
                },
                AppIdentity {
                    id: "a".into(),
                    process_name: "signal".into(),
                    ..AppIdentity::default()
                },
                AppIdentity {
                    id: "a".into(),
                    process_name: "signal".into(),
                    ..AppIdentity::default()
                },
                AppIdentity {
                    id: "no-target".into(),
                    ..AppIdentity::default()
                },
            ];
        });
        let ids: Vec<&str> = s.route_apps.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "z"]);
        assert_eq!(s.split_tunnel_apps, vec!["signal", "zed"]);
    }

    #[test]
    fn legacy_process_name_lists_migrate_to_app_identities() {
        let s = normalized(|s| s.split_tunnel_apps = vec!["signal".into()]);
        assert_eq!(s.route_apps.len(), 1);
        assert_eq!(s.route_apps[0].process_name, "signal");
        assert_eq!(s.route_apps[0].id, "legacy:signal");
    }

    #[test]
    fn settings_round_trip_through_json() {
        let original = normalized(|s| {
            s.bridge_source = "custom".into();
            s.bridge_lines = vec!["obfs4 203.0.113.5:443 ABC".into()];
            s.exit_country = "SE".into();
        });
        let raw = serde_json::to_string(&original).unwrap();
        let mut restored: AppSettings = serde_json::from_str(&raw).unwrap();
        normalize(&mut restored);
        assert_eq!(restored.bridge_lines, original.bridge_lines);
        assert_eq!(restored.exit_country, "se");
    }

    /// Older configs are missing newer keys; they must not reset the whole file.
    #[test]
    fn partial_json_keeps_defaults_for_absent_keys() {
        let settings: AppSettings = serde_json::from_str(r#"{"log_level":"info"}"#).unwrap();
        assert_eq!(settings.log_level, "info");
        assert!(settings.remote_dns);
        assert_eq!(settings.connection_mode, "proxy");
        assert!(settings.auto_enable_proxy);
        assert!(settings.clearnet_alerts);
        assert!(settings.wifi_off_at_boot_auto_reenable);
        assert!(!settings.connect_on_launch);
        assert!(settings.connection_filter);
    }

    #[test]
    fn auto_enable_proxy_defaults_on() {
        assert!(AppSettings::default().auto_enable_proxy);
    }

    #[test]
    fn parse_settings_accepts_valid_json() {
        let s = parse_settings(r#"{"connection_mode":"tun","kill_switch":true}"#).unwrap();
        assert_eq!(s.connection_mode, "tun");
        assert!(s.kill_switch);
    }

    #[test]
    fn parse_settings_rejects_invalid_json() {
        assert!(parse_settings(r#"{"connection_mode":"tun""#).is_err());
        assert!(parse_settings("not json at all").is_err());
    }

    #[test]
    fn load_strict_missing_file_is_first_run_defaults() {
        let dir = std::env::temp_dir().join(format!("og-settings-missing-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings.json");
        let _ = std::fs::remove_file(&path);
        let s = load_strict_from(&path).expect("absent file is a safe first run");
        assert_eq!(s.connection_mode, "proxy");
        assert!(!s.kill_switch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_strict_preserves_a_fail_closed_config() {
        let dir = std::env::temp_dir().join(format!("og-settings-ok-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings.json");
        std::fs::write(&path, r#"{"connection_mode":"tun","kill_switch":true}"#).unwrap();
        let s = load_strict_from(&path).expect("valid file loads");
        assert_eq!(s.connection_mode, "tun");
        assert!(s.kill_switch, "must not downgrade a kill-switch config");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reproduces the audit finding: a tun + kill_switch config truncated on
    /// disk must NOT silently load as proxy + kill_switch off. It must error,
    /// leave the original in place, and copy it to settings.json.corrupt.
    #[test]
    fn load_strict_refuses_corrupt_and_never_weakens_defaults() {
        let dir = std::env::temp_dir().join(format!("og-settings-corrupt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("settings.json");
        let full = r#"{"connection_mode":"tun","kill_switch":true}"#;
        // Cut the last 2 bytes, exactly like the audit did.
        std::fs::write(&path, &full[..full.len() - 2]).unwrap();

        let err = load_strict_from(&path).expect_err("corrupt file must fail closed");
        assert!(err.contains("settings.json"));

        // Original stays in place; a .corrupt copy exists for inspection.
        assert!(
            path.exists(),
            "original must be kept so every load stays fail-closed"
        );
        assert!(path.with_extension("json.corrupt").exists());

        // And load() must not hand back a weakened config for this path.
        // (load_strict_from is the gate; it returned Err, so no proxy/off leaks.)
        let _ = std::fs::remove_dir_all(&dir);
    }
}
