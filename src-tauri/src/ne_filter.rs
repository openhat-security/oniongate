//! macOS Network Extension companion: classify, heartbeat, unseen-bypass.
//!
//! The system extension (`macos/OnionGateFilter`) is the LuLu-style intercept.
//! This module is the policy and the fail-open detector. pf remains the packet
//! lock. Allow never punches clearnet.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::egress_watch::EgressWatch;
use crate::session::SessionPhase;
use crate::tor::process::{
    BROWSER_CONTROL_PORT, BROWSER_SOCKS_PORT, CONTROL_PORT, DNS_PORT, ISOLATED_SOCKS_PORT,
    SOCKS_PORT,
};

pub const FILTER_ID: &str = "com.adamsiwiec.oniongate.filter";
pub const HEARTBEAT_STALE_SECS: u64 = 8;
const MAX_HELD: usize = 64;

const HEARTBEAT_PATH: &str = "/Library/Application Support/OnionGate/filter/heartbeat.json";
const HELD_PATH: &str = "/Library/Application Support/OnionGate/filter/held.json";
const SEEN_PATH: &str = "/Library/Application Support/OnionGate/filter/seen.json";

static ANNOUNCED_HELD: LazyLock<Mutex<std::collections::HashSet<u32>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
static LAST_UNSEEN: LazyLock<Mutex<Vec<UnseenBypass>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    Allow,
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FilterAllowlist {
    pub session_active: bool,
    pub tor_endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FilterStatus {
    pub supported: bool,
    pub bundled: bool,
    pub installed: bool,
    pub running: bool,
    pub required: bool,
    pub session_active: bool,
    pub unseen_bypass: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldFlow {
    pub pid: u32,
    pub process: String,
    pub path: String,
    #[serde(default)]
    pub bundle_id: String,
    pub remote_host: String,
    pub remote_port: u16,
    pub proto: String,
    pub unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeenFlow {
    pub pid: u32,
    pub remote_host: String,
    pub remote_port: u16,
    pub unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Heartbeat {
    unix: u64,
    #[serde(default)]
    pid: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct UnseenBypass {
    pub pid: u32,
    pub process: String,
    pub remote: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn allowlist_path() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not resolve local data directory".to_string())?;
    let current = base.join("oniongate").join("filter-allowlist.json");
    if current.parent().is_some_and(|p| p.is_dir()) {
        return Ok(current);
    }
    Ok(base.join("tor-socks-gui").join("filter-allowlist.json"))
}

pub fn classify(
    remote_host: &str,
    remote_port: u16,
    proto: &str,
    allowlist: &FilterAllowlist,
) -> FilterVerdict {
    if !allowlist.session_active {
        return FilterVerdict::Allow;
    }
    if is_loopback(remote_host) {
        return FilterVerdict::Allow;
    }
    if proto.eq_ignore_ascii_case("udp") && (remote_port == 67 || remote_port == 68) {
        return FilterVerdict::Allow;
    }
    if is_tun_v4(remote_host) {
        return FilterVerdict::Allow;
    }
    if allowlist
        .tor_endpoints
        .iter()
        .any(|ip| ip == remote_host)
    {
        return FilterVerdict::Allow;
    }
    if is_local_oniongate_port(remote_port) && is_loopback(remote_host) {
        return FilterVerdict::Allow;
    }
    FilterVerdict::Drop
}

fn is_loopback(host: &str) -> bool {
    host == "127.0.0.1" || host == "::1" || host == "localhost"
}

fn is_local_oniongate_port(port: u16) -> bool {
    matches!(
        port,
        SOCKS_PORT
            | CONTROL_PORT
            | DNS_PORT
            | ISOLATED_SOCKS_PORT
            | BROWSER_SOCKS_PORT
            | BROWSER_CONTROL_PORT
    )
}

fn is_tun_v4(host: &str) -> bool {
    let Ok(IpAddr::V4(ip)) = host.parse() else {
        return false;
    };
    let o = ip.octets();
    o[0] == 172 && o[1] == 19 && o[2] == 0 && o[3] <= 3
}

/// Whether `finish_protected` may report Protected when the filter is in play.
pub fn protect_gate(
    bundled_or_installed: bool,
    running: bool,
    unseen_bypass: usize,
    setting_on: bool,
) -> Result<(), String> {
    if !setting_on || !bundled_or_installed {
        return Ok(());
    }
    if !running {
        return Err(
            "Connection filter is installed but not running. Approve it in System Settings or Disconnect."
                .into(),
        );
    }
    if unseen_bypass > 0 {
        return Err(format!(
            "Connection filter did not see {unseen_bypass} live clearnet flow(s). Apple can hide its own processes from a Network Extension, or the filter failed open. pf is still the packet lock."
        ));
    }
    Ok(())
}

pub fn status() -> FilterStatus {
    #[cfg(not(target_os = "macos"))]
    {
        return FilterStatus {
            supported: false,
            detail: "The connection filter is macOS-only".into(),
            ..FilterStatus::default()
        };
    }
    #[cfg(target_os = "macos")]
    {
        let settings = crate::settings::load();
        let bundled = bundle_present();
        let heartbeat = read_heartbeat();
        let running = heartbeat
            .as_ref()
            .is_some_and(|h| now_unix().saturating_sub(h.unix) <= HEARTBEAT_STALE_SECS);
        let installed = bundled || heartbeat.is_some() || systemextension_listed();
        let unseen = LAST_UNSEEN.lock().map(|v| v.len()).unwrap_or(0);
        let allowlist = load_allowlist();
        let required = settings.connection_filter && installed;
        let detail = if !bundled && !installed {
            "Not bundled. Unsigned debug stays on pf and the after-the-fact watch. A signed .pkg is required to load the filter."
                .into()
        } else if !running {
            "Installed but no live heartbeat. Approve the extension in System Settings → Network Extensions."
                .into()
        } else if unseen > 0 {
            format!(
                "Filter is up, but {unseen} clearnet flow(s) never reached it (Apple exclusion or fail-open)"
            )
        } else {
            "Filter is up. Clearnet flows are dropped here; pf remains the packet lock. Apple can still hide some of its own processes."
                .into()
        };
        FilterStatus {
            supported: true,
            bundled,
            installed,
            running,
            required,
            session_active: allowlist.session_active,
            unseen_bypass: unseen,
            detail,
        }
    }
}

pub fn start_monitor() {
    #[cfg(target_os = "macos")]
    {
        tauri::async_runtime::spawn(async {
            loop {
                let live = crate::tor::endpoints::live_transport_ips().await;
                let _ = tokio::task::spawn_blocking(move || {
                    publish_allowlist_with(&live);
                    announce_held();
                    maybe_degrade_on_fail_open();
                })
                .await;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }
}

pub fn publish_allowlist() {
    publish_allowlist_with(&[]);
}

fn publish_allowlist_with(extra: &[IpAddr]) {
    let settings = crate::settings::load();
    let phase = crate::session::load().phase;
    let session_wanted = matches!(
        phase,
        SessionPhase::Connecting | SessionPhase::Protected | SessionPhase::Degraded
    );
    let blocked = crate::tor::endpoints::strategy_blocks_strict_lock(&settings);
    let session_active = session_wanted && blocked.is_none();
    let mut endpoints = Vec::new();
    if session_active {
        if let Ok(ips) = crate::tor::endpoints::bootstrap_allowlist(&settings) {
            endpoints.extend(ips.into_iter().map(|ip| ip.to_string()));
        }
        for ip in crate::tor::endpoints::last_good_allowlist() {
            let s = ip.to_string();
            if !endpoints.contains(&s) {
                endpoints.push(s);
            }
        }
        for ip in extra {
            let s = ip.to_string();
            if !endpoints.contains(&s) {
                endpoints.push(s);
            }
        }
    }
    let doc = FilterAllowlist {
        session_active,
        tor_endpoints: endpoints,
    };
    let Ok(path) = allowlist_path() else {
        return;
    };
    if let Ok(raw) = serde_json::to_vec_pretty(&doc) {
        let _ = fs::write(path, raw);
    }
}

pub fn set_session_idle() {
    let doc = FilterAllowlist {
        session_active: false,
        tor_endpoints: Vec::new(),
    };
    if let Ok(path) = allowlist_path() {
        if let Ok(raw) = serde_json::to_vec_pretty(&doc) {
            let _ = fs::write(path, raw);
        }
    }
    if let Ok(mut unseen) = LAST_UNSEEN.lock() {
        unseen.clear();
    }
    if let Ok(mut held) = ANNOUNCED_HELD.lock() {
        held.clear();
    }
}

/// Compare live clearnet sockets to flows the extension recorded. A public
/// socket the filter never saw is an Apple exclusion or an NE fail-open.
pub fn reconcile_unseen(watch: &EgressWatch) -> Vec<UnseenBypass> {
    let seen = read_seen();
    let held = read_held();
    let cutoff = now_unix().saturating_sub(30);
    let mut unseen = Vec::new();
    for flow in &watch.flows {
        if flow.class != "clearnet" {
            continue;
        }
        let (host, port) = split_remote(&flow.remote);
        let matched = seen.iter().any(|s| {
            s.unix >= cutoff
                && (s.pid == flow.pid || (!host.is_empty() && s.remote_host == host && s.remote_port == port))
        }) || held.iter().any(|h| {
            h.unix >= cutoff
                && (h.pid == flow.pid
                    || (!host.is_empty() && h.remote_host == host && h.remote_port == port))
        });
        if !matched {
            unseen.push(UnseenBypass {
                pid: flow.pid,
                process: flow.process.clone(),
                remote: flow.remote.clone(),
            });
        }
    }
    if let Ok(mut guard) = LAST_UNSEEN.lock() {
        *guard = unseen.clone();
    }
    unseen
}

fn announce_held() {
    let phase = crate::session::load().phase;
    if !matches!(phase, SessionPhase::Protected | SessionPhase::Degraded) {
        return;
    }
    let held = read_held();
    let cutoff = now_unix().saturating_sub(30);
    if let Ok(mut announced) = ANNOUNCED_HELD.lock() {
        for flow in held {
            if flow.unix < cutoff || announced.contains(&flow.pid) {
                continue;
            }
            announced.insert(flow.pid);
            crate::logs::append(format!(
                "Connection filter stopped an outbound flow from {} (pid {})",
                flow.process, flow.pid
            ));
            if announced.len() >= MAX_HELD {
                break;
            }
        }
    }
}

pub fn activate() -> Result<String, String> {
    #[cfg(not(target_os = "macos"))]
    {
        return Err("The connection filter is macOS-only".into());
    }
    #[cfg(target_os = "macos")]
    {
        crate::session::update(|j| j.connection_filter_expected = true)?;
        run_ctl("activate")?;
        crate::logs::append("Connection filter activation requested");
        Ok("Approve the OnionGate connection filter in System Settings → Network Extensions if macOS asks. The filter drops clearnet; it does not replace pf.".into())
    }
}

pub fn deactivate() -> Result<String, String> {
    #[cfg(not(target_os = "macos"))]
    {
        return Err("The connection filter is macOS-only".into());
    }
    #[cfg(target_os = "macos")]
    {
        set_session_idle();
        crate::session::update(|j| j.connection_filter_expected = false)?;
        let _ = run_ctl("deactivate");
        crate::logs::append("Connection filter deactivation requested");
        Ok("Connection filter deactivated. pf is unchanged.".into())
    }
}

fn run_ctl(command: &str) -> Result<String, String> {
    let ctl = filter_ctl_path().ok_or_else(|| {
        "oniongate-filter-ctl is not in this bundle. A signed .pkg build embeds the filter; unsigned debug stays on pf."
            .to_string()
    })?;
    let output = Command::new(&ctl)
        .arg(command)
        .output()
        .map_err(|e| format!("Failed to run the filter activator: {e}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        return Err(if stderr.is_empty() {
            format!("filter activator {command} failed")
        } else {
            stderr
        });
    }
    Ok(stderr)
}

fn maybe_degrade_on_fail_open() {
    let settings = crate::settings::load();
    let phase = crate::session::load().phase;
    if phase != SessionPhase::Protected || !settings.connection_filter {
        return;
    }
    let filter = status();
    if !filter.bundled && !filter.installed {
        return;
    }
    if let Err(e) = protect_gate(
        filter.bundled || filter.installed,
        filter.running,
        filter.unseen_bypass,
        settings.connection_filter,
    ) {
        let _ = crate::session::set_phase(SessionPhase::Degraded, Some(e));
    }
}

fn filter_ctl_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let ctl = exe.parent()?.join("oniongate-filter-ctl");
    ctl.is_file().then_some(ctl)
}

fn bundle_present() -> bool {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(contents) = exe.parent().and_then(|p| p.parent()) {
            let sysex = contents
                .join("Library/SystemExtensions")
                .join(format!("{FILTER_ID}.systemextension"));
            if sysex.is_dir() {
                return true;
            }
        }
    }
    false
}

fn systemextension_listed() -> bool {
    let output = Command::new("/usr/bin/systemextensionsctl")
        .arg("list")
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains(FILTER_ID),
        Err(_) => false,
    }
}

fn load_allowlist() -> FilterAllowlist {
    let Ok(path) = allowlist_path() else {
        return FilterAllowlist::default();
    };
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn read_heartbeat() -> Option<Heartbeat> {
    read_json(HEARTBEAT_PATH)
}

fn read_held() -> Vec<HeldFlow> {
    #[derive(Deserialize)]
    struct Wrap {
        #[serde(default)]
        flows: Vec<HeldFlow>,
    }
    read_json::<Wrap>(HELD_PATH)
        .map(|w| w.flows)
        .unwrap_or_default()
}

fn read_seen() -> Vec<SeenFlow> {
    #[derive(Deserialize)]
    struct Wrap {
        #[serde(default)]
        flows: Vec<SeenFlow>,
    }
    read_json::<Wrap>(SEEN_PATH)
        .map(|w| w.flows)
        .unwrap_or_default()
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &str) -> Option<T> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn split_remote(remote: &str) -> (String, u16) {
    if let Some(rest) = remote.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            return (host.to_string(), port.parse().unwrap_or(0));
        }
    }
    if let Some((host, port)) = remote.rsplit_once(':') {
        return (host.to_string(), port.parse().unwrap_or(0));
    }
    (remote.to_string(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist(active: bool, endpoints: &[&str]) -> FilterAllowlist {
        FilterAllowlist {
            session_active: active,
            tor_endpoints: endpoints.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn idle_session_allows_everything() {
        let list = allowlist(false, &[]);
        assert_eq!(
            classify("203.0.113.9", 443, "tcp", &list),
            FilterVerdict::Allow
        );
    }

    #[test]
    fn loopback_and_dhcp_and_tor_are_allowed() {
        let list = allowlist(true, &["198.51.100.10"]);
        assert_eq!(
            classify("127.0.0.1", 9050, "tcp", &list),
            FilterVerdict::Allow
        );
        assert_eq!(classify("::1", 53, "udp", &list), FilterVerdict::Allow);
        assert_eq!(classify("192.168.1.1", 67, "udp", &list), FilterVerdict::Allow);
        assert_eq!(
            classify("198.51.100.10", 443, "tcp", &list),
            FilterVerdict::Allow
        );
        assert_eq!(
            classify("172.19.0.2", 443, "tcp", &list),
            FilterVerdict::Allow
        );
    }

    #[test]
    fn public_clearnet_is_dropped() {
        let list = allowlist(true, &["198.51.100.10"]);
        assert_eq!(
            classify("203.0.113.9", 443, "tcp", &list),
            FilterVerdict::Drop
        );
    }

    #[test]
    fn protect_gate_skips_when_not_installed() {
        assert!(protect_gate(false, false, 0, true).is_ok());
        assert!(protect_gate(true, true, 0, false).is_ok());
    }

    #[test]
    fn protect_gate_fails_closed_when_required_and_down() {
        let err = protect_gate(true, false, 0, true).unwrap_err();
        assert!(err.contains("not running"));
    }

    #[test]
    fn protect_gate_fails_closed_on_unseen_bypass() {
        let err = protect_gate(true, true, 2, true).unwrap_err();
        assert!(err.contains("did not see"));
        assert!(err.contains("Apple"));
    }

    #[test]
    fn protect_gate_ok_when_live_and_clean() {
        assert!(protect_gate(true, true, 0, true).is_ok());
    }
}
