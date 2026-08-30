//! macOS Network Extension companion: classify, heartbeat, unseen-bypass.
//!
//! The system extension (`macos/OnionGateFilter`) is the LuLu-style intercept.
//! This module is the policy and the fail-open detector. pf remains the packet
//! lock. Allow never punches clearnet.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::egress_watch::{ClearnetProcess, EgressWatch};
use crate::session::SessionPhase;
use crate::tor::process::{
    BROWSER_CONTROL_PORT, BROWSER_SOCKS_PORT, CONTROL_PORT, DNS_PORT, ISOLATED_SOCKS_PORT,
    SOCKS_PORT,
};

pub const FILTER_ID: &str = "com.adamsiwiec.oniongate.filter";
pub const HEARTBEAT_STALE_SECS: u64 = 8;
const MAX_HELD: usize = 64;
const CTL_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEMEXTENSIONSCTL_TIMEOUT: Duration = Duration::from_secs(2);
/// Current macOS pane. There is no top-level "Network Extensions" page.
const APPROVE_PATH: &str =
    "System Settings → General → Login Items & Extensions → Network Extensions";

#[cfg(target_os = "macos")]
static HOST_CAN_LOAD: LazyLock<bool> = LazyLock::new(host_is_developer_id);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SysexRow {
    Absent,
    Enabled,
    WaitingForUser,
    PresentOther,
}

const HEARTBEAT_PATH: &str = "/Library/Application Support/OnionGate/filter/heartbeat.json";
const HELD_PATH: &str = "/Library/Application Support/OnionGate/filter/held.json";
const SEEN_PATH: &str = "/Library/Application Support/OnionGate/filter/seen.json";

static ANNOUNCED_HELD: LazyLock<Mutex<std::collections::HashSet<u32>>> =
    LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
static LAST_UNSEEN: LazyLock<Mutex<Vec<UnseenBypass>>> = LazyLock::new(|| Mutex::new(Vec::new()));

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
    Ok(crate::paths::data_dir()?.join("filter-allowlist.json"))
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
    if allowlist.tor_endpoints.iter().any(|ip| ip == remote_host) {
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
        let can_load = *HOST_CAN_LOAD;
        let heartbeat = read_heartbeat();
        let running = heartbeat
            .as_ref()
            .is_some_and(|h| now_unix().saturating_sub(h.unix) <= HEARTBEAT_STALE_SECS);
        // Files in the .app and a leftover `systemextensionsctl` row are not
        // "installed". An ad-hoc / unsigned bundle cannot load a Network
        // Extension, so it never appears in Login Items. Only a live
        // heartbeat or an enabled Developer ID extension counts.
        let row = if can_load {
            systemextension_row()
        } else {
            SysexRow::Absent
        };
        let installed = running || row == SysexRow::Enabled;
        let unseen = LAST_UNSEEN.lock().map(|v| v.len()).unwrap_or(0);
        let allowlist = load_allowlist();
        let required = settings.connection_filter && installed;
        let detail = if !can_load {
            "This unsigned build cannot load a Network Extension, so OnionGate will not appear under Login Items. pf is the packet lock."
                .into()
        } else if running && unseen > 0 {
            format!(
                "Filter is up, but {unseen} clearnet flow(s) never reached it (Apple exclusion or fail-open)"
            )
        } else if running {
            "Filter is up. Clearnet flows are dropped here; pf remains the packet lock. Apple can still hide some of its own processes."
                .into()
        } else if row == SysexRow::WaitingForUser {
            format!("Approve OnionGate in {APPROVE_PATH}.")
        } else if row == SysexRow::Enabled {
            "Extension is enabled but the filter process has no live heartbeat.".into()
        } else if bundled {
            "Bundled but not loaded. pf is the packet lock.".into()
        } else {
            "Not bundled. A signed .pkg is required to load the filter.".into()
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
                && (s.pid == flow.pid
                    || (!host.is_empty() && s.remote_host == host && s.remote_port == port))
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
    let settings = crate::settings::load();
    let phase = crate::session::load().phase;
    if !settings.clearnet_alerts
        || !matches!(phase, SessionPhase::Protected | SessionPhase::Degraded)
    {
        return;
    }
    let held = read_held();
    let cutoff = now_unix().saturating_sub(30);
    let mut fresh = Vec::new();
    if let Ok(mut announced) = ANNOUNCED_HELD.lock() {
        for flow in held {
            if flow.unix < cutoff || announced.contains(&flow.pid) {
                continue;
            }
            announced.insert(flow.pid);
            fresh.push(ClearnetProcess {
                process: flow.process,
                pid: flow.pid,
                killable: flow.pid > 0,
                path: flow.path,
                location: format!("{}:{}", flow.remote_host, flow.remote_port),
                system: false,
                held: true,
            });
            if announced.len() >= MAX_HELD {
                break;
            }
        }
    }
    if !fresh.is_empty() {
        crate::alert::announce(fresh);
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
        Ok(format!(
            "If macOS asks, approve OnionGate in {APPROVE_PATH}. Unsigned builds never appear there. The filter drops clearnet; it does not replace pf."
        ))
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
        if heartbeat_live() {
            let _ = run_ctl("deactivate");
            crate::logs::append("Connection filter deactivation requested");
        } else {
            crate::logs::append(
                "Connection filter was not running; skipped filter-ctl so Quit cannot stall",
            );
        }
        Ok("Connection filter deactivated. pf is unchanged.".into())
    }
}

fn run_ctl(command: &str) -> Result<String, String> {
    let ctl = filter_ctl_path().ok_or_else(|| {
        "oniongate-filter-ctl is not in this bundle. A signed .pkg build embeds the filter; unsigned debug stays on pf."
            .to_string()
    })?;
    let output = run_timed(Command::new(&ctl).arg(command), CTL_TIMEOUT)
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

/// Kill the child if it outlives `limit`. `filter-ctl` used to wait up to
/// three minutes for System Extensions approval that never comes.
fn run_timed(cmd: &mut Command, limit: Duration) -> Result<std::process::Output, String> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn().map_err(|e| format!("spawn failed: {e}"))?;
    let pid = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(limit) {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(format!("wait failed: {e}")),
        Err(_) => {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            let _ = rx.recv_timeout(Duration::from_millis(250));
            Err(format!("timed out after {}s", limit.as_secs()))
        }
    }
}

fn maybe_degrade_on_fail_open() {
    let settings = crate::settings::load();
    let phase = crate::session::load().phase;
    if phase != SessionPhase::Protected || !settings.connection_filter {
        return;
    }
    let filter = status();
    if !filter.installed {
        return;
    }
    if let Err(e) = protect_gate(
        filter.installed,
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

pub fn heartbeat_live() -> bool {
    read_heartbeat().is_some_and(|h| now_unix().saturating_sub(h.unix) <= HEARTBEAT_STALE_SECS)
}

#[cfg(target_os = "macos")]
fn host_is_developer_id() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let app = exe
        .ancestors()
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("app"));
    let target = app.unwrap_or(exe.as_path());
    let Ok(output) = Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(target)
        .output()
    else {
        return false;
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if text.contains("Signature=adhoc") || text.contains("flags=0x2(adhoc)") {
        return false;
    }
    text.lines().any(|line| {
        line.strip_prefix("TeamIdentifier=")
            .is_some_and(|team| !team.is_empty() && team != "not set")
    })
}

#[cfg(target_os = "macos")]
fn systemextension_row() -> SysexRow {
    let output = run_timed(
        Command::new("/usr/bin/systemextensionsctl").arg("list"),
        SYSTEMEXTENSIONSCTL_TIMEOUT,
    );
    match output {
        Ok(out) => parse_systemextension_row(&String::from_utf8_lossy(&out.stdout), FILTER_ID),
        Err(_) => SysexRow::Absent,
    }
}

fn parse_systemextension_row(list: &str, id: &str) -> SysexRow {
    for line in list.lines() {
        if !line.contains(id) {
            continue;
        }
        let state = line
            .rsplit_once('[')
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(s, _)| s.trim())
            .unwrap_or("");
        if state == "activated enabled" {
            return SysexRow::Enabled;
        }
        if state.contains("waiting for user") {
            return SysexRow::WaitingForUser;
        }
        return SysexRow::PresentOther;
    }
    SysexRow::Absent
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
        assert_eq!(
            classify("192.168.1.1", 67, "udp", &list),
            FilterVerdict::Allow
        );
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

    #[test]
    fn sysex_row_ignores_unrelated_and_disabled() {
        let list = "\
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
\t*\tTC292Y5427\tcom.expressvpn.vpn.splittunnel (1.0/1)\tSplit\t[activated disabled]
*\t*\tVBG97UB4TA\tcom.objective-see.lulu.extension (4.3.1/4.3.1)\tLuLu\t[activated enabled]
";
        assert_eq!(parse_systemextension_row(list, FILTER_ID), SysexRow::Absent);
        let leftover = format!(
            "\t*\tNOTATEAM\t{FILTER_ID} (1.0/1)\tOnionGate\t[terminated waiting to uninstall on reboot]\n"
        );
        assert_eq!(
            parse_systemextension_row(&leftover, FILTER_ID),
            SysexRow::PresentOther
        );
        let waiting = format!(
            "\t*\tNOTATEAM\t{FILTER_ID} (1.0/1)\tOnionGate\t[activated waiting for user]\n"
        );
        assert_eq!(
            parse_systemextension_row(&waiting, FILTER_ID),
            SysexRow::WaitingForUser
        );
        let enabled =
            format!("*\t*\tTEAMID\t{FILTER_ID} (1.0/1)\tOnionGate\t[activated enabled]\n");
        assert_eq!(
            parse_systemextension_row(&enabled, FILTER_ID),
            SysexRow::Enabled
        );
    }
}
