//! Live connection census. Memory-only; never written to logs or SQLite.
//!
//! A background task samples TCP and UDP sockets (listen + established) and
//! classifies each flow. The UI may show full addresses because the snapshot
//! never leaves this process.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::tor::process::{
    BROWSER_CONTROL_PORT, BROWSER_SOCKS_PORT, CONTROL_PORT, DNS_PORT, ISOLATED_SOCKS_PORT,
    SOCKS_PORT,
};
#[cfg(target_os = "windows")]
use crate::win_console::HideConsole;

const MAX_ROWS: usize = 2000;
const MAX_ROWS_PER_PID: usize = 48;
const SCAN_INTERVAL: Duration = Duration::from_secs(2);
/// Ceiling on remembered announcements. Past this the watch stops popping up
/// rather than forgetting pids and re-nagging about them.
const MAX_ANNOUNCED: usize = 2048;

fn default_flow_count() -> u32 {
    1
}

/// TUN address block from `tun/mod.rs` (`172.19.0.1/30`).
const TUN_V4_NET: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 0);
const TUN_V4_PREFIX: u8 = 30;
const TUN_V6: Ipv6Addr = Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 0);
const TUN_V6_PREFIX: u8 = 126;

static SNAPSHOT: LazyLock<Mutex<EgressWatch>> =
    LazyLock::new(|| Mutex::new(EgressWatch::idle("Watch has not sampled yet")));

/// Pids already announced in this session. Memory-only, reset on teardown.
static ANNOUNCED: LazyLock<Mutex<HashSet<u32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowClass {
    ThroughOnionGate,
    TorTransport,
    Lan,
    Local,
    Bypass,
}

impl FlowClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::ThroughOnionGate => "through_tor",
            Self::TorTransport => "tor_transport",
            Self::Lan => "lan",
            Self::Local => "local",
            Self::Bypass => "clearnet",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressFlow {
    pub process: String,
    pub pid: u32,
    pub proto: String,
    pub direction: String,
    pub local: String,
    pub remote: String,
    pub class: String,
    pub path: String,
    pub location: String,
    pub system: bool,
    /// Sockets collapsed into this row (same pid, proto, remote, direction).
    #[serde(default = "default_flow_count")]
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressWatch {
    pub watching: bool,
    pub sampled_at_unix: u64,
    pub supported: bool,
    pub detail: String,
    pub through_oniongate: usize,
    pub tor_transport: usize,
    pub lan: usize,
    pub local: usize,
    pub listen: usize,
    pub bypass: usize,
    pub total: usize,
    pub truncated: bool,
    pub flows: Vec<EgressFlow>,
    pub clearnet_processes: Vec<ClearnetProcess>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearnetProcess {
    pub process: String,
    pub pid: u32,
    pub killable: bool,
    pub path: String,
    pub location: String,
    pub system: bool,
    /// The Network Extension held and dropped this flow. False means the
    /// socket was already live when the watch saw it.
    #[serde(default)]
    pub held: bool,
}

impl EgressWatch {
    fn idle(detail: impl Into<String>) -> Self {
        Self {
            watching: false,
            sampled_at_unix: 0,
            supported: cfg!(any(
                target_os = "macos",
                target_os = "linux",
                target_os = "windows"
            )),
            detail: detail.into(),
            through_oniongate: 0,
            tor_transport: 0,
            lan: 0,
            local: 0,
            listen: 0,
            bypass: 0,
            total: 0,
            truncated: false,
            flows: Vec::new(),
            clearnet_processes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct RawFlow {
    process: String,
    pid: u32,
    proto: &'static str,
    listen: bool,
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
    path: String,
}

pub fn snapshot() -> EgressWatch {
    SNAPSHOT
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| EgressWatch::idle("Watch lock unavailable"))
}

/// Latest sample. Never scans on the caller thread — the daemon owns lsof/ss.
pub fn current() -> EgressWatch {
    snapshot()
}

/// One-shot sample for the CLI. The GUI daemon should be used instead.
pub fn sample_now() -> EgressWatch {
    let next = scan();
    if let Ok(mut guard) = SNAPSHOT.lock() {
        *guard = next.clone();
    }
    next
}

pub fn start_monitor() {
    tauri::async_runtime::spawn(async {
        loop {
            let watch = tokio::task::spawn_blocking(scan).await;
            if let Ok(next) = watch {
                let _ = crate::ne_filter::reconcile_unseen(&next);
                announce_new_clearnet(&next);
                if let Ok(mut guard) = SNAPSHOT.lock() {
                    *guard = next;
                }
            }
            tokio::time::sleep(SCAN_INTERVAL).await;
        }
    });
}

/// Only a Protected session pops up, and only when the user has left clearnet
/// alerts on. A clearnet socket during connect or teardown is expected.
fn should_announce(alerts_enabled: bool, phase: crate::session::SessionPhase) -> bool {
    alerts_enabled && phase == crate::session::SessionPhase::Protected
}

/// Killable pids from this sample that have not been announced yet, recording
/// them as announced. Returned together so a burst becomes one popup instead of
/// one window per pid, and so a pid is never announced twice.
fn take_new_announcements(
    announced: &mut HashSet<u32>,
    processes: &[ClearnetProcess],
) -> Vec<ClearnetProcess> {
    let mut fresh = Vec::new();
    for process in processes {
        if !process.killable || announced.len() >= MAX_ANNOUNCED {
            continue;
        }
        if announced.insert(process.pid) {
            fresh.push(process.clone());
        }
    }
    fresh
}

/// Forget every announcement and take down any open popup. Called on teardown
/// so a new session starts from silence.
pub fn reset_announced() {
    let had_announcements = match ANNOUNCED.lock() {
        Ok(mut announced) => {
            let had = !announced.is_empty();
            announced.clear();
            had
        }
        Err(_) => false,
    };
    if had_announcements {
        crate::alert::dismiss();
    }
}

fn announce_new_clearnet(watch: &EgressWatch) {
    let phase = crate::session::load().phase;
    if !should_announce(crate::settings::load().clearnet_alerts, phase) {
        reset_announced();
        return;
    }
    let fresh = match ANNOUNCED.lock() {
        Ok(mut announced) => take_new_announcements(&mut announced, &watch.clearnet_processes),
        Err(_) => Vec::new(),
    };
    crate::alert::announce(fresh);
}

fn scan() -> EgressWatch {
    let sampled_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let raw = match collect_sockets() {
        Ok(rows) => rows,
        Err(detail) => {
            return EgressWatch {
                watching: true,
                sampled_at_unix,
                supported: true,
                detail,
                ..EgressWatch::idle("")
            };
        }
    };

    let allowed = transport_pids();
    let catalog = process_catalog(&raw);
    let listen_keys: HashSet<(u32, u16, &'static str)> = raw
        .iter()
        .filter(|f| f.listen)
        .map(|f| (f.pid, f.local_port, f.proto))
        .collect();

    let mut through_oniongate = 0usize;
    let mut tor_transport = 0usize;
    let mut lan = 0usize;
    let mut local = 0usize;
    let mut listen = 0usize;
    let mut bypass = 0usize;
    let mut flows = Vec::with_capacity(raw.len().min(MAX_ROWS));

    for flow in raw {
        if flow.listen {
            listen += 1;
        }
        let class = classify(&flow, &allowed);
        match class {
            FlowClass::ThroughOnionGate => through_oniongate += 1,
            FlowClass::TorTransport => tor_transport += 1,
            FlowClass::Lan => lan += 1,
            FlowClass::Local => local += 1,
            FlowClass::Bypass => bypass += 1,
        }
        if flows.len() >= MAX_ROWS {
            continue;
        }
        let inbound = !flow.listen
            && listen_keys.contains(&(flow.pid, flow.local_port, flow.proto))
            && !flow.remote.is_unspecified();
        let direction = if flow.listen {
            "listen"
        } else if inbound {
            "in"
        } else {
            "out"
        };
        let info = catalog.get(&flow.pid);
        let system = info.map(|i| i.system).unwrap_or(false);
        let process = display_name(&flow.process, flow.pid, info);
        let path = info.map(|i| i.path.clone()).unwrap_or_default();
        let location = info.map(|i| i.location.clone()).unwrap_or_default();
        flows.push(EgressFlow {
            process,
            pid: flow.pid,
            proto: flow.proto.into(),
            direction: direction.into(),
            local: format_endpoint(flow.local, flow.local_port),
            remote: if flow.listen || flow.remote.is_unspecified() {
                "*".into()
            } else {
                format_endpoint(flow.remote, flow.remote_port)
            },
            class: class.as_str().into(),
            path,
            location,
            system,
            count: 1,
        });
    }

    flows.sort_by(|a, b| {
        class_rank(&a.class)
            .cmp(&class_rank(&b.class))
            .then(a.process.cmp(&b.process))
            .then(a.remote.cmp(&b.remote))
    });
    flows = collapse_duplicate_flows(flows);
    flows = cap_rows_per_pid(flows);

    let total = through_oniongate + tor_transport + lan + local + bypass;
    let truncated = total > flows.len();
    let detail = if truncated {
        format!(
            "{total} sockets · {through_oniongate} through Tor · {bypass} not through Tor (showing {})",
            flows.len()
        )
    } else {
        format!("{total} sockets · {through_oniongate} through Tor · {bypass} not through Tor")
    };

    let clearnet_processes = unique_clearnet_processes(&flows);
    EgressWatch {
        watching: true,
        sampled_at_unix,
        supported: true,
        detail,
        through_oniongate,
        tor_transport,
        lan,
        local,
        listen,
        bypass,
        total,
        truncated,
        flows,
        clearnet_processes,
    }
}

pub fn unique_clearnet_processes(flows: &[EgressFlow]) -> Vec<ClearnetProcess> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for flow in flows {
        if flow.class != "clearnet" {
            continue;
        }
        if !seen.insert(flow.pid) {
            continue;
        }
        out.push(ClearnetProcess {
            killable: !flow.system
                && !crate::apps_lifecycle::is_protected_process(&flow.process, flow.pid),
            process: flow.process.clone(),
            pid: flow.pid,
            path: flow.path.clone(),
            location: flow.location.clone(),
            system: flow.system,
            held: false,
        });
    }
    out.sort_by(|a, b| a.process.cmp(&b.process).then(a.pid.cmp(&b.pid)));
    out
}

#[derive(Debug, Clone)]
struct ProcInfo {
    name: String,
    path: String,
    location: String,
    system: bool,
}

fn process_catalog(raw: &[RawFlow]) -> HashMap<u32, ProcInfo> {
    let mut map = HashMap::new();
    for flow in raw {
        if map.contains_key(&flow.pid) {
            continue;
        }
        let path = if !flow.path.is_empty() {
            Some(flow.path.clone())
        } else {
            pid_executable_path(flow.pid)
        };
        map.insert(flow.pid, proc_info(flow.pid, &flow.process, path));
    }
    map
}

fn proc_info(pid: u32, raw_name: &str, path: Option<String>) -> ProcInfo {
    if pid <= 1 {
        return ProcInfo {
            name: if pid == 0 {
                "kernel".into()
            } else {
                "launchd".into()
            },
            path: path.clone().unwrap_or_default(),
            location: path.unwrap_or_default(),
            system: true,
        };
    }
    let (location, path_name) = path
        .as_deref()
        .map(bundle_location_and_name)
        .unwrap_or_default();
    let name = if !path_name.is_empty() {
        path_name
    } else if usable_process_name(raw_name) {
        raw_name.to_string()
    } else {
        String::new()
    };
    let system = path.as_deref().is_some_and(is_system_executable);
    ProcInfo {
        name,
        path: path.unwrap_or_default(),
        location,
        system,
    }
}

fn usable_process_name(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty() && name != "unknown" && !name.starts_with("pid ")
}

fn display_name(raw: &str, pid: u32, info: Option<&ProcInfo>) -> String {
    if let Some(info) = info {
        if !info.name.is_empty() {
            return info.name.clone();
        }
    }
    if usable_process_name(raw) {
        return raw.to_string();
    }
    if let Some(info) = info {
        if !info.path.is_empty() {
            if let Some(name) = Path::new(&info.path).file_name() {
                let name = name.to_string_lossy();
                if !name.is_empty() {
                    return name.into_owned();
                }
            }
        }
    }
    format!("pid {pid}")
}

fn bundle_location_and_name(path: &str) -> (String, String) {
    let normalized = path.replace('\\', "/");
    if let Some(idx) = normalized.find(".app/") {
        let bundle = format!("{}.app", &normalized[..idx]);
        let name = Path::new(&bundle)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        return (bundle, name);
    }
    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    (path.to_string(), name)
}

pub(crate) fn is_system_executable(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    let p = p.as_str();
    p.starts_with("/system/")
        || p.starts_with("/usr/libexec/")
        || p.starts_with("/usr/sbin/")
        || p.starts_with("/sbin/")
        || p.starts_with("/usr/lib/")
        || p.starts_with("/usr/lib64/")
        || p.starts_with("/lib/")
        || p.starts_with("/lib64/")
        || p.starts_with("/usr/bin/")
        || p.starts_with("/bin/")
        || p.starts_with("/library/apple/")
        || p.contains("/system/library/")
        || p.contains("/windows/system32/")
        || p.contains("/windows/syswow64/")
        || p.contains("/windows/winsxs/")
        // Packaged OS shells (Start Menu, Settings, …) live under SystemApps /
        // WindowsApps, not System32 — still not safe kill targets.
        || p.contains("/windows/systemapps/")
        || p.contains("/program files/windowsapps/")
        || p.contains("/windows/immersivecontrolpanel/")
}

pub(crate) fn pid_executable_path(pid: u32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        return macos_pid_path(pid);
    }
    #[cfg(target_os = "linux")]
    {
        let link = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        return Some(link.to_string_lossy().into_owned());
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_pid_path(pid: u32) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = unsafe {
        proc_pidpath(
            pid as i32,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn proc_pidpath(pid: i32, buffer: *mut libc::c_char, buffersize: u32) -> i32;
}

/// Reveal the on-disk location for a pid currently in the census.
pub fn reveal_pid(pid: u32) -> Result<String, String> {
    let watch = current();
    let location = watch
        .flows
        .iter()
        .find(|flow| flow.pid == pid && !flow.location.is_empty())
        .map(|flow| flow.location.clone())
        .ok_or_else(|| "No on-disk location for that process in the current census".to_string())?;
    reveal_location(&location)?;
    Ok(location)
}

fn reveal_location(location: &str) -> Result<(), String> {
    let path = PathBuf::from(location);
    if !path.exists() {
        return Err("That path is no longer on disk".into());
    }
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("open")
            .args(["-R", location])
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            return Ok(());
        }
        return Err("Could not reveal the path in Finder".into());
    }
    #[cfg(target_os = "windows")]
    {
        let status = Command::new("explorer")
            .arg(format!("/select,{location}"))
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            return Ok(());
        }
        return Err("Could not reveal the path in Explorer".into());
    }
    #[cfg(target_os = "linux")]
    {
        let dir = if path.is_dir() {
            path
        } else {
            path.parent().map(Path::to_path_buf).unwrap_or(path)
        };
        let status = Command::new("xdg-open")
            .arg(&dir)
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            return Ok(());
        }
        return Err("Could not open the path".into());
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Revealing paths is not supported on this OS".into())
    }
}

fn class_rank(class: &str) -> u8 {
    match class {
        "clearnet" => 0,
        "through_tor" => 1,
        "tor_transport" => 2,
        "lan" => 3,
        _ => 4,
    }
}

fn format_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        IpAddr::V4(v4) => format!("{v4}:{port}"),
    }
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    }
}

fn skip_stale_tcp(proto: &str, state: &str) -> bool {
    if proto != "tcp" {
        return false;
    }
    let compact: String = state
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    matches!(
        compact.as_str(),
        "TIMEWAIT" | "CLOSED" | "CLOSEWAIT" | "FINWAIT1" | "FINWAIT2" | "CLOSING" | "LASTACK"
    )
}

fn collapse_duplicate_flows(flows: Vec<EgressFlow>) -> Vec<EgressFlow> {
    let mut order = Vec::new();
    let mut by_key: HashMap<(u32, String, String, String, String), EgressFlow> = HashMap::new();
    for flow in flows {
        let key = (
            flow.pid,
            flow.proto.clone(),
            flow.remote.clone(),
            flow.direction.clone(),
            flow.class.clone(),
        );
        if let Some(existing) = by_key.get_mut(&key) {
            existing.count = existing.count.saturating_add(flow.count.max(1));
            if existing.local != flow.local {
                existing.local = "*".into();
            }
        } else {
            order.push(key.clone());
            by_key.insert(key, flow);
        }
    }
    order
        .into_iter()
        .filter_map(|key| by_key.remove(&key))
        .collect()
}

fn cap_rows_per_pid(flows: Vec<EgressFlow>) -> Vec<EgressFlow> {
    let mut seen: HashMap<u32, usize> = HashMap::new();
    let mut out = Vec::with_capacity(flows.len().min(MAX_ROWS));
    for flow in flows {
        let n = seen.entry(flow.pid).or_insert(0);
        if *n >= MAX_ROWS_PER_PID {
            continue;
        }
        *n += 1;
        out.push(flow);
    }
    out
}

fn classify(flow: &RawFlow, allowed: &HashSet<u32>) -> FlowClass {
    if allowed.contains(&flow.pid) {
        return FlowClass::TorTransport;
    }
    if is_tun_local(flow.local) {
        return FlowClass::ThroughOnionGate;
    }
    if flow.listen {
        if flow.local.is_loopback() && is_oniongate_port(flow.local_port) {
            return FlowClass::ThroughOnionGate;
        }
        return FlowClass::Local;
    }
    if flow.remote.is_loopback() || flow.local.is_loopback() {
        if is_oniongate_port(flow.remote_port) || is_oniongate_port(flow.local_port) {
            return FlowClass::ThroughOnionGate;
        }
        return FlowClass::Local;
    }
    if is_private_or_link_local(flow.remote) {
        return FlowClass::Lan;
    }
    FlowClass::Bypass
}

fn is_oniongate_port(port: u16) -> bool {
    matches!(
        port,
        SOCKS_PORT
            | ISOLATED_SOCKS_PORT
            | BROWSER_SOCKS_PORT
            | CONTROL_PORT
            | BROWSER_CONTROL_PORT
            | DNS_PORT
    )
}

fn is_private_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local() || v4.is_loopback() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_private_or_link_local(IpAddr::V4(v4)))
        }
    }
}

fn is_tun_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_in_net(v4, TUN_V4_NET, TUN_V4_PREFIX),
        IpAddr::V6(v6) => ipv6_in_net(v6, TUN_V6, TUN_V6_PREFIX),
    }
}

fn ipv4_in_net(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn ipv6_in_net(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

fn transport_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    pids.insert(std::process::id());
    if let Some(tor) = crate::tor::find_tor_binary() {
        pids.extend(pids_for_path(&tor));
    }
    if let Some(sing) = crate::deps::find_singbox() {
        pids.extend(pids_for_path(&sing));
    }
    for transport in [
        crate::tor::pt::Transport::Obfs4,
        crate::tor::pt::Transport::Snowflake,
        crate::tor::pt::Transport::Webtunnel,
        crate::tor::pt::Transport::Meek,
    ] {
        if let Some(pt) = crate::tor::pt::find_pt_binary(transport) {
            pids.extend(pids_for_path(&pt));
        }
    }
    if let Some(sf) = crate::snowflake::find_proxy_binary() {
        pids.extend(pids_for_path(&sf));
    }
    pids.extend(pids_for_name("oniongate_helper"));
    pids.extend(pids_for_name("oniongate-helper"));
    pids
}

fn pids_for_path(path: &Path) -> HashSet<u32> {
    pids_for_name(&path.display().to_string())
}

fn pids_for_name(needle: &str) -> HashSet<u32> {
    if needle.is_empty() {
        return HashSet::new();
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        return Command::new("pgrep")
            .args(["-f", needle])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|line| line.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default();
    }
    #[cfg(target_os = "windows")]
    {
        let escaped = needle.replace('\'', "''");
        let script = format!(
            "Get-CimInstance Win32_Process | Where-Object {{ $_.ExecutablePath -like '*{escaped}*' -or $_.Name -like '*{escaped}*' }} | Select-Object -ExpandProperty ProcessId"
        );
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .hide_console()
            .output()
            .ok()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|line| line.trim().parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = needle;
        HashSet::new()
    }
}

fn collect_sockets() -> Result<Vec<RawFlow>, String> {
    #[cfg(target_os = "macos")]
    {
        return collect_macos();
    }
    #[cfg(target_os = "linux")]
    {
        return collect_ss();
    }
    #[cfg(target_os = "windows")]
    {
        return collect_windows();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("Live connection watch is not supported on this OS".into())
    }
}

#[cfg(target_os = "macos")]
fn process_names() -> HashMap<u32, String> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,comm="])
        .output()
        .ok();
    let Some(output) = output else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let line = line.trim();
        let Some((pid, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if let Ok(pid) = pid.trim().parse::<u32>() {
            map.insert(pid, name.trim().to_string());
        }
    }
    map
}

#[cfg(target_os = "macos")]
fn flow_key(flow: &RawFlow) -> (u32, &'static str, IpAddr, u16, IpAddr, u16, bool) {
    (
        flow.pid,
        flow.proto,
        flow.local,
        flow.local_port,
        flow.remote,
        flow.remote_port,
        flow.listen,
    )
}

#[cfg(target_os = "macos")]
fn collect_macos() -> Result<Vec<RawFlow>, String> {
    let names = process_names();
    let mut rows = Vec::new();
    let mut seen = HashSet::new();

    let lsof = Command::new("/usr/sbin/lsof")
        .args(["+c", "0", "-nP", "-iTCP", "-iUDP"])
        .output()
        .or_else(|_| {
            Command::new("lsof")
                .args(["+c", "0", "-nP", "-iTCP", "-iUDP"])
                .output()
        });
    if let Ok(output) = lsof {
        if output.status.success() {
            for flow in parse_lsof(&String::from_utf8_lossy(&output.stdout)) {
                let key = flow_key(&flow);
                if seen.insert(key) {
                    rows.push(flow);
                }
            }
        }
    }

    for args in [["-anv", "-p", "tcp"], ["-anv", "-p", "udp"]] {
        let output = Command::new("netstat").args(args).output();
        if let Ok(output) = output {
            if output.status.success() {
                for mut flow in parse_darwin_netstat(&String::from_utf8_lossy(&output.stdout)) {
                    if flow.process == "unknown" || flow.process.is_empty() {
                        if let Some(name) = names.get(&flow.pid) {
                            flow.process = name.clone();
                        } else if flow.pid == 0 {
                            flow.process = "kernel".into();
                        } else {
                            flow.process = format!("pid {}", flow.pid);
                        }
                    }
                    let key = flow_key(&flow);
                    if seen.insert(key) {
                        rows.push(flow);
                    }
                }
            }
        }
    }

    if rows.is_empty() {
        return Err("Could not list sockets (lsof/netstat)".into());
    }
    Ok(rows)
}

#[cfg(target_os = "linux")]
fn collect_ss() -> Result<Vec<RawFlow>, String> {
    let output = Command::new("ss")
        .args(["-tulpnH"])
        .output()
        .map_err(|e| format!("Could not list sockets (ss): {e}"))?;
    if !output.status.success() {
        return Err("ss could not list sockets".into());
    }
    Ok(parse_ss(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(target_os = "windows")]
fn collect_windows() -> Result<Vec<RawFlow>, String> {
    let script = r#"
$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [pscustomobject]@{
    pid = $_.OwningProcess
    name = $(if ($p) { $p.ProcessName } else { 'pid ' + $_.OwningProcess })
    path = $(if ($p -and $p.Path) { $p.Path } else { '' })
    proto = 'tcp'
    state = $_.State
    local = $_.LocalAddress
    lport = $_.LocalPort
    remote = $_.RemoteAddress
    rport = $_.RemotePort
  }
}
$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [pscustomobject]@{
    pid = $_.OwningProcess
    name = $(if ($p) { $p.ProcessName } else { 'pid ' + $_.OwningProcess })
    path = $(if ($p -and $p.Path) { $p.Path } else { '' })
    proto = 'udp'
    state = 'Listen'
    local = $_.LocalAddress
    lport = $_.LocalPort
    remote = '0.0.0.0'
    rport = 0
  }
}
@($tcp) + @($udp) | ConvertTo-Json -Compress
"#;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .hide_console()
        .output()
        .map_err(|e| format!("Could not list sockets: {e}"))?;
    if !output.status.success() {
        return Err("Could not list sockets".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_windows_json(text.trim()))
}

fn parse_lsof(text: &str) -> Vec<RawFlow> {
    let mut rows = Vec::new();
    for line in text.lines().skip(1) {
        if let Some(flow) = parse_lsof_line(line) {
            rows.push(flow);
        }
    }
    rows
}

fn parse_lsof_line(line: &str) -> Option<RawFlow> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }
    let process = parts[0].to_string();
    let pid = parts[1].parse().ok()?;
    let proto_idx = parts.iter().position(|p| *p == "TCP" || *p == "UDP")?;
    let proto = if parts[proto_idx] == "UDP" {
        "udp"
    } else {
        "tcp"
    };
    let spec = parts.get(proto_idx + 1)?;
    let state = parts.get(proto_idx + 2).copied().unwrap_or("");
    if skip_stale_tcp(proto, state) {
        return None;
    }
    let listen = state.contains("LISTEN") || (proto == "udp" && !spec.contains("->"));
    let (local, local_port, remote, remote_port) = parse_lsof_name(spec)?;
    Some(RawFlow {
        process,
        pid,
        proto,
        listen: listen || remote.is_unspecified(),
        local,
        local_port,
        remote,
        remote_port,
        path: String::new(),
    })
}

fn parse_lsof_name(spec: &str) -> Option<(IpAddr, u16, IpAddr, u16)> {
    if let Some((left, right)) = spec.split_once("->") {
        let (local, local_port) = parse_endpoint(left)?;
        let (remote, remote_port) = parse_endpoint(right)?;
        return Some((local, local_port, remote, remote_port));
    }
    let (local, local_port) = parse_endpoint(spec)?;
    Some((local, local_port, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

fn parse_darwin_netstat(text: &str) -> Vec<RawFlow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(flow) = parse_darwin_netstat_line(line) {
            rows.push(flow);
        }
    }
    rows
}

fn parse_darwin_netstat_line(line: &str) -> Option<RawFlow> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let proto_raw = parts[0];
    let proto = if proto_raw.starts_with("tcp") {
        "tcp"
    } else if proto_raw.starts_with("udp") {
        "udp"
    } else {
        return None;
    };
    let (local, local_port) = parse_darwin_addr(parts[3])?;
    let (remote, remote_port) = parse_darwin_addr(parts[4])?;
    let (listen, rest_at) = if proto == "tcp" {
        let state = parts.get(5).copied().unwrap_or("");
        if skip_stale_tcp(proto, state) {
            return None;
        }
        let listen = state.eq_ignore_ascii_case("LISTEN");
        (listen, 6usize)
    } else {
        (remote.is_unspecified() || remote_port == 0, 5usize)
    };
    let (process, pid) = parse_darwin_process_pid(&parts, rest_at);
    Some(RawFlow {
        process,
        pid,
        proto,
        listen,
        local,
        local_port,
        remote,
        remote_port,
        path: String::new(),
    })
}

/// Current macOS `netstat -anv` prints `name:pid` after byte counters.
/// Older builds printed a bare pid as the third integer after the state.
fn parse_darwin_process_pid(parts: &[&str], start: usize) -> (String, u32) {
    let mut ints = Vec::new();
    let mut i = start;
    while i < parts.len() && parts[i].chars().all(|c| c.is_ascii_digit()) {
        if let Ok(n) = parts[i].parse::<u32>() {
            ints.push(n);
        }
        i += 1;
    }
    let mut name_parts = Vec::new();
    while i < parts.len() {
        let tok = parts[i];
        if tok.starts_with("0x") {
            break;
        }
        if let Some((head, pid_s)) = tok.rsplit_once(':') {
            if !pid_s.is_empty() && pid_s.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(pid) = pid_s.parse::<u32>() {
                    if !head.is_empty() {
                        name_parts.push(head);
                    }
                    return (name_parts.join(" "), pid);
                }
            }
        }
        name_parts.push(tok);
        i += 1;
    }
    let pid = ints.get(2).copied().unwrap_or(0);
    (String::new(), pid)
}

fn parse_darwin_addr(spec: &str) -> Option<(IpAddr, u16)> {
    if spec == "*.*" || spec == "*" {
        return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    }
    if let Some(port) = spec.strip_prefix("*.") {
        return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), port.parse().ok()?));
    }
    let (ip, port) = spec.rsplit_once('.')?;
    let ip = if ip.starts_with('[') {
        ip.trim_matches(['[', ']']).parse().ok()?
    } else {
        ip.parse().ok()?
    };
    Some((canonicalize_ip(ip), port.parse().ok()?))
}

#[cfg(any(test, target_os = "linux"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_ss(text: &str) -> Vec<RawFlow> {
    let mut rows = Vec::new();
    for line in text.lines() {
        if let Some(flow) = parse_ss_line(line) {
            rows.push(flow);
        }
    }
    rows
}

#[cfg(any(test, target_os = "linux"))]
fn parse_ss_line(line: &str) -> Option<RawFlow> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let (state_or_recv, local_idx) = if parts[0].chars().all(|c| c.is_ascii_digit()) {
        ("ESTAB", 2usize)
    } else {
        (parts[0], 3usize)
    };
    if parts.len() <= local_idx + 1 {
        return None;
    }
    let proto = if line.contains("udp") || parts[0].eq_ignore_ascii_case("UNCONN") {
        "udp"
    } else {
        "tcp"
    };
    let listen = state_or_recv.eq_ignore_ascii_case("LISTEN")
        || state_or_recv.eq_ignore_ascii_case("UNCONN");
    if skip_stale_tcp(proto, state_or_recv) {
        return None;
    }
    let (local, local_port) = parse_endpoint(parts[local_idx])?;
    let (remote, remote_port) = parse_endpoint(parts[local_idx + 1])?;
    let rest = parts
        .get(local_idx + 2)
        .map(|_| parts[local_idx + 2..].join(" "))
        .unwrap_or_default();
    let pid = rest
        .split("pid=")
        .nth(1)
        .and_then(|s| s.split([',', ')']).next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let process = rest
        .split("((\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("unknown")
        .to_string();
    Some(RawFlow {
        process,
        pid,
        proto,
        listen,
        local,
        local_port,
        remote,
        remote_port,
        path: String::new(),
    })
}

#[cfg(target_os = "windows")]
fn parse_windows_json(text: &str) -> Vec<RawFlow> {
    if text.is_empty() {
        return Vec::new();
    }
    let value: serde_json::Value = serde_json::from_str(text).unwrap_or(serde_json::Value::Null);
    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(_) => vec![value],
        _ => return Vec::new(),
    };
    let mut rows = Vec::new();
    for item in items {
        let pid = item.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let process = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let proto = if item.get("proto").and_then(|v| v.as_str()) == Some("udp") {
            "udp"
        } else {
            "tcp"
        };
        let state = item.get("state").and_then(|v| v.as_str()).unwrap_or("");
        if skip_stale_tcp(proto, state) {
            continue;
        }
        let listen = state.eq_ignore_ascii_case("Listen");
        let Some(local) = item
            .get("local")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .map(canonicalize_ip)
        else {
            continue;
        };
        let local_port = item.get("lport").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let remote = item
            .get("remote")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .map(canonicalize_ip)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let remote_port = item.get("rport").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let path = item
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        rows.push(RawFlow {
            process,
            pid,
            proto,
            listen,
            local,
            local_port,
            remote,
            remote_port,
            path,
        });
    }
    rows
}

fn parse_endpoint(spec: &str) -> Option<(IpAddr, u16)> {
    let spec = spec.trim();
    if spec == "*" || spec == "*:*" || spec == "0.0.0.0:*" {
        return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    }
    if let Some(port) = spec.strip_prefix("*:") {
        return Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), port.parse().ok()?));
    }
    if let Some(rest) = spec.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        return Some((canonicalize_ip(ip.parse().ok()?), port.parse().ok()?));
    }
    let (ip, port) = spec.rsplit_once(':')?;
    Some((canonicalize_ip(ip.parse().ok()?), port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(process: &str, pid: u32, local: &str, remote: &str, remote_port: u16) -> RawFlow {
        RawFlow {
            process: process.into(),
            pid,
            proto: "tcp",
            listen: false,
            local: local.parse().unwrap(),
            local_port: 49152,
            remote: remote.parse().unwrap(),
            remote_port,
            path: String::new(),
        }
    }

    #[test]
    fn socks_loopback_is_through_oniongate() {
        let allowed = HashSet::new();
        let f = flow("firefox", 9, "127.0.0.1", "127.0.0.1", SOCKS_PORT);
        assert_eq!(classify(&f, &allowed), FlowClass::ThroughOnionGate);
        let f = flow("firefox", 9, "127.0.0.1", "127.0.0.1", BROWSER_SOCKS_PORT);
        assert_eq!(classify(&f, &allowed), FlowClass::ThroughOnionGate);
    }

    #[test]
    fn tun_local_address_is_through_oniongate() {
        let allowed = HashSet::new();
        let f = flow("chrome", 11, "172.19.0.2", "1.1.1.1", 443);
        assert_eq!(classify(&f, &allowed), FlowClass::ThroughOnionGate);
    }

    #[test]
    fn public_ip_from_app_is_bypass() {
        let allowed = HashSet::new();
        let f = flow("Slack", 22, "192.168.1.20", "8.8.8.8", 443);
        assert_eq!(classify(&f, &allowed), FlowClass::Bypass);
    }

    #[test]
    fn tor_pid_to_guard_is_transport() {
        let mut allowed = HashSet::new();
        allowed.insert(100);
        let f = flow("tor", 100, "192.168.1.20", "199.7.91.13", 443);
        assert_eq!(classify(&f, &allowed), FlowClass::TorTransport);
    }

    #[test]
    fn lan_stays_lan() {
        let allowed = HashSet::new();
        let f = flow("smb", 4, "192.168.1.20", "192.168.1.1", 445);
        assert_eq!(classify(&f, &allowed), FlowClass::Lan);
    }

    #[test]
    fn parse_lsof_ipv4_ipv6_and_listen() {
        let text = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
firefox  99 adam 12u IPv4 0x1 0t0 TCP 192.168.1.5:49152->8.8.8.8:443 (ESTABLISHED)
chrome   88 adam 13u IPv6 0x2 0t0 TCP [2001:db8::1]:5555->[2001:db8::2]:443 (ESTABLISHED)
tor      10 adam 6u  IPv4 0x3 0t0 TCP *:9050 (LISTEN)
mDNS     7  adam 4u  IPv4 0x4 0t0 UDP *:5353
";
        let rows = parse_lsof(text);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].process, "firefox");
        assert_eq!(rows[0].remote_port, 443);
        assert!(!rows[0].listen);
        assert_eq!(rows[1].remote, "2001:db8::2".parse::<IpAddr>().unwrap());
        assert!(rows[2].listen);
        assert_eq!(rows[2].local_port, 9050);
        assert!(rows[3].listen);
        assert_eq!(rows[3].proto, "udp");
    }

    #[test]
    fn parse_ss_users_field() {
        let line = r#"0  0  192.168.1.5:49152  8.8.8.8:443  users:(("firefox",pid=99,fd=12))"#;
        let flow = parse_ss_line(line).expect("ss line");
        assert_eq!(flow.process, "firefox");
        assert_eq!(flow.pid, 99);
        assert_eq!(flow.remote_port, 443);
    }

    #[test]
    fn parse_darwin_netstat_tcp_and_udp() {
        let tcp = "tcp4       0      0  127.0.0.1.9050         127.0.0.1.52918        ESTABLISHED 131072 131072  4012     0 0x0100 0x00000008";
        let listen = "tcp4       0      0  *.80                   *.*                    LISTEN      131072  131072    80      0 0x0100 0x00000106";
        let udp = "udp4       0      0  *.5353                 *.*                                196724   9216   123     0 0x0100 0x00000000";
        let t = parse_darwin_netstat_line(tcp).expect("tcp");
        assert_eq!(t.pid, 4012);
        assert_eq!(t.local_port, 9050);
        assert_eq!(t.remote_port, 52918);
        assert!(!t.listen);
        let l = parse_darwin_netstat_line(listen).expect("listen");
        assert!(l.listen);
        assert_eq!(l.local_port, 80);
        assert_eq!(l.pid, 80);
        let u = parse_darwin_netstat_line(udp).expect("udp");
        assert_eq!(u.proto, "udp");
        assert_eq!(u.local_port, 5353);
        assert_eq!(u.pid, 123);
    }

    #[test]
    fn parse_darwin_netstat_modern_name_pid() {
        let tcp = "tcp4       0      0  192.168.50.166.53517   104.18.19.125.443      ESTABLISHED          152            2  131072  131072              Slack:4242  00102 00000004 00000000000ddf72 00000080 01000800      2      0 000000";
        let t = parse_darwin_netstat_line(tcp).expect("tcp");
        assert_eq!(t.pid, 4242);
        assert_eq!(t.process, "Slack");
        assert_eq!(t.remote_port, 443);
        let spaced = "tcp4       0      0  127.0.0.1.62263        127.0.0.1.9050         ESTABLISHED           56           24  408300  146988 Cursor Helper (P:22437  00102 00000100 00000000000ddf71 20000081 04000800      3      0 000004";
        let s = parse_darwin_netstat_line(spaced).expect("spaced");
        assert_eq!(s.pid, 22437);
        assert_eq!(s.process, "Cursor Helper (P");
        let udp = "udp4       0      0  *.53483                *.*                                           0        32409  786896    9216          syslogd:369    00180 00000000 00000000000ddb15 20000000 04002800      2      0 000002";
        let u = parse_darwin_netstat_line(udp).expect("udp");
        assert_eq!(u.pid, 369);
        assert_eq!(u.process, "syslogd");
        let tor = "tcp4       0      0  192.168.50.166.52168   88.99.144.235.9001     ESTABLISHED            0            0  131072  131072              tor:55550  00102 00000004";
        let g = parse_darwin_netstat_line(tor).expect("tor");
        assert_eq!(g.pid, 55550);
        assert_eq!(g.process, "tor");
        assert_eq!(g.remote_port, 9001);
    }

    #[test]
    fn system_paths_and_app_bundles() {
        assert!(is_system_executable("/usr/libexec/apsd"));
        assert!(is_system_executable(
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        ));
        assert!(is_system_executable(r"C:\Windows\System32\svchost.exe"));
        assert!(is_system_executable(
            r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe"
        ));
        assert!(is_system_executable(
            r"C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.0.0.0_x64__8wekyb3d8bbwe\CalculatorApp.exe"
        ));
        assert!(!is_system_executable(
            r"C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe"
        ));
        assert!(!is_system_executable(
            "/Applications/Slack.app/Contents/MacOS/Slack"
        ));
        assert!(!is_system_executable("/usr/local/bin/node"));
        let (loc, name) = bundle_location_and_name(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        );
        assert_eq!(loc, "/Applications/Google Chrome.app");
        assert_eq!(name, "Google Chrome");
    }

    fn sample_flow(process: &str, pid: u32, class: &str, remote: &str, system: bool) -> EgressFlow {
        EgressFlow {
            process: process.into(),
            pid,
            proto: "tcp".into(),
            direction: "out".into(),
            local: "192.168.1.20:5555".into(),
            remote: remote.into(),
            class: class.into(),
            path: String::new(),
            location: String::new(),
            system,
            count: 1,
        }
    }

    #[test]
    fn snapshot_json_includes_destination() {
        let watch = {
            let mut w = EgressWatch::idle("t");
            w.flows
                .push(sample_flow("Slack", 1, "clearnet", "8.8.8.8:443", false));
            w
        };
        let json = serde_json::to_string(&watch).unwrap();
        assert!(json.contains("8.8.8.8:443"));
    }

    #[test]
    fn unique_clearnet_dedupes_pid_and_skips_protected() {
        let flows = vec![
            sample_flow("Slack", 4242, "clearnet", "8.8.8.8:443", false),
            sample_flow("Slack", 4242, "clearnet", "1.1.1.1:443", false),
            sample_flow("Finder", 99, "clearnet", "8.8.8.8:443", false),
            sample_flow("apsd", 77, "clearnet", "17.57.144.11:5223", true),
            sample_flow("firefox", 7, "through_tor", "127.0.0.1:9050", false),
        ];
        let procs = unique_clearnet_processes(&flows);
        assert_eq!(procs.len(), 3);
        let slack = procs.iter().find(|p| p.process == "Slack").unwrap();
        assert!(slack.killable);
        let finder = procs.iter().find(|p| p.process == "Finder").unwrap();
        assert!(!finder.killable);
        let apsd = procs.iter().find(|p| p.process == "apsd").unwrap();
        assert!(apsd.system);
        assert!(!apsd.killable);
    }

    #[test]
    fn stale_tcp_states_are_dropped() {
        assert!(skip_stale_tcp("tcp", "(TIME_WAIT)"));
        assert!(skip_stale_tcp("tcp", "TimeWait"));
        assert!(skip_stale_tcp("tcp", "CLOSE_WAIT"));
        assert!(!skip_stale_tcp("tcp", "(ESTABLISHED)"));
        assert!(!skip_stale_tcp("tcp", "SYN_SENT"));
        assert!(!skip_stale_tcp("udp", "TIME_WAIT"));
        let text = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
apsd     520 adam 12u IPv4 0x1 0t0 TCP 192.168.1.5:49152->17.57.144.11:5223 (ESTABLISHED)
apsd     520 adam 13u IPv4 0x2 0t0 TCP 192.168.1.5:49153->17.57.144.11:5223 (TIME_WAIT)
apsd     520 adam 14u IPv4 0x3 0t0 TCP 192.168.1.5:49154->17.57.144.11:5223 (CLOSE_WAIT)
";
        let rows = parse_lsof(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 520);
        assert_eq!(rows[0].local_port, 49152);
    }

    #[test]
    fn ipv4_mapped_addresses_canonicalize() {
        let mapped: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert_eq!(
            canonicalize_ip(mapped),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        let text = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
apsd 520 adam 12u IPv6 0x1 0t0 TCP [::ffff:192.168.1.5]:49152->[::ffff:8.8.8.8]:443 (ESTABLISHED)
";
        let rows = parse_lsof(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local, "192.168.1.5".parse::<IpAddr>().unwrap());
        assert_eq!(rows[0].remote, "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn collapse_same_pid_and_destination() {
        let mut a = sample_flow("apsd", 520, "clearnet", "17.57.144.11:5223", true);
        a.local = "192.168.1.5:1000".into();
        let mut b = sample_flow("apsd", 520, "clearnet", "17.57.144.11:5223", true);
        b.local = "192.168.1.5:1001".into();
        let mut c = sample_flow("apsd", 520, "clearnet", "1.1.1.1:443", true);
        c.local = "192.168.1.5:1002".into();
        let collapsed = collapse_duplicate_flows(vec![a, b, c]);
        assert_eq!(collapsed.len(), 2);
        let apple = collapsed
            .iter()
            .find(|f| f.remote == "17.57.144.11:5223")
            .unwrap();
        assert_eq!(apple.count, 2);
        assert_eq!(apple.local, "*");
        let other = collapsed
            .iter()
            .find(|f| f.remote == "1.1.1.1:443")
            .unwrap();
        assert_eq!(other.count, 1);
    }

    fn clearnet(process: &str, pid: u32, killable: bool) -> ClearnetProcess {
        ClearnetProcess {
            process: process.into(),
            pid,
            killable,
            path: format!("/Applications/{process}.app/Contents/MacOS/{process}"),
            location: format!("/Applications/{process}.app"),
            system: !killable,
            held: false,
        }
    }

    #[test]
    fn a_clearnet_pid_is_announced_once_and_never_again() {
        let mut announced = HashSet::new();
        let sample = vec![clearnet("Slack", 4242, true)];
        let first = take_new_announcements(&mut announced, &sample);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].pid, 4242);
        // The same process keeps showing up in every 2s sample; it must not
        // re-nag once it has been announced.
        assert!(take_new_announcements(&mut announced, &sample).is_empty());
        assert!(take_new_announcements(&mut announced, &sample).is_empty());
    }

    #[test]
    fn a_burst_collapses_into_one_payload() {
        let mut announced = HashSet::new();
        let burst = vec![
            clearnet("Slack", 1, true),
            clearnet("Discord", 2, true),
            clearnet("Spotify", 3, true),
        ];
        // One payload with all three, not three payloads (one window per pid).
        let fresh = take_new_announcements(&mut announced, &burst);
        assert_eq!(fresh.len(), 3);
        assert_eq!(announced.len(), 3);

        // A fourth process joining the burst announces only itself.
        let mut later = burst.clone();
        later.push(clearnet("Zoom", 4, true));
        let fresh = take_new_announcements(&mut announced, &later);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].pid, 4);
    }

    #[test]
    fn unkillable_processes_are_never_announced() {
        let mut announced = HashSet::new();
        let sample = vec![
            clearnet("apsd", 77, false),
            clearnet("Finder", 88, false),
            clearnet("Slack", 99, true),
        ];
        let fresh = take_new_announcements(&mut announced, &sample);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].process, "Slack");
        assert_eq!(announced.len(), 1);
    }

    #[test]
    fn only_a_protected_session_with_alerts_on_announces() {
        use crate::session::SessionPhase;

        assert!(should_announce(true, SessionPhase::Protected));
        // Opt-out setting wins even while protected.
        assert!(!should_announce(false, SessionPhase::Protected));
        // Clearnet during connect or teardown is expected, not a surprise.
        for phase in [
            SessionPhase::Disconnected,
            SessionPhase::Connecting,
            SessionPhase::Degraded,
            SessionPhase::Recovering,
        ] {
            assert!(!should_announce(true, phase));
        }
    }

    #[test]
    fn announcements_stop_rather_than_forget_at_the_ceiling() {
        let mut announced: HashSet<u32> = (0..MAX_ANNOUNCED as u32).collect();
        let fresh = take_new_announcements(&mut announced, &[clearnet("Slack", 999_999, true)]);
        assert!(fresh.is_empty());
        assert_eq!(announced.len(), MAX_ANNOUNCED);
    }

    /// Exercises the real process-wide announcement set. No other test touches
    /// it, so the parallel runner cannot interleave here.
    #[test]
    fn teardown_resets_the_announced_set() {
        if let Ok(mut announced) = ANNOUNCED.lock() {
            announced.insert(4242);
        }
        reset_announced();
        assert!(ANNOUNCED.lock().unwrap().is_empty());
        // Idempotent: a second teardown has nothing to dismiss.
        reset_announced();
        assert!(ANNOUNCED.lock().unwrap().is_empty());
    }

    #[test]
    fn cap_prevents_one_pid_from_filling_the_table() {
        let flows: Vec<EgressFlow> = (0..80)
            .map(|i| sample_flow("apsd", 520, "clearnet", &format!("203.0.113.{i}:443"), true))
            .collect();
        let capped = cap_rows_per_pid(flows);
        assert_eq!(capped.len(), MAX_ROWS_PER_PID);
        assert!(capped.iter().all(|f| f.pid == 520));
    }
}
