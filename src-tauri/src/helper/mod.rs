//! Privileged helper protocol shared between the OnionGate app and the root
//! helper daemon (`oniongate-helper`).
//!
//! Security model:
//! - The daemon runs with elevated privileges, installed ONCE (macOS launchd
//!   daemon, Linux systemd service, Windows service). The app talks to it over a
//!   local IPC endpoint (Unix domain socket on macOS/Linux, named pipe on
//!   Windows).
//! - The daemon NEVER executes arbitrary shell/commands from the client. It
//!   accepts only the fixed, typed [`HelperRequest`] variants below, and the
//!   privileged rulesets are baked into the daemon — the client cannot supply
//!   command text, paths, or rules.
//! - On Unix the daemon authenticates the peer by uid (must match the console
//!   user). On macOS a signed helper also requires the peer's code signature
//!   (Team ID / `com.adamsiwiec.oniongate`). Unsigned debug builds stay UID-only.
//! - Anything the daemon executes is pinned: [`HelperRequest::TunStart`] carries
//!   routing intent, not a config, and the daemon generates the sing-box config
//!   itself, stores it root-owned, and execs a root-owned copy of sing-box that
//!   the installer placed outside any user-writable directory.
//! - The app-side [`client`] transparently reports "unavailable" when the helper
//!   is not installed/running, so callers fall back to the interactive
//!   elevation prompt and unsigned builds behave exactly as before.

use serde::{Deserialize, Serialize};

pub mod client;
pub mod identity;
pub mod service;

/// Stable service identifier used across platforms.
pub const HELPER_LABEL: &str = "com.adamsiwiec.oniongate.helper";

/// Unix domain socket the daemon listens on (macOS/Linux). Root-controlled dir.
#[cfg(unix)]
pub const SOCKET_PATH: &str = "/var/run/oniongate-helper.sock";

/// Windows named pipe the service listens on.
#[cfg(windows)]
pub const PIPE_NAME: &str = r"\\.\pipe\oniongate-helper";

/// Typed, whitelisted operations the daemon will perform with elevated
/// privileges. There is deliberately no "run arbitrary command" variant; each
/// operation applies a fixed, daemon-owned policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HelperRequest {
    /// Liveness/authorization probe.
    Ping,
    /// Apply the platform kill switch.
    /// Empty `tcp_endpoints` = UDP/QUIC + IPv6 only. Non-empty = macOS default-deny
    /// NIC lock synthesized by the helper from those IPs (never client pf text).
    KillSwitchEnable {
        #[serde(default)]
        tcp_endpoints: Vec<String>,
        #[serde(default)]
        tcp_exceptions: Vec<String>,
        #[serde(default)]
        allow_lan: bool,
    },
    /// Remove the platform kill switch.
    KillSwitchDisable,
    /// Apply the transition network lock (UDP/QUIC + IPv6; Windows also TCP).
    /// `tor_path` is required on Windows so Tor can still reach guards; it must
    /// be an absolute path whose final component is `tor` or `tor.exe`. Unix
    /// backends ignore it (pf/nft cannot match Tor by executable path).
    /// Non-empty `tcp_endpoints` on macOS load the same default-deny policy on
    /// the transition anchor so bootstrap is not an open TCP window.
    NetworkLockEnable {
        tor_path: String,
        #[serde(default)]
        tcp_endpoints: Vec<String>,
        #[serde(default)]
        tcp_exceptions: Vec<String>,
        #[serde(default)]
        allow_lan: bool,
    },
    /// Remove the transition network lock.
    NetworkLockDisable,
    /// Harvest recent pflog deny headers (macOS NIC lock). Message is JSON.
    DenyLogHarvest,
    /// SIGTERM, then SIGKILL, a single pid. The helper resolves the executable
    /// itself and refuses system / protected / OnionGate processes. Used for
    /// root VPN daemons (ExpressVPN and similar) that a user kill cannot stop.
    TerminatePid { pid: u32 },
    /// Quit an .app bundle: unload launchd jobs that exec it, then stop every
    /// process whose executable lives in that bundle. Client sends only a pid.
    StopApplication { pid: u32 },
    /// Bring up the sing-box TUN. The client sends routing intent only: the
    /// helper validates it, regenerates the sing-box config itself, writes it to
    /// a root-owned path of its own choosing, and execs the pinned sing-box
    /// copy. Neither the binary, the config, nor the log path comes from the
    /// client. macOS-only.
    TunStart { spec: TunSpec },
    /// Stop every process whose resolved executable is the pinned sing-box.
    /// macOS-only.
    TunStop,
    /// Randomize the primary Wi-Fi MAC address. Takes no arguments: the helper
    /// resolves the device and draws the address itself. macOS-only.
    MacRandomize,
    /// Power the primary Wi-Fi radio on or off. macOS-only.
    WifiSetPower { on: bool },
    /// Apply OS SOCKS to the live default-route service. The helper resolves
    /// services itself and only ever points at the baked-in local Tor listener.
    /// macOS-only. No client-supplied host, port, or service name.
    SocksEnable,
    /// Restore the helper-captured SOCKS snapshot, or turn off OnionGate SOCKS.
    /// macOS-only.
    SocksDisable,
}

/// Upper bound on the routed-application list the helper will accept. An
/// over-long list is rejected outright rather than truncated, so the tunnel can
/// never end up guarding fewer applications than the user asked for.
pub const MAX_ROUTED_APPS: usize = 64;

/// One routed application, reduced to exactly the three fields the sing-box
/// config builder reads. Carries no command line and no arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunRoutedApp {
    pub process_name: String,
    pub executable_path: String,
    pub circuit_epoch: u64,
}

/// Routing intent for [`HelperRequest::TunStart`]. This is deliberately *not* a
/// config path: the helper regenerates the sing-box config from these fields so
/// the privileged side never loads a document the client authored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunSpec {
    pub remote_dns: bool,
    pub strict_tcp_lock: bool,
    pub split_tunnel: bool,
    /// `only` or `except`; any other value is refused.
    pub app_routing_policy: String,
    pub circuit_epoch: u64,
    pub route_apps: Vec<TunRoutedApp>,
}

impl Default for TunSpec {
    fn default() -> Self {
        Self {
            remote_dns: true,
            strict_tcp_lock: false,
            split_tunnel: false,
            app_routing_policy: "only".into(),
            circuit_epoch: 0,
            route_apps: Vec::new(),
        }
    }
}

impl TunSpec {
    pub(crate) fn from_settings(settings: &crate::settings::AppSettings) -> Self {
        Self {
            remote_dns: settings.remote_dns,
            strict_tcp_lock: settings.strict_tcp_lock,
            split_tunnel: settings.split_tunnel,
            app_routing_policy: settings.app_routing_policy.clone(),
            circuit_epoch: settings.circuit_epoch,
            route_apps: settings
                .route_apps
                .iter()
                .map(|app| TunRoutedApp {
                    process_name: app.process_name.clone(),
                    executable_path: app.executable_path.clone(),
                    circuit_epoch: app.circuit_epoch,
                })
                .collect(),
        }
    }

    /// Root-side admission check. Every failure is a refusal — nothing is
    /// clamped, dropped, or rewritten into something the user did not ask for.
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self.app_routing_policy.as_str(), "only" | "except") {
            return Err(format!(
                "unknown app routing policy {:?}",
                self.app_routing_policy
            ));
        }
        if self.route_apps.len() > MAX_ROUTED_APPS {
            return Err(format!(
                "too many routed applications ({}, limit {MAX_ROUTED_APPS})",
                self.route_apps.len()
            ));
        }
        for app in &self.route_apps {
            if app.executable_path.is_empty() {
                if app.process_name.trim().is_empty() {
                    return Err(
                        "routed application has neither a process name nor an executable path"
                            .into(),
                    );
                }
                continue;
            }
            let path = std::path::Path::new(&app.executable_path);
            if !path.is_absolute() {
                return Err(format!(
                    "routed application path is not absolute: {}",
                    app.executable_path
                ));
            }
            if !path.exists() {
                return Err(format!(
                    "routed application path does not exist: {}",
                    app.executable_path
                ));
            }
        }
        Ok(())
    }
}

impl HelperRequest {
    pub fn kill_switch_udp() -> Self {
        Self::KillSwitchEnable {
            tcp_endpoints: Vec::new(),
            tcp_exceptions: Vec::new(),
            allow_lan: false,
        }
    }

    pub fn network_lock(tor_path: String) -> Self {
        Self::NetworkLockEnable {
            tor_path,
            tcp_endpoints: Vec::new(),
            tcp_exceptions: Vec::new(),
            allow_lan: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
}

impl HelperResponse {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
        }
    }
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
        }
    }
}

/// Status of the installed helper, surfaced to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperStatus {
    /// Whether the platform supports the helper.
    pub supported: bool,
    /// Whether the service is installed (registered with launchd/systemd/SCM).
    pub installed: bool,
    /// Whether the daemon is reachable right now.
    pub running: bool,
    pub detail: String,
}

/// Newline-delimited JSON framing. One request/response per line keeps the
/// protocol trivial to implement identically on both sides.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn decode<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, String> {
    serde_json::from_str(line.trim_end()).map_err(|e| e.to_string())
}

/// Root-side terminate used by `oniongate-helper`. The executable is resolved
/// live; the client cannot supply a path or command line.
pub fn execute_terminate_pid(pid: u32) -> HelperResponse {
    match crate::apps_lifecycle::helper_terminate_pid(pid) {
        Ok(msg) => HelperResponse::ok(msg),
        Err(e) => HelperResponse::err(e),
    }
}

pub fn execute_stop_application(pid: u32) -> HelperResponse {
    match crate::apps_lifecycle::helper_stop_application(pid) {
        Ok(msg) => HelperResponse::ok(msg),
        Err(e) => HelperResponse::err(e),
    }
}

const HELPER_SOCKS_RESTORE: &str = "/var/run/oniongate-socks-restore.json";

pub fn execute_socks_enable() -> HelperResponse {
    #[cfg(target_os = "macos")]
    {
        let mut saved = load_helper_socks_snapshot().unwrap_or_default();
        match crate::proxy::macos::enable_as_root(&mut saved) {
            Ok(msg) => match save_helper_socks_snapshot(&saved) {
                Ok(()) => HelperResponse::ok(msg),
                Err(e) => {
                    let _ = crate::proxy::macos::disable_as_root(&mut saved);
                    HelperResponse::err(e)
                }
            },
            Err(e) => HelperResponse::err(e),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        HelperResponse::err("system SOCKS via the helper is macOS-only")
    }
}

pub fn execute_socks_disable() -> HelperResponse {
    #[cfg(target_os = "macos")]
    {
        let mut saved = load_helper_socks_snapshot().unwrap_or_default();
        let result = crate::proxy::macos::disable_as_root(&mut saved);
        let _ = std::fs::remove_file(HELPER_SOCKS_RESTORE);
        match result {
            Ok(msg) => HelperResponse::ok(msg),
            Err(e) => HelperResponse::err(e),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        HelperResponse::err("system SOCKS via the helper is macOS-only")
    }
}

#[cfg(target_os = "macos")]
fn load_helper_socks_snapshot() -> Option<crate::proxy::SavedProxyState> {
    let raw = std::fs::read_to_string(HELPER_SOCKS_RESTORE).ok()?;
    serde_json::from_str(&raw).ok()
}

#[cfg(target_os = "macos")]
fn save_helper_socks_snapshot(saved: &crate::proxy::SavedProxyState) -> Result<(), String> {
    let raw = serde_json::to_vec(saved).map_err(|e| e.to_string())?;
    let temp = format!("{HELPER_SOCKS_RESTORE}.tmp");
    std::fs::write(&temp, raw).map_err(|e| format!("Failed to store SOCKS restore snapshot: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to protect SOCKS restore snapshot: {e}"))?;
    }
    std::fs::rename(&temp, HELPER_SOCKS_RESTORE)
        .map_err(|e| format!("Failed to commit SOCKS restore snapshot: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_as_tagged_json() {
        for req in [
            HelperRequest::Ping,
            HelperRequest::KillSwitchEnable {
                tcp_endpoints: vec![],
                tcp_exceptions: vec![],
                allow_lan: false,
            },
            HelperRequest::KillSwitchDisable,
            HelperRequest::NetworkLockEnable {
                tor_path: r"C:\OnionGate\tor.exe".into(),
                tcp_endpoints: vec![],
                tcp_exceptions: vec![],
                allow_lan: false,
            },
            HelperRequest::NetworkLockDisable,
            HelperRequest::DenyLogHarvest,
            HelperRequest::TerminatePid { pid: 529 },
            HelperRequest::StopApplication { pid: 529 },
            HelperRequest::TunStart {
                spec: TunSpec {
                    split_tunnel: true,
                    route_apps: vec![TunRoutedApp {
                        process_name: "signal".into(),
                        executable_path: String::new(),
                        circuit_epoch: 7,
                    }],
                    ..TunSpec::default()
                },
            },
            HelperRequest::TunStop,
            HelperRequest::MacRandomize,
            HelperRequest::WifiSetPower { on: true },
            HelperRequest::SocksEnable,
            HelperRequest::SocksDisable,
        ] {
            let line = encode(&req).unwrap();
            assert!(line.ends_with(b"\n"));
            let text = String::from_utf8(line).unwrap();
            let back: HelperRequest = decode(&text).unwrap();
            assert_eq!(back, req);
        }
    }

    #[test]
    fn kill_switch_enable_uses_snake_case_tag() {
        let text = String::from_utf8(
            encode(&HelperRequest::KillSwitchEnable {
                tcp_endpoints: vec![],
                tcp_exceptions: vec![],
                allow_lan: false,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(text.contains("\"op\":\"kill_switch_enable\""));
    }

    #[test]
    fn response_helpers_set_ok_flag() {
        assert!(HelperResponse::ok("x").ok);
        assert!(!HelperResponse::err("x").ok);
    }

    #[test]
    fn rejects_malformed_line() {
        assert!(decode::<HelperRequest>("not json").is_err());
    }

    /// The protocol boundary is the whole security model: the daemon only ever
    /// dispatches variants it names. A syntactically valid request with an
    /// operation tag the enum does not know — the shape an attacker who wants
    /// arbitrary execution would send — is a hard decode error, never a
    /// dispatchable request. A known tag whose field is the wrong type is
    /// refused rather than coerced into a best-effort value.
    #[test]
    fn the_protocol_boundary_refuses_unknown_and_mistyped_requests() {
        // There is deliberately no "run arbitrary command" variant.
        assert!(decode::<HelperRequest>(r#"{"op":"run_shell","cmd":"rm -rf /"}"#).is_err());
        assert!(decode::<HelperRequest>(r#"{"op":"exec","path":"/bin/sh"}"#).is_err());
        // A wrong-typed field is refused, not coerced.
        assert!(decode::<HelperRequest>(r#"{"op":"wifi_set_power","on":"yes"}"#).is_err());
        assert!(decode::<HelperRequest>(r#"{"op":"terminate_pid","pid":"root"}"#).is_err());
        // Missing the discriminant entirely is refused.
        assert!(decode::<HelperRequest>(r#"{"pid":529}"#).is_err());
    }

    /// The daemon authenticates the peer from kernel-attested credentials
    /// (`getpeereid` / `LOCAL_PEERPID` / `proc_pidpath` / code signature),
    /// never from the request body. Encode every variant and confirm the wire
    /// form carries no field a client could set to impersonate a uid, a pid's
    /// executable, or a code signature — the attestation cannot be supplied,
    /// and therefore cannot be spoofed, by the client.
    #[test]
    fn no_request_field_can_impersonate_peer_attestation() {
        let variants = [
            HelperRequest::Ping,
            HelperRequest::kill_switch_udp(),
            HelperRequest::KillSwitchDisable,
            HelperRequest::network_lock(String::new()),
            HelperRequest::NetworkLockDisable,
            HelperRequest::DenyLogHarvest,
            HelperRequest::TerminatePid { pid: 529 },
            HelperRequest::StopApplication { pid: 529 },
            HelperRequest::TunStart {
                spec: TunSpec::default(),
            },
            HelperRequest::TunStop,
            HelperRequest::MacRandomize,
            HelperRequest::WifiSetPower { on: true },
            HelperRequest::SocksEnable,
            HelperRequest::SocksDisable,
        ];
        for req in variants {
            let text = String::from_utf8(encode(&req).unwrap())
                .unwrap()
                .to_ascii_lowercase();
            for forbidden in [
                "peer",
                "euid",
                "egid",
                "\"uid\"",
                "\"gid\"",
                "team",
                "signature",
                "codesign",
                "identifier",
                "entitlement",
                "getpeereid",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{forbidden} must not be on the wire: {text}"
                );
            }
        }
    }

    #[test]
    fn invalid_endpoint_strings_are_rejected_by_strict_parser() {
        assert!(crate::firewall::strict::parse_ip("1.2.3.4; rm").is_err());
        assert!(crate::firewall::strict::parse_ip_list(&["not-an-ip".into()], 8).is_err());
    }

    #[test]
    fn terminate_pid_uses_snake_case_tag() {
        let text =
            String::from_utf8(encode(&HelperRequest::TerminatePid { pid: 529 }).unwrap()).unwrap();
        assert!(text.contains("\"op\":\"terminate_pid\""));
        assert!(text.contains("\"pid\":529"));
    }

    #[test]
    fn stop_application_uses_snake_case_tag() {
        let text = String::from_utf8(encode(&HelperRequest::StopApplication { pid: 529 }).unwrap())
            .unwrap();
        assert!(text.contains("\"op\":\"stop_application\""));
        assert!(text.contains("\"pid\":529"));
    }

    #[test]
    fn tun_requests_use_snake_case_tags() {
        let start = String::from_utf8(
            encode(&HelperRequest::TunStart {
                spec: TunSpec::default(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(start.contains("\"op\":\"tun_start\""));
        assert!(start.contains("\"app_routing_policy\":\"only\""));

        let stop = String::from_utf8(encode(&HelperRequest::TunStop).unwrap()).unwrap();
        assert!(stop.contains("\"op\":\"tun_stop\""));
    }

    #[test]
    fn wifi_requests_use_snake_case_tags() {
        let mac = String::from_utf8(encode(&HelperRequest::MacRandomize).unwrap()).unwrap();
        assert!(mac.contains("\"op\":\"mac_randomize\""));

        let power =
            String::from_utf8(encode(&HelperRequest::WifiSetPower { on: false }).unwrap()).unwrap();
        assert!(power.contains("\"op\":\"wifi_set_power\""));
        assert!(power.contains("\"on\":false"));
    }

    #[test]
    fn socks_requests_use_snake_case_tags_and_carry_no_target() {
        for req in [HelperRequest::SocksEnable, HelperRequest::SocksDisable] {
            let text = String::from_utf8(encode(&req).unwrap()).unwrap();
            assert!(
                text.contains("\"op\":\"socks_enable\"") || text.contains("\"op\":\"socks_disable\"")
            );
            for forbidden in ["service", "host", "port", "server", "networksetup"] {
                assert!(
                    !text.contains(forbidden),
                    "{forbidden} must not be on the wire: {text}"
                );
            }
        }
    }

    /// The TUN request carries routing intent only. A config, binary, or log
    /// path on the wire would hand the root side a client-authored document.
    #[test]
    fn tun_start_carries_no_paths_of_its_own() {
        let text = String::from_utf8(
            encode(&HelperRequest::TunStart {
                spec: TunSpec::default(),
            })
            .unwrap(),
        )
        .unwrap();
        for forbidden in ["config_path", "binary", "log_path", "singbox"] {
            assert!(
                !text.contains(forbidden),
                "{forbidden} must not be on the wire: {text}"
            );
        }
    }

    fn spec_with(apps: Vec<TunRoutedApp>) -> TunSpec {
        TunSpec {
            split_tunnel: true,
            route_apps: apps,
            ..TunSpec::default()
        }
    }

    #[test]
    fn spec_rejects_a_relative_executable_path() {
        let spec = spec_with(vec![TunRoutedApp {
            process_name: "signal".into(),
            executable_path: "../../bin/signal".into(),
            circuit_epoch: 0,
        }]);
        let err = spec.validate().unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn spec_rejects_a_missing_executable_path() {
        let spec = spec_with(vec![TunRoutedApp {
            process_name: "signal".into(),
            executable_path: "/nonexistent/oniongate/never/here".into(),
            circuit_epoch: 0,
        }]);
        assert!(spec.validate().is_err());
    }

    #[test]
    fn spec_rejects_an_unknown_routing_policy() {
        let spec = TunSpec {
            app_routing_policy: "everything".into(),
            ..TunSpec::default()
        };
        let err = spec.validate().unwrap_err();
        assert!(err.contains("policy"), "{err}");
    }

    #[test]
    fn spec_rejects_an_over_long_application_list() {
        let apps = (0..=MAX_ROUTED_APPS)
            .map(|i| TunRoutedApp {
                process_name: format!("app{i}"),
                ..TunRoutedApp::default()
            })
            .collect();
        let err = spec_with(apps).validate().unwrap_err();
        assert!(err.contains("too many"), "{err}");
    }

    #[test]
    fn spec_accepts_process_names_and_the_two_known_policies() {
        for policy in ["only", "except"] {
            let spec = TunSpec {
                app_routing_policy: policy.into(),
                split_tunnel: true,
                route_apps: vec![TunRoutedApp {
                    process_name: "signal".into(),
                    ..TunRoutedApp::default()
                }],
                ..TunSpec::default()
            };
            assert!(spec.validate().is_ok(), "{policy} must be accepted");
        }
    }
}
