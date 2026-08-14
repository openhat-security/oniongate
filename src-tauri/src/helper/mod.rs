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
}
