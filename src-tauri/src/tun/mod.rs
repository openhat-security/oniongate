use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};

use crate::deps;
use crate::settings::AppSettings;
use crate::tor::process::ISOLATED_SOCKS_PORT;
use crate::tor::{DNS_PORT, SOCKS_HOST};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunStatus {
    pub supported: bool,
    pub running: bool,
    pub singbox_available: bool,
    pub singbox_path: Option<String>,
    pub config_path: Option<String>,
    pub detail: String,
}

fn app_dir() -> Result<PathBuf, String> {
    crate::tor::process::ensure_data_dir()
}

pub fn config_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("sing-box-tun.json"))
}

pub fn log_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("sing-box.log"))
}

/// sing-box 1.12 replaced the `address: "udp://host:port"` server form with typed
/// servers, and 1.13 refuses to start on the old one rather than warning.
fn dns_server(remote_dns: bool) -> (serde_json::Value, &'static str) {
    if remote_dns {
        (
            serde_json::json!({
                "type": "udp",
                "tag": "tor-dns",
                "server": SOCKS_HOST,
                "server_port": DNS_PORT,
                "detour": "direct"
            }),
            "tor-dns",
        )
    } else {
        (
            serde_json::json!({
                "type": "local",
                "tag": "system-dns"
            }),
            "system-dns",
        )
    }
}

/// Generate sing-box TUN → Tor SOCKS config (UDP/QUIC blocked).
pub fn write_config() -> Result<PathBuf, String> {
    let path = config_path()?;
    let settings = crate::settings::load();
    let log_output = log_path()?.display().to_string();
    let config = build_config(&settings, &log_output);
    let raw = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize sing-box config: {e}"))?;
    fs::write(&path, raw).map_err(|e| format!("Failed to write sing-box config: {e}"))?;
    Ok(path)
}

fn build_config(settings: &AppSettings, log_output: &str) -> serde_json::Value {
    let (dns_server, dns_tag) = dns_server(settings.remote_dns);

    let mut rules = vec![
        serde_json::json!({ "protocol": "quic", "outbound": "block" }),
        serde_json::json!({ "network": "udp", "port": 443, "outbound": "block" }),
        serde_json::json!({ "network": "udp", "outbound": "block" }),
    ];

    // Tor's own connection to a guard is a public destination, so without this it
    // falls through to `tor-socks` and is handed back to Tor, which dials the same
    // guard again. Sits after the UDP blocks so Tor gains no UDP path, and matches
    // on path so an unrelated binary named `tor` cannot claim the exemption.
    if let Some(tor) = crate::tor::find_tor_binary() {
        rules.push(serde_json::json!({
            "process_path": [tor.display().to_string()],
            "outbound": "direct"
        }));
    }

    rules.push(serde_json::json!({ "ip_is_private": true, "outbound": "direct" }));

    // Applications get no IPv6 path. This has to come after the private-address
    // rule so link-local and ULA still reach the LAN, and after the Tor exemption
    // so Tor can still reach guards over IPv6 on an IPv6-only network.
    rules.push(serde_json::json!({ "ip_version": 6, "outbound": "block" }));

    let mut outbounds = vec![
        serde_json::json!({
            "type": "socks",
            "tag": "tor-socks",
            "server": SOCKS_HOST,
            "server_port": ISOLATED_SOCKS_PORT,
            "version": "5",
            "username": "oniongate-default",
            "password": settings.circuit_epoch.to_string()
        }),
        serde_json::json!({ "type": "block", "tag": "block" }),
        serde_json::json!({ "type": "direct", "tag": "direct" }),
    ];

    let final_outbound = if settings.split_tunnel && !settings.route_apps.is_empty() {
        for (index, app) in settings.route_apps.iter().enumerate() {
            let tag = format!("tor-app-{index}");
            if settings.app_routing_policy == "only" {
                outbounds.push(serde_json::json!({
                    "type": "socks",
                    "tag": tag,
                    "server": SOCKS_HOST,
                    "server_port": ISOLATED_SOCKS_PORT,
                    "version": "5",
                    "username": format!("oniongate-{index}"),
                    "password": app.circuit_epoch.to_string()
                }));
            }
            let outbound = if settings.app_routing_policy == "only" {
                tag
            } else {
                "direct".into()
            };
            let mut rule = serde_json::json!({ "outbound": outbound });
            if !app.executable_path.is_empty() {
                rule["process_path"] = serde_json::json!([app.executable_path]);
            } else {
                rule["process_name"] = serde_json::json!([app.process_name]);
            }
            rules.insert(0, rule);
        }
        if settings.app_routing_policy == "only" {
            "direct"
        } else {
            "tor-socks"
        }
    } else {
        "tor-socks"
    };

    // Inbound `sniff` was removed in sing-box 1.13 in favour of a rule action, and
    // it has to stay ahead of everything so later rules can match sniffed traffic.
    rules.insert(0, serde_json::json!({ "action": "sniff" }));

    serde_json::json!({
        "log": {
            "level": "info",
            "output": log_output,
            "timestamp": true
        },
        "dns": {
            "servers": [dns_server],
            "final": dns_tag,
            // IPv6 egress is blocked, so handing applications AAAA records would
            // only produce connections that are refused. Never resolve them.
            "strategy": "ipv4_only"
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "torsocks0",
            // The IPv6 prefix exists so sing-box installs IPv6 routes and the
            // block rule above can reject that traffic. Without it, sing-box
            // installs no IPv6 route and IPv6 leaves via the physical interface.
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1500,
            "auto_route": true,
            "strict_route": true,
            "stack": "system"
        }],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": final_outbound,
            "auto_detect_interface": true
        }
    })
}

pub fn process_seems_running() -> bool {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        return std::process::Command::new("pgrep")
            .args(["-f", "sing-box run -c"])
            .output()
            .map(|o| o.status.success() && !o.stdout.is_empty())
            .unwrap_or(false);
    }
    #[cfg(target_os = "windows")]
    {
        return std::process::Command::new("tasklist.exe")
            .args(["/FI", "IMAGENAME eq sing-box.exe", "/NH"])
            .output()
            .map(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("sing-box.exe")
            })
            .unwrap_or(false);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Best-effort: TUN interface exists (macOS/Linux).
fn tun_iface_present() -> bool {
    #[cfg(target_os = "macos")]
    {
        // Preferred name from config; also accept any utun if sing-box is up.
        if std::process::Command::new("ifconfig")
            .arg("torsocks0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return true;
        }
        // sing-box on macOS often binds utun*; presence + process is enough.
        return process_seems_running();
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/sys/class/net/torsocks0").exists() || process_seems_running()
    }
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetAdapter -InterfaceAlias torsocks0 -ErrorAction SilentlyContinue",
            ])
            .output();
        output
            .map(|result| result.status.success() && !result.stdout.is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

async fn wait_until_running(timeout_ms: u64) -> bool {
    let steps = (timeout_ms / 200).max(1);
    for _ in 0..steps {
        if process_seems_running() && tun_iface_present() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    process_seems_running()
}

fn last_log_tail() -> String {
    let Ok(path) = log_path() else {
        return String::new();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return String::new();
    };
    raw.lines()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" | ")
}

pub fn status(child: &Option<Child>) -> TunStatus {
    let sing = deps::find_singbox();
    let managed_alive = child.as_ref().and_then(|c| c.id()).is_some();
    let running = managed_alive || process_seems_running();
    let supported = cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    ));
    TunStatus {
        supported,
        running,
        singbox_available: sing.is_some(),
        singbox_path: sing.as_ref().map(|p| p.display().to_string()),
        config_path: config_path().ok().map(|p| p.display().to_string()),
        detail: if !supported {
            "TUN mode is not supported on this OS yet".into()
        } else if sing.is_none() {
            deps::deps_status()
                .into_iter()
                .next()
                .map(|d| d.hint)
                .unwrap_or_else(|| "sing-box not found".into())
        } else if running {
            "TUN active (system traffic via sing-box → Tor SOCKS)".into()
        } else {
            "TUN idle — administrator approval required to start".into()
        },
    }
}

/// Start sing-box TUN. Requires root/admin; denial or failure does not soft-succeed.
pub async fn start(managed: &mut Option<Child>) -> Result<String, String> {
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = managed;
        return Err("TUN mode is only available on macOS and Linux".into());
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        if process_seems_running() {
            return Ok("TUN (sing-box) already running".into());
        }

        let sing = deps::find_singbox().ok_or_else(|| {
            let hint = deps::deps_status()
                .into_iter()
                .next()
                .map(|d| d.hint)
                .unwrap_or_default();
            format!("sing-box not found. {hint}")
        })?;
        let cfg = write_config()?;
        let log = log_path()?;
        // Truncate old log so we can spot fresh failures.
        let _ = fs::write(&log, "");

        crate::logs::append(format!("Starting sing-box TUN with {}", cfg.display()));

        // TUN requires privileges. Do NOT fall back to an unelevated spawn —
        // that can leave a process running without a real tunnel and look "connected".
        start_elevated(&sing, &cfg, &log).await?;
        *managed = None;

        if !wait_until_running(4000).await {
            let tail = last_log_tail();
            let hint = if tail.is_empty() {
                String::new()
            } else {
                format!(" Log: {tail}")
            };
            return Err(format!(
                "Administrator approval was denied or sing-box failed to create the TUN. Stay on Proxy mode, or approve the admin prompt and try again.{hint}"
            ));
        }

        Ok("TUN started with administrator privileges (sing-box → Tor SOCKS)".into())
    }
}

#[cfg(target_os = "macos")]
async fn start_elevated(
    sing: &std::path::Path,
    cfg: &std::path::Path,
    log: &std::path::Path,
) -> Result<String, String> {
    let shell = format!(
        "{} run -c {} >>{} 2>&1 & echo $!",
        shell_escape(&sing.display().to_string()),
        shell_escape(&cfg.display().to_string()),
        shell_escape(&log.display().to_string())
    );
    let output = Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "do shell script \"{}\" with administrator privileges",
            shell.replace('\\', "\\\\").replace('"', "\\\"")
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok("Elevated sing-box launch accepted".into())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        if msg.contains("User canceled") || msg.contains("-128") {
            Err("Administrator permission denied — TUN was not started".into())
        } else if msg.is_empty() {
            Err("Administrator launch failed or was cancelled — TUN was not started".into())
        } else {
            Err(format!("Administrator launch failed: {msg}"))
        }
    }
}

#[cfg(target_os = "linux")]
async fn start_elevated(
    sing: &std::path::Path,
    cfg: &std::path::Path,
    log: &std::path::Path,
) -> Result<String, String> {
    let bg = format!(
        "{} run -c {} >>{} 2>&1 &",
        shell_escape(&sing.display().to_string()),
        shell_escape(&cfg.display().to_string()),
        shell_escape(&log.display().to_string())
    );
    if which::which("pkexec").is_ok() {
        let output = Command::new("pkexec")
            .args(["sh", "-c", &bg])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if output.status.success() {
            return Ok("Elevated sing-box launch accepted".into());
        }
        return Err(
            "Administrator permission denied or pkexec failed — TUN was not started".into(),
        );
    }
    let output = Command::new("sudo")
        .args(["-n", "sh", "-c", &bg])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok("Elevated sing-box launch accepted".into())
    } else {
        Err("Need admin rights for TUN (pkexec or passwordless sudo). Permission denied — TUN was not started".into())
    }
}

#[cfg(target_os = "windows")]
async fn start_elevated(
    sing: &std::path::Path,
    cfg: &std::path::Path,
    _log: &std::path::Path,
) -> Result<String, String> {
    let sing = sing.display().to_string().replace('\'', "''");
    let cfg = cfg.display().to_string().replace('\'', "''");
    let script = format!(
        "Start-Process -FilePath '{sing}' -Verb RunAs -WindowStyle Hidden -ArgumentList 'run','-c','{cfg}'"
    );
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| e.to_string())?;
    status
        .success()
        .then_some("Elevated sing-box launch accepted".into())
        .ok_or_else(|| "Administrator permission denied — TUN was not started".into())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub async fn stop(managed: &mut Option<Child>) -> Result<String, String> {
    if let Some(mut child) = managed.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
        crate::logs::append("Stopped managed sing-box process");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let _ = Command::new("pkill")
            .args(["-f", "sing-box run -c"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        tokio::time::sleep(Duration::from_millis(350)).await;

        // Root-owned sing-box (from admin start) may ignore user pkill.
        if process_seems_running() {
            stop_elevated().await?;
            tokio::time::sleep(Duration::from_millis(350)).await;
        }

        if process_seems_running() {
            return Err(
                "sing-box is still running (likely needs admin to kill). Approve the prompt or run: sudo pkill -f 'sing-box run -c'"
                    .into(),
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("taskkill.exe")
            .args(["/IM", "sing-box.exe", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        tokio::time::sleep(Duration::from_millis(350)).await;
        if process_seems_running() {
            stop_elevated().await?;
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
        if process_seems_running() {
            return Err("sing-box.exe is still running after elevated Taskkill".into());
        }
    }

    Ok("Stopped TUN / sing-box".into())
}

#[cfg(target_os = "macos")]
async fn stop_elevated() -> Result<(), String> {
    let output = Command::new("osascript")
        .arg("-e")
        .arg("do shell script \"pkill -f 'sing-box run -c' || true\" with administrator privileges")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") || stderr.contains("-128") {
            Err("Administrator permission denied while stopping TUN".into())
        } else {
            Err("Failed to stop elevated sing-box".into())
        }
    }
}

#[cfg(target_os = "windows")]
async fn stop_elevated() -> Result<(), String> {
    let script =
        "Start-Process taskkill.exe -Verb RunAs -Wait -ArgumentList '/IM','sing-box.exe','/F'";
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| e.to_string())?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "Administrator permission denied while stopping TUN".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_dns_uses_the_udp_dnsport() {
        let (server, tag) = dns_server(true);
        assert_eq!(tag, "tor-dns");
        assert_eq!(server["type"], "udp");
        assert_eq!(server["server"], SOCKS_HOST);
        assert_eq!(server["server_port"], DNS_PORT);
    }

    #[test]
    fn disabled_remote_dns_uses_system_resolver() {
        let (server, tag) = dns_server(false);
        assert_eq!(tag, "system-dns");
        assert_eq!(server["type"], "local");
    }

    /// The legacy `address` form makes sing-box 1.13 exit fatally at startup.
    #[test]
    fn dns_servers_never_use_the_removed_address_form() {
        for remote in [true, false] {
            let (server, _) = dns_server(remote);
            assert!(
                server.get("address").is_none(),
                "legacy DNS address form is rejected by sing-box: {server}"
            );
        }
    }

    #[test]
    fn applications_get_no_ipv6_path() {
        let config = build_config(&AppSettings::default(), "/tmp/sing-box.log");
        let ipv6 = rules(&config)
            .iter()
            .position(|r| r["ip_version"] == 6 && r["outbound"] == "block")
            .expect("IPv6 must be blocked");
        let private = rules(&config)
            .iter()
            .position(|r| r["ip_is_private"] == true)
            .expect("private addresses must stay direct");

        // Ordering carries the meaning: LAN-local IPv6 has to be matched before
        // the block, otherwise link-local traffic dies with it.
        assert!(private < ipv6, "private rule must precede the IPv6 block");

        // Capturing IPv6 is what makes the block reachable at all.
        let addresses = config["inbounds"][0]["address"].as_array().unwrap();
        assert!(
            addresses.iter().any(|a| a.as_str().unwrap().contains(':')),
            "TUN needs an IPv6 prefix or IPv6 never enters the tunnel: {addresses:?}"
        );
        assert_eq!(config["dns"]["strategy"], "ipv4_only");
    }

    /// Routing Tor's own guard connections back into the tunnel hands them to
    /// Tor, which dials the same guard again.
    #[test]
    fn tor_traffic_is_exempt_from_the_tunnel() {
        let Some(tor) = crate::tor::find_tor_binary() else {
            return;
        };
        let config = build_config(&AppSettings::default(), "/tmp/sing-box.log");
        let all = rules(&config);
        let exemption = all
            .iter()
            .position(|r| {
                r["process_path"]
                    .as_array()
                    .is_some_and(|p| p.iter().any(|v| v == &tor.display().to_string()))
                    && r["outbound"] == "direct"
            })
            .expect("Tor must be exempt from the tunnel");
        let ipv6 = all
            .iter()
            .position(|r| r["ip_version"] == 6)
            .expect("IPv6 must be blocked");
        let udp = all
            .iter()
            .position(|r| r["network"] == "udp" && r.get("port").is_none())
            .expect("UDP must be blocked");

        // Before the IPv6 block so Tor still works on IPv6-only networks, after
        // the UDP block so the exemption grants Tor no UDP path.
        assert!(udp < exemption, "Tor must not gain a UDP path");
        assert!(exemption < ipv6, "Tor must still reach guards over IPv6");
    }

    /// Config schema drift is silent until sing-box refuses to start, which is a
    /// broken TUN mode rather than a failing build. Ask the shipped binary
    /// directly instead of asserting against a schema we remember.
    #[test]
    fn shipped_singbox_accepts_every_generated_config() {
        let Some(singbox) = deps::find_singbox() else {
            return;
        };

        let variants: [(&str, AppSettings); 3] = [
            ("default", AppSettings::default()),
            (
                "system dns",
                AppSettings {
                    remote_dns: false,
                    ..AppSettings::default()
                },
            ),
            (
                "split tunnel",
                AppSettings {
                    split_tunnel: true,
                    app_routing_policy: "only".into(),
                    route_apps: vec![app("a", "signal", 7)],
                    ..AppSettings::default()
                },
            ),
        ];

        for (label, settings) in variants {
            let config = build_config(&settings, "/tmp/sing-box-test.log");
            let path = std::env::temp_dir().join(format!(
                "oniongate-singbox-check-{}.json",
                label.replace(' ', "-")
            ));
            fs::write(&path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

            let output = std::process::Command::new(&singbox)
                .arg("check")
                .arg("-c")
                .arg(&path)
                .output()
                .expect("run sing-box check");
            let _ = fs::remove_file(&path);

            assert!(
                output.status.success(),
                "sing-box rejected the {label} config:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    use crate::settings::AppIdentity;

    fn app(id: &str, process: &str, epoch: u64) -> AppIdentity {
        AppIdentity {
            id: id.into(),
            label: id.into(),
            process_name: process.into(),
            circuit_epoch: epoch,
            ..AppIdentity::default()
        }
    }

    fn rules(config: &serde_json::Value) -> &Vec<serde_json::Value> {
        config["route"]["rules"].as_array().unwrap()
    }

    fn outbound_tags(config: &serde_json::Value) -> Vec<String> {
        config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tag"].as_str().unwrap().to_string())
            .collect()
    }

    /// Tunnelling UDP would leak past Tor, so every UDP path must hit `block`.
    #[test]
    fn udp_and_quic_are_always_blocked() {
        let config = build_config(&AppSettings::default(), "/tmp/sing-box.log");
        let blocked: Vec<&serde_json::Value> = rules(&config)
            .iter()
            .filter(|r| r["outbound"] == "block")
            .collect();
        assert!(blocked.iter().any(|r| r["protocol"] == "quic"));
        assert!(blocked
            .iter()
            .any(|r| r["network"] == "udp" && r["port"] == 443));
        assert!(blocked
            .iter()
            .any(|r| r["network"] == "udp" && r.get("port").is_none()));
    }

    #[test]
    fn default_settings_send_everything_through_tor() {
        let config = build_config(&AppSettings::default(), "/tmp/sing-box.log");
        assert_eq!(config["route"]["final"], "tor-socks");
        assert_eq!(config["outbounds"][0]["server_port"], ISOLATED_SOCKS_PORT);
        assert_eq!(config["inbounds"][0]["strict_route"], true);
    }

    /// `only` guards the listed apps: they get Tor, everything else goes direct.
    #[test]
    fn only_policy_routes_listed_apps_through_isolated_circuits() {
        let settings = AppSettings {
            split_tunnel: true,
            app_routing_policy: "only".into(),
            route_apps: vec![app("a", "signal", 7), app("b", "hexchat", 9)],
            ..AppSettings::default()
        };
        let config = build_config(&settings, "/tmp/sing-box.log");

        assert_eq!(config["route"]["final"], "direct");

        let tags = outbound_tags(&config);
        assert!(tags.contains(&"tor-app-0".to_string()));
        assert!(tags.contains(&"tor-app-1".to_string()));

        let app_rules: Vec<&serde_json::Value> = rules(&config)
            .iter()
            .filter(|r| r.get("process_name").is_some())
            .collect();
        assert_eq!(app_rules.len(), 2);
        for rule in app_rules {
            let out = rule["outbound"].as_str().unwrap();
            assert!(out.starts_with("tor-app-"), "{rule}");
        }
    }

    /// Distinct SOCKS credentials per app keep their circuits unlinkable.
    #[test]
    fn each_routed_app_gets_unique_socks_credentials() {
        let settings = AppSettings {
            split_tunnel: true,
            app_routing_policy: "only".into(),
            route_apps: vec![app("a", "signal", 7), app("b", "hexchat", 9)],
            ..AppSettings::default()
        };
        let config = build_config(&settings, "/tmp/sing-box.log");
        let creds: Vec<(String, String)> = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["type"] == "socks")
            .map(|o| {
                (
                    o["username"].as_str().unwrap().to_string(),
                    o["password"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let unique: std::collections::HashSet<&(String, String)> = creds.iter().collect();
        assert_eq!(unique.len(), creds.len(), "duplicate circuit credentials");
        assert!(creds.contains(&("oniongate-0".into(), "7".into())));
        assert!(creds.contains(&("oniongate-1".into(), "9".into())));
    }

    /// `except` inverts the policy: listed apps bypass Tor, the rest are guarded.
    #[test]
    fn except_policy_sends_listed_apps_direct_and_the_rest_via_tor() {
        let settings = AppSettings {
            split_tunnel: true,
            app_routing_policy: "except".into(),
            route_apps: vec![app("a", "zoom", 3)],
            ..AppSettings::default()
        };
        let config = build_config(&settings, "/tmp/sing-box.log");

        assert_eq!(config["route"]["final"], "tor-socks");
        let rule = rules(&config)
            .iter()
            .find(|r| r.get("process_name").is_some())
            .unwrap();
        assert_eq!(rule["outbound"], "direct");
        assert!(!outbound_tags(&config).contains(&"tor-app-0".to_string()));
    }

    /// A recorded executable path is a stronger identity than a process name.
    #[test]
    fn executable_path_is_preferred_over_process_name() {
        let settings = AppSettings {
            split_tunnel: true,
            route_apps: vec![AppIdentity {
                id: "a".into(),
                process_name: "signal".into(),
                executable_path: "/Applications/Signal.app/Contents/MacOS/Signal".into(),
                ..AppIdentity::default()
            }],
            ..AppSettings::default()
        };
        let config = build_config(&settings, "/tmp/sing-box.log");
        let rule = rules(&config)
            .iter()
            .find(|r| r.get("process_path").is_some())
            .unwrap();
        assert_eq!(
            rule["process_path"][0],
            "/Applications/Signal.app/Contents/MacOS/Signal"
        );
        assert!(rule.get("process_name").is_none());
    }

    /// Split tunnel with no apps selected must not silently drop the guard.
    #[test]
    fn empty_split_tunnel_still_routes_everything_through_tor() {
        let settings = AppSettings {
            split_tunnel: true,
            route_apps: Vec::new(),
            ..AppSettings::default()
        };
        let config = build_config(&settings, "/tmp/sing-box.log");
        assert_eq!(config["route"]["final"], "tor-socks");
    }
}

#[cfg(target_os = "linux")]
async fn stop_elevated() -> Result<(), String> {
    let script = "pkill -f 'sing-box run -c' || true";
    if which::which("pkexec").is_ok() {
        let status = Command::new("pkexec")
            .args(["sh", "-c", script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|e| e.to_string())?;
        if status.success() {
            return Ok(());
        }
        return Err("pkexec failed while stopping TUN".into());
    }
    let status = Command::new("sudo")
        .args(["-n", "sh", "-c", script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("Need admin rights to stop root-owned sing-box".into())
    }
}
