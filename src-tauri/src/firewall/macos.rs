use std::fs;
use std::process::Stdio;

use tokio::process::Command;

use super::{FirewallStatus, NetworkLockStatus};

const KS_ANCHOR: &str = "tor.socks.gui";
const LOCK_ANCHOR: &str = "tor.socks.gui.lock";

fn rules_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::tor::process::ensure_data_dir()?;
    Ok(dir.join("pf-killswitch.conf"))
}

fn lock_rules_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::tor::process::ensure_data_dir()?;
    Ok(dir.join("pf-networklock.conf"))
}

fn marker_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::tor::process::ensure_data_dir()?;
    Ok(dir.join("killswitch.active"))
}

fn lock_marker_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::tor::process::ensure_data_dir()?;
    Ok(dir.join("networklock.active"))
}

fn live_anchor_blocks(anchor: &str, needle: &str) -> Option<bool> {
    std::process::Command::new("pfctl")
        .args(["-a", anchor, "-sr"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            let rules = String::from_utf8_lossy(&out.stdout);
            rules.contains(needle) && rules.contains("block")
        })
}

pub fn status() -> FirewallStatus {
    let marker_active =
        marker_path().ok().and_then(|p| fs::read_to_string(p).ok()) == Some("1".into());
    let live = live_anchor_blocks(KS_ANCHOR, "proto udp");
    let active = live.unwrap_or(marker_active);
    let verified_live = live.is_some();
    FirewallStatus {
        supported: true,
        active,
        verified_live,
        marker_active,
        detail: if active {
            if verified_live {
                "Kill switch on: live pf anchor blocks UDP/QUIC and clearnet IPv6".into()
            } else {
                "Kill-switch marker exists; live pf inspection requires permission".into()
            }
        } else if marker_active {
            "Recovery marker exists, but the pf anchor is not active".into()
        } else {
            "Kill switch inactive (live pf anchor inspected)".into()
        },
    }
}

pub fn network_lock_status() -> NetworkLockStatus {
    let marker_active =
        lock_marker_path().ok().and_then(|p| fs::read_to_string(p).ok()) == Some("1".into());
    let live = live_anchor_blocks(LOCK_ANCHOR, "inet6");
    let active = live.unwrap_or(marker_active);
    let verified_live = live.is_some();
    NetworkLockStatus {
        supported: true,
        active,
        verified_live,
        marker_active,
        detail: if active {
            if verified_live {
                "Network lock on: clearnet UDP/QUIC and IPv6 blocked during the transition".into()
            } else {
                "Network-lock marker exists; live pf inspection requires permission".into()
            }
        } else if marker_active {
            "Recovery marker exists, but the network-lock pf anchor is not active".into()
        } else {
            "Network lock inactive".into()
        },
    }
}

/// Steady-state: block clearnet UDP/QUIC and IPv6. Loopback stays open for Tor.
fn pf_rules() -> String {
    "\
# OnionGate — steady-state UDP/QUIC + IPv6 leak protection
pass out quick on lo0 all
pass out quick to 127.0.0.1
pass out quick to ::1
block drop out quick inet6 from any to any
block drop out quick proto udp from any to any
"
    .into()
}

/// Transition lock: same containment as the kill switch. TCP fail-closed during
/// the bootstrap window comes from quitting/suspending apps and, once TUN is
/// up, from sing-box `strict_route`. macOS pf cannot match Tor by executable
/// path, so a full TCP block here would also brick Tor's guard connections.
fn pf_lock_rules() -> String {
    "\
# OnionGate — transition network lock (UDP/QUIC + IPv6)
pass out quick on lo0 all
pass out quick to 127.0.0.1
pass out quick to ::1
block drop out quick inet6 from any to any
block drop out quick proto udp from any to any
"
    .into()
}

pub async fn enable() -> Result<String, String> {
    let path = rules_path()?;
    fs::write(&path, pf_rules()).map_err(|e| e.to_string())?;

    if crate::helper::client::available() {
        let via_helper = tokio::task::spawn_blocking(|| {
            crate::helper::client::request(&crate::helper::HelperRequest::KillSwitchEnable)
        })
        .await
        .map_err(|e| e.to_string())?;
        match via_helper {
            Ok(resp) if resp.ok => {}
            Ok(resp) => return Err(resp.message),
            Err(_) => {
                let script = format!(
                    "pfctl -a {KS_ANCHOR} -f {} && pfctl -e || true",
                    shell_escape(&path.display().to_string())
                );
                run_admin(&script).await?;
            }
        }
    } else {
        let script = format!(
            "pfctl -a {KS_ANCHOR} -f {} && pfctl -e || true",
            shell_escape(&path.display().to_string())
        );
        run_admin(&script).await?;
    }
    fs::write(marker_path()?, "1").map_err(|e| e.to_string())?;
    crate::logs::append("Kill switch enabled (macOS pf UDP + IPv6 block)");
    Ok("Kill switch enabled (UDP/QUIC and IPv6 blocked via pf)".into())
}

pub async fn disable() -> Result<String, String> {
    if crate::helper::client::available() {
        let via_helper = tokio::task::spawn_blocking(|| {
            crate::helper::client::request(&crate::helper::HelperRequest::KillSwitchDisable)
        })
        .await
        .map_err(|e| e.to_string())?;
        if let Ok(resp) = via_helper {
            if !resp.ok {
                return Err(resp.message);
            }
        } else {
            let script = format!("pfctl -a {KS_ANCHOR} -F all || true");
            run_admin(&script).await?;
        }
    } else {
        let script = format!("pfctl -a {KS_ANCHOR} -F all || true");
        run_admin(&script).await?;
    }
    let live = status();
    if live.verified_live && live.active {
        return Err("pf anchor still contains OnionGate rules after restore".into());
    }
    if let Ok(p) = marker_path() {
        let _ = fs::remove_file(p);
    }
    crate::logs::append("Kill switch disabled (macOS pf)");
    Ok("Kill switch disabled".into())
}

pub async fn enable_network_lock() -> Result<String, String> {
    let path = lock_rules_path()?;
    fs::write(&path, pf_lock_rules()).map_err(|e| e.to_string())?;

    if crate::helper::client::available() {
        let via_helper = tokio::task::spawn_blocking(|| {
            crate::helper::client::request(&crate::helper::HelperRequest::NetworkLockEnable {
                tor_path: String::new(),
            })
        })
        .await
        .map_err(|e| e.to_string())?;
        match via_helper {
            Ok(resp) if resp.ok => {}
            Ok(resp) => return Err(resp.message),
            Err(_) => {
                let script = format!(
                    "pfctl -a {LOCK_ANCHOR} -f {} && pfctl -e || true",
                    shell_escape(&path.display().to_string())
                );
                run_admin(&script).await?;
            }
        }
    } else {
        let script = format!(
            "pfctl -a {LOCK_ANCHOR} -f {} && pfctl -e || true",
            shell_escape(&path.display().to_string())
        );
        run_admin(&script).await?;
    }
    fs::write(lock_marker_path()?, "1").map_err(|e| e.to_string())?;
    crate::logs::append("Network lock enabled (macOS pf UDP + IPv6)");
    Ok("Network locked for the transition (UDP/QUIC and IPv6 blocked)".into())
}

pub async fn disable_network_lock() -> Result<String, String> {
    if crate::helper::client::available() {
        let via_helper = tokio::task::spawn_blocking(|| {
            crate::helper::client::request(&crate::helper::HelperRequest::NetworkLockDisable)
        })
        .await
        .map_err(|e| e.to_string())?;
        if let Ok(resp) = via_helper {
            if !resp.ok {
                return Err(resp.message);
            }
        } else {
            let script = format!("pfctl -a {LOCK_ANCHOR} -F all || true");
            run_admin(&script).await?;
        }
    } else {
        let script = format!("pfctl -a {LOCK_ANCHOR} -F all || true");
        run_admin(&script).await?;
    }
    let live = network_lock_status();
    if live.verified_live && live.active {
        return Err("network-lock pf anchor still active after restore".into());
    }
    if let Ok(p) = lock_marker_path() {
        let _ = fs::remove_file(p);
    }
    crate::logs::append("Network lock disabled (macOS pf)");
    Ok("Network lock cleared".into())
}

async fn run_admin(shell: &str) -> Result<(), String> {
    let status = Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "do shell script \"{}\" with administrator privileges",
            shell.replace('\\', "\\\\").replace('"', "\\\"")
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("Administrator authorization failed or was cancelled".into())
    }
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf_rules_block_clearnet_udp_and_ipv6_but_allow_loopback() {
        let rules = pf_rules();
        assert!(rules.contains("block drop out quick proto udp from any to any"));
        assert!(rules.contains("block drop out quick inet6 from any to any"));
        assert!(rules.contains("pass out quick on lo0 all"));
        assert!(rules.contains("pass out quick to 127.0.0.1"));
        assert!(rules.contains("pass out quick to ::1"));

        let first_block = rules
            .lines()
            .position(|l| l.starts_with("block drop"))
            .unwrap();
        for pass in rules
            .lines()
            .enumerate()
            .filter_map(|(index, line)| line.starts_with("pass").then_some(index))
        {
            assert!(
                pass < first_block,
                "loopback passes must precede the quick block rules"
            );
        }
    }

    #[test]
    fn lock_rules_match_transition_posture() {
        let rules = pf_lock_rules();
        assert!(rules.contains("block drop out quick inet6"));
        assert!(rules.contains("block drop out quick proto udp"));
        assert!(rules.contains("pass out quick to ::1"));
    }

    #[test]
    fn shell_escape_neutralises_quotes_and_metacharacters() {
        assert_eq!(shell_escape("/tmp/pf.conf"), "'/tmp/pf.conf'");
        assert_eq!(
            shell_escape("/tmp/a b/pf.conf"),
            "'/tmp/a b/pf.conf'",
            "spaces must stay inside the quotes"
        );
        assert_eq!(
            shell_escape("/tmp/'; rm -rf /; echo '"),
            "'/tmp/'\\''; rm -rf /; echo '\\'''"
        );
    }

    #[test]
    fn escaped_paths_survive_a_round_trip_through_sh() {
        let nasty = "/tmp/weird '$(id)` dir/pf.conf";
        let escaped = shell_escape(nasty);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {escaped}"))
            .output()
            .expect("sh runs");
        assert_eq!(String::from_utf8_lossy(&out.stdout), nasty);
    }
}
