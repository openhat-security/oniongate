use std::fs;
use std::process::Stdio;

use tokio::process::Command;

use super::{FirewallStatus, NetworkLockStatus};

const TABLE: &str = "tor_socks_gui_ks";
const LOCK_TABLE: &str = "tor_socks_gui_lock";

fn marker_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::tor::process::ensure_data_dir()?;
    Ok(dir.join("killswitch.active"))
}

fn lock_marker_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::tor::process::ensure_data_dir()?;
    Ok(dir.join("networklock.active"))
}

fn table_live(table: &str, needle: &str) -> Option<bool> {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            let rules = String::from_utf8_lossy(&out.stdout);
            rules.contains("hook output") && rules.contains(needle) && rules.contains("drop")
        })
}

pub fn status() -> FirewallStatus {
    let marker_active =
        marker_path().ok().and_then(|p| fs::read_to_string(p).ok()) == Some("1".into());
    let live = table_live(TABLE, "udp");
    let active = live.unwrap_or(marker_active);
    let verified_live = live.is_some();
    FirewallStatus {
        supported: true,
        active,
        verified_live,
        marker_active,
        detail: if active {
            if verified_live {
                "Kill switch on: live nftables table blocks UDP/QUIC and clearnet IPv6".into()
            } else {
                "Kill-switch marker exists; live nftables inspection requires permission".into()
            }
        } else if marker_active {
            "Recovery marker exists, but the nftables table is not active".into()
        } else {
            "Kill switch inactive (live nftables table inspected)".into()
        },
    }
}

pub fn network_lock_status() -> NetworkLockStatus {
    let marker_active =
        lock_marker_path().ok().and_then(|p| fs::read_to_string(p).ok()) == Some("1".into());
    let live = table_live(LOCK_TABLE, "ip6");
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
                "Network-lock marker exists; live nftables inspection requires permission".into()
            }
        } else if marker_active {
            "Recovery marker exists, but the network-lock table is not active".into()
        } else {
            "Network lock inactive".into()
        },
    }
}

fn nft_script_enable(table: &str) -> String {
    format!(
        "\
nft list table inet {table} >/dev/null 2>&1 && nft delete table inet {table} || true
nft add table inet {table}
nft 'add chain inet {table} output {{ type filter hook output priority 0; policy accept; }}'
nft add rule inet {table} output oif lo accept
nft add rule inet {table} output ip daddr 127.0.0.1 accept
nft add rule inet {table} output ip6 daddr ::1 accept
nft add rule inet {table} output ip6 daddr != ::1 drop
nft add rule inet {table} output udp dport 53 drop
nft add rule inet {table} output udp dport 443 drop
nft add rule inet {table} output meta l4proto udp drop
"
    )
}

fn nft_script_disable(table: &str) -> String {
    format!("nft delete table inet {table} 2>/dev/null || true\n")
}

pub async fn enable() -> Result<String, String> {
    apply_script(
        &nft_script_enable(TABLE),
        crate::helper::HelperRequest::KillSwitchEnable,
    )
    .await?;
    fs::write(marker_path()?, "1").map_err(|e| e.to_string())?;
    crate::logs::append("Kill switch enabled (Linux nftables UDP + IPv6 block)");
    Ok("Kill switch enabled (UDP/QUIC and IPv6 blocked via nftables)".into())
}

pub async fn disable() -> Result<String, String> {
    apply_script(
        &nft_script_disable(TABLE),
        crate::helper::HelperRequest::KillSwitchDisable,
    )
    .await?;
    let live = status();
    if live.verified_live && live.active {
        return Err("nftables table still exists after restore".into());
    }
    if let Ok(p) = marker_path() {
        let _ = fs::remove_file(p);
    }
    crate::logs::append("Kill switch disabled (Linux nftables)");
    Ok("Kill switch disabled".into())
}

pub async fn enable_network_lock() -> Result<String, String> {
    apply_script(
        &nft_script_enable(LOCK_TABLE),
        crate::helper::HelperRequest::NetworkLockEnable {
            tor_path: String::new(),
        },
    )
    .await?;
    fs::write(lock_marker_path()?, "1").map_err(|e| e.to_string())?;
    crate::logs::append("Network lock enabled (Linux nftables UDP + IPv6)");
    Ok("Network locked for the transition (UDP/QUIC and IPv6 blocked)".into())
}

pub async fn disable_network_lock() -> Result<String, String> {
    apply_script(
        &nft_script_disable(LOCK_TABLE),
        crate::helper::HelperRequest::NetworkLockDisable,
    )
    .await?;
    let live = network_lock_status();
    if live.verified_live && live.active {
        return Err("network-lock nftables table still exists after restore".into());
    }
    if let Ok(p) = lock_marker_path() {
        let _ = fs::remove_file(p);
    }
    crate::logs::append("Network lock disabled (Linux nftables)");
    Ok("Network lock cleared".into())
}

async fn apply_script(
    script: &str,
    request: crate::helper::HelperRequest,
) -> Result<(), String> {
    if crate::helper::client::available() {
        let via = tokio::task::spawn_blocking(move || crate::helper::client::request(&request))
            .await
            .map_err(|e| e.to_string())?;
        match via {
            Ok(resp) if resp.ok => return Ok(()),
            Ok(resp) => return Err(resp.message),
            Err(_) => run_root(script).await?,
        }
    } else {
        run_root(script).await?;
    }
    Ok(())
}

async fn run_root(script: &str) -> Result<(), String> {
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
        return Err("pkexec failed or was cancelled".into());
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
        Err("Need pkexec or passwordless sudo to manage nftables rules".into())
    }
}
