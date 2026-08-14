use std::fs;
use std::process::Stdio;

use tokio::process::Command;

use super::{FirewallStatus, NetworkLockStatus};

const RULE: &str = "OnionGate UDP Internet Guard";
const RULE_V6: &str = "OnionGate IPv6 Internet Guard";
const RULE_V6_LO: &str = "OnionGate IPv6 Loopback Allow";
const LOCK_UDP: &str = "OnionGate Transition UDP Lock";
const LOCK_V6: &str = "OnionGate Transition IPv6 Lock";
const LOCK_V6_LO: &str = "OnionGate Transition IPv6 Loopback Allow";
const LOCK_TCP: &str = "OnionGate Transition TCP Lock";
const LOCK_TOR_ALLOW: &str = "OnionGate Transition Tor Allow";

fn lock_marker_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::tor::process::ensure_data_dir()?;
    Ok(dir.join("networklock.active"))
}

fn rule_enabled(name: &str) -> Option<bool> {
    let script = format!(
        "(Get-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True').Count",
        name.replace('\'', "''")
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output();
    output
        .ok()
        .filter(|result| result.status.success())
        .map(|result| {
            String::from_utf8_lossy(&result.stdout)
                .trim()
                .parse::<u32>()
                .unwrap_or(0)
                > 0
        })
}

pub fn status() -> FirewallStatus {
    let udp = rule_enabled(RULE);
    let v6 = rule_enabled(RULE_V6);
    let active = matches!(udp, Some(true)) || matches!(v6, Some(true));
    let verified_live = udp.is_some();
    FirewallStatus {
        supported: true,
        active,
        verified_live,
        marker_active: false,
        strict_deny_live: false,
        detail: if active {
            "Windows Defender Firewall blocks outbound UDP and IPv6 to the Internet".into()
        } else {
            "OnionGate Windows firewall rules are inactive".into()
        },
    }
}

pub fn network_lock_status() -> NetworkLockStatus {
    let marker_active = lock_marker_path()
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        == Some("1".into());
    let udp = rule_enabled(LOCK_UDP);
    let active = matches!(udp, Some(true)) || marker_active;
    let verified_live = udp.is_some();
    NetworkLockStatus {
        supported: true,
        active,
        verified_live,
        marker_active,
        detail: if active {
            "Network lock on: clearnet UDP, IPv6, and TCP blocked (Tor.exe allowed)".into()
        } else {
            "Network lock inactive".into()
        },
    }
}

fn ks_enable_script() -> String {
    format!(
        "Get-NetFirewallRule -DisplayName '{RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{RULE_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{RULE_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         New-NetFirewallRule -DisplayName '{RULE}' -Direction Outbound -Action Block -Protocol UDP -RemoteAddress Internet -Profile Any | Out-Null; \
         New-NetFirewallRule -DisplayName '{RULE_V6_LO}' -Direction Outbound -Action Allow -Protocol Any -RemoteAddress '::1' -Profile Any | Out-Null; \
         New-NetFirewallRule -DisplayName '{RULE_V6}' -Direction Outbound -Action Block -Protocol Any -RemoteAddress '::/0' -Profile Any | Out-Null"
    )
}

fn ks_disable_script() -> String {
    format!(
        "Get-NetFirewallRule -DisplayName '{RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{RULE_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{RULE_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
    )
}

pub async fn enable() -> Result<String, String> {
    if crate::helper::client::available() {
        let via = tokio::task::spawn_blocking(|| {
            crate::helper::client::request(&crate::helper::HelperRequest::kill_switch_udp())
        })
        .await
        .map_err(|e| e.to_string())?;
        match via {
            Ok(resp) if resp.ok => {
                if !status().active {
                    return Err(
                        "Windows firewall rules were not visible after helper enable".into(),
                    );
                }
                return Ok(resp.message);
            }
            Ok(resp) => return Err(resp.message),
            Err(_) => {}
        }
    }
    run_admin(&ks_enable_script()).await?;
    if !status().active {
        return Err("Windows firewall rule was not visible after elevation".into());
    }
    Ok("Windows UDP/QUIC and IPv6 Internet guard enabled".into())
}

pub async fn disable() -> Result<String, String> {
    if crate::helper::client::available() {
        let via = tokio::task::spawn_blocking(|| {
            crate::helper::client::request(&crate::helper::HelperRequest::KillSwitchDisable)
        })
        .await
        .map_err(|e| e.to_string())?;
        match via {
            Ok(resp) if resp.ok => {
                if status().active {
                    return Err("Windows firewall rules remain active after helper restore".into());
                }
                return Ok(resp.message);
            }
            Ok(resp) => return Err(resp.message),
            Err(_) => {}
        }
    }
    run_admin(&ks_disable_script()).await?;
    if status().active {
        return Err("Windows firewall rule remains active after restore".into());
    }
    Ok("Windows UDP/QUIC and IPv6 Internet guard disabled".into())
}

pub async fn enable_network_lock() -> Result<String, String> {
    let tor_path = crate::tor::find_tor_binary()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if crate::helper::client::available() {
        let path_for_helper = tor_path.clone();
        let via = tokio::task::spawn_blocking(move || {
            crate::helper::client::request(&crate::helper::HelperRequest::network_lock(
                path_for_helper,
            ))
        })
        .await
        .map_err(|e| e.to_string())?;
        match via {
            Ok(resp) if resp.ok => {
                fs::write(lock_marker_path()?, "1").map_err(|e| e.to_string())?;
                return Ok(resp.message);
            }
            Ok(resp) => return Err(resp.message),
            Err(_) => {}
        }
    }

    run_admin(&lock_enable_script(&tor_path)).await?;
    fs::write(lock_marker_path()?, "1").map_err(|e| e.to_string())?;
    if !network_lock_status().active {
        return Err("Windows network-lock rules were not visible after elevation".into());
    }
    Ok("Network locked for the transition (UDP/IPv6/TCP blocked; Tor allowed)".into())
}

pub async fn disable_network_lock() -> Result<String, String> {
    if crate::helper::client::available() {
        let via = tokio::task::spawn_blocking(|| {
            crate::helper::client::request(&crate::helper::HelperRequest::NetworkLockDisable)
        })
        .await
        .map_err(|e| e.to_string())?;
        match via {
            Ok(resp) if resp.ok => {
                if let Ok(p) = lock_marker_path() {
                    let _ = fs::remove_file(p);
                }
                return Ok(resp.message);
            }
            Ok(resp) => return Err(resp.message),
            Err(_) => {}
        }
    }
    run_admin(&lock_disable_script()).await?;
    if let Ok(p) = lock_marker_path() {
        let _ = fs::remove_file(p);
    }
    if network_lock_status().active {
        return Err("Windows network-lock rules remain active after restore".into());
    }
    Ok("Network lock cleared".into())
}

fn lock_enable_script(tor_path: &str) -> String {
    let tor_allow = if tor_path.is_empty() {
        String::new()
    } else {
        let escaped = tor_path.replace('\'', "''");
        format!(
            "Get-NetFirewallRule -DisplayName '{LOCK_TOR_ALLOW}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             New-NetFirewallRule -DisplayName '{LOCK_TOR_ALLOW}' -Direction Outbound -Action Allow -Program '{escaped}' -RemoteAddress Any -Profile Any | Out-Null; "
        )
    };
    format!(
        "{tor_allow}\
         Get-NetFirewallRule -DisplayName '{LOCK_UDP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{LOCK_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{LOCK_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{LOCK_TCP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         New-NetFirewallRule -DisplayName '{LOCK_UDP}' -Direction Outbound -Action Block -Protocol UDP -RemoteAddress Internet -Profile Any | Out-Null; \
         New-NetFirewallRule -DisplayName '{LOCK_V6_LO}' -Direction Outbound -Action Allow -Protocol Any -RemoteAddress '::1' -Profile Any | Out-Null; \
         New-NetFirewallRule -DisplayName '{LOCK_V6}' -Direction Outbound -Action Block -Protocol Any -RemoteAddress '::/0' -Profile Any | Out-Null; \
         New-NetFirewallRule -DisplayName '{LOCK_TCP}' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress Internet -Profile Any | Out-Null"
    )
}

fn lock_disable_script() -> String {
    format!(
        "Get-NetFirewallRule -DisplayName '{LOCK_UDP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{LOCK_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{LOCK_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{LOCK_TCP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         Get-NetFirewallRule -DisplayName '{LOCK_TOR_ALLOW}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
    )
}

async fn run_admin(script: &str) -> Result<(), String> {
    let escaped = script.replace('\'', "''");
    let command = format!(
        "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-NonInteractive','-Command','{escaped}'"
    );
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map_err(|e| e.to_string())?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "Administrator authorization failed or was cancelled".into())
}
