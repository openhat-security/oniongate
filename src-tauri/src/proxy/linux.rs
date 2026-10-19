use std::process::Command;

use super::{ProxyStatus, SavedProxyState};
use crate::tor::{SOCKS_HOST, SOCKS_PORT};

fn gsettings_get(schema: &str, key: &str) -> Result<String, String> {
    let output = Command::new("gsettings")
        .args(["get", schema, key])
        .output()
        .map_err(|e| format!("gsettings not available: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if err.is_empty() {
            format!("gsettings get {schema} {key} failed")
        } else {
            err
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn gsettings_set(schema: &str, key: &str, value: &str) -> Result<(), String> {
    let status = Command::new("gsettings")
        .args(["set", schema, key, value])
        .status()
        .map_err(|e| format!("gsettings not available: {e}"))?;
    if !status.success() {
        return Err(format!("gsettings set {schema} {key} failed"));
    }
    Ok(())
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('\'').to_string()
}

/// GNOME proxy settings only take effect when a D-Bus session (and therefore a
/// dconf backend) is present. On a headless server `gsettings set` returns
/// success but the write is discarded, so `start` would set the proxy, fail to
/// verify it, and exit non-zero. Detect that case so callers can skip the step.
fn session_bus_available() -> bool {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return true;
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if std::path::Path::new(&dir).join("bus").exists() {
            return true;
        }
    }
    false
}

pub fn get_status() -> ProxyStatus {
    if !session_bus_available() {
        return ProxyStatus {
            supported: false,
            enabled: false,
            detail: "no D-Bus session; GNOME proxy settings are not writable".into(),
            host: SOCKS_HOST.into(),
            port: SOCKS_PORT,
        };
    }
    let mode = match gsettings_get("org.gnome.system.proxy", "mode") {
        Ok(m) => unquote(&m),
        Err(e) => {
            return ProxyStatus {
                supported: false,
                enabled: false,
                detail: format!("GNOME proxy settings unavailable ({e})"),
                host: SOCKS_HOST.into(),
                port: SOCKS_PORT,
            };
        }
    };

    let host = gsettings_get("org.gnome.system.proxy.socks", "host")
        .map(|h| unquote(&h))
        .unwrap_or_default();
    let port = gsettings_get("org.gnome.system.proxy.socks", "port")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);

    let enabled = mode == "manual" && host == SOCKS_HOST && port == SOCKS_PORT;

    ProxyStatus {
        supported: true,
        enabled,
        detail: if enabled {
            format!("GNOME SOCKS proxy on {host}:{port}")
        } else {
            format!("GNOME proxy mode '{mode}' (socks {host}:{port})")
        },
        host: SOCKS_HOST.into(),
        port: SOCKS_PORT,
    }
}

pub fn capture() -> Result<SavedProxyState, String> {
    let mode = unquote(&gsettings_get("org.gnome.system.proxy", "mode")?);
    let host = unquote(&gsettings_get("org.gnome.system.proxy.socks", "host").unwrap_or_default());
    let port = gsettings_get("org.gnome.system.proxy.socks", "port")
        .ok()
        .and_then(|p| p.parse::<i32>().ok());

    Ok(SavedProxyState {
        platform: "linux".into(),
        linux_mode: Some(mode),
        linux_socks_host: Some(host),
        linux_socks_port: port,
        ..SavedProxyState::default()
    })
}

pub fn enable(saved: &mut SavedProxyState) -> Result<String, String> {
    if saved.linux_mode.is_none() {
        *saved = capture()?;
    }

    gsettings_set("org.gnome.system.proxy", "mode", "manual")?;
    gsettings_set(
        "org.gnome.system.proxy.socks",
        "host",
        &format!("'{SOCKS_HOST}'"),
    )?;
    gsettings_set(
        "org.gnome.system.proxy.socks",
        "port",
        &SOCKS_PORT.to_string(),
    )?;

    if !get_status().enabled {
        if let Some(mode) = saved.linux_mode.clone() {
            let _ = gsettings_set("org.gnome.system.proxy", "mode", &format!("'{mode}'"));
            if let Some(host) = saved.linux_socks_host.clone() {
                let _ = gsettings_set("org.gnome.system.proxy.socks", "host", &format!("'{host}'"));
            }
            if let Some(port) = saved.linux_socks_port {
                let _ = gsettings_set("org.gnome.system.proxy.socks", "port", &port.to_string());
            }
        } else {
            let _ = gsettings_set("org.gnome.system.proxy", "mode", "'none'");
        }
        return Err("GNOME SOCKS did not verify as enabled to the local Tor listener".into());
    }

    Ok("Enabled GNOME system SOCKS proxy to 127.0.0.1:9050".into())
}

pub fn disable(saved: &mut SavedProxyState) -> Result<String, String> {
    if let Some(mode) = saved.linux_mode.clone() {
        gsettings_set("org.gnome.system.proxy", "mode", &format!("'{mode}'"))?;
        if let Some(host) = saved.linux_socks_host.clone() {
            gsettings_set("org.gnome.system.proxy.socks", "host", &format!("'{host}'"))?;
        }
        if let Some(port) = saved.linux_socks_port {
            gsettings_set("org.gnome.system.proxy.socks", "port", &port.to_string())?;
        }
        saved.linux_mode = None;
        saved.linux_socks_host = None;
        saved.linux_socks_port = None;
        return Ok("Restored previous GNOME proxy settings".into());
    }

    gsettings_set("org.gnome.system.proxy", "mode", "'none'")?;
    Ok("Disabled GNOME system proxy".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_session_bus_reports_unsupported() {
        let prev_dbus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS");
        let prev_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");
        // Point XDG_RUNTIME_DIR at a dir with no `bus` socket.
        let tmp = std::env::temp_dir().join("oniongate-proxy-test-nobus");
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);

        let status = get_status();
        assert!(!status.supported, "headless host must report unsupported");
        assert!(status.detail.contains("D-Bus"));

        match prev_dbus {
            Some(v) => std::env::set_var("DBUS_SESSION_BUS_ADDRESS", v),
            None => std::env::remove_var("DBUS_SESSION_BUS_ADDRESS"),
        }
        match prev_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }
}
