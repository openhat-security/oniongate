use super::{ProxyStatus, SavedProxyState};
use crate::tor::{SOCKS_HOST, SOCKS_PORT};
use crate::win_console::HideConsole;

const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

fn query(name: &str) -> Option<String> {
    let output = std::process::Command::new("reg")
        .args(["query", KEY, "/v", name])
        .hide_console()
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| line.contains(name))
        .and_then(|line| line.split_whitespace().last())
        .map(str::to_string)
}

fn set(name: &str, kind: &str, value: &str) -> Result<(), String> {
    let status = std::process::Command::new("reg")
        .args(["add", KEY, "/v", name, "/t", kind, "/d", value, "/f"])
        .hide_console()
        .status()
        .map_err(|e| e.to_string())?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("Failed to update Windows proxy value {name}"))
}

pub fn get_status() -> ProxyStatus {
    let enabled = query("ProxyEnable")
        .and_then(|value| {
            u32::from_str_radix(value.trim_start_matches("0x"), 16)
                .ok()
                .or_else(|| value.parse().ok())
        })
        .unwrap_or(0)
        != 0;
    let server = query("ProxyServer").unwrap_or_default();
    let oniongate = enabled && server.contains(&format!("{SOCKS_HOST}:{SOCKS_PORT}"));
    ProxyStatus {
        supported: true,
        enabled: oniongate,
        detail: if oniongate {
            format!("Windows SOCKS proxy enabled ({server})")
        } else {
            format!(
                "Windows proxy {} ({server})",
                if enabled { "enabled" } else { "off" }
            )
        },
        host: SOCKS_HOST.into(),
        port: SOCKS_PORT,
    }
}

pub fn capture() -> Result<SavedProxyState, String> {
    Ok(SavedProxyState {
        platform: "windows".into(),
        windows_proxy_enable: query("ProxyEnable").and_then(|value| {
            u32::from_str_radix(value.trim_start_matches("0x"), 16)
                .ok()
                .or_else(|| value.parse().ok())
        }),
        windows_proxy_server: query("ProxyServer"),
        windows_proxy_override: query("ProxyOverride"),
        ..SavedProxyState::default()
    })
}

pub fn enable(saved: &mut SavedProxyState) -> Result<String, String> {
    if saved.platform != "windows" {
        *saved = capture()?;
    }
    set(
        "ProxyServer",
        "REG_SZ",
        &format!("socks={SOCKS_HOST}:{SOCKS_PORT}"),
    )?;
    set("ProxyEnable", "REG_DWORD", "1")?;
    if !get_status().enabled {
        if let Some(server) = &saved.windows_proxy_server {
            let _ = set("ProxyServer", "REG_SZ", server);
        }
        if let Some(override_value) = &saved.windows_proxy_override {
            let _ = set("ProxyOverride", "REG_SZ", override_value);
        }
        let _ = set(
            "ProxyEnable",
            "REG_DWORD",
            &saved.windows_proxy_enable.unwrap_or(0).to_string(),
        );
        return Err("Windows SOCKS did not verify as enabled to the local Tor listener".into());
    }
    Ok("Enabled Windows SOCKS proxy for WinINet-aware applications".into())
}

pub fn disable(saved: &mut SavedProxyState) -> Result<String, String> {
    if let Some(server) = &saved.windows_proxy_server {
        set("ProxyServer", "REG_SZ", server)?;
    }
    if let Some(override_value) = &saved.windows_proxy_override {
        set("ProxyOverride", "REG_SZ", override_value)?;
    }
    set(
        "ProxyEnable",
        "REG_DWORD",
        &saved.windows_proxy_enable.unwrap_or(0).to_string(),
    )?;
    *saved = SavedProxyState::default();
    Ok("Restored previous Windows proxy settings".into())
}
