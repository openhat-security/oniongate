use std::process::Command;

use super::{MacosServiceSnapshot, ProxyStatus, SavedProxyState};
use crate::tor::{SOCKS_HOST, SOCKS_PORT};

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkService {
    name: String,
    device: String,
    disabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServicePlan {
    primary: NetworkService,
    others: Vec<NetworkService>,
}

fn run(args: &[&str]) -> Result<String, String> {
    run_networksetup("networksetup", args)
}

fn run_privileged(args: &[&str]) -> Result<String, String> {
    run_networksetup("/usr/sbin/networksetup", args)
}

fn run_networksetup(binary: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run networksetup: {e}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if err.is_empty() {
            "networksetup failed".into()
        } else {
            format!("networksetup failed: {err}")
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn socks_port() -> String {
    SOCKS_PORT.to_string()
}

fn socks_points_at_tor(snap: &MacosServiceSnapshot) -> bool {
    snap.enabled && snap.server == SOCKS_HOST && snap.port == socks_port()
}

/// Whether a captured snapshot should be restored as "set previous proxy"
/// or "turn SOCKS off".
fn restore_previous_proxy(snap: &MacosServiceSnapshot) -> bool {
    snap.enabled && !snap.server.is_empty()
}

/// `(1) Wi-Fi` / `(3) *VPN` → (name, disabled).
fn parse_service_order_name_line(line: &str) -> Option<(String, bool)> {
    let line = line.trim();
    let rest = line.strip_prefix('(')?;
    let close = rest.find(')')?;
    let index = rest[..close].trim();
    if index.is_empty() || !index.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut name = rest[close + 1..].trim().to_string();
    if name.is_empty() {
        return None;
    }
    let disabled = name.starts_with('*');
    if disabled {
        name = name.trim_start_matches('*').trim().to_string();
        if name.is_empty() {
            return None;
        }
    }
    Some((name, disabled))
}

/// `(Hardware Port: USB 10/100/1000 LAN, Device: en8)` → device.
fn parse_service_order_device_line(line: &str) -> Option<String> {
    let inner = line.trim().strip_prefix('(')?.strip_suffix(')')?;
    let device = inner.split("Device: ").nth(1)?.trim();
    if device.is_empty() {
        return None;
    }
    Some(device.to_string())
}

fn parse_network_service_order(text: &str) -> Vec<NetworkService> {
    let mut pending: Option<(String, bool)> = None;
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(svc) = parse_service_order_name_line(line) {
            pending = Some(svc);
            continue;
        }
        if let Some(device) = parse_service_order_device_line(line) {
            if let Some((name, disabled)) = pending.take() {
                out.push(NetworkService {
                    name,
                    device,
                    disabled,
                });
            }
        }
    }
    out
}

fn parse_default_route_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(iface) = line.trim().strip_prefix("interface:") {
            let device = iface.trim();
            if !device.is_empty() {
                return Some(device.to_string());
            }
        }
    }
    None
}

fn enabled_services(services: &[NetworkService]) -> Vec<NetworkService> {
    services.iter().filter(|s| !s.disabled).cloned().collect()
}

fn resolve_primary<'a>(services: &'a [NetworkService], device: &str) -> Option<&'a NetworkService> {
    services.iter().find(|s| !s.disabled && s.device == device)
}

fn plan_from(services: &[NetworkService], default_device: &str) -> Result<ServicePlan, String> {
    let enabled = enabled_services(services);
    if enabled.is_empty() {
        return Err("No enabled network services found".into());
    }
    let primary = resolve_primary(&enabled, default_device)
        .cloned()
        .ok_or_else(|| {
            "No enabled network service matches the default-route interface; refusing to guess"
                .to_string()
        })?;
    let others = enabled
        .into_iter()
        .filter(|s| s.name != primary.name)
        .collect();
    Ok(ServicePlan { primary, others })
}

fn services_to_mutate(plan: &ServicePlan) -> Vec<String> {
    std::iter::once(plan.primary.name.clone())
        .chain(plan.others.iter().map(|s| s.name.clone()))
        .collect()
}

fn parse_socks_output(service: &str, text: &str) -> MacosServiceSnapshot {
    let mut enabled = false;
    let mut server = String::new();
    let mut port = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Enabled: ") {
            enabled = v.eq_ignore_ascii_case("Yes");
        } else if let Some(v) = line.strip_prefix("Server: ") {
            server = v.to_string();
        } else if let Some(v) = line.strip_prefix("Port: ") {
            port = v.to_string();
        }
    }
    MacosServiceSnapshot {
        service: service.to_string(),
        enabled,
        server,
        port,
    }
}

fn primary_socks_live(primary: &str, snaps: &[MacosServiceSnapshot]) -> bool {
    snaps
        .iter()
        .find(|s| s.service == primary)
        .is_some_and(socks_points_at_tor)
}

fn list_service_order() -> Result<Vec<NetworkService>, String> {
    let out = run(&["-listnetworkserviceorder"])?;
    Ok(parse_network_service_order(&out))
}

fn default_route_device() -> Result<String, String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| format!("Failed to read the default route: {e}"))?;
    if !output.status.success() {
        return Err("Could not read the default route; refusing to guess a network service".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_default_route_interface(&text)
        .ok_or_else(|| "Default route has no interface; refusing to guess a network service".into())
}

fn service_plan() -> Result<ServicePlan, String> {
    let services = list_service_order()?;
    let device = default_route_device()?;
    plan_from(&services, &device)
}

fn get_socks(service: &str) -> Result<MacosServiceSnapshot, String> {
    let out = run(&["-getsocksfirewallproxy", service])?;
    Ok(parse_socks_output(service, &out))
}

fn apply_socks_with(run_cmd: fn(&[&str]) -> Result<String, String>, service: &str) -> Result<(), String> {
    run_cmd(&["-setsocksfirewallproxy", service, SOCKS_HOST, &socks_port()])?;
    run_cmd(&["-setsocksfirewallproxystate", service, "on"])?;
    Ok(())
}

fn apply_all(run_cmd: fn(&[&str]) -> Result<String, String>, plan: &ServicePlan) -> Result<(), String> {
    apply_socks_with(run_cmd, &plan.primary.name)?;
    for other in &plan.others {
        apply_socks_with(run_cmd, &other.name)?;
    }
    Ok(())
}

fn verify_primary(plan: &ServicePlan) -> bool {
    get_socks(&plan.primary.name)
        .ok()
        .is_some_and(|live| socks_points_at_tor(&live))
}

/// Put each captured service back. Does not clear `saved` — the journal still
/// owns that snapshot until a successful disable.
fn restore_snapshots_with(
    run_cmd: fn(&[&str]) -> Result<String, String>,
    snaps: &[MacosServiceSnapshot],
) -> Result<(), String> {
    for snap in snaps {
        if restore_previous_proxy(snap) {
            run_cmd(&[
                "-setsocksfirewallproxy",
                &snap.service,
                &snap.server,
                &snap.port,
            ])?;
            run_cmd(&["-setsocksfirewallproxystate", &snap.service, "on"])?;
        } else {
            run_cmd(&["-setsocksfirewallproxystate", &snap.service, "off"])?;
        }
    }
    Ok(())
}

fn restore_snapshots(snaps: &[MacosServiceSnapshot]) -> Result<(), String> {
    restore_snapshots_with(run, snaps)
}

fn capture_into(saved: &mut SavedProxyState, plan: &ServicePlan) -> Result<(), String> {
    if saved.macos_services.is_empty() {
        *saved = capture_plan(plan)?;
    } else {
        for name in services_to_mutate(plan) {
            if !saved.macos_services.iter().any(|s| s.service == name) {
                saved.macos_services.push(get_socks(&name)?);
            }
        }
    }
    Ok(())
}

fn helper_socks_call(enable: bool) -> Result<String, String> {
    let req = if enable {
        crate::helper::HelperRequest::SocksEnable
    } else {
        crate::helper::HelperRequest::SocksDisable
    };
    let response = crate::helper::client::request(&req)
        .map_err(|e| format!("The privileged helper did not answer: {e}"))?;
    if response.ok {
        Ok(response.message)
    } else {
        Err(response.message)
    }
}

fn apply_and_verify(
    run_cmd: fn(&[&str]) -> Result<String, String>,
    plan: &ServicePlan,
    saved: &SavedProxyState,
) -> Result<String, String> {
    let apply_err = apply_all(run_cmd, plan).err();
    if apply_err.is_none() && verify_primary(plan) {
        return Ok(format!(
            "System SOCKS proxy enabled on {}",
            services_to_mutate(plan).join(", ")
        ));
    }
    let restore_err = restore_snapshots_with(run_cmd, &saved.macos_services).err();
    let err = apply_err.unwrap_or_else(|| {
        format!(
            "System SOCKS on {} did not verify as enabled to the local Tor listener",
            plan.primary.name
        )
    });
    match restore_err {
        Some(restore) => Err(format!("{err}. Also failed to restore previous SOCKS: {restore}")),
        None => Err(err),
    }
}

fn capture_plan(plan: &ServicePlan) -> Result<SavedProxyState, String> {
    let mut saved = SavedProxyState {
        platform: "macos".into(),
        ..SavedProxyState::default()
    };
    for name in services_to_mutate(plan) {
        saved.macos_services.push(get_socks(&name)?);
    }
    Ok(saved)
}

pub fn get_status() -> ProxyStatus {
    match service_plan() {
        Ok(plan) => match get_socks(&plan.primary.name) {
            Ok(snap) if socks_points_at_tor(&snap) => ProxyStatus {
                supported: true,
                enabled: true,
                detail: format!("SOCKS enabled on {}", plan.primary.name),
                host: SOCKS_HOST.into(),
                port: SOCKS_PORT,
            },
            Ok(_) => ProxyStatus {
                supported: true,
                enabled: false,
                detail: format!(
                    "SOCKS off on the default-route service ({})",
                    plan.primary.name
                ),
                host: SOCKS_HOST.into(),
                port: SOCKS_PORT,
            },
            Err(e) => ProxyStatus {
                supported: true,
                enabled: false,
                detail: e,
                host: SOCKS_HOST.into(),
                port: SOCKS_PORT,
            },
        },
        Err(e) => ProxyStatus {
            supported: true,
            enabled: false,
            detail: e,
            host: SOCKS_HOST.into(),
            port: SOCKS_PORT,
        },
    }
}

pub fn capture() -> Result<SavedProxyState, String> {
    let plan = service_plan()?;
    capture_plan(&plan)
}

pub fn enable(saved: &mut SavedProxyState) -> Result<String, String> {
    let plan = service_plan()?;
    capture_into(saved, &plan)?;
    match apply_and_verify(run, &plan, saved) {
        Ok(msg) => Ok(msg),
        Err(user_err) => {
            if !crate::helper::client::available() {
                return Err(format!(
                    "{user_err}. The privileged helper is not running, so OnionGate cannot apply SOCKS as administrator"
                ));
            }
            match helper_socks_call(true) {
                Ok(msg) if verify_primary(&plan) => Ok(msg),
                Ok(_) => {
                    let _ = helper_socks_call(false);
                    let _ = restore_snapshots(&saved.macos_services);
                    Err(format!(
                        "{user_err}. The privileged helper applied SOCKS but the default-route service did not verify"
                    ))
                }
                Err(helper_err) => {
                    let _ = helper_socks_call(false);
                    let _ = restore_snapshots(&saved.macos_services);
                    Err(format!("{user_err}. Helper SOCKS failed: {helper_err}"))
                }
            }
        }
    }
}

pub(crate) fn enable_as_root(saved: &mut SavedProxyState) -> Result<String, String> {
    let plan = service_plan()?;
    capture_into(saved, &plan)?;
    apply_and_verify(run_privileged, &plan, saved)
}

pub fn disable(saved: &mut SavedProxyState) -> Result<String, String> {
    let had_snapshots = !saved.macos_services.is_empty();
    let ours = any_socks_at_tor();
    let local = disable_local(saved, run);
    // Skip the helper when SOCKS was never ours. After a .pkg install the
    // helper is always up; a no-op SocksDisable on Quit parked the UI for 20s.
    if crate::helper::client::available() && (had_snapshots || ours) {
        let _ = helper_socks_call(false);
    }
    local
}

fn any_socks_at_tor() -> bool {
    let Ok(services) = list_service_order() else {
        return false;
    };
    enabled_services(&services)
        .iter()
        .any(|svc| get_socks(&svc.name).ok().is_some_and(|s| socks_points_at_tor(&s)))
}

pub(crate) fn disable_as_root(saved: &mut SavedProxyState) -> Result<String, String> {
    disable_local(saved, run_privileged)
}

fn disable_local(
    saved: &mut SavedProxyState,
    run_cmd: fn(&[&str]) -> Result<String, String>,
) -> Result<String, String> {
    if !saved.macos_services.is_empty() {
        restore_snapshots_with(run_cmd, &saved.macos_services)?;
        saved.macos_services.clear();
        return Ok("Restored previous SOCKS proxy settings".into());
    }

    let services = list_service_order()?;
    let enabled = enabled_services(&services);
    if enabled.is_empty() {
        return Err("No enabled network services available to disable".into());
    }
    for svc in &enabled {
        if get_socks(&svc.name).ok().is_some_and(|s| socks_points_at_tor(&s)) {
            run_cmd(&["-setsocksfirewallproxystate", &svc.name, "off"])?;
        }
    }
    Ok("Disabled system SOCKS proxy".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_SERVICE_ORDER: &str = r#"
An asterisk (*) denotes that a network service is disabled.
(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en8)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(4) iPhone USB
(Hardware Port: iPhone USB, Device: en7)
"#;

    const USER_DEFAULT_ROUTE: &str = r#"
   route to: default
destination: default
       mask: default
    gateway: 203.0.113.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
"#;

    const DISABLED_AND_RENAMED: &str = r#"
An asterisk (*) denotes that a network service is disabled.
(1) Office Ethernet
(Hardware Port: USB 10/100/1000 LAN, Device: en8)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) *Legacy Ethernet
(Hardware Port: Ethernet, Device: en9)

(4) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
"#;

    fn snap(service: &str, enabled: bool, server: &str, port: &str) -> MacosServiceSnapshot {
        MacosServiceSnapshot {
            service: service.into(),
            enabled,
            server: server.into(),
            port: port.into(),
        }
    }

    #[test]
    fn en0_resolves_to_wifi_not_usb_lan() {
        let services = parse_network_service_order(USER_SERVICE_ORDER);
        let device = parse_default_route_interface(USER_DEFAULT_ROUTE).unwrap();
        assert_eq!(device, "en0");
        let plan = plan_from(&services, &device).unwrap();
        assert_eq!(plan.primary.name, "Wi-Fi");
        assert_eq!(plan.primary.device, "en0");
        let others: Vec<&str> = plan.others.iter().map(|s| s.name.as_str()).collect();
        assert!(others.contains(&"USB 10/100/1000 LAN"));
        assert!(!others.contains(&"Wi-Fi"));
    }

    #[test]
    fn disabled_star_prefix_services_are_skipped() {
        let services = parse_network_service_order(DISABLED_AND_RENAMED);
        let legacy = services
            .iter()
            .find(|s| s.device == "en9")
            .expect("legacy ethernet");
        assert!(legacy.disabled);
        assert_eq!(legacy.name, "Legacy Ethernet");

        let enabled = enabled_services(&services);
        assert!(enabled.iter().all(|s| s.name != "Legacy Ethernet"));
        assert!(resolve_primary(&enabled, "en9").is_none());
        assert!(plan_from(&services, "en9").is_err());
    }

    #[test]
    fn renamed_service_is_used_not_hardware_port() {
        let services = parse_network_service_order(DISABLED_AND_RENAMED);
        let plan = plan_from(&services, "en8").unwrap();
        assert_eq!(plan.primary.name, "Office Ethernet");
        assert_ne!(plan.primary.name, "USB 10/100/1000 LAN");
        assert_eq!(plan.primary.device, "en8");
    }

    #[test]
    fn leftover_other_service_on_is_not_enabled() {
        let snaps = [
            snap("USB 10/100/1000 LAN", true, SOCKS_HOST, &socks_port()),
            snap("Wi-Fi", false, SOCKS_HOST, &socks_port()),
        ];
        assert!(
            !primary_socks_live("Wi-Fi", &snaps),
            "primary off must not count leftover USB LAN SOCKS as enabled"
        );
        assert!(primary_socks_live("USB 10/100/1000 LAN", &snaps));
    }

    #[test]
    fn primary_on_is_enabled_even_if_others_off() {
        let snaps = [
            snap("USB 10/100/1000 LAN", false, "", "0"),
            snap("Wi-Fi", true, SOCKS_HOST, &socks_port()),
        ];
        assert!(primary_socks_live("Wi-Fi", &snaps));
    }

    #[test]
    fn restore_turns_off_when_the_snapshot_was_off() {
        assert!(!restore_previous_proxy(&snap("Wi-Fi", false, SOCKS_HOST, &socks_port())));
        assert!(!restore_previous_proxy(&snap("Wi-Fi", true, "", "9050")));
        assert!(restore_previous_proxy(&snap("Wi-Fi", true, "10.0.0.1", "1080")));
    }

    #[test]
    fn socks_parser_reads_enabled_server_and_port() {
        let snap = parse_socks_output(
            "Wi-Fi",
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 9050\nAuthenticated Proxy Enabled: 0\n",
        );
        assert!(socks_points_at_tor(&snap));
        let off = parse_socks_output("Wi-Fi", "Enabled: No\nServer: 127.0.0.1\nPort: 9050\n");
        assert!(!socks_points_at_tor(&off));
    }
}
