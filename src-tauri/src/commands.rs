use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::process::Child;
use tokio::sync::Mutex as AsyncMutex;

use crate::bypass::{self, BypassHelpers, ShellHookStatus};
use crate::ip::{self, IpReport};
use crate::logs::{self, TorLogs};
use crate::proxy::{self, ProxyStatus, SavedProxyState};
use crate::settings::{self, AppSettings};
use crate::tor::{self, CONTROL_PORT, DNS_PORT, SOCKS_HOST, SOCKS_PORT};

pub struct AppState {
    pub managed_tor: AsyncMutex<Option<Child>>,
    pub managed_singbox: AsyncMutex<Option<Child>>,
    pub managed_snowflake: AsyncMutex<Option<Child>>,
    pub saved_proxy: Mutex<SavedProxyState>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            managed_tor: AsyncMutex::new(None),
            managed_singbox: AsyncMutex::new(None),
            managed_snowflake: AsyncMutex::new(None),
            saved_proxy: Mutex::new(crate::session::load().original_proxy.unwrap_or_default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStatus {
    pub tor_installed: bool,
    pub tor_path: Option<String>,
    pub socks_up: bool,
    pub control_up: bool,
    pub dns_up: bool,
    pub remote_dns: bool,
    pub bridges_enabled: bool,
    pub bridge_count: usize,
    pub smart_connect: bool,
    pub exit_country: String,
    pub bootstrap_progress: Option<u32>,
    pub connection_mode: String,
    pub kill_switch: bool,
    pub pt: Vec<tor::PtStatus>,
    pub tun: crate::tun::TunStatus,
    pub firewall: crate::firewall::FirewallStatus,
    pub network_lock: crate::firewall::NetworkLockStatus,
    pub deps: Vec<crate::deps::DepStatus>,
    pub proxy: ProxyStatus,
    pub socks_host: String,
    pub socks_port: u16,
    pub control_port: u16,
    pub dns_port: u16,
    pub install_hint: String,
    pub persistence_changes: usize,
    pub session_phase: crate::session::SessionPhase,
    pub connection_filter: crate::ne_filter::FilterStatus,
}

fn finish_protected() -> Result<(), String> {
    crate::connect::finish_protected()
}

fn install_hint() -> String {
    if tor::find_tor_binary().is_some() {
        return "Using bundled or system Tor".into();
    }
    "Bundled Tor missing — developers: run npm run deps (scripts/download-deps.sh)".into()
}

#[tauri::command]
pub async fn get_status() -> AppStatus {
    let tor_path = tor::find_tor_binary().map(|p| p.display().to_string());
    let settings = settings::load();
    let socks_up = tor::socks_reachable();
    let bootstrap_progress = if socks_up {
        tor::bootstrap_progress().await.ok()
    } else {
        None
    };
    AppStatus {
        tor_installed: tor_path.is_some(),
        tor_path,
        socks_up,
        control_up: tor::control_reachable(),
        dns_up: tor::dns_reachable(),
        remote_dns: settings.remote_dns,
        bridges_enabled: settings.bridges_enabled,
        bridge_count: settings.bridge_lines.len(),
        smart_connect: settings.smart_connect,
        exit_country: settings.exit_country.clone(),
        bootstrap_progress,
        connection_mode: settings.connection_mode.clone(),
        kill_switch: settings.kill_switch,
        pt: tor::pt_status_all(),
        tun: crate::tun::status(&None),
        firewall: crate::firewall::status(),
        network_lock: crate::firewall::network_lock_status(),
        deps: crate::deps::deps_status(),
        proxy: proxy::get_status(),
        socks_host: SOCKS_HOST.into(),
        socks_port: SOCKS_PORT,
        control_port: CONTROL_PORT,
        dns_port: DNS_PORT,
        install_hint: install_hint(),
        persistence_changes: crate::workstation::persistence_change_count(),
        session_phase: crate::session::load().phase,
        connection_filter: crate::ne_filter::status(),
    }
}

#[tauri::command]
pub fn get_settings() -> AppSettings {
    settings::load()
}

#[tauri::command]
pub fn update_settings(next: AppSettings) -> Result<AppSettings, String> {
    settings::update(|s| *s = next)
}

/// Mark the first-run setup wizard complete (or dismissed).
#[tauri::command]
pub fn set_setup_complete(done: bool) -> Result<AppSettings, String> {
    settings::update(|s| s.setup_complete = done)
}

/// Status of the installed privileged helper (installed/running).
#[tauri::command]
pub fn privileged_helper_status() -> crate::helper::HelperStatus {
    crate::helper::service::status()
}

/// Install the privileged helper (one elevation prompt); afterward its typed
/// kill-switch operations run without prompting.
#[tauri::command]
pub async fn install_privileged_helper() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(crate::helper::service::install)
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

/// Remove the privileged helper.
#[tauri::command]
pub async fn remove_privileged_helper() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(crate::helper::service::uninstall)
        .await
        .map_err(|e| format!("task join error: {e}"))?
}

/// Trigger the admin authorization once so later privileged operations (system
/// proxy, TUN, firewall, hardening) reuse the cached authorization instead of
/// prompting repeatedly. Runs a trivial elevated no-op.
///
/// Skipped entirely in helper-backed TUN mode: the helper performs the routing
/// and firewall mutations itself, so priming would be a prompt that buys the
/// user nothing.
#[tauri::command]
pub async fn prime_admin_auth() -> Result<String, String> {
    if settings::load().connection_mode == "tun" && crate::tun::helper_backed() {
        return Ok("Administrator access is not needed: the privileged helper is running".into());
    }
    tauri::async_runtime::spawn_blocking(|| {
        crate::elevate::run_shell_with_prompt(
            "/usr/bin/true",
            "OnionGate needs administrator access once to set up secure routing \
             (system proxy, TUN, and firewall). You can skip this and approve \
             individual changes later.",
        )
    })
    .await
    .map_err(|e| format!("task join error: {e}"))??;
    Ok("Administrator access granted for this session".into())
}

#[tauri::command]
pub fn get_tor_logs() -> TorLogs {
    logs::get_logs()
}

#[tauri::command]
pub fn clear_tor_logs() -> Result<String, String> {
    logs::clear()?;
    Ok("Logs cleared".into())
}

#[tauri::command]
pub async fn set_remote_dns(state: State<'_, AppState>, enabled: bool) -> Result<String, String> {
    settings::set_remote_dns(enabled)?;

    if !tor::socks_reachable() {
        return Ok(if enabled {
            "Remote DNS enabled. Start Tor to activate DNSPort 9053 (socks5h for app DNS).".into()
        } else {
            "Remote DNS disabled.".into()
        });
    }

    // Prefer live SETCONF; fall back to managed restart so torrc DNSPort is applied.
    match tor::apply_remote_dns(enabled).await {
        Ok(msg) => {
            if enabled && !tor::dns_reachable() {
                let mut guard = state.managed_tor.lock().await;
                let _ = tor::restart_managed_for_dns(&mut guard).await?;
                return Ok(format!(
                    "{msg}. Restarted Tor; DNSPort {} should be active for dig @{} -p {}",
                    DNS_PORT, SOCKS_HOST, DNS_PORT
                ));
            }
            Ok(msg)
        }
        Err(_) => {
            let mut guard = state.managed_tor.lock().await;
            tor::restart_managed_for_dns(&mut guard).await?;
            Ok(if enabled {
                format!(
                    "Remote DNS on via managed Tor (DNSPort {SOCKS_HOST}:{DNS_PORT}). Use socks5h / Firefox socks_remote_dns; OS resolver may still leak for some apps."
                )
            } else {
                "Remote DNS off; restarted Tor without DNSPort.".into()
            })
        }
    }
}

#[tauri::command]
pub async fn arm_network_lock() -> Result<String, String> {
    crate::session::begin_connect()?;
    crate::firewall::arm_for_transition().await
}

#[tauri::command]
pub async fn disarm_network_lock() -> Result<String, String> {
    // Only disarm when we never reached a protected session — used when the
    // user cancels the pre-connect dialog.
    let phase = crate::session::load().phase;
    if phase == crate::session::SessionPhase::Protected {
        return Err("Cannot disarm the network lock while protected".into());
    }
    let msg = crate::firewall::disarm_after_transition().await?;
    if phase == crate::session::SessionPhase::Connecting {
        let _ = crate::session::clear();
    }
    Ok(msg)
}

#[tauri::command]
pub async fn quit_user_applications() -> Result<crate::apps_lifecycle::QuitAppsResult, String> {
    crate::apps_lifecycle::quit_user_applications().await
}

/// Applications OnionGate closed that it can launch again. The ledger is
/// memory-only, so this is empty in a fresh session and after teardown.
#[tauri::command]
pub async fn list_reopenable_apps() -> Result<Vec<crate::apps_lifecycle::ReopenableApp>, String> {
    Ok(crate::apps_lifecycle::reopenable_apps())
}

/// Relaunch the closed-application ledger. Refuses unless TUN is live and the
/// session is verified Protected, and validates every bundle before launching.
#[tauri::command]
pub async fn reopen_closed_apps() -> Result<String, String> {
    crate::apps_lifecycle::reopen_closed_apps().await
}

#[tauri::command]
pub async fn start_tor(state: State<'_, AppState>) -> Result<String, String> {
    crate::connect::bring_up(
        &state.managed_tor,
        &state.managed_singbox,
        &state.saved_proxy,
    )
    .await
}

#[tauri::command]
pub fn get_bridge_lines() -> Vec<String> {
    settings::load().bridge_lines
}

#[tauri::command]
pub fn set_bridge_lines(text: String) -> Result<AppSettings, String> {
    let lines = tor::bridges::parse_bridge_lines(&text);
    settings::update(|s| {
        s.bridge_lines = lines;
        if !s.bridge_lines.is_empty() {
            s.bridge_source = "custom".into();
            s.last_connect_strategy = "bridges".into();
        }
    })
}

#[tauri::command]
pub fn set_bridges_enabled(enabled: bool) -> Result<AppSettings, String> {
    if enabled && settings::load().bridge_lines.is_empty() {
        return Err("Add at least one bridge line before enabling".into());
    }
    settings::update(|s| {
        if enabled {
            s.bridges_enabled = true;
            // Home "None" forces bridges off in normalize — leave that mode when enabling.
            if s.bridge_source == "none" || s.bridge_source.is_empty() {
                s.bridge_source = "custom".into();
            }
            s.last_connect_strategy = "bridges".into();
        } else {
            s.bridges_enabled = false;
        }
    })
}

#[tauri::command]
pub async fn apply_tor_config(state: State<'_, AppState>) -> Result<String, String> {
    // Bridges / PT / exit pin need a managed restart so torrc is authoritative.
    // Lock clearnet for the restart window so apps cannot race onto a direct path.
    let _ = crate::session::set_phase(crate::session::SessionPhase::Connecting, None);
    let lock_msg = crate::firewall::arm_for_transition().await?;
    let mut guard = state.managed_tor.lock().await;
    let msg = match tor::restart_managed(&mut guard).await {
        Ok(m) => m,
        Err(e) => {
            let _ =
                crate::session::set_phase(crate::session::SessionPhase::Degraded, Some(e.clone()));
            return Err(e);
        }
    };
    crate::logs::append(&msg);
    let unlock = crate::firewall::disarm_after_transition()
        .await
        .unwrap_or_else(|e| format!("transition lock still held ({e})"));
    finish_protected()?;
    Ok(format!("{lock_msg}. {msg}. {unlock}"))
}

#[tauri::command]
pub async fn set_exit_country(
    state: State<'_, AppState>,
    country: String,
) -> Result<NewIdentityResult, String> {
    let settings = settings::update(|s| s.exit_country = country.clone())?;
    let cc = settings.exit_country.clone();

    if !tor::control_reachable() {
        let message = if cc.is_empty() {
            "Exit pin cleared. Start Tor to apply.".to_string()
        } else {
            format!("Exit pin set to {{{cc}}}. Start Tor (or Apply) to use it.")
        };
        return Ok(NewIdentityResult {
            message,
            ips: ip::refresh_ips().await,
        });
    }

    let message = match tor::apply_exit_country(&cc).await {
        Ok(msg) => msg,
        Err(_) => {
            let mut guard = state.managed_tor.lock().await;
            tor::restart_managed(&mut guard).await?;
            if cc.is_empty() {
                "Exit pin cleared; Tor restarted.".to_string()
            } else {
                format!("Exit pin {{{cc}}} applied via Tor restart.")
            }
        }
    };

    // Changing the exit pin issues NEWNYM (or restarts Tor); wait for the new
    // circuit and retry the Tor IP so the refreshed location reflects the new
    // exit country instead of racing the rebuilding circuit.
    let ips = ip::refresh_ips_after_newnym().await;
    let message = match (&ips.tor_ip, &ips.tor_location) {
        (Some(ip), Some(loc)) => format!("{message} Tor IP: {ip} ({})", loc.label),
        (Some(ip), None) => format!("{message} Tor IP: {ip}"),
        _ => message,
    };
    Ok(NewIdentityResult { message, ips })
}

#[tauri::command]
pub async fn fetch_bridges() -> Result<tor::bridges::FetchBridgesResult, String> {
    tor::bridges::fetch_bridge_lines_for("obfs4").await
}

#[tauri::command]
pub async fn fetch_bridges_for(
    transport: String,
) -> Result<tor::bridges::FetchBridgesResult, String> {
    tor::bridges::fetch_bridge_lines_for(&transport).await
}

#[tauri::command]
pub async fn test_onion_connectivity(
    host: String,
    port: u16,
) -> Result<tor::onion::OnionConnectivityResult, String> {
    tor::onion::test_connectivity(&host, port).await
}

#[tauri::command]
pub async fn run_leak_verifier() -> crate::verify::LeakReport {
    crate::verify::run().await
}

#[tauri::command]
pub fn get_latest_leak_report() -> Result<Option<crate::verify::LeakReport>, String> {
    crate::db::latest_leak_report()
}

#[tauri::command]
pub fn export_latest_leak_report(path: String) -> Result<String, String> {
    let report = crate::db::latest_leak_report()?
        .ok_or_else(|| "Run the leak verifier before exporting".to_string())?;
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to export report: {e}"))?;
    Ok(format!("Exported redacted report to {path}"))
}

#[tauri::command]
pub fn get_egress_watch() -> crate::egress_watch::EgressWatch {
    crate::egress_watch::current()
}

#[tauri::command]
pub fn reveal_egress_path(pid: u32) -> Result<String, String> {
    crate::egress_watch::reveal_pid(pid)
}

#[tauri::command]
pub async fn start_onion_service(
    local_port: u16,
    virtual_port: u16,
    private: bool,
) -> Result<crate::onion_service::OnionProject, String> {
    crate::onion_service::start(local_port, virtual_port, private).await
}

#[tauri::command]
pub fn list_onion_services() -> Vec<crate::onion_service::OnionProject> {
    crate::onion_service::list()
}

#[tauri::command]
pub async fn stop_onion_service(service_id: String) -> Result<String, String> {
    crate::onion_service::stop(&service_id).await
}

#[tauri::command]
pub async fn audit_onion_service(
    service_id: String,
) -> Result<crate::onion_service::audit::OnionAudit, String> {
    crate::onion_service::audit_temporary(&service_id).await
}

#[tauri::command]
pub fn list_permanent_sites() -> Vec<crate::onion_service::persistent::PermanentSiteView> {
    crate::onion_service::persistent::list()
}

#[tauri::command]
pub async fn add_permanent_site(
    nickname: String,
    local_port: u16,
    virtual_port: u16,
    enable_auth: bool,
) -> Result<crate::onion_service::persistent::PermanentSiteView, String> {
    crate::onion_service::persistent::add(&nickname, local_port, virtual_port, enable_auth).await
}

#[tauri::command]
pub async fn remove_permanent_site(id: String) -> Result<String, String> {
    crate::onion_service::persistent::remove(&id).await
}

#[tauri::command]
pub async fn rename_permanent_site(
    id: String,
    nickname: String,
) -> Result<crate::onion_service::persistent::PermanentSiteView, String> {
    crate::onion_service::persistent::rename(&id, &nickname).await
}

#[tauri::command]
pub async fn add_permanent_site_client(
    id: String,
    name: String,
) -> Result<crate::onion_service::persistent::IssuedCredential, String> {
    crate::onion_service::persistent::add_client(&id, &name).await
}

#[tauri::command]
pub async fn revoke_permanent_site_client(id: String, name: String) -> Result<String, String> {
    crate::onion_service::persistent::revoke_client(&id, &name).await
}

#[tauri::command]
pub async fn set_permanent_site_auth(
    id: String,
    enabled: bool,
) -> Result<crate::onion_service::persistent::PermanentSiteView, String> {
    crate::onion_service::persistent::set_auth_enabled(&id, enabled).await
}

#[tauri::command]
pub async fn audit_permanent_site(
    id: String,
) -> Result<crate::onion_service::audit::OnionAudit, String> {
    crate::onion_service::audit_permanent(&id).await
}

#[tauri::command]
pub fn get_workstation_posture() -> Vec<crate::workstation::PostureCheck> {
    crate::workstation::posture()
}

#[tauri::command]
pub fn get_persistence_report() -> Result<crate::workstation::PersistenceReport, String> {
    crate::workstation::persistence()
}

#[tauri::command]
pub fn save_persistence_baseline() -> Result<String, String> {
    crate::workstation::save_persistence_baseline()
}

/// Explicit Background/Login Items scan (`sfltool dumpbtm`). Runs only on user
/// request so the Full Disk Access prompt is not raised repeatedly.
#[tauri::command]
pub fn scan_login_items() -> crate::workstation::LoginItemsSnapshot {
    crate::workstation::login_items_snapshot()
}

/// Open the Full Disk Access settings pane so the user can grant access once.
#[tauri::command]
pub fn open_full_disk_access_settings() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
            .status()
            .map_err(|e| e.to_string())?;
        Ok("Opened Full Disk Access settings — enable OnionGate, then scan again.".into())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Full Disk Access settings are macOS only".into())
    }
}

#[tauri::command]
pub fn save_bridge_library(lines: Vec<String>) -> Result<String, String> {
    let n = crate::db::save_library_lines(&lines)?;
    Ok(format!("Saved {n} bridge(s) to library"))
}

#[tauri::command]
pub fn list_bridge_library() -> Result<Vec<String>, String> {
    crate::db::list_library()
}

#[tauri::command]
pub async fn get_session_overview() -> crate::db::SessionOverview {
    let connected = tor::socks_reachable();
    if connected {
        if let (Ok((r, w)), Ok(c)) = (tor::traffic_counters().await, tor::circuit_count().await) {
            let _ = crate::db::sample_traffic(r, w, c);
        }
    }
    crate::db::overview(connected)
}

#[tauri::command]
pub fn scan_bridges(lines: Option<Vec<String>>) -> Vec<tor::bridges::BridgeScanResult> {
    let list = lines.unwrap_or_else(|| settings::load().bridge_lines);
    tor::bridges::scan_bridges(&list)
}

#[tauri::command]
pub async fn apply_scanned_bridges(
    state: State<'_, AppState>,
    lines: Vec<String>,
    enable: bool,
) -> Result<String, String> {
    let parsed = lines
        .iter()
        .filter_map(|l| tor::bridges::normalize_bridge_line(l))
        .collect::<Vec<_>>();
    settings::update(|s| {
        s.bridge_lines = parsed;
        s.bridges_enabled = enable && !s.bridge_lines.is_empty();
        if enable && !s.bridge_lines.is_empty() {
            s.bridge_source = "custom".into();
        }
    })?;

    if tor::socks_reachable() || enable {
        let mut guard = state.managed_tor.lock().await;
        let msg = tor::restart_managed(&mut guard).await?;
        return Ok(format!(
            "Applied {} bridge(s). {msg}",
            settings::load().bridge_lines.len()
        ));
    }
    Ok(format!(
        "Saved {} bridge(s). Start Tor to connect.",
        settings::load().bridge_lines.len()
    ))
}

#[tauri::command]
pub async fn get_bootstrap_progress() -> Result<u32, String> {
    tor::bootstrap_progress().await
}

#[tauri::command]
pub async fn search_relays(
    query: String,
    limit: Option<u32>,
) -> Result<Vec<crate::routing::RelayInfo>, String> {
    crate::routing::search_relays(&query, limit.unwrap_or(20) as usize).await
}

#[tauri::command]
pub fn pin_relay(role: String, fingerprint: String) -> Result<AppSettings, String> {
    let fp = fingerprint.trim().to_uppercase();
    if fp.len() < 16 {
        return Err("Fingerprint looks too short".into());
    }
    match role.as_str() {
        "entry" | "middle" | "exit" => {}
        _ => return Err("role must be entry, middle, or exit".into()),
    }
    settings::update(|s| match role.as_str() {
        "entry" => s.entry_nodes = fp,
        "middle" => s.middle_nodes = fp,
        "exit" => {
            s.exit_nodes_fp = fp;
            s.exit_country.clear();
        }
        _ => {}
    })
}

#[tauri::command]
pub fn clear_relay_pins() -> Result<AppSettings, String> {
    settings::update(|s| {
        s.entry_nodes.clear();
        s.middle_nodes.clear();
        s.exit_nodes_fp.clear();
    })
}

#[tauri::command]
pub fn set_split_tunnel(enabled: bool, apps: String) -> Result<AppSettings, String> {
    let list: Vec<String> = apps
        .split(|c| c == ',' || c == '\n')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    settings::update(|s| {
        s.split_tunnel = enabled;
        s.split_tunnel_apps = list;
    })
}

#[tauri::command]
pub fn set_app_routing(
    enabled: bool,
    policy: String,
    session_guard: bool,
    apps: Vec<crate::settings::AppIdentity>,
) -> Result<AppSettings, String> {
    settings::update(|s| {
        s.split_tunnel = enabled;
        s.app_routing_policy = policy;
        s.session_guard = session_guard;
        s.route_apps = apps;
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRouteStatus {
    pub id: String,
    pub label: String,
    pub running: bool,
    pub routed: bool,
    pub exit_ip: Option<String>,
    pub detail: String,
}

fn identity_running(app: &crate::settings::AppIdentity) -> bool {
    let output = if !app.executable_path.is_empty() {
        std::process::Command::new("pgrep")
            .args(["-f", &app.executable_path])
            .output()
    } else {
        std::process::Command::new("pgrep")
            .args(["-x", &app.process_name])
            .output()
    };
    output
        .map(|result| result.status.success() && !result.stdout.is_empty())
        .unwrap_or(false)
}

#[tauri::command]
pub async fn get_app_route_statuses() -> Vec<AppRouteStatus> {
    let settings = settings::load();
    let protected = tor::socks_reachable() && crate::tun::process_seems_running();
    let mut statuses = Vec::new();
    for (index, app) in settings.route_apps.iter().enumerate() {
        let selected_through_tor = settings.app_routing_policy == "only";
        let routed = settings.split_tunnel && protected && selected_through_tor;
        let exit_ip = if routed {
            crate::ip::fetch_via_isolated(index, app.circuit_epoch)
                .await
                .ok()
        } else {
            None
        };
        statuses.push(AppRouteStatus {
            id: app.id.clone(),
            label: app.label.clone(),
            running: identity_running(app),
            routed,
            exit_ip,
            detail: if routed {
                "Dedicated IsolateSOCKSAuth circuit is reachable".into()
            } else if settings.app_routing_policy == "except" {
                "Selected as a direct-route exception".into()
            } else if !protected {
                "TUN or Tor is not active".into()
            } else {
                "Application routing is disabled".into()
            },
        });
    }
    statuses
}

#[tauri::command]
pub async fn rotate_app_circuit(
    state: State<'_, AppState>,
    app_id: String,
) -> Result<String, String> {
    let saved = settings::update(|s| {
        if let Some(app) = s.route_apps.iter_mut().find(|app| app.id == app_id) {
            app.circuit_epoch = app.circuit_epoch.saturating_add(1);
        }
    })?;
    let app = saved
        .route_apps
        .iter()
        .find(|app| app.id == app_id)
        .ok_or_else(|| "Application identity not found".to_string())?;
    if crate::tun::process_seems_running() {
        let mut managed = state.managed_singbox.lock().await;
        crate::tun::stop(&mut managed).await?;
        crate::tun::start(&mut managed).await?;
    }
    Ok(format!(
        "Rotated isolated circuit credentials for {}",
        app.label
    ))
}

/// Open a native file picker and resolve a process name for TUN split tunnel.
///
/// Must be `async`: `blocking_pick_file` must not run on the main thread or the
/// app freezes/deadlocks with the event loop (especially on macOS).
#[tauri::command]
pub async fn pick_split_app(
    app: tauri::AppHandle,
) -> Result<Option<crate::detect::SplitAppPick>, String> {
    use tauri_plugin_dialog::DialogExt;

    let dialog = app
        .dialog()
        .file()
        .set_title("Add app to split tunnel")
        .set_can_create_directories(false);

    #[cfg(target_os = "macos")]
    let dialog = dialog
        .set_directory("/Applications")
        .add_filter("Applications", &["app"]);
    #[cfg(target_os = "linux")]
    let dialog = {
        let home_apps = dirs::home_dir()
            .map(|h| h.join(".local/share/applications"))
            .filter(|p| p.is_dir());
        if let Some(dir) = home_apps {
            dialog.set_directory(dir)
        } else {
            dialog.set_directory("/usr/share/applications")
        }
        // No extension filter: pick .desktop entries or binaries under /usr/bin, etc.
    };

    // Runs on a worker thread because this command is async.
    let Some(file) = dialog.blocking_pick_file() else {
        return Ok(None);
    };
    let path = file
        .into_path()
        .map_err(|e| format!("Could not resolve path: {e}"))?;
    Ok(Some(crate::detect::resolve_split_app(&path)?))
}

#[tauri::command]
pub fn get_snowflake_status(state: State<'_, AppState>) -> crate::snowflake::SnowflakeStatus {
    match state.managed_snowflake.try_lock() {
        Ok(guard) => crate::snowflake::status(&guard),
        Err(_) => crate::snowflake::status(&None),
    }
}

#[tauri::command]
pub async fn start_snowflake(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.managed_snowflake.lock().await;
    crate::snowflake::start(&mut guard).await
}

#[tauri::command]
pub async fn stop_snowflake(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.managed_snowflake.lock().await;
    crate::snowflake::stop(&mut guard).await
}

#[tauri::command]
pub fn get_harden_items() -> Vec<crate::harden::HardenItem> {
    crate::harden::list()
}

#[tauri::command]
pub async fn apply_harden(id: String, enable: bool) -> Result<String, String> {
    crate::harden::apply(&id, enable).await
}

#[tauri::command]
pub async fn stop_tor(state: State<'_, AppState>) -> Result<String, String> {
    let _ = crate::db::end_session();
    // Full session teardown: TUN, kill switch, system proxy, snowflake, Tor, PT orphans.
    let result = crate::cleanup::teardown_session(
        &state.managed_tor,
        &state.managed_singbox,
        &state.managed_snowflake,
        &state.saved_proxy,
        crate::cleanup::TeardownMode::Disconnect,
    )
    .await;
    end_of_session_memory();
    result
}

/// Drop the memory-only state that belongs to the session that just ended: the
/// reopen ledger, so a later session cannot relaunch its apps, and the clearnet
/// announcements, so the next Protected session alerts from scratch.
fn end_of_session_memory() {
    crate::apps_lifecycle::clear_reopen_ledger();
    crate::egress_watch::reset_announced();
}

#[tauri::command]
pub fn get_recovery_status() -> crate::session::RecoveryStatus {
    crate::session::recovery_status()
}

#[tauri::command]
pub fn get_connection_filter_status() -> crate::ne_filter::FilterStatus {
    crate::ne_filter::status()
}

#[tauri::command]
pub fn activate_connection_filter() -> Result<String, String> {
    crate::ne_filter::activate()
}

#[tauri::command]
pub fn deactivate_connection_filter() -> Result<String, String> {
    crate::ne_filter::deactivate()
}

#[tauri::command]
pub async fn emergency_restore(state: State<'_, AppState>) -> Result<String, String> {
    let _ = crate::db::end_session();
    let result = crate::cleanup::teardown_session(
        &state.managed_tor,
        &state.managed_singbox,
        &state.managed_snowflake,
        &state.saved_proxy,
        crate::cleanup::TeardownMode::RestoreHost,
    )
    .await;
    end_of_session_memory();
    result
}

#[tauri::command]
pub async fn start_tun(state: State<'_, AppState>) -> Result<String, String> {
    if !tor::socks_reachable() {
        return Err("Start Tor before enabling TUN mode".into());
    }
    crate::session::expect_tun(true)?;
    let mut sb = state.managed_singbox.lock().await;
    match crate::tun::start(&mut sb).await {
        Ok(msg) => {
            settings::update(|s| s.connection_mode = "tun".into())?;
            let settings = settings::load();
            if settings.kill_switch {
                crate::session::expect_firewall(true)?;
                match crate::firewall::enable_kill_switch().await {
                    Ok(k) => {
                        crate::session::set_phase(crate::session::SessionPhase::Protected, None)?;
                        Ok(format!("{msg}. {k}"))
                    }
                    Err(e) => {
                        let _ = crate::session::set_phase(
                            crate::session::SessionPhase::Degraded,
                            Some(e.clone()),
                        );
                        Err(format!(
                            "{msg}, but the requested kill switch was not verified ({e}). \
                             The session is degraded."
                        ))
                    }
                }
            } else {
                crate::session::set_phase(crate::session::SessionPhase::Protected, None)?;
                Ok(msg)
            }
        }
        Err(e) => {
            let _ = settings::update(|s| s.connection_mode = "proxy".into());
            let _ = crate::tun::stop(&mut sb).await;
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn stop_tun(state: State<'_, AppState>) -> Result<String, String> {
    let mut sb = state.managed_singbox.lock().await;
    let msg = crate::tun::stop(&mut sb).await?;
    crate::session::expect_tun(false)?;
    settings::update(|s| s.connection_mode = "proxy".into())?;
    Ok(msg)
}

#[tauri::command]
pub async fn set_kill_switch(enabled: bool) -> Result<String, String> {
    settings::update(|s| s.kill_switch = enabled)?;
    if enabled {
        crate::session::expect_firewall(true)?;
        match crate::firewall::enable_kill_switch().await {
            Ok(message) => {
                if tor::socks_reachable() && crate::tun::process_seems_running() {
                    crate::session::set_phase(crate::session::SessionPhase::Protected, None)?;
                }
                Ok(message)
            }
            Err(error) => {
                if crate::session::load().phase != crate::session::SessionPhase::Disconnected {
                    let _ = crate::session::set_phase(
                        crate::session::SessionPhase::Degraded,
                        Some(error.clone()),
                    );
                }
                Err(error)
            }
        }
    } else {
        let result = crate::firewall::disable_kill_switch().await;
        if result.is_ok() {
            crate::session::expect_firewall(false)?;
            if tor::socks_reachable() && crate::tun::process_seems_running() {
                crate::session::set_phase(crate::session::SessionPhase::Protected, None)?;
            }
        } else if crate::session::load().phase != crate::session::SessionPhase::Disconnected {
            let error = result.as_ref().err().cloned().unwrap_or_default();
            let _ = crate::session::set_phase(crate::session::SessionPhase::Degraded, Some(error));
        }
        result
    }
}

#[tauri::command]
pub fn set_connection_mode(mode: String) -> Result<AppSettings, String> {
    settings::update(|s| s.connection_mode = mode)
}

#[tauri::command]
pub fn enable_proxy(state: State<'_, AppState>) -> Result<String, String> {
    if !tor::socks_reachable() {
        return Err("Tor SOCKS is not reachable on 127.0.0.1:9050. Start Tor first.".into());
    }
    let mut saved = state
        .saved_proxy
        .lock()
        .map_err(|_| "State lock poisoned".to_string())?;
    if crate::session::load().original_proxy.is_none() {
        let snapshot = proxy::capture()?;
        crate::session::record_proxy_before(snapshot.clone())?;
        *saved = snapshot;
    }
    proxy::enable(&mut saved)
}

#[tauri::command]
pub fn disable_proxy(state: State<'_, AppState>) -> Result<String, String> {
    let mut saved = state
        .saved_proxy
        .lock()
        .map_err(|_| "State lock poisoned".to_string())?;
    let result = proxy::disable(&mut saved);
    if result.is_ok() {
        let _ = crate::session::update(|j| {
            j.proxy_changed = false;
            j.original_proxy = None;
        });
    }
    result
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIdentityResult {
    pub message: String,
    pub ips: IpReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillClearnetIdentityResult {
    pub kill: crate::apps_lifecycle::ClearnetKillResult,
    pub identity: NewIdentityResult,
    pub detail: String,
}

#[tauri::command]
pub async fn new_identity(state: State<'_, AppState>) -> Result<NewIdentityResult, String> {
    new_identity_inner(state).await
}

async fn new_identity_inner(state: State<'_, AppState>) -> Result<NewIdentityResult, String> {
    {
        let mut guard = state.managed_tor.lock().await;
        tor::ensure_tor_with_control(&mut guard).await?;
    }
    let message = tor::new_identity().await?;
    let _ = crate::db::bump_identity();
    // Wait for circuits and retry Tor IP so the UI does not show a transient failure.
    let ips = ip::refresh_ips_after_newnym().await;
    let message = match (&ips.tor_ip, &ips.tor_location) {
        (Some(ip), Some(loc)) => format!("{message}. Tor IP: {ip} ({})", loc.label),
        (Some(ip), None) => format!("{message}. Tor IP: {ip}"),
        _ => format!(
            "{message}. Tor IP not ready yet: {}",
            ips.tor_error.as_deref().unwrap_or("unknown error")
        ),
    };
    Ok(NewIdentityResult { message, ips })
}

/// Kill processes with live clearnet sockets, then request NEWNYM. Never
/// accepts caller-supplied PIDs — only the current census.
#[tauri::command]
pub async fn kill_clearnet_and_new_identity(
    state: State<'_, AppState>,
) -> Result<KillClearnetIdentityResult, String> {
    if !tor::socks_reachable() || !tor::control_reachable() {
        return Err(
            "Connect to Tor before killing clearnet processes and requesting a new identity".into(),
        );
    }
    let kill = crate::apps_lifecycle::kill_clearnet_processes().await?;
    let identity = new_identity_inner(state).await?;
    let detail = format!("{}. {}", kill.detail, identity.message);
    Ok(KillClearnetIdentityResult {
        kill,
        identity,
        detail,
    })
}

/// Kill one process from the live Not through Tor census. Destinations are
/// never accepted or logged; only pid and process name appear in the result.
#[tauri::command]
pub async fn kill_clearnet_process(
    pid: u32,
) -> Result<crate::apps_lifecycle::ProcessKillResult, String> {
    crate::apps_lifecycle::kill_clearnet_process(pid).await
}

#[tauri::command]
pub fn get_ips() -> IpReport {
    ip::current()
}

#[tauri::command]
pub async fn refresh_ips() -> IpReport {
    ip::refresh_ips().await
}

#[tauri::command]
pub fn get_bypass_helpers() -> BypassHelpers {
    bypass::helpers()
}

#[tauri::command]
pub fn write_shell_env() -> Result<String, String> {
    bypass::write_shell_env()
}

#[tauri::command]
pub fn get_shell_hook_status() -> ShellHookStatus {
    bypass::shell_hook_status()
}

#[tauri::command]
pub fn install_shell_hook() -> Result<String, String> {
    bypass::install_shell_hook()
}

#[tauri::command]
pub fn uninstall_shell_hook() -> Result<String, String> {
    bypass::uninstall_shell_hook()
}

#[tauri::command]
pub fn write_firefox_user_js() -> Result<String, String> {
    bypass::write_firefox_user_js()
}

#[tauri::command]
pub fn detect_apps() -> crate::detect::DetectReport {
    crate::detect::detect_apps()
}

#[tauri::command]
pub fn exit_country_options() -> Vec<crate::detect::ExitCountryOption> {
    crate::detect::exit_country_options()
}

#[tauri::command]
pub fn get_advanced_status() -> bypass::AdvancedStatus {
    bypass::advanced_status()
}

#[tauri::command]
pub fn configure_advanced_item(id: String) -> Result<String, String> {
    bypass::configure_item(&id)
}

#[tauri::command]
pub fn remove_advanced_item(id: String) -> Result<String, String> {
    bypass::remove_item(&id)
}

#[tauri::command]
pub fn get_shell_proxy_status() -> bypass::ShellProxyStatus {
    bypass::shell_proxy_status()
}

#[tauri::command]
pub fn set_shell_proxy_mode(mode: String) -> Result<String, String> {
    bypass::set_shell_proxy_mode(&mode)
}

#[tauri::command]
pub async fn test_network() -> ip::NetworkTestResult {
    ip::test_network().await
}

#[tauri::command]
pub fn detect_vpn() -> crate::vpn_detect::VpnStatus {
    crate::vpn_detect::detect()
}

#[tauri::command]
pub fn get_macports_status() -> crate::harden::MacPortsStatus {
    crate::harden::macports_status()
}

#[tauri::command]
pub fn open_macports_download() -> Result<String, String> {
    crate::harden::open_macports_download()
}

#[tauri::command]
pub fn get_kill_siri_status() -> crate::harden::KillSiriStatus {
    crate::harden::kill_siri_status()
}

#[tauri::command]
pub fn get_deny_log() -> crate::deny_log::DenyLogSnapshot {
    crate::deny_log::snapshot()
}

#[tauri::command]
pub fn acknowledge_deny(process: String, dest: String, port: u16, proto: String) {
    crate::deny_log::acknowledge(&process, &dest, port, &proto);
}

#[tauri::command]
pub async fn add_strict_exception(dest: String, persist: bool) -> Result<String, String> {
    let ip = crate::firewall::strict::parse_ip(&dest)?;
    let settings = settings::load();
    if !settings.strict_tcp_lock {
        return Err("NIC lock is off".into());
    }
    let addr = ip.to_string();
    crate::logs::append("NIC lock exception added (destination hole; session degraded)");
    settings::update(|s| {
        if !s.strict_tcp_exceptions.contains(&addr) {
            s.strict_tcp_exceptions.push(addr.clone());
        }
        if !persist {
            // Session-only: still stored in settings so pf can reload; user is warned.
        }
    })?;
    crate::session::set_phase(
        crate::session::SessionPhase::Degraded,
        Some("NIC lock has a destination exception (machine-wide leak)".into()),
    )?;
    crate::firewall::enable_kill_switch().await
}

#[tauri::command]
pub async fn remove_strict_exception(dest: String) -> Result<String, String> {
    settings::update(|s| {
        s.strict_tcp_exceptions.retain(|item| item != &dest);
    })?;
    crate::logs::append("NIC lock exception removed");
    crate::firewall::enable_kill_switch().await
}

/// Allowlisted public pages only. The UI never supplies a URL string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectLink {
    Docs,
    Github,
    License,
}

const DOCS_URL: &str = "https://openhat-security.github.io/oniongate/";
const GITHUB_URL: &str = "https://github.com/openhat-security/oniongate";
const LICENSE_URL: &str = "https://github.com/openhat-security/oniongate/blob/main/LICENSE";

fn project_link_url(link: ProjectLink) -> &'static str {
    match link {
        ProjectLink::Docs => DOCS_URL,
        ProjectLink::Github => GITHUB_URL,
        ProjectLink::License => LICENSE_URL,
    }
}

fn open_https_url(url: &'static str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("refusing to open a non-https project link".into());
    }
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open")
        .arg(url)
        .status()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    let status = std::process::Command::new("xdg-open")
        .arg(url)
        .status()
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "windows")]
    let status = {
        use crate::win_console::HideConsole;
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", "start", "", url]).hide_console();
        cmd.status().map_err(|e| e.to_string())?
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        return Err("Opening project links is not supported on this OS".into());
    }
    if status.success() {
        Ok(())
    } else {
        Err("Could not open the link in a browser".into())
    }
}

/// The `.pkg` installer stages the uninstaller inside the bundle. DMG and
/// from-source installs never have it, so the error has to point somewhere real.
const MISSING_UNINSTALLER: &str =
    "This copy of OnionGate has no built-in uninstaller. It ships only with the macOS .pkg \
     installer, not with the DMG or a build from source. To remove OnionGate, run \
     scripts/macos-pkg/uninstall-oniongate.sh from the OnionGate repository — it does the same \
     work and keeps your data unless you pass --purge-data.";

/// `…/OnionGate.app/Contents/MacOS/oniongate` → `…/Contents/Resources/uninstall.command`.
fn uninstaller_path_for(exe: &std::path::Path) -> Option<std::path::PathBuf> {
    let contents = exe.parent()?.parent()?;
    if contents.file_name()? != "Contents" {
        return None;
    }
    Some(contents.join("Resources").join("uninstall.command"))
}

/// Hand the bundled uninstaller to the user's own session so Terminal runs it
/// and the script asks for administrator access itself. OnionGate never
/// executes it as root, and never runs it without the user seeing it.
#[tauri::command]
pub async fn open_uninstaller() -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("The bundled uninstaller is macOS-only.".into());
    }
    if crate::apps_lifecycle::running_as_root() {
        return Err(
            "Refusing to run the uninstaller from a privileged process. Open OnionGate as your \
             own user and try again."
                .into(),
        );
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("Could not locate the running OnionGate bundle: {e}"))?;
    let script = uninstaller_path_for(&exe).ok_or_else(|| MISSING_UNINSTALLER.to_string())?;
    if !script.is_file() {
        return Err(MISSING_UNINSTALLER.into());
    }
    let status = tokio::process::Command::new("/usr/bin/open")
        .arg(&script)
        .status()
        .await
        .map_err(|e| format!("Could not open the uninstaller: {e}"))?;
    if !status.success() {
        return Err("Could not open the uninstaller in Terminal.".into());
    }
    Ok(
        "Opened the OnionGate uninstaller in Terminal. It asks you to confirm and requests \
        administrator access itself. Your settings and Onion Host keys are kept unless you \
        choose to purge data."
            .into(),
    )
}

/// Open the docs site, the project GitHub page, or the GPL-3.0 license text in
/// the system browser.
#[tauri::command]
pub fn open_project_link(link: ProjectLink) -> Result<String, String> {
    open_https_url(project_link_url(link))?;
    Ok(match link {
        ProjectLink::Docs => "Opened the OnionGate docs".into(),
        ProjectLink::Github => "Opened the OnionGate GitHub page".into(),
        ProjectLink::License => "Opened the OnionGate license".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_links_are_fixed_https() {
        assert_eq!(
            project_link_url(ProjectLink::Docs),
            "https://openhat-security.github.io/oniongate/"
        );
        assert_eq!(
            project_link_url(ProjectLink::Github),
            "https://github.com/openhat-security/oniongate"
        );
        assert_eq!(
            project_link_url(ProjectLink::License),
            "https://github.com/openhat-security/oniongate/blob/main/LICENSE"
        );
        assert!(DOCS_URL.starts_with("https://"));
        assert!(GITHUB_URL.starts_with("https://"));
        assert!(LICENSE_URL.starts_with("https://"));
    }

    #[test]
    fn project_link_enum_deserializes_from_ui_tags() {
        assert_eq!(
            serde_json::from_str::<ProjectLink>("\"docs\"").unwrap(),
            ProjectLink::Docs
        );
        assert_eq!(
            serde_json::from_str::<ProjectLink>("\"github\"").unwrap(),
            ProjectLink::Github
        );
        assert_eq!(
            serde_json::from_str::<ProjectLink>("\"license\"").unwrap(),
            ProjectLink::License
        );
        assert!(serde_json::from_str::<ProjectLink>("\"https://evil.example\"").is_err());
    }

    #[test]
    fn missing_uninstaller_message_points_at_the_repository_script() {
        // The UI surfaces this verbatim, so it has to name the fallback and say
        // why the bundled one is absent.
        assert!(MISSING_UNINSTALLER.contains("scripts/macos-pkg/uninstall-oniongate.sh"));
        assert!(MISSING_UNINSTALLER.contains(".pkg"));
        assert!(MISSING_UNINSTALLER.contains("DMG"));
        assert!(MISSING_UNINSTALLER.contains("--purge-data"));
        assert!(!MISSING_UNINSTALLER.contains("uninstall.command"));
    }

    #[test]
    fn uninstaller_resolves_next_to_the_running_executable() {
        assert_eq!(
            uninstaller_path_for(std::path::Path::new(
                "/Applications/OnionGate.app/Contents/MacOS/oniongate"
            )),
            Some(std::path::PathBuf::from(
                "/Applications/OnionGate.app/Contents/Resources/uninstall.command"
            ))
        );
        // A from-source `cargo run` binary is not inside a bundle at all.
        assert_eq!(
            uninstaller_path_for(std::path::Path::new(
                "/Users/me/oniongate/src-tauri/target/debug/OnionGate"
            )),
            None
        );
        assert_eq!(
            uninstaller_path_for(std::path::Path::new("/oniongate")),
            None
        );
    }
}
