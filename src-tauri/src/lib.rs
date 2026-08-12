mod apps_lifecycle;
mod bypass;
mod cleanup;
pub mod cli;
mod commands;
mod db;
mod deps;
mod detect;
mod egress_watch;
mod elevate;
mod firewall;
mod harden;
pub mod helper;
mod ip;
mod logs;
mod onion_service;
mod proxy;
mod routing;
mod session;
mod session_guard;
mod settings;
mod snowflake;
mod tor;
mod tray;
mod tun;
mod verify;
mod vpn_detect;
mod workstation;

use commands::AppState;
use tauri::{Manager, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            if let Err(e) = db::init() {
                eprintln!("SQLite init failed: {e}");
            }
            if let Err(e) = tray::setup(app) {
                eprintln!("Tray setup failed: {e}");
            }
            let recovery = session::recovery_status();
            if recovery.needed {
                logs::append(format!(
                    "Interrupted session detected at startup ({:?}); Emergency Restore is available",
                    recovery.phase
                ));
            } else if recovery.detail.starts_with("A stale") {
                let _ = session::clear();
            }
            session_guard::start_monitor();
            workstation::start_monitor();
            egress_watch::start_monitor();
            ip::start_monitor();
            Ok(())
        })
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_settings,
            commands::update_settings,
            commands::set_setup_complete,
            commands::prime_admin_auth,
            commands::privileged_helper_status,
            commands::install_privileged_helper,
            commands::remove_privileged_helper,
            commands::set_remote_dns,
            commands::get_tor_logs,
            commands::clear_tor_logs,
            commands::start_tor,
            commands::stop_tor,
            commands::arm_network_lock,
            commands::disarm_network_lock,
            commands::quit_user_applications,
            commands::get_recovery_status,
            commands::emergency_restore,
            commands::start_tun,
            commands::stop_tun,
            commands::set_kill_switch,
            commands::set_connection_mode,
            commands::get_bridge_lines,
            commands::set_bridge_lines,
            commands::set_bridges_enabled,
            commands::apply_tor_config,
            commands::set_exit_country,
            commands::fetch_bridges,
            commands::fetch_bridges_for,
            commands::test_onion_connectivity,
            commands::run_leak_verifier,
            commands::get_latest_leak_report,
            commands::export_latest_leak_report,
            commands::get_egress_watch,
            commands::reveal_egress_path,
            commands::start_onion_service,
            commands::list_onion_services,
            commands::stop_onion_service,
            commands::audit_onion_service,
            commands::list_permanent_sites,
            commands::add_permanent_site,
            commands::remove_permanent_site,
            commands::rename_permanent_site,
            commands::add_permanent_site_client,
            commands::revoke_permanent_site_client,
            commands::set_permanent_site_auth,
            commands::audit_permanent_site,
            commands::save_bridge_library,
            commands::list_bridge_library,
            commands::get_session_overview,
            commands::scan_bridges,
            commands::apply_scanned_bridges,
            commands::get_bootstrap_progress,
            commands::search_relays,
            commands::pin_relay,
            commands::clear_relay_pins,
            commands::set_split_tunnel,
            commands::set_app_routing,
            commands::get_app_route_statuses,
            commands::rotate_app_circuit,
            commands::pick_split_app,
            commands::get_snowflake_status,
            commands::start_snowflake,
            commands::stop_snowflake,
            commands::get_harden_items,
            commands::apply_harden,
            commands::enable_proxy,
            commands::disable_proxy,
            commands::new_identity,
            commands::kill_clearnet_and_new_identity,
            commands::refresh_ips,
            commands::get_ips,
            commands::get_bypass_helpers,
            commands::write_shell_env,
            commands::get_shell_hook_status,
            commands::install_shell_hook,
            commands::uninstall_shell_hook,
            commands::write_firefox_user_js,
            commands::detect_apps,
            commands::exit_country_options,
            commands::get_advanced_status,
            commands::configure_advanced_item,
            commands::remove_advanced_item,
            commands::get_shell_proxy_status,
            commands::set_shell_proxy_mode,
            commands::test_network,
            commands::detect_vpn,
            commands::get_macports_status,
            commands::open_macports_download,
            commands::get_kill_siri_status,
            commands::get_workstation_posture,
            commands::get_persistence_report,
            commands::save_persistence_baseline,
            commands::scan_login_items,
            commands::open_full_disk_access_settings,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            tauri::RunEvent::WindowEvent {
                label,
                event: WindowEvent::CloseRequested { api, .. },
                ..
            } if label == "main" => {
                // Keep OnionGate in the menu bar / tray; hide instead of quitting.
                if let Some(window) = app_handle.get_webview_window("main") {
                    let _ = window.hide();
                }
                api.prevent_close();
            }
            tauri::RunEvent::Exit => {
                let state = app_handle.state::<AppState>();
                cleanup::teardown_session_blocking(
                    &state.managed_tor,
                    &state.managed_singbox,
                    &state.managed_snowflake,
                    &state.saved_proxy,
                );
            }
            _ => {}
        });
}
