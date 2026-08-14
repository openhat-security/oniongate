//! Native menu-bar / system-tray status and controls for all desktop targets.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_os = "windows")]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, Runtime,
};

const TRAY_ID: &str = "oniongate-tray";
static ACTION_BUSY: AtomicBool = AtomicBool::new(false);

fn tray_image() -> tauri::Result<Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes = include_bytes!("../icons/tray-macos.png");
    #[cfg(not(target_os = "macos"))]
    let bytes = include_bytes!("../icons/tray-color.png");
    Image::from_bytes(bytes)
}

fn status_label() -> String {
    let phase = crate::session::load().phase;
    if phase == crate::session::SessionPhase::Recovering {
        return "Recovering".into();
    }
    if phase == crate::session::SessionPhase::Connecting {
        return "Connecting".into();
    }
    if phase == crate::session::SessionPhase::Degraded {
        return "Degraded".into();
    }

    let socks = crate::tor::socks_reachable();
    let control = crate::tor::control_reachable();
    if !socks {
        return if phase == crate::session::SessionPhase::Protected {
            "Degraded"
        } else {
            "Disconnected"
        }
        .into();
    }
    if !control {
        return "Tor starting".into();
    }

    let settings = crate::settings::load();
    let firewall = crate::firewall::status();
    if settings.strict_tcp_lock
        && (!firewall.strict_deny_live || !settings.strict_tcp_exceptions.is_empty())
    {
        return "Degraded".into();
    }
    let dns_ready = !settings.remote_dns || crate::tor::dns_reachable();
    let firewall_ready = if settings.kill_switch {
        firewall.active && firewall.verified_live
    } else {
        true
    };
    if crate::tun::process_seems_running() {
        if phase == crate::session::SessionPhase::Protected && dns_ready && firewall_ready {
            "Protected · TUN".into()
        } else {
            "TUN active · unverified".into()
        }
    } else if crate::proxy::get_status().enabled {
        if phase == crate::session::SessionPhase::Protected && dns_ready && firewall_ready {
            if settings.bridges_enabled {
                "Protected · bridges".into()
            } else {
                "Protected · proxy".into()
            }
        } else {
            "Proxy active · unverified".into()
        }
    } else {
        "Tor ready".into()
    }
}

fn refresh_menu<R: Runtime>(
    app: &AppHandle<R>,
    status: &MenuItem<R>,
    connect: &MenuItem<R>,
    new_identity: &MenuItem<R>,
    restore: &MenuItem<R>,
) {
    if ACTION_BUSY.load(Ordering::SeqCst) {
        set_working(status, connect, new_identity, restore);
        return;
    }
    let label = status_label();
    let tor_live = crate::tor::socks_reachable();
    let control_live = crate::tor::control_reachable();
    let recovery_needed = crate::session::recovery_status().needed;

    let _ = status.set_text(format!("Status: {label}"));
    let _ = connect.set_text(if tor_live {
        "Disconnect & restore"
    } else {
        "Connect Tor"
    });
    let _ = connect.set_enabled(true);
    let _ = new_identity.set_enabled(tor_live && control_live);
    let _ = restore.set_enabled(recovery_needed);
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(format!("OnionGate — {label}")));
    }
}

fn set_working<R: Runtime>(
    status: &MenuItem<R>,
    connect: &MenuItem<R>,
    new_identity: &MenuItem<R>,
    restore: &MenuItem<R>,
) {
    let _ = status.set_text("Status: Working…");
    let _ = connect.set_enabled(false);
    let _ = new_identity.set_enabled(false);
    let _ = restore.set_enabled(false);
}

pub fn setup<R: Runtime>(app: &tauri::App<R>) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "Status: Starting…", false, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "Connect Tor", true, None::<&str>)?;
    let new_identity = MenuItem::with_id(app, "new_identity", "New Identity", false, None::<&str>)?;
    let restore = MenuItem::with_id(
        app,
        "emergency_restore",
        "Emergency Restore",
        false,
        None::<&str>,
    )?;
    let action_sep = PredefinedMenuItem::separator(app)?;
    let show = MenuItem::with_id(app, "show", "Open OnionGate", true, None::<&str>)?;
    let open_verify =
        MenuItem::with_id(app, "open_verify", "Verify Protection…", true, None::<&str>)?;
    let open_host = MenuItem::with_id(app, "open_host", "Onion Host…", true, None::<&str>)?;
    let open_logs = MenuItem::with_id(app, "open_logs", "View Logs…", true, None::<&str>)?;
    let hide = MenuItem::with_id(app, "hide", "Hide Window", true, None::<&str>)?;
    let quit_sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Quit OnionGate", true, None::<&str>)?;
    let menu = Menu::with_items(
        app,
        &[
            &status,
            &connect,
            &new_identity,
            &restore,
            &action_sep,
            &show,
            &open_verify,
            &open_host,
            &open_logs,
            &hide,
            &quit_sep,
            &quit,
        ],
    )?;

    let event_status = status.clone();
    let event_connect = connect.clone();
    let event_identity = new_identity.clone();
    let event_restore = restore.clone();
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .icon(tray_image()?)
        .tooltip("OnionGate — Starting")
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "connect" => {
                if ACTION_BUSY.swap(true, Ordering::SeqCst) {
                    return;
                }
                set_working(
                    &event_status,
                    &event_connect,
                    &event_identity,
                    &event_restore,
                );
                let app = app.clone();
                let status = event_status.clone();
                let connect = event_connect.clone();
                let new_identity = event_identity.clone();
                let restore = event_restore.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<crate::commands::AppState>();
                    let result = if crate::tor::socks_reachable() {
                        crate::commands::stop_tor(state).await
                    } else {
                        crate::commands::start_tor(state).await
                    };
                    if let Err(error) = result {
                        crate::logs::append(format!("Tray connection action failed: {error}"));
                    }
                    ACTION_BUSY.store(false, Ordering::SeqCst);
                    refresh_menu(&app, &status, &connect, &new_identity, &restore);
                });
            }
            "new_identity" => {
                if ACTION_BUSY.swap(true, Ordering::SeqCst) {
                    return;
                }
                set_working(
                    &event_status,
                    &event_connect,
                    &event_identity,
                    &event_restore,
                );
                let app = app.clone();
                let status = event_status.clone();
                let connect = event_connect.clone();
                let new_identity = event_identity.clone();
                let restore = event_restore.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(error) = crate::tor::new_identity().await {
                        crate::logs::append(format!("Tray identity change failed: {error}"));
                    } else {
                        let _ = crate::db::bump_identity();
                        crate::logs::append("New Tor identity requested from tray");
                    }
                    ACTION_BUSY.store(false, Ordering::SeqCst);
                    refresh_menu(&app, &status, &connect, &new_identity, &restore);
                });
            }
            "emergency_restore" => {
                if ACTION_BUSY.swap(true, Ordering::SeqCst) {
                    return;
                }
                set_working(
                    &event_status,
                    &event_connect,
                    &event_identity,
                    &event_restore,
                );
                let app = app.clone();
                let status = event_status.clone();
                let connect = event_connect.clone();
                let new_identity = event_identity.clone();
                let restore = event_restore.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<crate::commands::AppState>();
                    if let Err(error) = crate::commands::emergency_restore(state).await {
                        crate::logs::append(format!("Tray emergency restore failed: {error}"));
                    }
                    ACTION_BUSY.store(false, Ordering::SeqCst);
                    refresh_menu(&app, &status, &connect, &new_identity, &restore);
                });
            }
            "show" => show_main(app),
            "open_verify" => show_view(app, "verify"),
            "open_host" => show_view(app, "host"),
            "open_logs" => show_view(app, "logs"),
            "hide" => hide_main(app),
            "quit" => app.exit(0),
            _ => {}
        });

    #[cfg(target_os = "macos")]
    {
        builder = builder.icon_as_template(true).show_menu_on_left_click(true);
    }
    #[cfg(target_os = "windows")]
    {
        builder = builder
            .show_menu_on_left_click(false)
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show_main(tray.app_handle());
                }
            });
    }

    let _tray = builder.build(app)?;
    let app_handle = app.handle().clone();
    refresh_menu(&app_handle, &status, &connect, &new_identity, &restore);

    let poll_status = status.clone();
    let poll_connect = connect.clone();
    let poll_identity = new_identity.clone();
    let poll_restore = restore.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            refresh_menu(
                &app_handle,
                &poll_status,
                &poll_connect,
                &poll_identity,
                &poll_restore,
            );
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        }
    });

    Ok(())
}

fn show_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn show_view<R: Runtime>(app: &AppHandle<R>, view: &str) {
    show_main(app);
    let _ = app.emit("tray:navigate", view);
}

fn hide_main<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}

#[cfg(test)]
mod tests {
    use super::tray_image;
    use tauri::image::Image;

    #[test]
    fn tray_asset_is_small_rgba_png() {
        let image = tray_image().expect("tray PNG decodes");
        assert_eq!((image.width(), image.height()), (32, 32));
        assert!(image.rgba().chunks_exact(4).any(|pixel| pixel[3] == 0));
        assert!(image.rgba().chunks_exact(4).any(|pixel| pixel[3] > 0));
    }

    #[test]
    fn app_icon_has_transparent_corners() {
        let image = Image::from_bytes(include_bytes!("../icons/icon.png"))
            .expect("application icon PNG decodes");
        assert_eq!((image.width(), image.height()), (512, 512));
        let width = image.width() as usize;
        let height = image.height() as usize;
        let alpha = |x: usize, y: usize| image.rgba()[(y * width + x) * 4 + 3];
        for (x, y) in [
            (0, 0),
            (width - 1, 0),
            (0, height - 1),
            (width - 1, height - 1),
        ] {
            assert_eq!(alpha(x, y), 0, "corner ({x}, {y}) must be transparent");
        }
        assert!(alpha(width / 2, height / 2) > 0);
    }
}
