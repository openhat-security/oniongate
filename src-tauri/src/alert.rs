//! In-app clearnet alert popup.
//!
//! Deliberately **not** an OS notification. A macOS user notification hands its
//! text to Apple's notification service, which persists and syncs it outside
//! OnionGate — so the name of a process that just leaked would leave the app.
//! This window keeps the whole alert in-process; the payload is memory-only and
//! goes to one webview over one Tauri event.
//!
//! The popup itself is rendered by the UI at `index.html#clearnet-alert`, and
//! its "Kill it now" button calls the existing `kill_clearnet_process` command.
//! There is no second kill path here.

use std::sync::{LazyLock, Mutex, OnceLock};

use tauri::webview::{PageLoadEvent, PageLoadPayload};
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::egress_watch::ClearnetProcess;

/// Window label the UI keys its hash route to. Also the capability subject in
/// `capabilities/default.json`.
pub const WINDOW_LABEL: &str = "clearnet-alert";
/// Event carrying `Vec<ClearnetProcess>` to that window.
pub const PROCESSES_EVENT: &str = "clearnet-alert-processes";
/// No separate HTML entry point: the UI branches on the hash in `main.tsx`.
const ALERT_ROUTE: &str = "index.html#clearnet-alert";

const WIDTH: f64 = 392.0;
const HEIGHT: f64 = 316.0;

static APP: OnceLock<AppHandle> = OnceLock::new();
/// Latest payload. Kept so a webview that finishes loading *after* the emit
/// still gets its list, without re-running detection.
static PENDING: LazyLock<Mutex<Vec<ClearnetProcess>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Hand the window layer to the alert. Until this is called (CLI, unit tests)
/// every entry point below is a no-op.
pub fn register(app: AppHandle) {
    let _ = APP.set(app);
}

/// Show the popup for `processes`, reusing the window when it is already open.
///
/// One call per detection burst: the caller passes every newly seen process so
/// this opens a single window listing all of them, never one window per pid.
pub fn announce(processes: Vec<ClearnetProcess>) {
    if processes.is_empty() {
        return;
    }
    let Some(app) = APP.get() else {
        return;
    };
    if let Ok(mut pending) = PENDING.lock() {
        *pending = processes;
    }
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || show(&handle));
}

/// Close the popup and drop the payload. A clearnet alert belongs to the
/// session that raised it and must not outlive it.
pub fn dismiss() {
    if let Ok(mut pending) = PENDING.lock() {
        pending.clear();
    }
    let Some(app) = APP.get() else {
        return;
    };
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(window) = handle.get_webview_window(WINDOW_LABEL) {
            let _ = window.close();
        }
    });
}

fn show(app: &AppHandle) {
    if let Some(existing) = app.get_webview_window(WINDOW_LABEL) {
        let _ = existing.show();
        emit_pending(app);
        return;
    }

    let handle = app.clone();
    let on_page_load = move |_window: WebviewWindow, payload: PageLoadPayload<'_>| {
        if payload.event() == PageLoadEvent::Finished {
            emit_pending(&handle);
        }
    };

    let built = WebviewWindowBuilder::new(app, WINDOW_LABEL, WebviewUrl::App(ALERT_ROUTE.into()))
        .title("OnionGate — not going through Tor")
        .inner_size(WIDTH, HEIGHT)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .always_on_top(true)
        // Ride along on whichever space is in front, including a full-screen
        // app's, instead of yanking the user to another one.
        .visible_on_all_workspaces(true)
        // Never take key focus: an alert that steals keystrokes from a
        // full-screen app is worse than the leak it reports.
        .focused(false)
        .accept_first_mouse(true)
        .decorations(false)
        .shadow(true)
        .center()
        .on_page_load(on_page_load)
        .build();

    if let Err(e) = built {
        crate::logs::append(format!("Clearnet alert window could not be opened: {e}"));
    }
}

fn emit_pending(app: &AppHandle) {
    let payload = PENDING
        .lock()
        .map(|pending| pending.clone())
        .unwrap_or_default();
    if payload.is_empty() {
        return;
    }
    let _ = app.emit_to(WINDOW_LABEL, PROCESSES_EVENT, payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_label_event_and_route_match_the_ui_contract() {
        assert_eq!(WINDOW_LABEL, "clearnet-alert");
        assert_eq!(PROCESSES_EVENT, "clearnet-alert-processes");
        assert_eq!(ALERT_ROUTE, "index.html#clearnet-alert");
    }

    #[test]
    fn announce_without_a_window_layer_is_a_no_op() {
        // No AppHandle is registered in unit tests, so this must not panic and
        // must not leave a payload behind for a later session.
        announce(Vec::new());
        assert!(PENDING.lock().unwrap().is_empty());
        dismiss();
        assert!(PENDING.lock().unwrap().is_empty());
    }
}
