//! Opt-in OS privacy helpers.
//!
//! Licensing, per file — the blanket "everything here is clean-room" claim this
//! header used to make is no longer true:
//!
//! * Clean-room, written for OnionGate, containing no third-party code:
//!   `boot_lock.rs`, `login_item.rs`, `mac_random.rs`, `macports.rs`, `linux.rs`,
//!   and every item in `macos.rs` except the ones its own header names.
//! * Derived from term7's "MacOS-Privacy-and-Security-Enhancements" (GPL-3.0)
//!   and carrying a GPL-3.0 section 5(a) modification notice in their own
//!   headers: `wifi_boot.rs` (from `05_WiFi-OFF`), `kill_siri.rs` (from
//!   `02_Kill-Siri`), and the specific `macos.rs` items listed there.
//!
//! OnionGate is GPL-3.0 too, so the obligation is accurate attribution and
//! marking of modifications, not relicensing.
//!
//! Credit without derivation: privacy.sexy and drduh's macOS Security and
//! Privacy Guide (both cited by term7 in turn), and term7 `04_SpoofMAC`, whose
//! approach `mac_random.rs` deliberately does not follow.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod boot_lock;
#[cfg(target_os = "macos")]
mod kill_siri;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod login_item;
#[cfg(target_os = "macos")]
mod mac_random;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macports;
#[cfg(target_os = "macos")]
mod wifi_boot;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardenItem {
    pub id: String,
    pub title: String,
    pub description: String,
    pub active: bool,
    pub supported: bool,
    pub detail: String,
    /// `privacy` | `security` | `tools`
    pub group: String,
    /// `toggle` | `install` | `link` | `guide`
    pub control: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSiriStatus {
    pub installed: bool,
    pub agent_loaded: bool,
    pub running: Vec<String>,
    pub total_watched: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacPortsStatus {
    pub installed: bool,
    pub version: String,
    pub path: String,
    pub macos_version: String,
    pub macos_name: String,
    pub download_url: String,
    pub install_page: String,
    pub detail: String,
}

pub fn list() -> Vec<HardenItem> {
    #[cfg(target_os = "macos")]
    {
        return macos::list();
    }
    #[cfg(target_os = "linux")]
    {
        return linux::list();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

pub async fn apply(id: &str, enable: bool) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return macos::apply(id, enable).await;
    }
    #[cfg(target_os = "linux")]
    {
        return linux::apply(id, enable).await;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (id, enable);
        Err("Hardening helpers are macOS/Linux only".into())
    }
}

/// Called by the session module the moment the phase transitions into
/// `Protected`. On macOS this fires the guarded, idempotent Wi-Fi auto
/// re-enable (radio back on only if the boot daemon is installed, the setting
/// is on, and the radio is currently off); a no-op on other platforms.
pub fn on_session_protected() {
    #[cfg(target_os = "macos")]
    {
        wifi_boot::on_session_protected();
    }
}

pub fn kill_siri_status() -> KillSiriStatus {
    #[cfg(target_os = "macos")]
    {
        return kill_siri::status();
    }
    #[cfg(not(target_os = "macos"))]
    {
        KillSiriStatus {
            installed: false,
            agent_loaded: false,
            running: Vec::new(),
            total_watched: 0,
            detail: "Kill Siri is macOS only".into(),
        }
    }
}

pub fn macports_status() -> MacPortsStatus {
    #[cfg(target_os = "macos")]
    {
        return macports::status();
    }
    #[cfg(not(target_os = "macos"))]
    {
        MacPortsStatus {
            installed: false,
            version: String::new(),
            path: String::new(),
            macos_version: String::new(),
            macos_name: String::new(),
            download_url: String::new(),
            install_page: "https://www.macports.org/install.php".into(),
            detail: "MacPorts helpers are macOS only".into(),
        }
    }
}

pub fn open_macports_download() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return macports::open_download();
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("MacPorts helpers are macOS only".into())
    }
}

/// Checks shared by the generators in this module: everything we hand to
/// `launchd` is linted, and every script we hand to `bash` is parsed, before it
/// can reach a user's machine.
#[cfg(test)]
pub(crate) mod tests_support {
    use std::path::PathBuf;
    use std::process::Command;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("oniongate-harden-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join(name)
    }

    fn tool_exists(bin: &str) -> bool {
        std::path::Path::new(bin).is_file()
    }

    /// Set `ONIONGATE_KEEP_TEST_ARTIFACTS=1` to leave the generated plists and
    /// scripts on disk so they can be inspected or linted by hand.
    fn keep_artifacts() -> bool {
        std::env::var_os("ONIONGATE_KEEP_TEST_ARTIFACTS").is_some()
    }

    pub fn assert_plutil_lint(contents: &str, name: &str) {
        if !tool_exists("/usr/bin/plutil") {
            return;
        }
        let path = scratch(name);
        std::fs::write(&path, contents).expect("write plist");
        let out = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&path)
            .output()
            .expect("run plutil");
        if !keep_artifacts() {
            let _ = std::fs::remove_file(&path);
        }
        assert!(
            out.status.success(),
            "plutil -lint rejected {name}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub fn assert_bash_parses(script: &str, name: &str) {
        if !tool_exists("/bin/bash") {
            return;
        }
        let path = scratch(name);
        std::fs::write(&path, script).expect("write script");
        let out = Command::new("/bin/bash")
            .arg("-n")
            .arg(&path)
            .output()
            .expect("run bash -n");
        if !keep_artifacts() {
            let _ = std::fs::remove_file(&path);
        }
        assert!(
            out.status.success(),
            "bash -n rejected {name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
