//! Install / uninstall / status for the privileged helper.
//!
//! Each platform can register a persistent privileged service with a SINGLE
//! elevation prompt at install time; supported typed operations then use IPC
//! without another prompt:
//! - macOS: a launchd system daemon (`launchctl bootstrap`).
//! - Linux: a systemd system service.
//! - Windows: a Windows service (SCM).

#[cfg(target_os = "macos")]
use super::HELPER_LABEL;
use super::{client, HelperStatus};
#[cfg(target_os = "windows")]
use crate::win_console::HideConsole;

#[allow(dead_code)]
fn helper_binary() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe
        .parent()
        .ok_or_else(|| "cannot resolve app directory".to_string())?;
    #[cfg(windows)]
    let name = "oniongate-helper.exe";
    #[cfg(not(windows))]
    let name = "oniongate-helper";
    let path = dir.join(name);
    if !path.exists() {
        return Err(format!(
            "helper binary not found next to the app at {}",
            path.display()
        ));
    }
    Ok(path)
}

#[cfg(unix)]
fn current_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

pub fn status() -> HelperStatus {
    #[cfg(target_os = "macos")]
    {
        macos_status()
    }
    #[cfg(target_os = "linux")]
    {
        linux_status()
    }
    #[cfg(target_os = "windows")]
    {
        windows_status()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        HelperStatus {
            supported: false,
            installed: false,
            running: false,
            detail: "The privileged helper is not supported on this platform".into(),
        }
    }
}

pub fn install() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        macos_install()
    }
    #[cfg(target_os = "linux")]
    {
        linux_install()
    }
    #[cfg(target_os = "windows")]
    {
        windows_install()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("The privileged helper is not supported on this platform".into())
    }
}

/// Install the helper if it is missing, or replace it when the built binary
/// changed. No elevation when the installed copy is already running and matches.
pub fn ensure() -> Result<String, String> {
    let built = helper_binary()?;
    if client::available() {
        if let Some(installed) = installed_helper_path() {
            if file_sha256(&built) == file_sha256(std::path::Path::new(installed)) {
                return Ok("Privileged helper already running".into());
            }
        }
    }
    install()
}

fn installed_helper_path() -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        Some(MACOS_HELPER_DEST)
    }
    #[cfg(target_os = "linux")]
    {
        Some(LINUX_HELPER_DEST)
    }
    #[cfg(target_os = "windows")]
    {
        Some(WINDOWS_HELPER_DEST)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

fn file_sha256(path: &std::path::Path) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).ok()?;
    Some(Sha256::digest(bytes).into())
}

pub fn uninstall() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        macos_uninstall()
    }
    #[cfg(target_os = "linux")]
    {
        linux_uninstall()
    }
    #[cfg(target_os = "windows")]
    {
        windows_uninstall()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err("The privileged helper is not supported on this platform".into())
    }
}

// ------------------------------ macOS ------------------------------

#[cfg(target_os = "macos")]
const MACOS_HELPER_DEST: &str = "/Library/PrivilegedHelperTools/com.adamsiwiec.oniongate.helper";
#[cfg(target_os = "macos")]
const MACOS_PLIST_DEST: &str = "/Library/LaunchDaemons/com.adamsiwiec.oniongate.helper.plist";

#[cfg(target_os = "macos")]
fn macos_status() -> HelperStatus {
    let installed = std::path::Path::new(MACOS_PLIST_DEST).exists();
    let running = client::available();
    HelperStatus {
        supported: true,
        installed,
        running,
        detail: if running {
            "Helper installed and running — typed privileged operations apply without prompts"
                .into()
        } else if installed {
            "Helper installed but not running (it starts at boot/login)".into()
        } else {
            "Helper not installed — privileged changes use the administrator prompt".into()
        },
    }
}

#[cfg(target_os = "macos")]
fn macos_install() -> Result<String, String> {
    use crate::elevate::shell_quote;
    let src = helper_binary()?;
    if let Ok(app) = std::env::current_exe() {
        crate::helper::identity::verify_helper_for_install(&src, &app)?;
    }
    let uid = current_uid();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{HELPER_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{MACOS_HELPER_DEST}</string>
    <string>--allow-uid</string>
    <string>{uid}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#
    );
    let plist_src = crate::tor::process::ensure_data_dir()?.join("helper.plist");
    std::fs::write(&plist_src, plist).map_err(|e| e.to_string())?;

    let script = format!(
        "mkdir -p /Library/PrivilegedHelperTools && \
         cp {src} {dest_bin} && chown root:wheel {dest_bin} && chmod 544 {dest_bin} && \
         cp {plist_src} {dest_plist} && chown root:wheel {dest_plist} && chmod 644 {dest_plist} && \
         launchctl bootout system {dest_plist} 2>/dev/null || true; \
         launchctl bootstrap system {dest_plist} && launchctl enable system/{label}",
        src = shell_quote(&src.to_string_lossy()),
        dest_bin = shell_quote(MACOS_HELPER_DEST),
        plist_src = shell_quote(&plist_src.to_string_lossy()),
        dest_plist = shell_quote(MACOS_PLIST_DEST),
        label = HELPER_LABEL,
    );
    crate::elevate::run_shell_with_prompt(
        &script,
        "OnionGate is installing its background helper so it won't ask for your password again.",
    )?;
    Ok("Privileged helper installed".into())
}

#[cfg(target_os = "macos")]
fn macos_uninstall() -> Result<String, String> {
    use crate::elevate::shell_quote;
    let script = format!(
        "launchctl bootout system {dest_plist} 2>/dev/null || true; rm -f {dest_plist} {dest_bin}",
        dest_plist = shell_quote(MACOS_PLIST_DEST),
        dest_bin = shell_quote(MACOS_HELPER_DEST),
    );
    crate::elevate::run_shell_with_prompt(&script, "OnionGate is removing its background helper.")?;
    Ok("Privileged helper removed".into())
}

// ------------------------------ Linux ------------------------------

#[cfg(target_os = "linux")]
const LINUX_HELPER_DEST: &str = "/usr/local/lib/oniongate/oniongate-helper";
#[cfg(target_os = "linux")]
const LINUX_UNIT_DEST: &str = "/etc/systemd/system/oniongate-helper.service";

#[cfg(target_os = "linux")]
fn linux_status() -> HelperStatus {
    let installed = std::path::Path::new(LINUX_UNIT_DEST).exists();
    let running = client::available();
    HelperStatus {
        supported: true,
        installed,
        running,
        detail: if running {
            "Helper installed and running — typed privileged operations apply without prompts"
                .into()
        } else if installed {
            "Helper installed but not running".into()
        } else {
            "Helper not installed — privileged changes prompt via pkexec/sudo".into()
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_install() -> Result<String, String> {
    use crate::elevate::shell_quote;
    let src = helper_binary()?;
    let uid = current_uid();
    let unit = format!(
        "[Unit]\nDescription=OnionGate privileged helper\nAfter=network.target\n\n\
         [Service]\nType=simple\nExecStart={LINUX_HELPER_DEST} --allow-uid {uid}\nRestart=on-failure\n\n\
         [Install]\nWantedBy=multi-user.target\n"
    );
    let unit_src = crate::tor::process::ensure_data_dir()?.join("oniongate-helper.service");
    std::fs::write(&unit_src, unit).map_err(|e| e.to_string())?;

    let script = format!(
        "mkdir -p /usr/local/lib/oniongate && \
         cp {src} {dest_bin} && chown root:root {dest_bin} && chmod 755 {dest_bin} && \
         cp {unit_src} {dest_unit} && chmod 644 {dest_unit} && \
         systemctl daemon-reload && systemctl enable --now oniongate-helper.service",
        src = shell_quote(&src.to_string_lossy()),
        dest_bin = shell_quote(LINUX_HELPER_DEST),
        unit_src = shell_quote(&unit_src.to_string_lossy()),
        dest_unit = shell_quote(LINUX_UNIT_DEST),
    );
    crate::elevate::run_shell(&script)?;
    Ok("Privileged helper installed".into())
}

#[cfg(target_os = "linux")]
fn linux_uninstall() -> Result<String, String> {
    use crate::elevate::shell_quote;
    let script = format!(
        "systemctl disable --now oniongate-helper.service 2>/dev/null || true; \
         rm -f {dest_unit} {dest_bin}; systemctl daemon-reload",
        dest_unit = shell_quote(LINUX_UNIT_DEST),
        dest_bin = shell_quote(LINUX_HELPER_DEST),
    );
    crate::elevate::run_shell(&script)?;
    Ok("Privileged helper removed".into())
}

// ------------------------------ Windows ------------------------------

#[cfg(target_os = "windows")]
const WINDOWS_SERVICE: &str = "OnionGateHelper";
#[cfg(target_os = "windows")]
const WINDOWS_HELPER_DEST: &str = r"C:\Program Files\OnionGate\oniongate-helper.exe";

#[cfg(target_os = "windows")]
fn windows_status() -> HelperStatus {
    let installed = std::process::Command::new("sc.exe")
        .args(["query", WINDOWS_SERVICE])
        .hide_console()
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let running = client::available();
    HelperStatus {
        supported: true,
        installed,
        running,
        detail: if running {
            "Helper service installed and running — typed privileged operations apply without prompts"
                .into()
        } else if installed {
            "Helper service installed but not running".into()
        } else {
            "Helper not installed — privileged changes prompt via UAC".into()
        },
    }
}

#[cfg(target_os = "windows")]
fn run_elevated_powershell(inner: &str) -> Result<(), String> {
    // Runs `inner` in an elevated PowerShell (single UAC prompt).
    let escaped = inner.replace('\'', "''");
    let command = format!(
        "Start-Process powershell.exe -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-Command','{escaped}'"
    );
    let status = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .hide_console()
        .status()
        .map_err(|e| e.to_string())?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "Administrator authorization failed or was cancelled".into())
}

#[cfg(target_os = "windows")]
fn windows_install() -> Result<String, String> {
    let src = helper_binary()?;
    let inner = format!(
        "New-Item -ItemType Directory -Force -Path 'C:\\Program Files\\OnionGate' | Out-Null; \
         Copy-Item '{src}' '{dest}' -Force; \
         sc.exe create {svc} binPath= '\"{dest}\" --service' start= auto; \
         sc.exe start {svc}",
        src = src.to_string_lossy().replace('\'', "''"),
        dest = WINDOWS_HELPER_DEST,
        svc = WINDOWS_SERVICE,
    );
    run_elevated_powershell(&inner)?;
    Ok("Privileged helper service installed".into())
}

#[cfg(target_os = "windows")]
fn windows_uninstall() -> Result<String, String> {
    let inner = format!(
        "sc.exe stop {svc}; sc.exe delete {svc}; \
         Remove-Item '{dest}' -Force -ErrorAction SilentlyContinue",
        svc = WINDOWS_SERVICE,
        dest = WINDOWS_HELPER_DEST,
    );
    run_elevated_powershell(&inner)?;
    Ok("Privileged helper service removed".into())
}
