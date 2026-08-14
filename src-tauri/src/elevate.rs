//! Run short shell scripts with administrator privileges.

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

/// Escape for embedding inside `do shell script "…"` (AppleScript).
#[cfg(target_os = "macos")]
fn apple_script_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Default message shown in the macOS authorization dialog. Without an explicit
/// prompt macOS shows "osascript wants to make changes", which users don't
/// recognize and frequently cancel.
pub const DEFAULT_PROMPT: &str =
    "OnionGate needs administrator access to change this system setting.";

/// Run a shell script as root with the default prompt. Prompts for admin approval.
pub fn run_shell(script: &str) -> Result<(), String> {
    run_shell_with_prompt(script, DEFAULT_PROMPT)
}

/// Run a shell script as root, showing `prompt` in the authorization dialog.
///
/// On macOS the admin authorization is cached by the Security framework for a
/// few minutes per app, so priming it once (see `prime_admin_auth`) lets later
/// privileged operations run without re-prompting.
pub fn run_shell_with_prompt(script: &str, prompt: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "do shell script \"{}\" with prompt \"{}\" with administrator privileges",
                apple_script_escape(script),
                apple_script_escape(prompt),
            ))
            .output()
            .map_err(|e| format!("osascript failed: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // -128 = user cancelled the authorization dialog.
        if stderr.contains("-128") || stderr.contains("User canceled") {
            return Err(
                "Administrator prompt was cancelled. Choose OK and enter your password (or use Touch ID) to apply this change."
                    .into(),
            );
        }
        Err(format!(
            "Administrator authorization failed: {}",
            stderr.trim()
        ))
    }

    #[cfg(target_os = "linux")]
    {
        let _ = prompt;
        if which::which("pkexec").is_ok() {
            let status = Command::new("pkexec")
                .args(["bash", "-c", script])
                .status()
                .map_err(|e| format!("pkexec failed: {e}"))?;
            if status.success() {
                return Ok(());
            }
            return Err("Administrator authorization failed or was cancelled".into());
        }
        let status = Command::new("sudo")
            .args(["bash", "-c", script])
            .status()
            .map_err(|e| format!("sudo failed: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err("Need admin rights (pkexec or sudo). Authorization failed.".into())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (script, prompt);
        Err("Elevated shell writes are not supported on this platform".into())
    }
}

/// Like [`run_shell_with_prompt`], but returns stdout and stderr for the UI.
pub fn run_shell_captured(script: &str, prompt: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "do shell script \"{}\" with prompt \"{}\" with administrator privileges",
                apple_script_escape(script),
                apple_script_escape(prompt),
            ))
            .output()
            .map_err(|e| format!("osascript failed: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut combined = String::new();
        if !stdout.trim().is_empty() {
            combined.push_str(stdout.trim());
        }
        if !stderr.trim().is_empty() {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(stderr.trim());
        }
        if output.status.success() {
            return Ok(combined);
        }
        if stderr.contains("-128") || stderr.contains("User canceled") {
            return Err(
                "Administrator prompt was cancelled. Choose OK and enter your password (or use Touch ID) to apply this change."
                    .into(),
            );
        }
        Err(if combined.is_empty() {
            "Administrator authorization failed".into()
        } else {
            combined
        })
    }
    #[cfg(target_os = "linux")]
    {
        let _ = prompt;
        let output = if which::which("pkexec").is_ok() {
            Command::new("pkexec")
                .args(["bash", "-c", script])
                .output()
                .map_err(|e| format!("pkexec failed: {e}"))?
        } else {
            Command::new("sudo")
                .args(["bash", "-c", script])
                .output()
                .map_err(|e| format!("sudo failed: {e}"))?
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut combined = String::new();
        if !stdout.trim().is_empty() {
            combined.push_str(stdout.trim());
        }
        if !stderr.trim().is_empty() {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(stderr.trim());
        }
        if output.status.success() {
            Ok(combined)
        } else if combined.is_empty() {
            Err("Administrator authorization failed or was cancelled".into())
        } else {
            Err(combined)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (script, prompt);
        Err("Elevated shell writes are not supported on this platform".into())
    }
}

pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
