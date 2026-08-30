//! Kill Siri watchdog: a user LaunchAgent that kills Siri helpers and clears
//! Siri's on-disk artefacts whenever Assistant activity is detected.
//!
//! MODIFICATION NOTICE (GPL-3.0 section 5(a)):
//! This file contains work derived from term7's
//! "MacOS-Privacy-and-Security-Enhancements" (GPL-3.0), specifically
//! `02_Kill-Siri/killswitch/kill-siri.sh` (the watched process list),
//! `02_Kill-Siri/killswitch/kill_siri-helper.sh` (the artefact list) and
//! `02_Kill-Siri/script/SPEEDY-INSTALL_kill-siri.sh` (the `SiriVocabulary`
//! immutable-flag workaround). Modified by the OnionGate project on 2026-08-15:
//!   * upstream's root LaunchDaemon plus trigger-file dance is collapsed into a
//!     single per-user LaunchAgent — none of the work needs root, and the
//!     upstream layout has a root job executing a script in world-writable
//!     `/Users/Shared`;
//!   * no log file is written at all (upstream writes a `chmod 666` log that
//!     records every Siri artefact path it touches);
//!   * uninstall clears the `uchg` flag upstream leaves behind, so the user is
//!     not left with an undeletable folder;
//!   * the script is generated, not downloaded, and never runs `eval`.
//!
//! Upstream: https://codeberg.org/term7/MacOS-Privacy-and-Security-Enhancements

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::KillSiriStatus;

const LABEL: &str = "com.adamsiwiec.oniongate.kill-siri";
const LEGACY_LABEL: &str = "com.tor-socks-gui.kill-siri";

/// Same process names term7 watches — detected live with pgrep.
pub const SIRI_PROCS: &[&str] = &[
    "SiriAUSP",
    "siriinferenced",
    "siriactionsd",
    "siriknowledged",
    "sirittsd",
    "SiriTTSSynthesizerAU",
    "assistantd",
    "com.apple.siri.embeddedspeech",
    "com.apple.SiriTTSService.TrialProxy",
    "com.apple.siri-distributed-evaluation",
];

/// Files Siri leaves in `~/Library/Assistant`, from term7's Kill-Siri helper.
/// `SiriAnalytics.db` is a local record of what you asked Siri; the watchdog is
/// pointless while it survives.
pub const SIRI_ARTIFACT_FILES: &[&str] = &[
    "SiriAnalytics.db",
    "SiriAnalytics.db-shm",
    "SiriAnalytics.db-wal",
    "session_did_finish_timestamp",
    "assistantdDidLaunch",
    ".DS_Store",
];

/// Directories cleared alongside them. `SiriVocabulary` is handled separately:
/// a LaunchAgent cannot remove it, so install replaces it with an empty,
/// immutable directory instead.
pub const SIRI_ARTIFACT_DIRS: &[&str] = &["CustomVocabulary", "SiriReferenceResolution"];

const VOCABULARY_DIR: &str = "SiriVocabulary";

fn support_dir() -> Result<PathBuf, String> {
    let base = crate::paths::data_dir()?.join("kill-siri");
    fs::create_dir_all(&base).map_err(|e| format!("Failed to create kill-siri dir: {e}"))?;
    Ok(base)
}

fn script_path() -> Result<PathBuf, String> {
    Ok(support_dir()?.join("kill-siri.sh"))
}

fn agent_plist_path() -> Result<PathBuf, String> {
    let dir = dirs::home_dir()
        .ok_or_else(|| "Could not resolve home directory".to_string())?
        .join("Library/LaunchAgents");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create LaunchAgents: {e}"))?;
    Ok(dir.join(format!("{LABEL}.plist")))
}

fn assistant_watch_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join("Library/Assistant")
}

pub fn running_processes() -> Vec<String> {
    let mut out = Vec::new();
    for name in SIRI_PROCS {
        // Match term7: pgrep by name (not only exact -x; some Siri helpers are longer).
        let ok = Command::new("/usr/bin/pgrep")
            .arg(name)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            out.push((*name).to_string());
        }
    }
    out
}

fn current_uid() -> String {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "501".into())
}

fn agent_loaded() -> bool {
    let uid = current_uid();
    Command::new("launchctl")
        .args(["print", &format!("gui/{uid}/{LABEL}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Siri artefacts still sitting in `~/Library/Assistant` right now.
pub fn leftover_artifacts() -> usize {
    let dir = assistant_watch_path();
    let files = SIRI_ARTIFACT_FILES
        .iter()
        .filter(|name| dir.join(name).is_file())
        .count();
    let dirs = SIRI_ARTIFACT_DIRS
        .iter()
        .filter(|name| dir.join(name).is_dir())
        .count();
    files + dirs
}

/// True when `SiriVocabulary` carries the user-immutable flag, i.e. Siri can no
/// longer write learned vocabulary back into it.
pub fn vocabulary_locked() -> bool {
    let path = assistant_watch_path().join(VOCABULARY_DIR);
    if !path.is_dir() {
        return false;
    }
    Command::new("/bin/ls")
        .args(["-ldO", &path.display().to_string()])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("uchg"))
        .unwrap_or(false)
}

pub fn status() -> KillSiriStatus {
    let script = script_path().ok().and_then(|p| fs::read_to_string(p).ok());
    let plist_ok = agent_plist_path().map(|p| p.is_file()).unwrap_or(false);
    let current = script_body(&assistant_watch_path());
    let script_ok = script.is_some();
    let script_current = script.as_deref() == Some(current.as_str());
    let installed = script_ok && plist_ok;
    let loaded = agent_loaded();
    let running = running_processes();
    let total = SIRI_PROCS.len();
    let mut detail = format!("{}/{} Siri-related processes running", running.len(), total);
    if installed && loaded {
        detail.push_str(" · killswitch installed");
    } else if installed {
        detail.push_str(" · files present, agent not loaded");
    } else {
        detail.push_str(" · killswitch not installed");
    }
    if installed && !script_current {
        detail.push_str(" · installed script is an older version, re-install to update it");
    }
    if installed && loaded && !running.is_empty() {
        detail.push_str(
            " · OS may have respawned some processes (watchdog clears on next Assistant activity)",
        );
    }
    let leftovers = leftover_artifacts();
    if leftovers > 0 {
        detail.push_str(&format!(" · {leftovers} Siri data artefact(s) on disk"));
    }
    if vocabulary_locked() {
        detail.push_str(" · SiriVocabulary locked");
    }
    KillSiriStatus {
        installed,
        agent_loaded: loaded,
        running,
        total_watched: total,
        detail,
    }
}

/// The watchdog script. Kills the Siri helpers, then clears the artefacts they
/// leave behind in `assistant_dir`.
///
/// The agent watches the same directory the cleanup writes to, so a cleanup
/// re-triggers the agent once; the script is idempotent, so the second pass
/// finds nothing and the loop settles. launchd's 10-second throttle bounds it.
pub fn script_body(assistant_dir: &Path) -> String {
    let dir = crate::elevate::shell_quote(&assistant_dir.display().to_string());
    let mut body = String::from(
        "#!/bin/bash\n\
         # Generated by OnionGate — Kill Siri watchdog.\n\
         # Derived from term7 MacOS-Privacy-and-Security-Enhancements 02_Kill-Siri\n\
         # (GPL-3.0), modified: single user agent, no logging, no command strings.\n\
         set -u\n\nPROCS=(\n",
    );
    for name in SIRI_PROCS {
        body.push_str(&format!("  {name}\n"));
    }
    body.push_str(")\n\nARTIFACTS=(\n");
    for name in SIRI_ARTIFACT_FILES {
        body.push_str(&format!("  {name}\n"));
    }
    body.push_str(")\n\nARTIFACT_DIRS=(\n");
    for name in SIRI_ARTIFACT_DIRS {
        body.push_str(&format!("  {name}\n"));
    }
    body.push_str(&format!(
        ")\n\nASSISTANT={dir}\n\n\
         for proc in \"${{PROCS[@]}}\"; do\n  \
         if /usr/bin/pgrep \"$proc\" >/dev/null 2>&1; then\n    \
         /usr/bin/pkill -9 \"$proc\" >/dev/null 2>&1 || true\n  \
         fi\ndone\n\n\
         for artifact in \"${{ARTIFACTS[@]}}\"; do\n  \
         if [ -f \"$ASSISTANT/$artifact\" ]; then\n    \
         /bin/rm -f -- \"$ASSISTANT/$artifact\" >/dev/null 2>&1 || true\n  \
         fi\ndone\n\n\
         for folder in \"${{ARTIFACT_DIRS[@]}}\"; do\n  \
         if [ -d \"$ASSISTANT/$folder\" ]; then\n    \
         /bin/rm -rf -- \"$ASSISTANT/$folder\" >/dev/null 2>&1 || true\n  \
         fi\ndone\n\nexit 0\n"
    ));
    body
}

fn write_script() -> Result<PathBuf, String> {
    let path = script_path()?;
    let body = script_body(&assistant_watch_path());
    fs::write(&path, body).map_err(|e| format!("Failed to write kill-siri.sh: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)
            .map_err(|e| e.to_string())?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).map_err(|e| e.to_string())?;
    }
    Ok(path)
}

pub fn plist_body(script: &Path, watch: &Path) -> String {
    let script = super::login_item::xml_escape(&script.display().to_string());
    let watch = super::login_item::xml_escape(&watch.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{script}</string>
  </array>
  <key>WatchPaths</key>
  <array>
    <string>{watch}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"#
    )
}

fn bootout_legacy(domain: &str) {
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{domain}/{LEGACY_LABEL}")])
        .status();
    if let Some(home) = dirs::home_dir() {
        let _ = fs::remove_file(home.join(format!("Library/LaunchAgents/{LEGACY_LABEL}.plist")));
    }
}

fn write_plist(script: &Path) -> Result<PathBuf, String> {
    let plist = agent_plist_path()?;
    let content = plist_body(script, &assistant_watch_path());
    fs::write(&plist, content).map_err(|e| format!("Failed to write LaunchAgent: {e}"))?;
    Ok(plist)
}

pub fn install() -> Result<String, String> {
    let script = write_script()?;
    let plist = write_plist(&script)?;
    let _ = fs::create_dir_all(assistant_watch_path());
    let domain = format!("gui/{}", current_uid());
    bootout_legacy(&domain);
    // bootout if already loaded, then bootstrap
    let _ = Command::new("launchctl")
        .args(["bootout", &domain, &plist.to_string_lossy()])
        .status();
    let status = Command::new("launchctl")
        .args(["bootstrap", &domain, &plist.to_string_lossy()])
        .status()
        .map_err(|e| format!("launchctl bootstrap failed: {e}"))?;
    if !status.success() {
        return Err("Failed to load Kill Siri LaunchAgent".into());
    }
    // Run once immediately
    let _ = Command::new(&script).status();
    let locked = lock_vocabulary();
    crate::logs::append("Hardening: Kill Siri killswitch installed");
    Ok(format!(
        "Kill Siri killswitch installed (LaunchAgent): Siri helpers are killed and Siri's on-disk artefacts cleared on every Assistant write.{} SIP stays on — this is a watchdog, not a permanent disable. Re-apply after major OS updates if needed.",
        if locked {
            " SiriVocabulary is now an empty, immutable folder."
        } else {
            " SiriVocabulary could not be locked (it may be protected on this release)."
        }
    ))
}

/// A LaunchAgent cannot delete `SiriVocabulary`, so replace it once, at install
/// time, with an empty directory the user-immutable flag pins shut. term7 does
/// the same in their installer; `uninstall` clears the flag again.
fn lock_vocabulary() -> bool {
    let path = assistant_watch_path().join(VOCABULARY_DIR);
    let target = path.display().to_string();
    let _ = Command::new("/usr/bin/chflags")
        .args(["nouchg", &target])
        .status();
    let _ = fs::remove_dir_all(&path);
    if fs::create_dir_all(&path).is_err() {
        return false;
    }
    Command::new("/usr/bin/chflags")
        .args(["uchg", &target])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn uninstall() -> Result<String, String> {
    let domain = format!("gui/{}", current_uid());
    bootout_legacy(&domain);
    if let Ok(plist) = agent_plist_path() {
        let _ = Command::new("launchctl")
            .args(["bootout", &domain, &plist.to_string_lossy()])
            .status();
        let _ = fs::remove_file(plist);
    }
    if let Ok(script) = script_path() {
        let _ = fs::remove_file(script);
    }
    if let Ok(dir) = support_dir() {
        let _ = fs::remove_dir(dir);
    }
    // Leaving `uchg` behind would hand the user a folder they cannot delete.
    let vocabulary = assistant_watch_path().join(VOCABULARY_DIR);
    let _ = Command::new("/usr/bin/chflags")
        .args(["nouchg", &vocabulary.display().to_string()])
        .status();
    crate::logs::append("Hardening: Kill Siri killswitch removed");
    Ok("Kill Siri killswitch uninstalled (SiriVocabulary unlocked)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_kills_every_watched_process_and_clears_every_artifact() {
        let body = script_body(Path::new("/Users/me/Library/Assistant"));
        for name in SIRI_PROCS {
            assert!(body.contains(name), "missing process {name}");
        }
        for name in SIRI_ARTIFACT_FILES {
            assert!(body.contains(name), "missing artefact {name}");
        }
        for name in SIRI_ARTIFACT_DIRS {
            assert!(body.contains(name), "missing artefact dir {name}");
        }
        assert!(body.contains("pkill -9"));
        assert!(
            !body.lines().any(|l| l.trim_start().starts_with("eval ")),
            "never eval a command string"
        );
        assert!(!body.contains("/Users/Shared"), "no world-writable paths");
    }

    /// A home directory with a space or a quote must not break out of the
    /// generated script.
    #[test]
    fn the_assistant_path_is_shell_quoted() {
        let body = script_body(Path::new("/Users/od d'e/Library/Assistant"));
        assert!(body.contains(r"ASSISTANT='/Users/od d'\''e/Library/Assistant'"));
        super::super::tests_support::assert_bash_parses(&body, "kill-siri-quoted.sh");
    }

    #[test]
    fn the_generated_script_parses_as_bash() {
        super::super::tests_support::assert_bash_parses(
            &script_body(Path::new("/Users/me/Library/Assistant")),
            "kill-siri.sh",
        );
    }

    #[test]
    fn the_generated_agent_passes_plutil_lint() {
        let script = PathBuf::from("/Users/me/Library/Application Support/kill-siri.sh");
        let watch = PathBuf::from("/Users/me/Library/Assistant");
        let plist = plist_body(&script, &watch);
        assert!(plist.contains(&format!("<string>{LABEL}</string>")));
        assert!(plist.contains("<key>WatchPaths</key>"));
        super::super::tests_support::assert_plutil_lint(&plist, "kill-siri.plist");
    }
}
