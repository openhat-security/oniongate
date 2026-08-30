//! Launch OnionGate at login through a per-user LaunchAgent.
//!
//! Clean-room: written for OnionGate against Apple's documented `launchd.plist`
//! keys. It carries no third-party code.
//!
//! The agent is a *user* agent (`~/Library/LaunchAgents`), never a root
//! LaunchDaemon: starting a GUI application from a privileged daemon would run
//! it outside the user's session and outside the sandbox the app expects.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const LABEL: &str = "com.adamsiwiec.oniongate.launch-at-login";

/// Everything the item reports comes from reading the installed agent back —
/// nothing here is remembered from the moment we wrote it.
#[derive(Debug, Clone)]
pub struct LoginItemStatus {
    pub installed: bool,
    pub loaded: bool,
    pub run_at_load: bool,
    /// The program the installed agent points at still exists.
    pub target_exists: bool,
    pub detail: String,
}

fn agents_dir() -> Result<PathBuf, String> {
    let dir = dirs::home_dir()
        .ok_or_else(|| "Could not resolve home directory".to_string())?
        .join("Library/LaunchAgents");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create LaunchAgents: {e}"))?;
    Ok(dir)
}

fn plist_path() -> Result<PathBuf, String> {
    Ok(agents_dir()?.join(format!("{LABEL}.plist")))
}

fn current_uid() -> String {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "501".into())
}

fn agent_loaded() -> bool {
    Command::new("/bin/launchctl")
        .args(["print", &format!("gui/{}/{LABEL}", current_uid())])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The `.app` bundle that contains `exe`, when there is one.
pub fn bundle_root(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .find(|p| {
            p.extension()
                .map(|e| e.eq_ignore_ascii_case("app"))
                .unwrap_or(false)
        })
        .map(|p| p.to_path_buf())
}

/// A bundled build is launched through `open` so LaunchServices sets the app up
/// the way a user double-click would; a bare binary (dev builds) is exec'd.
pub fn launch_arguments(exe: &Path) -> Vec<String> {
    match bundle_root(exe) {
        Some(bundle) => vec![
            "/usr/bin/open".into(),
            "-a".into(),
            bundle.display().to_string(),
        ],
        None => vec![exe.display().to_string()],
    }
}

pub fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub fn plist_body(args: &[String]) -> String {
    let mut program = String::new();
    for arg in args {
        program.push_str(&format!("    <string>{}</string>\n", xml_escape(arg)));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{program}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
"#
    )
}

/// Read the `<string>` members of the `<array>` that follows `key`.
pub fn parse_string_array(xml: &str, key: &str) -> Vec<String> {
    let Some(after_key) = xml.split_once(&format!("<key>{key}</key>")).map(|(_, r)| r) else {
        return Vec::new();
    };
    let Some(open) = after_key.find("<array>") else {
        return Vec::new();
    };
    let body = &after_key[open + "<array>".len()..];
    let Some(close) = body.find("</array>") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = &body[..close];
    while let Some(start) = rest.find("<string>") {
        let tail = &rest[start + "<string>".len()..];
        let Some(end) = tail.find("</string>") else {
            break;
        };
        out.push(xml_unescape(tail[..end].trim()));
        rest = &tail[end..];
    }
    out
}

/// Read the `<true/>` / `<false/>` that follows `key`.
pub fn parse_bool(xml: &str, key: &str) -> Option<bool> {
    let after_key = xml
        .split_once(&format!("<key>{key}</key>"))
        .map(|(_, r)| r)?;
    let trimmed = after_key.trim_start();
    if trimmed.starts_with("<true/>") {
        Some(true)
    } else if trimmed.starts_with("<false/>") {
        Some(false)
    } else {
        None
    }
}

pub fn status() -> LoginItemStatus {
    let Ok(path) = plist_path() else {
        return LoginItemStatus {
            installed: false,
            loaded: false,
            run_at_load: false,
            target_exists: false,
            detail: "Could not resolve ~/Library/LaunchAgents".into(),
        };
    };
    let Ok(xml) = fs::read_to_string(&path) else {
        return LoginItemStatus {
            installed: false,
            loaded: false,
            run_at_load: false,
            target_exists: false,
            detail: "No login agent installed".into(),
        };
    };

    let target = parse_string_array(&xml, "ProgramArguments");
    let run_at_load = parse_bool(&xml, "RunAtLoad").unwrap_or(false);
    let loaded = agent_loaded();
    // The path the agent actually points at — the app may have been moved or
    // replaced since the agent was written.
    let target_path = target.last().cloned().unwrap_or_default();
    let target_exists = !target_path.is_empty() && Path::new(&target_path).exists();
    let matches_current = std::env::current_exe()
        .map(|exe| launch_arguments(&exe) == target)
        .unwrap_or(false);

    let mut detail = if target_path.is_empty() {
        "Login agent has no program arguments".to_string()
    } else {
        format!("Agent starts {target_path}")
    };
    if !run_at_load {
        detail.push_str(" · RunAtLoad is not set");
    }
    if !target_exists {
        detail.push_str(" · that path no longer exists");
    } else if !matches_current {
        detail.push_str(" · points at a different copy than the running app");
    }
    detail.push_str(if loaded {
        " · registered with launchd"
    } else {
        " · not registered with launchd (log out and back in, or re-apply)"
    });

    LoginItemStatus {
        installed: true,
        loaded,
        run_at_load,
        target_exists,
        detail,
    }
}

pub fn install() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Could not resolve this app: {e}"))?;
    let args = launch_arguments(&exe);
    let path = plist_path()?;
    fs::write(&path, plist_body(&args)).map_err(|e| format!("Failed to write login agent: {e}"))?;

    let domain = format!("gui/{}", current_uid());
    let target = path.to_string_lossy().to_string();
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &domain, &target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let ok = Command::new("/bin/launchctl")
        .args(["bootstrap", &domain, &target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err(
            "Wrote the login agent but launchd refused to register it. It will still load at your next login."
                .into(),
        );
    }
    crate::logs::append("Hardening: launch at login enabled");
    Ok(format!(
        "OnionGate will start at login ({}). Remove it here any time.",
        args.last().cloned().unwrap_or_default()
    ))
}

pub fn uninstall() -> Result<String, String> {
    let path = plist_path()?;
    let domain = format!("gui/{}", current_uid());
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &domain, &path.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("Failed to remove login agent: {e}")),
    }
    crate::logs::append("Hardening: launch at login disabled");
    Ok("OnionGate will no longer start at login".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundled_build_is_launched_through_open() {
        let exe = Path::new("/Applications/OnionGate.app/Contents/MacOS/oniongate");
        assert_eq!(
            launch_arguments(exe),
            vec!["/usr/bin/open", "-a", "/Applications/OnionGate.app"]
        );
    }

    #[test]
    fn a_bare_binary_is_launched_directly() {
        let exe = Path::new("/Users/me/src/oniongate/target/debug/oniongate");
        assert_eq!(
            launch_arguments(exe),
            vec!["/Users/me/src/oniongate/target/debug/oniongate"]
        );
    }

    #[test]
    fn the_generated_agent_round_trips_through_the_parser() {
        let args = launch_arguments(Path::new("/Applications/OnionGate.app/Contents/MacOS/og"));
        let xml = plist_body(&args);
        assert_eq!(parse_string_array(&xml, "ProgramArguments"), args);
        assert_eq!(parse_bool(&xml, "RunAtLoad"), Some(true));
        assert_eq!(parse_bool(&xml, "KeepAlive"), Some(false));
        assert!(xml.contains(&format!("<string>{LABEL}</string>")));
    }

    /// A path with XML metacharacters must survive the write/read round trip,
    /// or the status check silently compares the wrong string.
    #[test]
    fn paths_with_xml_metacharacters_survive_the_round_trip() {
        let args = vec!["/Applications/Onion & <Gate>.app".to_string()];
        let xml = plist_body(&args);
        assert!(xml.contains("Onion &amp; &lt;Gate&gt;"));
        assert_eq!(parse_string_array(&xml, "ProgramArguments"), args);
    }

    #[test]
    fn a_missing_key_parses_as_absent_rather_than_defaulting_to_on() {
        let xml = plist_body(&["/bin/true".to_string()]);
        assert_eq!(parse_bool(&xml, "LimitLoadToSessionType"), None);
        assert!(parse_string_array(&xml, "WatchPaths").is_empty());
    }

    #[test]
    fn generated_agent_passes_plutil_lint() {
        let xml = plist_body(&launch_arguments(Path::new(
            "/Applications/OnionGate.app/Contents/MacOS/oniongate",
        )));
        super::super::tests_support::assert_plutil_lint(&xml, "launch-at-login.plist");
    }
}
