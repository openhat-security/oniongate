//! OS-aware detection of apps that commonly bypass system SOCKS.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedApp {
    pub id: String,
    pub title: String,
    pub group: String,
    pub description: String,
    /// True if the base app appears installed on this device.
    pub installed: bool,
    /// Tor helper / SOCKS config currently applied.
    pub configured: bool,
    pub detail: String,
    pub note: String,
    pub configure_label: String,
    pub can_remove: bool,
    /// Process names for TUN split-tunnel rules.
    pub process_names: Vec<String>,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectReport {
    pub os: String,
    pub os_label: String,
    pub apps: Vec<DetectedApp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitCountryOption {
    pub code: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitAppPick {
    /// Process name for sing-box `process_name` rules.
    pub process_name: String,
    pub label: String,
    pub path: String,
    pub id: String,
    pub executable_path: String,
    pub bundle_id: Option<String>,
    pub signing_id: Option<String>,
}

fn os_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "other"
    }
}

fn os_label() -> String {
    match os_name() {
        "macos" => "macOS".into(),
        "linux" => "Linux".into(),
        "windows" => "Windows".into(),
        _ => "Unsupported".into(),
    }
}

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(target_os = "macos")]
fn detect_macos() -> Vec<DetectedApp> {
    use crate::bypass;

    let status = bypass::advanced_status();
    let by_id = |id: &str| status.items.iter().find(|i| i.id == id);

    let tor_browser_installed = PathBuf::from("/Applications/Tor Browser.app").is_dir()
        || home().join("Applications/Tor Browser.app").is_dir();
    let chrome_installed = PathBuf::from("/Applications/Google Chrome.app").is_dir()
        || PathBuf::from("/Applications/Chromium.app").is_dir();
    let firefox_installed = PathBuf::from("/Applications/Firefox.app").is_dir()
        || home()
            .join("Library/Application Support/Firefox/Profiles")
            .is_dir();
    let cursor_installed = PathBuf::from("/Applications/Cursor.app").is_dir()
        || home().join("Library/Application Support/Cursor").is_dir();
    let vscode_installed = PathBuf::from("/Applications/Visual Studio Code.app").is_dir()
        || home().join("Library/Application Support/Code").is_dir();
    let discord_installed = PathBuf::from("/Applications/Discord.app").is_dir();
    let slack_installed = PathBuf::from("/Applications/Slack.app").is_dir();
    let claude_installed = home().join(".claude").is_dir() || which::which("claude").is_ok();

    let map = |id: &str,
               title: &str,
               group: &str,
               installed: bool,
               processes: &[&str],
               fallback_note: &str|
     -> Option<DetectedApp> {
        if !installed {
            return None;
        }
        let item = by_id(id);
        Some(DetectedApp {
            id: id.into(),
            title: item
                .map(|i| i.title.clone())
                .unwrap_or_else(|| title.into()),
            group: group.into(),
            description: item
                .map(|i| i.description.clone())
                .unwrap_or_else(|| "Forces traffic through Tor SOCKS.".into()),
            installed: true,
            configured: item.map(|i| i.configured).unwrap_or(false),
            detail: item
                .map(|i| i.detail.clone())
                .unwrap_or_else(|| "Detected on this Mac".into()),
            note: item
                .and_then(|i| i.note.clone())
                .unwrap_or_else(|| fallback_note.into()),
            configure_label: item
                .map(|i| i.configure_label.clone())
                .unwrap_or_else(|| "Configure".into()),
            can_remove: item.map(|i| i.can_remove).unwrap_or(false),
            process_names: processes.iter().map(|s| (*s).into()).collect(),
            os: "macos".into(),
        })
    };

    [
        map(
            "tor_browser",
            "Tor Browser via OnionGate",
            "browsers",
            tor_browser_installed,
            &["firefox", "Tor Browser"],
            "Use the OnionGate launcher so Tor Browser skips its own Tor (Whonix-style).",
        ),
        map(
            "chrome",
            "Google Chrome",
            "browsers",
            chrome_installed,
            &["Google Chrome", "Chrome"],
            "Chrome often ignores OS SOCKS / uses Secure DNS outside Tor.",
        ),
        map(
            "firefox",
            "Firefox",
            "browsers",
            firefox_installed,
            &["firefox", "Firefox"],
            "Firefox needs its own SOCKS + remote DNS prefs.",
        ),
        map(
            "cursor",
            "Cursor",
            "apps",
            cursor_installed,
            &["Cursor"],
            "Cursor defaults to ignoring the OS proxy.",
        ),
        map(
            "vscode",
            "VS Code",
            "apps",
            vscode_installed,
            &["Code", "Electron"],
            "VS Code/Electron often ignores system SOCKS.",
        ),
        map(
            "claude_code",
            "Claude Code",
            "apps",
            claude_installed,
            &["claude"],
            "CLI may need explicit proxy env.",
        ),
        map(
            "discord",
            "Discord",
            "apps",
            discord_installed,
            &["Discord"],
            "Discord ignores OS proxy — use Discord Tor launcher.",
        ),
        map(
            "slack",
            "Slack",
            "apps",
            slack_installed,
            &["Slack"],
            "Slack desktop typically bypasses system SOCKS.",
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(target_os = "linux")]
fn detect_linux() -> Vec<DetectedApp> {
    use crate::bypass;

    let status = bypass::advanced_status();
    let by_id = |id: &str| status.items.iter().find(|i| i.id == id);

    let bin_ok = |names: &[&str]| names.iter().any(|n| which::which(n).is_ok());
    let desktop_ok = |names: &[&str]| {
        let bases = [
            home().join(".local/share/applications"),
            PathBuf::from("/usr/share/applications"),
            PathBuf::from("/var/lib/flatpak/exports/share/applications"),
        ];
        names.iter().any(|name| {
            bases.iter().any(|b| {
                b.join(format!("{name}.desktop")).is_file()
                    || b.join(format!("google-{name}.desktop")).is_file()
            })
        })
    };

    let tor_browser_installed = home().join("tor-browser/Browser/start-tor-browser").is_file()
        || home()
            .join("tor-browser_en-US/Browser/start-tor-browser")
            .is_file()
        || bin_ok(&["torbrowser", "tor-browser"])
        || desktop_ok(&["torbrowser", "tor-browser", "start-tor-browser"]);
    let chrome_installed = bin_ok(&[
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ]) || desktop_ok(&["google-chrome", "chromium"]);
    let firefox_installed = bin_ok(&["firefox", "firefox-bin"]) || desktop_ok(&["firefox"]);
    let cursor_installed =
        bin_ok(&["cursor"]) || home().join(".config/Cursor").is_dir() || desktop_ok(&["cursor"]);
    let vscode_installed = bin_ok(&["code", "code-insiders"])
        || home().join(".config/Code").is_dir()
        || desktop_ok(&["code"]);
    let discord_installed = bin_ok(&["discord", "Discord"]) || desktop_ok(&["discord"]);
    let slack_installed = bin_ok(&["slack"]) || desktop_ok(&["slack"]);
    let claude_installed = home().join(".claude").is_dir() || which::which("claude").is_ok();

    let map = |id: &str,
               title: &str,
               group: &str,
               installed: bool,
               processes: &[&str],
               fallback_note: &str|
     -> Option<DetectedApp> {
        if !installed {
            return None;
        }
        let item = by_id(id);
        Some(DetectedApp {
            id: id.into(),
            title: item
                .map(|i| i.title.clone())
                .unwrap_or_else(|| title.into()),
            group: group.into(),
            description: item
                .map(|i| i.description.clone())
                .unwrap_or_else(|| "Forces traffic through Tor SOCKS.".into()),
            installed: true,
            configured: item.map(|i| i.configured).unwrap_or(false),
            detail: item
                .map(|i| i.detail.clone())
                .unwrap_or_else(|| "Detected on this system".into()),
            note: item
                .and_then(|i| i.note.clone())
                .unwrap_or_else(|| fallback_note.into()),
            configure_label: item
                .map(|i| i.configure_label.clone())
                .unwrap_or_else(|| "Configure".into()),
            can_remove: item.map(|i| i.can_remove).unwrap_or(false),
            process_names: processes.iter().map(|s| (*s).into()).collect(),
            os: "linux".into(),
        })
    };

    [
        map(
            "tor_browser",
            "Tor Browser via OnionGate",
            "browsers",
            tor_browser_installed,
            &["firefox", "tor-browser"],
            "Use the OnionGate launcher so Tor Browser skips its own Tor (Whonix-style).",
        ),
        map(
            "chrome",
            "Chrome / Chromium",
            "browsers",
            chrome_installed,
            &["chrome", "chromium", "google-chrome"],
            "Chrome often ignores OS SOCKS / uses Secure DNS outside Tor.",
        ),
        map(
            "firefox",
            "Firefox",
            "browsers",
            firefox_installed,
            &["firefox"],
            "Firefox needs its own SOCKS + remote DNS prefs.",
        ),
        map(
            "cursor",
            "Cursor",
            "apps",
            cursor_installed,
            &["cursor", "Cursor"],
            "Cursor defaults to ignoring the OS proxy.",
        ),
        map(
            "vscode",
            "VS Code",
            "apps",
            vscode_installed,
            &["code", "Code"],
            "VS Code/Electron often ignores system SOCKS.",
        ),
        map(
            "claude_code",
            "Claude Code",
            "apps",
            claude_installed,
            &["claude"],
            "CLI may need explicit proxy env.",
        ),
        map(
            "discord",
            "Discord",
            "apps",
            discord_installed,
            &["Discord", "discord"],
            "Discord ignores OS proxy — use Discord Tor launcher.",
        ),
        map(
            "slack",
            "Slack",
            "apps",
            slack_installed,
            &["slack", "Slack"],
            "Slack desktop typically bypasses system SOCKS.",
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_other() -> Vec<DetectedApp> {
    Vec::new()
}

pub fn detect_apps() -> DetectReport {
    let apps = {
        #[cfg(target_os = "macos")]
        {
            detect_macos()
        }
        #[cfg(target_os = "linux")]
        {
            detect_linux()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            detect_other()
        }
    };
    DetectReport {
        os: os_name().into(),
        os_label: os_label(),
        apps,
    }
}

/// Turn a user-picked path (.app / binary / .desktop) into a split-tunnel process name.
pub fn resolve_split_app(path: &std::path::Path) -> Result<SplitAppPick, String> {
    if !path.exists() {
        return Err(format!("Path not found: {}", path.display()));
    }

    let path_str = path.display().to_string();
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path_str.clone());

    // macOS application bundle
    if file_name.ends_with(".app")
        || path.extension().and_then(|e| e.to_str()) == Some("app")
        || (path.is_dir() && path.join("Contents/MacOS").is_dir())
    {
        let label = file_name.trim_end_matches(".app").to_string();
        let executable = macos_bundle_executable(path);
        let process_name = executable
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| label.clone());
        let executable_path = executable
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| path_str.clone());
        let bundle_id = macos_bundle_id(path);
        let signing_id = executable.as_ref().and_then(|p| macos_signing_id(p));
        let id = bundle_id
            .as_ref()
            .map(|id| format!("bundle:{id}"))
            .unwrap_or_else(|| format!("path:{executable_path}"));
        return Ok(SplitAppPick {
            process_name,
            label,
            path: path_str,
            id,
            executable_path,
            bundle_id,
            signing_id,
        });
    }

    // Linux desktop entry
    if path.extension().and_then(|e| e.to_str()) == Some("desktop") {
        if let Some(exec) = parse_desktop_exec(path) {
            let process_name = std::path::Path::new(&exec)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| exec.clone());
            let label = file_name.trim_end_matches(".desktop").to_string();
            return Ok(SplitAppPick {
                process_name,
                label,
                path: path_str,
                id: format!("path:{exec}"),
                executable_path: exec,
                bundle_id: None,
                signing_id: None,
            });
        }
    }

    let process_name = path
        .file_stem()
        .or_else(|| path.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or(file_name.clone());

    Ok(SplitAppPick {
        id: format!("path:{path_str}"),
        executable_path: path_str.clone(),
        process_name,
        label: file_name,
        path: path_str,
        bundle_id: None,
        signing_id: None,
    })
}

fn macos_bundle_executable(app: &std::path::Path) -> Option<PathBuf> {
    let macos_dir = app.join("Contents/MacOS");
    let entries = std::fs::read_dir(&macos_dir).ok()?;
    let mut binaries = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            binaries.push(p);
        }
    }
    if binaries.is_empty() {
        return None;
    }
    let preferred = app
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(match_bin) = binaries.iter().find(|p| {
        p.file_name()
            .map(|n| n.to_string_lossy() == preferred)
            .unwrap_or(false)
    }) {
        return Some(match_bin.clone());
    }
    Some(binaries[0].clone())
}

#[cfg(target_os = "macos")]
fn macos_bundle_id(app: &std::path::Path) -> Option<String> {
    let plist = app.join("Contents/Info");
    let output = std::process::Command::new("defaults")
        .args(["read", &plist.display().to_string(), "CFBundleIdentifier"])
        .output()
        .ok()?;
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(not(target_os = "macos"))]
fn macos_bundle_id(_app: &std::path::Path) -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn macos_signing_id(executable: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new("codesign")
        .args(["-dv", "--verbose=4", &executable.display().to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stderr);
    text.lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "not set")
        .map(str::to_string)
}

#[cfg(not(target_os = "macos"))]
fn macos_signing_id(_executable: &std::path::Path) -> Option<String> {
    None
}

fn parse_desktop_exec(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Exec=") {
            let token = rest
                .split_whitespace()
                .next()?
                .trim_matches('"')
                .to_string();
            if !token.is_empty() && !token.starts_with('%') {
                return Some(token);
            }
        }
    }
    None
}

/// Common exit-country presets for UI dropdowns.
pub fn exit_country_options() -> Vec<ExitCountryOption> {
    [
        ("", "Any exit"),
        ("us", "United States"),
        ("de", "Germany"),
        ("nl", "Netherlands"),
        ("ch", "Switzerland"),
        ("se", "Sweden"),
        ("no", "Norway"),
        ("fi", "Finland"),
        ("ca", "Canada"),
        ("gb", "United Kingdom"),
        ("fr", "France"),
        ("jp", "Japan"),
    ]
    .into_iter()
    .map(|(code, label)| ExitCountryOption {
        code: code.into(),
        label: label.into(),
    })
    .collect()
}
