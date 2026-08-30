use std::fs;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::tor::{
    control_cookie_path, BROWSER_CONTROL_PORT, BROWSER_SOCKS_PORT, SOCKS_HOST, SOCKS_PORT,
};

const HOOK_MARKER_BEGIN: &str = "# >>> oniongate >>>";
const HOOK_MARKER_END: &str = "# <<< oniongate <<<";
const LEGACY_HOOK_MARKER_BEGIN: &str = "# >>> tor-socks-gui >>>";
const LEGACY_HOOK_MARKER_END: &str = "# <<< tor-socks-gui <<<";
const ETC_DIR: &str = "/etc/oniongate";
const LEGACY_ETC_DIR: &str = "/etc/tor-socks-gui";
const ETC_ENV_PATH: &str = "/etc/oniongate/env";
const ETC_SHELL_PATH: &str = "/etc/oniongate/shell.sh";
#[cfg(target_os = "linux")]
const LINUX_PROFILE_D: &str = "/etc/profile.d/oniongate.sh";
#[cfg(target_os = "linux")]
const LEGACY_LINUX_PROFILE_D: &str = "/etc/profile.d/tor-socks-gui.sh";
const HOOK_SOURCE_LINE: &str = r#"[ -f /etc/oniongate/shell.sh ] && . /etc/oniongate/shell.sh"#;
const FIREFOX_MARKER_BEGIN: &str = "// >>> oniongate >>>";
const FIREFOX_MARKER_END: &str = "// <<< oniongate <<<";
const LEGACY_FIREFOX_MARKER_BEGIN: &str = "// >>> tor-socks-gui >>>";
const LEGACY_FIREFOX_MARKER_END: &str = "// <<< tor-socks-gui <<<";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedItem {
    pub id: String,
    /// UI group key: "shell" | "browsers" | "apps"
    pub group: String,
    pub title: String,
    pub description: String,
    pub configured: bool,
    pub detail: String,
    pub configure_label: String,
    pub can_remove: bool,
    /// Extra warning / explanation shown in the UI.
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedStatus {
    pub items: Vec<AdvancedItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassHelpers {
    pub shell_exports: String,
    pub curl_example: String,
    pub chrome_launch: String,
    pub firefox_prefs: String,
    pub notes: Vec<String>,
    pub shell_hook_installed: bool,
    pub shell_hook_targets: Vec<String>,
    pub advanced: AdvancedStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellHookStatus {
    pub installed: bool,
    pub hook_path: String,
    pub targets: Vec<String>,
}

fn socks_url() -> String {
    format!("socks5h://{SOCKS_HOST}:{SOCKS_PORT}")
}

fn socks_plain() -> String {
    format!("socks5://{SOCKS_HOST}:{SOCKS_PORT}")
}

fn firefox_prefs_block() -> String {
    format!(
        "{FIREFOX_MARKER_BEGIN}\n\
user_pref(\"network.proxy.type\", 1);\n\
user_pref(\"network.proxy.socks\", \"{SOCKS_HOST}\");\n\
user_pref(\"network.proxy.socks_port\", {SOCKS_PORT});\n\
user_pref(\"network.proxy.socks_version\", 5);\n\
user_pref(\"network.proxy.socks_remote_dns\", true);\n\
{FIREFOX_MARKER_END}"
    )
}

pub fn helpers() -> BypassHelpers {
    let socks = socks_url();
    let socks_plain = socks_plain();
    let hook = shell_hook_status();

    BypassHelpers {
        shell_exports: format!(
            "# socks5h = resolve DNS remotely through Tor\nexport ALL_PROXY={socks}\nexport all_proxy={socks}"
        ),
        curl_example: format!(
            "curl --proxy {socks} https://api.ipify.org"
        ),
        chrome_launch: format!(
            "# Launcher written by the app to ~/.oniongate/launch-chrome-tor.sh\nopen -a \"Google Chrome\" --args --proxy-server={socks_plain}"
        ),
        firefox_prefs: firefox_prefs_block(),
        notes: vec![
            "Advanced applies configs automatically — use Configure on each row.".into(),
            "Some Electron apps still ignore proxies; verify with the Tor IP check.".into(),
        ],
        shell_hook_installed: hook.installed,
        shell_hook_targets: hook.targets.clone(),
        advanced: advanced_status(),
    }
}

pub fn advanced_status() -> AdvancedStatus {
    let snippet_path = app_dir().ok().map(|d| d.join("firefox-user.js"));
    let snippet_ok = snippet_path.as_ref().map(|p| p.is_file()).unwrap_or(false);
    let profile = find_firefox_profile();
    let profile_ok = profile
        .as_ref()
        .map(|p| firefox_profile_configured(p))
        .unwrap_or(false);

    let tor_browser = tor_browser_launcher_status();
    let chrome = chrome_app_status();
    let cursor = ide_proxy_status("Cursor");
    let vscode = ide_proxy_status("Code");
    let claude = claude_code_status();
    let discord = electron_app_status("Discord Tor");
    let slack = electron_app_status("Slack Tor");

    let items = vec![
        AdvancedItem {
            id: "tor_browser".into(),
            group: "browsers".into(),
            title: "Tor Browser via OnionGate".into(),
            description:
                "Installs a launcher that skips Tor Browser's own Tor and uses OnionGate's."
                    .into(),
            configured: tor_browser.installed,
            detail: tor_browser.detail,
            configure_label: if tor_browser.installed {
                "Reinstall".into()
            } else {
                "Install launcher".into()
            },
            can_remove: tor_browser.installed,
            note: Some(
                "Stock Tor Browser starts its own Tor on 9150. Under OnionGate TUN that stacks Tor-over-Tor and breaks the connection check. This launcher sets TOR_SKIP_LAUNCH and points SOCKS/control at OnionGate (9150/9151), so about:tor treats Tor as externally managed. Open the launcher, not the normal Tor Browser icon. OnionGate must be Connected first."
                    .into(),
            ),
        },
        AdvancedItem {
            id: "chrome".into(),
            group: "browsers".into(),
            title: "Chrome Tor app".into(),
            description: "Installs a separate Chrome Tor app (Chrome icon) that forces SOCKS.".into(),
            configured: chrome.installed,
            detail: chrome.detail,
            configure_label: if chrome.installed {
                "Reinstall".into()
            } else {
                "Install app".into()
            },
            can_remove: chrome.installed,
            note: Some(
                "Regular Chrome often bypasses Tor even when the OS SOCKS proxy is on: it may ignore system proxy, use its own proxy settings, or resolve DNS via Chrome Secure DNS / DoH outside Tor. Use this Chrome Tor app (or Firefox config) instead of relying on normal Chrome."
                    .into(),
            ),
        },
        AdvancedItem {
            id: "firefox".into(),
            group: "browsers".into(),
            title: "Firefox SOCKS + remote DNS".into(),
            description: "Applies SOCKS prefs to your default Firefox profile user.js.".into(),
            configured: profile_ok || snippet_ok,
            detail: match (&profile, profile_ok, snippet_ok) {
                (Some(p), true, _) => format!("Applied in {}", p.display()),
                (Some(p), false, true) => {
                    format!("Snippet ready; profile not applied yet ({})", p.display())
                }
                (None, _, true) => "Snippet written; no Firefox profile found".into(),
                _ => "Not configured".into(),
            },
            configure_label: if profile_ok {
                "Reapply".into()
            } else {
                "Configure".into()
            },
            can_remove: profile_ok || snippet_ok,
            note: Some(
                "Firefox does not follow the macOS/Linux system proxy by default — it needs its own SOCKS settings (and socks_remote_dns)."
                    .into(),
            ),
        },
        AdvancedItem {
            id: "cursor".into(),
            group: "apps".into(),
            title: "Cursor".into(),
            description: "Writes SOCKS proxy settings into Cursor's settings.json.".into(),
            configured: cursor.configured,
            detail: cursor.detail,
            configure_label: if cursor.configured { "Reapply".into() } else { "Configure".into() },
            can_remove: cursor.configured,
            note: Some(
                "Cursor defaults to ignoring the OS proxy (http.proxySupport=override with empty http.proxy). This forces socks5://127.0.0.1:9050. Fully quit Cursor after applying. AI features may still partially bypass depending on Cursor version."
                    .into(),
            ),
        },
        AdvancedItem {
            id: "vscode".into(),
            group: "apps".into(),
            title: "VS Code".into(),
            description: "Writes SOCKS proxy settings into VS Code's settings.json.".into(),
            configured: vscode.configured,
            detail: vscode.detail,
            configure_label: if vscode.configured { "Reapply".into() } else { "Configure".into() },
            can_remove: vscode.configured,
            note: Some(
                "VS Code/Electron often ignores system SOCKS unless http.proxy is set explicitly."
                    .into(),
            ),
        },
        AdvancedItem {
            id: "claude_code".into(),
            group: "apps".into(),
            title: "Claude Code".into(),
            description: "Adds proxy env to ~/.claude/settings.json for the Claude Code CLI.".into(),
            configured: claude.configured,
            detail: claude.detail,
            configure_label: if claude.configured { "Reapply".into() } else { "Configure".into() },
            can_remove: claude.configured,
            note: Some(
                "Claude Code does not officially support SOCKS proxies (HTTP/HTTPS preferred). This still sets env in settings.json and pairs best with Shell auto-proxy. If requests fail, you may need an HTTP→SOCKS bridge."
                    .into(),
            ),
        },
        AdvancedItem {
            id: "discord".into(),
            group: "apps".into(),
            title: "Discord Tor app".into(),
            description: "Installs a Discord launcher app that forces --proxy-server through Tor.".into(),
            configured: discord.installed,
            detail: discord.detail,
            configure_label: if discord.installed { "Reinstall".into() } else { "Install app".into() },
            can_remove: discord.installed,
            note: Some(
                "Discord ignores OS proxy settings. Use the installed Discord Tor app instead of the normal Discord app."
                    .into(),
            ),
        },
        AdvancedItem {
            id: "slack".into(),
            group: "apps".into(),
            title: "Slack Tor app".into(),
            description: "Installs a Slack launcher app that forces --proxy-server through Tor.".into(),
            configured: slack.installed,
            detail: slack.detail,
            configure_label: if slack.installed { "Reinstall".into() } else { "Install app".into() },
            can_remove: slack.installed,
            note: Some(
                "Slack desktop typically bypasses system SOCKS. Launch Slack Tor instead of normal Slack."
                    .into(),
            ),
        },
    ];

    AdvancedStatus { items }
}

struct ChromeAppStatus {
    installed: bool,
    detail: String,
}

fn chrome_app_status() -> ChromeAppStatus {
    #[cfg(target_os = "macos")]
    {
        let app = macos_chrome_tor_app_path();
        if app.is_dir() {
            return ChromeAppStatus {
                installed: true,
                detail: format!("App installed at {}", app.display()),
            };
        }
        return ChromeAppStatus {
            installed: false,
            detail: "Not installed in ~/Applications".into(),
        };
    }
    #[cfg(target_os = "linux")]
    {
        let desktop = linux_chrome_tor_desktop_path();
        if desktop.is_file() {
            return ChromeAppStatus {
                installed: true,
                detail: format!("App menu entry at {}", desktop.display()),
            };
        }
        return ChromeAppStatus {
            installed: false,
            detail: "Not installed in ~/.local/share/applications".into(),
        };
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        ChromeAppStatus {
            installed: false,
            detail: "Unsupported platform".into(),
        }
    }
}

fn home_dir() -> Result<PathBuf, String> {
    dirs::home_dir().ok_or_else(|| "Could not resolve home directory".to_string())
}

fn app_dir() -> Result<PathBuf, String> {
    let dir = home_dir()?.join(".oniongate");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn hook_script_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("shell-hook.sh"))
}

fn shell_hook_script() -> String {
    format!(
        r#"# Generated by OnionGate — do not edit by hand (re-install from the app).
# Installed at /etc/oniongate/shell.sh
# Enables shell proxy env only when Tor SOCKS is reachable on {host}:{port}.

TOR_SOCKS_HOST="{host}"
TOR_SOCKS_PORT="{port}"
TOR_SOCKS_URL="socks5h://${{TOR_SOCKS_HOST}}:${{TOR_SOCKS_PORT}}"

__tor_socks_port_up() {{
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 1 "$TOR_SOCKS_HOST" "$TOR_SOCKS_PORT" >/dev/null 2>&1 && return 0
  fi
  if command -v timeout >/dev/null 2>&1; then
    timeout 1 bash -c "echo >/dev/tcp/${{TOR_SOCKS_HOST}}/${{TOR_SOCKS_PORT}}" >/dev/null 2>&1 && return 0
  fi
  if [ -n "${{BASH_VERSION:-}}" ]; then
    (echo >/dev/tcp/${{TOR_SOCKS_HOST}}/${{TOR_SOCKS_PORT}}) >/dev/null 2>&1 && return 0
  fi
  if [ -n "${{ZSH_VERSION:-}}" ]; then
    zmodload zsh/net/tcp 2>/dev/null || true
    if ztcp "$TOR_SOCKS_HOST" "$TOR_SOCKS_PORT" 2>/dev/null; then
      ztcp -c
      return 0
    fi
  fi
  return 1
}}

tor_socks_off() {{
  unset ALL_PROXY all_proxy HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
  export TOR_SOCKS_SHELL=off
}}

tor_socks_on() {{
  export ALL_PROXY="$TOR_SOCKS_URL"
  export all_proxy="$TOR_SOCKS_URL"
  export TOR_SOCKS_SHELL=on
}}

tor_socks_sync() {{
  if __tor_socks_port_up; then
    tor_socks_on
    return 0
  fi
  tor_socks_off
  return 1
}}

tor_socks_sync >/dev/null 2>&1 || true

if [ -n "${{ZSH_VERSION:-}}" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null || true
  _tor_socks_precmd() {{ tor_socks_sync >/dev/null 2>&1 || true; }}
  add-zsh-hook precmd _tor_socks_precmd 2>/dev/null || true
elif [ -n "${{BASH_VERSION:-}}" ]; then
  __tor_socks_prompt_cmd() {{ tor_socks_sync >/dev/null 2>&1 || true; }}
  case "${{PROMPT_COMMAND:-}}" in
    *__tor_socks_prompt_cmd*) ;;
    "") PROMPT_COMMAND="__tor_socks_prompt_cmd" ;;
    *) PROMPT_COMMAND="__tor_socks_prompt_cmd;${{PROMPT_COMMAND}}" ;;
  esac
fi
"#,
        host = SOCKS_HOST,
        port = SOCKS_PORT
    )
}

fn rc_candidates() -> Result<Vec<PathBuf>, String> {
    let home = home_dir()?;
    let shell = std::env::var("SHELL").unwrap_or_default();
    let mut paths = Vec::new();

    if shell.contains("zsh") {
        paths.push(home.join(".zshrc"));
    } else if shell.contains("bash") {
        paths.push(home.join(".bashrc"));
        paths.push(home.join(".bash_profile"));
    } else {
        paths.push(home.join(".zshrc"));
        paths.push(home.join(".bashrc"));
    }

    #[cfg(target_os = "macos")]
    {
        let zshrc = home.join(".zshrc");
        if !paths.contains(&zshrc) {
            paths.insert(0, zshrc);
        }
    }

    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn rc_has_hook(contents: &str) -> bool {
    contents.contains(HOOK_MARKER_BEGIN)
        || contents.contains(LEGACY_HOOK_MARKER_BEGIN)
        || contents.contains("oniongate/shell-hook.sh")
        || contents.contains("tor-socks-gui/shell-hook.sh")
        || contents.contains("/etc/oniongate/shell.sh")
        || contents.contains("/etc/tor-socks-gui/shell.sh")
}

fn etc_env_contents() -> String {
    format!(
        "# Generated by OnionGate\n\
         # Config: {ETC_ENV_PATH}\n\
         # Usage: source {ETC_ENV_PATH}\n\
         {}\n",
        helpers().shell_exports
    )
}

#[cfg(target_os = "linux")]
fn linux_profile_d_contents() -> String {
    format!(
        "{HOOK_MARKER_BEGIN}\n\
         # OnionGate — system shell proxy\n\
         {HOOK_SOURCE_LINE}\n\
         {HOOK_MARKER_END}\n"
    )
}

fn elevated_write_file(path: &str, contents: &str) -> Result<(), String> {
    let tmp = std::env::temp_dir().join(format!(
        "oniongate-{}-{}.tmp",
        std::process::id(),
        path.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32))
    ));
    fs::write(&tmp, contents).map_err(|e| format!("Failed to stage temp file: {e}"))?;
    let qtmp = crate::elevate::shell_quote(&tmp.to_string_lossy());
    let qpath = crate::elevate::shell_quote(path);
    let qdir = crate::elevate::shell_quote(ETC_DIR);
    #[cfg(target_os = "macos")]
    let chown = format!("chown root:wheel {qpath}");
    #[cfg(target_os = "linux")]
    let chown = format!("chown root:root {qpath}");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let chown = format!("true");
    let script = format!("mkdir -p {qdir} && cp {qtmp} {qpath} && chmod 644 {qpath} && {chown}");
    let result = crate::elevate::run_shell(&script);
    let _ = fs::remove_file(&tmp);
    result
}

fn elevated_remove_paths(paths: &[&str]) -> Result<(), String> {
    let existing: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|p| Path::new(p).exists())
        .collect();
    if existing.is_empty() {
        return Ok(());
    }
    let rm = existing
        .iter()
        .map(|p| format!("rm -f {}", crate::elevate::shell_quote(p)))
        .collect::<Vec<_>>()
        .join(" && ");
    crate::elevate::run_shell(&rm)
}

fn system_rc_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![PathBuf::from("/etc/zshrc"), PathBuf::from("/etc/bashrc")]
    }
    #[cfg(target_os = "linux")]
    {
        Vec::new()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

fn ensure_system_hook(path: &Path) -> Result<bool, String> {
    let existing = if path.exists() {
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?
    } else {
        String::new()
    };
    if rc_has_hook(&existing) {
        return Ok(false);
    }
    let mut next = existing;
    if !next.ends_with('\n') && !next.is_empty() {
        next.push('\n');
    }
    next.push_str(&format!(
        "\n{HOOK_MARKER_BEGIN}\n# OnionGate — auto proxy env when Tor is up\n{HOOK_SOURCE_LINE}\n{HOOK_MARKER_END}\n"
    ));
    elevated_write_file(&path.display().to_string(), &next)?;
    Ok(true)
}

fn remove_system_hook(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    let existing =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    if !rc_has_hook(&existing) {
        return Ok(false);
    }
    let cleaned = strip_hook_block(&existing);
    elevated_write_file(&path.display().to_string(), &cleaned)?;
    Ok(true)
}

fn cleanup_legacy_user_shell() {
    let _ = uninstall_user_shell_hook();
    if let Ok(home) = home_dir() {
        let legacy = home.join(".tor-socks-env");
        let _ = fs::remove_file(legacy);
    }
}

fn uninstall_user_shell_hook() -> Result<(), String> {
    for rc in rc_candidates()? {
        let _ = remove_hook_from_rc(&rc);
    }
    if let Ok(hook_path) = hook_script_path() {
        if hook_path.exists() {
            let _ = fs::remove_file(hook_path);
        }
    }
    Ok(())
}

fn strip_hook_block(contents: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in contents.lines() {
        if line.trim() == HOOK_MARKER_BEGIN || line.trim() == LEGACY_HOOK_MARKER_BEGIN {
            skipping = true;
            continue;
        }
        if line.trim() == HOOK_MARKER_END || line.trim() == LEGACY_HOOK_MARKER_END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.lines()
        .filter(|l| {
            !l.contains("oniongate/shell-hook.sh")
                && !l.contains("tor-socks-gui/shell-hook.sh")
                && !l.contains("/etc/oniongate/shell.sh")
                && !l.contains("/etc/tor-socks-gui/shell.sh")
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

fn remove_hook_from_rc(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    let existing =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    if !rc_has_hook(&existing) {
        return Ok(false);
    }
    let cleaned = strip_hook_block(&existing);
    fs::write(path, cleaned).map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    Ok(true)
}

pub fn shell_hook_status() -> ShellHookStatus {
    let hook_path = ETC_SHELL_PATH.to_string();
    let mut targets = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if Path::new(LINUX_PROFILE_D).is_file() {
            targets.push(LINUX_PROFILE_D.to_string());
        }
    }

    for rc in system_rc_paths() {
        if rc.exists() {
            if let Ok(contents) = fs::read_to_string(&rc) {
                if rc_has_hook(&contents) {
                    targets.push(rc.display().to_string());
                }
            }
        }
    }

    // Legacy user hooks still count as "installed" until cleaned.
    if let Ok(rcs) = rc_candidates() {
        for rc in rcs {
            if rc.exists() {
                if let Ok(contents) = fs::read_to_string(&rc) {
                    if rc_has_hook(&contents) {
                        targets.push(rc.display().to_string());
                    }
                }
            }
        }
    }

    let hook_exists = Path::new(ETC_SHELL_PATH).is_file()
        || hook_script_path().map(|p| p.is_file()).unwrap_or(false);
    ShellHookStatus {
        installed: hook_exists && !targets.is_empty(),
        hook_path,
        targets,
    }
}

pub fn install_shell_hook() -> Result<String, String> {
    cleanup_legacy_user_shell();
    elevated_write_file(ETC_SHELL_PATH, &shell_hook_script())?;
    // Keep a static env file alongside for `source` convenience.
    elevated_write_file(ETC_ENV_PATH, &etc_env_contents())?;

    let mut updated: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        elevated_write_file(LINUX_PROFILE_D, &linux_profile_d_contents())?;
        updated.push(LINUX_PROFILE_D.to_string());
    }

    #[cfg(target_os = "macos")]
    {
        for rc in system_rc_paths() {
            match ensure_system_hook(&rc) {
                Ok(true) => updated.push(rc.display().to_string()),
                Ok(false) => updated.push(format!("{} (already present)", rc.display())),
                Err(e) => return Err(e),
            }
        }
    }

    if updated.is_empty() {
        updated.push(ETC_SHELL_PATH.into());
    }

    crate::logs::append("Configured system shell auto-proxy under /etc/oniongate");
    Ok(format!(
        "Shell auto configured ({}). Open a new terminal.",
        updated.join(", ")
    ))
}

pub fn uninstall_shell_hook() -> Result<String, String> {
    cleanup_legacy_user_shell();
    let mut removed = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if Path::new(LINUX_PROFILE_D).exists() || Path::new(LEGACY_LINUX_PROFILE_D).exists() {
            elevated_remove_paths(&[LINUX_PROFILE_D, LEGACY_LINUX_PROFILE_D])?;
            removed.push(LINUX_PROFILE_D.to_string());
        }
    }

    #[cfg(target_os = "macos")]
    {
        for rc in system_rc_paths() {
            if remove_system_hook(&rc)? {
                removed.push(rc.display().to_string());
            }
        }
    }

    if Path::new(ETC_SHELL_PATH).exists() || Path::new("/etc/tor-socks-gui/shell.sh").exists() {
        elevated_remove_paths(&[ETC_SHELL_PATH, "/etc/tor-socks-gui/shell.sh"])?;
        if Path::new(ETC_SHELL_PATH).exists() {
            removed.push(ETC_SHELL_PATH.to_string());
        }
        removed.push(LEGACY_ETC_DIR.to_string());
    }

    crate::logs::append("Removed system shell auto-proxy hook");
    if removed.is_empty() {
        Ok("Shell hook removed".into())
    } else {
        Ok(format!("Removed shell hook: {}", removed.join(", ")))
    }
}

pub fn write_shell_env() -> Result<String, String> {
    cleanup_legacy_user_shell();
    elevated_write_file(ETC_ENV_PATH, &etc_env_contents())?;
    crate::logs::append(format!("Wrote {ETC_ENV_PATH}"));
    Ok(format!("Wrote {ETC_ENV_PATH}"))
}

pub fn remove_shell_env() -> Result<String, String> {
    cleanup_legacy_user_shell();
    if Path::new(ETC_ENV_PATH).exists() {
        elevated_remove_paths(&[ETC_ENV_PATH])?;
        crate::logs::append(format!("Removed {ETC_ENV_PATH}"));
        Ok(format!("Removed {ETC_ENV_PATH}"))
    } else {
        Ok("Shell env file was not present".into())
    }
}

fn firefox_profiles_root() -> Option<PathBuf> {
    let home = home_dir().ok()?;
    #[cfg(target_os = "macos")]
    {
        return Some(home.join("Library/Application Support/Firefox/Profiles"));
    }
    #[cfg(target_os = "linux")]
    {
        return Some(home.join(".mozilla/firefox"));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = home;
        None
    }
}

fn find_firefox_profile() -> Option<PathBuf> {
    let root = firefox_profiles_root()?;
    if !root.is_dir() {
        return None;
    }
    let mut profiles: Vec<PathBuf> = fs::read_dir(&root)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    if profiles.is_empty() {
        return None;
    }
    // Prefer default-release / default
    profiles.sort_by_key(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains("default-release") {
            0
        } else if name.contains("default") {
            1
        } else {
            2
        }
    });
    profiles.into_iter().next()
}

fn firefox_profile_configured(profile: &Path) -> bool {
    let user_js = profile.join("user.js");
    let Ok(contents) = fs::read_to_string(user_js) else {
        return false;
    };
    (contents.contains(FIREFOX_MARKER_BEGIN) || contents.contains(LEGACY_FIREFOX_MARKER_BEGIN))
        && contents.contains("network.proxy.socks_remote_dns")
}

fn strip_firefox_block(contents: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in contents.lines() {
        if line.trim() == FIREFOX_MARKER_BEGIN || line.trim() == LEGACY_FIREFOX_MARKER_BEGIN {
            skipping = true;
            continue;
        }
        if line.trim() == FIREFOX_MARKER_END || line.trim() == LEGACY_FIREFOX_MARKER_END {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

pub fn write_firefox_user_js() -> Result<String, String> {
    let dir = app_dir()?;
    let snippet = dir.join("firefox-user.js");
    let block = firefox_prefs_block();
    fs::write(&snippet, format!("{block}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", snippet.display()))?;

    let Some(profile) = find_firefox_profile() else {
        crate::logs::append("Firefox snippet written; no profile found to apply");
        return Ok(format!(
            "Wrote {}. No Firefox profile found to apply automatically.",
            snippet.display()
        ));
    };

    let user_js = profile.join("user.js");
    let existing = if user_js.exists() {
        fs::read_to_string(&user_js)
            .map_err(|e| format!("Failed to read {}: {e}", user_js.display()))?
    } else {
        String::new()
    };
    let cleaned = strip_firefox_block(&existing);
    let next = format!("{cleaned}{block}\n");
    fs::write(&user_js, next).map_err(|e| format!("Failed to write {}: {e}", user_js.display()))?;
    crate::logs::append(format!(
        "Applied Firefox Tor prefs to {}",
        user_js.display()
    ));
    Ok(format!(
        "Configured Firefox profile (restart Firefox): {}",
        user_js.display()
    ))
}

pub fn remove_firefox_config() -> Result<String, String> {
    let mut msgs = Vec::new();
    let snippet = app_dir()?.join("firefox-user.js");
    if snippet.exists() {
        fs::remove_file(&snippet)
            .map_err(|e| format!("Failed to remove {}: {e}", snippet.display()))?;
        msgs.push("removed snippet".into());
    }
    if let Some(profile) = find_firefox_profile() {
        let user_js = profile.join("user.js");
        if user_js.exists() {
            let existing = fs::read_to_string(&user_js)
                .map_err(|e| format!("Failed to read {}: {e}", user_js.display()))?;
            if existing.contains(FIREFOX_MARKER_BEGIN) {
                let cleaned = strip_firefox_block(&existing);
                fs::write(&user_js, cleaned)
                    .map_err(|e| format!("Failed to write {}: {e}", user_js.display()))?;
                msgs.push(format!("cleared {}", user_js.display()));
            }
        }
    }
    if msgs.is_empty() {
        Ok("Firefox config was not present".into())
    } else {
        crate::logs::append("Removed Firefox Tor prefs");
        Ok(format!("Firefox config removed ({})", msgs.join(", ")))
    }
}

#[cfg(target_os = "macos")]
fn macos_chrome_tor_app_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join("Applications")
        .join("Chrome Tor.app")
}

#[cfg(target_os = "linux")]
fn linux_chrome_tor_desktop_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join(".local/share/applications/chrome-tor.desktop")
}

#[cfg(unix)]
fn chmod_exec(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .map_err(|e| format!("Failed to stat {}: {e}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).map_err(|e| format!("Failed to chmod {}: {e}", path.display()))
}

#[cfg(target_os = "macos")]
fn install_macos_chrome_tor_app() -> Result<String, String> {
    let chrome_app = PathBuf::from("/Applications/Google Chrome.app");
    if !chrome_app.is_dir() {
        return Err("Google Chrome.app not found in /Applications".into());
    }

    let app = macos_chrome_tor_app_path();
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&macos).map_err(|e| format!("Failed to create app bundle: {e}"))?;
    fs::create_dir_all(&resources).map_err(|e| format!("Failed to create Resources: {e}"))?;

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Chrome Tor</string>
  <key>CFBundleIdentifier</key>
  <string>com.adamsiwiec.chrome-tor</string>
  <key>CFBundleName</key>
  <string>Chrome Tor</string>
  <key>CFBundleDisplayName</key>
  <string>Chrome Tor</string>
  <key>CFBundleIconFile</key>
  <string>app</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
"#
    );
    fs::write(contents.join("Info.plist"), plist)
        .map_err(|e| format!("Failed to write Info.plist: {e}"))?;

    let proxy = socks_plain();
    let exe = macos.join("Chrome Tor");
    let script = format!(
        "#!/bin/zsh\n# Generated by OnionGate — opens Chrome through Tor SOCKS\nexec open -na \"Google Chrome\" --args --proxy-server={proxy} \"$@\"\n"
    );
    fs::write(&exe, script).map_err(|e| format!("Failed to write launcher: {e}"))?;
    chmod_exec(&exe)?;

    // Reuse Google Chrome's icon so it looks native in Launchpad / Applications.
    let icns_src = chrome_app.join("Contents/Resources/app.icns");
    let icns_dst = resources.join("app.icns");
    if icns_src.is_file() {
        fs::copy(&icns_src, &icns_dst).map_err(|e| format!("Failed to copy Chrome icon: {e}"))?;
    }

    // Also keep a helper script under ~/.oniongate for debugging.
    let helper = app_dir()?.join("launch-chrome-tor.sh");
    fs::write(
        &helper,
        format!("#!/bin/zsh\nexec open -a \"{}\"\n", app.display()),
    )
    .map_err(|e| format!("Failed to write helper script: {e}"))?;
    chmod_exec(&helper)?;

    // Refresh Launch Services so Spotlight/Launchpad pick it up.
    let _ = Command::new("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister")
        .args(["-f", &app.display().to_string()])
        .status();

    crate::logs::append(format!("Installed Chrome Tor.app at {}", app.display()));
    Ok(format!(
        "Installed Chrome Tor in {}. Open it from Applications / Launchpad (Chrome icon).",
        app.display()
    ))
}

#[cfg(target_os = "macos")]
fn remove_macos_chrome_tor_app() -> Result<String, String> {
    let app = macos_chrome_tor_app_path();
    if app.is_dir() {
        fs::remove_dir_all(&app).map_err(|e| format!("Failed to remove {}: {e}", app.display()))?;
    }
    let helper = app_dir()?.join("launch-chrome-tor.sh");
    if helper.exists() {
        let _ = fs::remove_file(helper);
    }
    crate::logs::append("Removed Chrome Tor.app");
    Ok("Removed Chrome Tor from ~/Applications".into())
}

#[cfg(target_os = "linux")]
fn find_linux_chrome_bin() -> Option<String> {
    for name in [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ] {
        if which::which(name).is_ok() {
            return Some(name.into());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn find_linux_chrome_icon() -> Option<PathBuf> {
    let candidates = [
        "/usr/share/icons/hicolor/256x256/apps/google-chrome.png",
        "/usr/share/icons/hicolor/128x128/apps/google-chrome.png",
        "/usr/share/icons/hicolor/256x256/apps/chromium.png",
        "/usr/share/pixmaps/google-chrome.png",
        "/usr/share/pixmaps/chromium.png",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.is_file())
}

#[cfg(target_os = "linux")]
fn install_linux_chrome_tor_app() -> Result<String, String> {
    let bin =
        find_linux_chrome_bin().ok_or_else(|| "Chrome/Chromium not found on PATH".to_string())?;
    let proxy = socks_plain();

    let apps_dir = home_dir()?.join(".local/share/applications");
    fs::create_dir_all(&apps_dir).map_err(|e| format!("Failed to create applications dir: {e}"))?;

    let icons_dir = home_dir()?.join(".local/share/icons/hicolor/256x256/apps");
    fs::create_dir_all(&icons_dir).map_err(|e| format!("Failed to create icons dir: {e}"))?;

    let mut icon_name = "google-chrome".to_string();
    if let Some(src) = find_linux_chrome_icon() {
        let dst = icons_dir.join("chrome-tor.png");
        if fs::copy(&src, &dst).is_ok() {
            icon_name = "chrome-tor".into();
        }
    }

    let wrapper = app_dir()?.join("launch-chrome-tor.sh");
    let script = format!(
        "#!/usr/bin/env bash\n# Generated by OnionGate\nexec {bin} --proxy-server={proxy} \"$@\"\n"
    );
    fs::write(&wrapper, script).map_err(|e| format!("Failed to write launcher: {e}"))?;
    chmod_exec(&wrapper)?;

    let desktop = linux_chrome_tor_desktop_path();
    let entry = format!(
        "[Desktop Entry]\n\
Type=Application\n\
Version=1.0\n\
Name=Chrome Tor\n\
GenericName=Web Browser\n\
Comment=Google Chrome via Tor SOCKS proxy\n\
Exec=\"{}\" %U\n\
Icon={icon_name}\n\
Terminal=false\n\
Categories=Network;WebBrowser;\n\
StartupNotify=true\n\
MimeType=text/html;text/xml;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;\n",
        wrapper.display()
    );
    fs::write(&desktop, entry).map_err(|e| format!("Failed to write desktop entry: {e}"))?;

    // Refresh desktop database when available.
    let _ = Command::new("update-desktop-database")
        .arg(apps_dir.display().to_string())
        .status();

    crate::logs::append(format!(
        "Installed Chrome Tor desktop app at {}",
        desktop.display()
    ));
    Ok(format!(
        "Installed Chrome Tor in your app menu ({})",
        desktop.display()
    ))
}

#[cfg(target_os = "linux")]
fn remove_linux_chrome_tor_app() -> Result<String, String> {
    let desktop = linux_chrome_tor_desktop_path();
    if desktop.exists() {
        fs::remove_file(&desktop)
            .map_err(|e| format!("Failed to remove {}: {e}", desktop.display()))?;
    }
    let icon = home_dir()?.join(".local/share/icons/hicolor/256x256/apps/chrome-tor.png");
    if icon.exists() {
        let _ = fs::remove_file(icon);
    }
    let wrapper = app_dir()?.join("launch-chrome-tor.sh");
    if wrapper.exists() {
        let _ = fs::remove_file(wrapper);
    }
    crate::logs::append("Removed Chrome Tor desktop app");
    Ok("Removed Chrome Tor from your app menu".into())
}

pub fn write_chrome_launcher() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return install_macos_chrome_tor_app();
    }
    #[cfg(target_os = "linux")]
    {
        return install_linux_chrome_tor_app();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Chrome Tor app install is not supported on this platform".into())
    }
}

pub fn remove_chrome_launcher() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return remove_macos_chrome_tor_app();
    }
    #[cfg(target_os = "linux")]
    {
        return remove_linux_chrome_tor_app();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Chrome Tor app remove is not supported on this platform".into())
    }
}

#[derive(Clone)]
struct IdeProxyStatus {
    configured: bool,
    detail: String,
}

fn ide_settings_path(app_name: &str) -> Option<PathBuf> {
    let home = home_dir().ok()?;
    #[cfg(target_os = "macos")]
    {
        return Some(
            home.join("Library/Application Support")
                .join(app_name)
                .join("User/settings.json"),
        );
    }
    #[cfg(target_os = "linux")]
    {
        let dir = if app_name == "Cursor" {
            home.join(".config/Cursor/User/settings.json")
        } else {
            home.join(".config/Code/User/settings.json")
        };
        return Some(dir);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = home;
        let _ = app_name;
        None
    }
}

fn ide_proxy_status(app_name: &str) -> IdeProxyStatus {
    let Some(path) = ide_settings_path(app_name) else {
        return IdeProxyStatus {
            configured: false,
            detail: "Unsupported platform".into(),
        };
    };
    if !path.is_file() {
        return IdeProxyStatus {
            configured: false,
            detail: format!("No settings.json yet ({})", path.display()),
        };
    }
    let Ok(raw) = fs::read_to_string(&path) else {
        return IdeProxyStatus {
            configured: false,
            detail: format!("Unreadable {}", path.display()),
        };
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return IdeProxyStatus {
            configured: false,
            detail: format!("Invalid JSON at {}", path.display()),
        };
    };
    let proxy = v.get("http.proxy").and_then(|x| x.as_str()).unwrap_or("");
    let configured = proxy.contains("127.0.0.1:9050") || proxy.contains("localhost:9050");
    IdeProxyStatus {
        configured,
        detail: if configured {
            format!("Proxy set in {}", path.display())
        } else {
            format!("Present but not Tor-proxied ({})", path.display())
        },
    }
}

fn merge_ide_proxy_settings(path: &Path) -> Result<(), String> {
    let mut root = if path.exists() {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        serde_json::from_str::<serde_json::Value>(&raw)
            .map_err(|e| format!("Invalid JSON in {}: {e}", path.display()))?
    } else {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
        }
        serde_json::json!({})
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "settings.json root must be an object".to_string())?;
    obj.insert(
        "http.proxy".into(),
        serde_json::Value::String(format!("socks5://{SOCKS_HOST}:{SOCKS_PORT}")),
    );
    obj.insert(
        "http.proxySupport".into(),
        serde_json::Value::String("override".into()),
    );
    obj.insert("http.proxyStrictSSL".into(), serde_json::Value::Bool(true));
    // Cursor/VS Code AI stacks often need HTTP/1.1 for proxy compatibility.
    if path.display().to_string().contains("Cursor") {
        obj.insert(
            "cursor.general.disableHttp2".into(),
            serde_json::Value::Bool(true),
        );
    }
    let out = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    fs::write(path, format!("{out}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

fn clear_ide_proxy_settings(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    let raw =
        fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let mut root: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid JSON in {}: {e}", path.display()))?;
    let Some(obj) = root.as_object_mut() else {
        return Ok(false);
    };
    let keys = [
        "http.proxy",
        "http.proxySupport",
        "http.proxyStrictSSL",
        "cursor.general.disableHttp2",
    ];
    let mut changed = false;
    for k in keys {
        if obj.remove(k).is_some() {
            changed = true;
        }
    }
    if changed {
        let out = serde_json::to_string_pretty(&root)
            .map_err(|e| format!("Failed to serialize settings: {e}"))?;
        fs::write(path, format!("{out}\n"))
            .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    }
    Ok(changed)
}

pub fn configure_cursor() -> Result<String, String> {
    let path = ide_settings_path("Cursor")
        .ok_or_else(|| "Cursor settings path unsupported".to_string())?;
    merge_ide_proxy_settings(&path)?;
    crate::logs::append(format!("Configured Cursor proxy in {}", path.display()));
    Ok(format!(
        "Configured Cursor Tor proxy in {}. Fully quit and reopen Cursor.",
        path.display()
    ))
}

pub fn remove_cursor() -> Result<String, String> {
    let path = ide_settings_path("Cursor")
        .ok_or_else(|| "Cursor settings path unsupported".to_string())?;
    if clear_ide_proxy_settings(&path)? {
        crate::logs::append("Removed Cursor Tor proxy settings");
        Ok("Removed Tor proxy keys from Cursor settings.json".into())
    } else {
        Ok("Cursor Tor proxy settings were not present".into())
    }
}

pub fn configure_vscode() -> Result<String, String> {
    let path =
        ide_settings_path("Code").ok_or_else(|| "VS Code settings path unsupported".to_string())?;
    merge_ide_proxy_settings(&path)?;
    crate::logs::append(format!("Configured VS Code proxy in {}", path.display()));
    Ok(format!(
        "Configured VS Code Tor proxy in {}. Fully quit and reopen VS Code.",
        path.display()
    ))
}

pub fn remove_vscode() -> Result<String, String> {
    let path =
        ide_settings_path("Code").ok_or_else(|| "VS Code settings path unsupported".to_string())?;
    if clear_ide_proxy_settings(&path)? {
        crate::logs::append("Removed VS Code Tor proxy settings");
        Ok("Removed Tor proxy keys from VS Code settings.json".into())
    } else {
        Ok("VS Code Tor proxy settings were not present".into())
    }
}

#[derive(Clone)]
struct ClaudeStatus {
    configured: bool,
    detail: String,
}

fn claude_settings_path() -> Option<PathBuf> {
    Some(home_dir().ok()?.join(".claude/settings.json"))
}

fn claude_code_status() -> ClaudeStatus {
    let Some(path) = claude_settings_path() else {
        return ClaudeStatus {
            configured: false,
            detail: "Unsupported".into(),
        };
    };
    if !path.is_file() {
        return ClaudeStatus {
            configured: false,
            detail: format!("No {}", path.display()),
        };
    }
    let Ok(raw) = fs::read_to_string(&path) else {
        return ClaudeStatus {
            configured: false,
            detail: "Unreadable settings".into(),
        };
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return ClaudeStatus {
            configured: false,
            detail: "Invalid JSON".into(),
        };
    };
    let env = v.get("env").and_then(|e| e.as_object());
    let configured = env
        .map(|e| {
            e.values().any(|val| {
                val.as_str()
                    .map(|s| s.contains("127.0.0.1:9050") || s.contains("localhost:9050"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);
    ClaudeStatus {
        configured,
        detail: if configured {
            format!("Proxy env set in {}", path.display())
        } else {
            format!("Settings exist without Tor proxy ({})", path.display())
        },
    }
}

pub fn configure_claude_code() -> Result<String, String> {
    let path = claude_settings_path().ok_or_else(|| "Claude settings path missing".to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }
    let mut root = if path.exists() {
        let raw = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
        serde_json::from_str::<serde_json::Value>(&raw)
            .map_err(|e| format!("Invalid JSON in {}: {e}", path.display()))?
    } else {
        serde_json::json!({})
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "settings.json root must be an object".to_string())?;
    let socks = format!("socks5h://{SOCKS_HOST}:{SOCKS_PORT}");
    let mut env = obj
        .get("env")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    env.insert("ALL_PROXY".into(), serde_json::Value::String(socks.clone()));
    env.insert(
        "HTTPS_PROXY".into(),
        serde_json::Value::String(socks.clone()),
    );
    env.insert("HTTP_PROXY".into(), serde_json::Value::String(socks));
    obj.insert("env".into(), serde_json::Value::Object(env));
    let out = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    fs::write(&path, format!("{out}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    crate::logs::append(format!(
        "Configured Claude Code proxy env in {}",
        path.display()
    ));
    Ok(format!(
        "Configured Claude Code proxy env in {}. Note: Claude Code may not fully support SOCKS.",
        path.display()
    ))
}

pub fn remove_claude_code() -> Result<String, String> {
    let path = claude_settings_path().ok_or_else(|| "Claude settings path missing".to_string())?;
    if !path.exists() {
        return Ok("Claude Code settings were not present".into());
    }
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
    let mut root: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("Invalid JSON in {}: {e}", path.display()))?;
    let Some(obj) = root.as_object_mut() else {
        return Ok("Claude settings unchanged".into());
    };
    if let Some(env) = obj.get_mut("env").and_then(|v| v.as_object_mut()) {
        for k in [
            "ALL_PROXY",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "all_proxy",
            "https_proxy",
            "http_proxy",
        ] {
            env.remove(k);
        }
        if env.is_empty() {
            obj.remove("env");
        }
    }
    let out = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("Failed to serialize settings: {e}"))?;
    fs::write(&path, format!("{out}\n"))
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    crate::logs::append("Removed Claude Code Tor proxy env");
    Ok("Removed Tor proxy env from Claude Code settings.json".into())
}

#[derive(Clone)]
struct ElectronAppStatus {
    installed: bool,
    detail: String,
}

fn electron_app_status(display_name: &str) -> ElectronAppStatus {
    #[cfg(target_os = "macos")]
    {
        let app = home_dir()
            .map(|h| h.join("Applications").join(format!("{display_name}.app")))
            .unwrap_or_default();
        if app.is_dir() {
            return ElectronAppStatus {
                installed: true,
                detail: format!("App at {}", app.display()),
            };
        }
        return ElectronAppStatus {
            installed: false,
            detail: format!("Not installed in ~/Applications/{display_name}.app"),
        };
    }
    #[cfg(target_os = "linux")]
    {
        let desktop = home_dir()
            .map(|h| {
                h.join(".local/share/applications").join(format!(
                    "{}.desktop",
                    display_name.to_lowercase().replace(' ', "-")
                ))
            })
            .unwrap_or_default();
        if desktop.is_file() {
            return ElectronAppStatus {
                installed: true,
                detail: format!("App menu entry at {}", desktop.display()),
            };
        }
        return ElectronAppStatus {
            installed: false,
            detail: "Not installed in app menu".into(),
        };
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = display_name;
        ElectronAppStatus {
            installed: false,
            detail: "Unsupported platform".into(),
        }
    }
}

#[cfg(target_os = "macos")]
fn install_macos_electron_tor_app(
    display_name: &str,
    bundle_id: &str,
    source_app: &str,
    open_name: &str,
) -> Result<String, String> {
    let source = PathBuf::from("/Applications").join(source_app);
    if !source.is_dir() {
        return Err(format!("{source_app} not found in /Applications"));
    }
    let app = home_dir()?
        .join("Applications")
        .join(format!("{display_name}.app"));
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&macos).map_err(|e| format!("Failed to create app bundle: {e}"))?;
    fs::create_dir_all(&resources).map_err(|e| format!("Failed to create Resources: {e}"))?;

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>{display_name}</string>
  <key>CFBundleIdentifier</key>
  <string>{bundle_id}</string>
  <key>CFBundleName</key>
  <string>{display_name}</string>
  <key>CFBundleDisplayName</key>
  <string>{display_name}</string>
  <key>CFBundleIconFile</key>
  <string>app</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
</dict>
</plist>
"#
    );
    fs::write(contents.join("Info.plist"), plist)
        .map_err(|e| format!("Failed to write Info.plist: {e}"))?;

    let proxy = socks_plain();
    let exe = macos.join(display_name);
    let script =
        format!("#!/bin/zsh\nexec open -na \"{open_name}\" --args --proxy-server={proxy} \"$@\"\n");
    fs::write(&exe, script).map_err(|e| format!("Failed to write launcher: {e}"))?;
    chmod_exec(&exe)?;

    // Prefer electron.icns / app.icns from the real app.
    for name in ["electron.icns", "app.icns", "discord.icns", "Slack.icns"] {
        let src = source.join("Contents/Resources").join(name);
        if src.is_file() {
            fs::copy(&src, resources.join("app.icns"))
                .map_err(|e| format!("Failed to copy icon: {e}"))?;
            break;
        }
    }

    let _ = Command::new("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister")
        .args(["-f", &app.display().to_string()])
        .status();

    crate::logs::append(format!("Installed {display_name}.app"));
    Ok(format!(
        "Installed {display_name} at {}. Use it instead of the normal app.",
        app.display()
    ))
}

#[cfg(target_os = "macos")]
fn remove_macos_electron_tor_app(display_name: &str) -> Result<String, String> {
    let app = home_dir()?
        .join("Applications")
        .join(format!("{display_name}.app"));
    if app.is_dir() {
        fs::remove_dir_all(&app).map_err(|e| format!("Failed to remove {}: {e}", app.display()))?;
        crate::logs::append(format!("Removed {display_name}.app"));
        Ok(format!("Removed {display_name} from ~/Applications"))
    } else {
        Ok(format!("{display_name} was not installed"))
    }
}

#[cfg(target_os = "linux")]
fn install_linux_electron_tor_app(
    display_name: &str,
    bin_candidates: &[&str],
    icon_candidates: &[&str],
) -> Result<String, String> {
    let bin = bin_candidates
        .iter()
        .find(|b| which::which(b).is_ok())
        .copied()
        .ok_or_else(|| format!("{display_name} binary not found on PATH"))?;
    let proxy = socks_plain();
    let slug = display_name.to_lowercase().replace(' ', "-");
    let wrapper = app_dir()?.join(format!("launch-{slug}.sh"));
    fs::write(
        &wrapper,
        format!("#!/usr/bin/env bash\nexec {bin} --proxy-server={proxy} \"$@\"\n"),
    )
    .map_err(|e| format!("Failed to write launcher: {e}"))?;
    chmod_exec(&wrapper)?;

    let apps_dir = home_dir()?.join(".local/share/applications");
    fs::create_dir_all(&apps_dir).map_err(|e| format!("Failed to create applications dir: {e}"))?;
    let desktop = apps_dir.join(format!("{slug}.desktop"));

    let mut icon = bin.to_string();
    for cand in icon_candidates {
        let p = PathBuf::from(cand);
        if p.is_file() {
            let icons = home_dir()?.join(".local/share/icons/hicolor/256x256/apps");
            fs::create_dir_all(&icons).ok();
            let dst = icons.join(format!("{slug}.png"));
            if fs::copy(&p, &dst).is_ok() {
                icon = slug.clone();
            }
            break;
        }
    }

    let entry = format!(
        "[Desktop Entry]\nType=Application\nName={display_name}\nComment={display_name} via Tor SOCKS\nExec=\"{}\" %U\nIcon={icon}\nTerminal=false\nCategories=Network;\n",
        wrapper.display()
    );
    fs::write(&desktop, entry).map_err(|e| format!("Failed to write desktop entry: {e}"))?;
    let _ = Command::new("update-desktop-database")
        .arg(apps_dir.display().to_string())
        .status();
    crate::logs::append(format!("Installed {display_name} desktop app"));
    Ok(format!("Installed {display_name} in your app menu"))
}

#[cfg(target_os = "linux")]
fn remove_linux_electron_tor_app(display_name: &str) -> Result<String, String> {
    let slug = display_name.to_lowercase().replace(' ', "-");
    let desktop = home_dir()?
        .join(".local/share/applications")
        .join(format!("{slug}.desktop"));
    if desktop.exists() {
        fs::remove_file(&desktop)
            .map_err(|e| format!("Failed to remove {}: {e}", desktop.display()))?;
    }
    let wrapper = app_dir()?.join(format!("launch-{slug}.sh"));
    if wrapper.exists() {
        let _ = fs::remove_file(wrapper);
    }
    Ok(format!("Removed {display_name} from app menu"))
}

pub fn configure_discord() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return install_macos_electron_tor_app(
            "Discord Tor",
            "com.adamsiwiec.discord-tor",
            "Discord.app",
            "Discord",
        );
    }
    #[cfg(target_os = "linux")]
    {
        return install_linux_electron_tor_app(
            "Discord Tor",
            &["discord", "Discord"],
            &[
                "/usr/share/icons/hicolor/256x256/apps/discord.png",
                "/usr/share/pixmaps/discord.png",
            ],
        );
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported platform".into())
    }
}

pub fn remove_discord() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return remove_macos_electron_tor_app("Discord Tor");
    }
    #[cfg(target_os = "linux")]
    {
        return remove_linux_electron_tor_app("Discord Tor");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported platform".into())
    }
}

pub fn configure_slack() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return install_macos_electron_tor_app(
            "Slack Tor",
            "com.adamsiwiec.slack-tor",
            "Slack.app",
            "Slack",
        );
    }
    #[cfg(target_os = "linux")]
    {
        return install_linux_electron_tor_app(
            "Slack Tor",
            &["slack", "Slack"],
            &[
                "/usr/share/icons/hicolor/256x256/apps/slack.png",
                "/usr/share/pixmaps/slack.png",
            ],
        );
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported platform".into())
    }
}

pub fn remove_slack() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return remove_macos_electron_tor_app("Slack Tor");
    }
    #[cfg(target_os = "linux")]
    {
        return remove_linux_electron_tor_app("Slack Tor");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported platform".into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellProxyStatus {
    /// "off" | "auto" | "manual"
    pub mode: String,
    pub script: String,
    pub script_path: String,
    pub detail: String,
}

pub fn shell_proxy_status() -> ShellProxyStatus {
    let hook = shell_hook_status();
    let env_ok = Path::new(ETC_ENV_PATH).is_file();
    let script = helpers().shell_exports;
    let mode = if hook.installed || Path::new(ETC_SHELL_PATH).is_file() {
        "auto"
    } else if env_ok {
        "manual"
    } else {
        "off"
    };
    let detail = match mode {
        "auto" => {
            if hook.targets.is_empty() {
                format!("Auto: {ETC_SHELL_PATH}")
            } else {
                format!("Auto: {}", hook.targets.join(", "))
            }
        }
        "manual" => format!("Manual: source {ETC_ENV_PATH}"),
        _ => "Off — shell proxy not configured".into(),
    };
    let script_path = if mode == "manual" {
        ETC_ENV_PATH.to_string()
    } else if mode == "auto" {
        ETC_SHELL_PATH.to_string()
    } else {
        ETC_ENV_PATH.to_string()
    };
    ShellProxyStatus {
        mode: mode.into(),
        script,
        script_path,
        detail,
    }
}

pub fn set_shell_proxy_mode(mode: &str) -> Result<String, String> {
    match mode {
        "off" => {
            // Best-effort: tear down auto hook and env (each may prompt once).
            let hook_msg = uninstall_shell_hook().unwrap_or_else(|e| e);
            let env_msg = if Path::new(ETC_ENV_PATH).exists() {
                remove_shell_env().unwrap_or_else(|e| e)
            } else {
                "env absent".into()
            };
            // If shell.sh gone but env remains after failed env remove, still try.
            let _ = elevated_remove_paths(&[
                ETC_ENV_PATH,
                ETC_SHELL_PATH,
                "/etc/tor-socks-gui/env",
                "/etc/tor-socks-gui/shell.sh",
            ]);
            crate::logs::append("Shell proxy mode: off");
            Ok(format!("Shell proxy off ({hook_msg}; {env_msg})"))
        }
        "auto" => {
            let msg = install_shell_hook()?;
            crate::logs::append("Shell proxy mode: auto");
            Ok(format!("Shell proxy auto. {msg}"))
        }
        "manual" => {
            // Remove auto hook pieces but keep/write env.
            let _ = uninstall_shell_hook();
            let path = write_shell_env()?;
            crate::logs::append("Shell proxy mode: manual");
            Ok(format!(
                "Shell proxy manual. {path}. Run: source {ETC_ENV_PATH}"
            ))
        }
        _ => Err(format!("Unknown shell proxy mode: {mode}")),
    }
}

pub fn configure_item(id: &str) -> Result<String, String> {
    match id {
        "tor_browser" => write_tor_browser_launcher(),
        "firefox" => write_firefox_user_js(),
        "chrome" => write_chrome_launcher(),
        "cursor" => configure_cursor(),
        "vscode" => configure_vscode(),
        "claude_code" => configure_claude_code(),
        "discord" => configure_discord(),
        "slack" => configure_slack(),
        _ => Err(format!("Unknown advanced item: {id}")),
    }
}

pub fn remove_item(id: &str) -> Result<String, String> {
    match id {
        "tor_browser" => remove_tor_browser_launcher(),
        "firefox" => remove_firefox_config(),
        "chrome" => remove_chrome_launcher(),
        "cursor" => remove_cursor(),
        "vscode" => remove_vscode(),
        "claude_code" => remove_claude_code(),
        "discord" => remove_discord(),
        "slack" => remove_slack(),
        _ => Err(format!("Cannot remove advanced item: {id}")),
    }
}

struct TorBrowserLauncherStatus {
    installed: bool,
    detail: String,
}

fn tor_browser_launcher_status() -> TorBrowserLauncherStatus {
    #[cfg(target_os = "macos")]
    {
        let app = macos_tor_browser_launcher_path();
        if app.is_dir() {
            return TorBrowserLauncherStatus {
                installed: true,
                detail: format!("Launcher at {}", app.display()),
            };
        }
        let found = find_tor_browser_app()
            .map(|p| format!("Tor Browser found at {}", p.display()))
            .unwrap_or_else(|| "Tor Browser.app not found yet".into());
        return TorBrowserLauncherStatus {
            installed: false,
            detail: format!("Not installed in ~/Applications ({found})"),
        };
    }
    #[cfg(target_os = "linux")]
    {
        let desktop = linux_tor_browser_launcher_desktop_path();
        if desktop.is_file() {
            return TorBrowserLauncherStatus {
                installed: true,
                detail: format!("App menu entry at {}", desktop.display()),
            };
        }
        let found = find_linux_tor_browser_start()
            .map(|p| format!("start-tor-browser at {}", p.display()))
            .unwrap_or_else(|| "Tor Browser not found yet".into());
        return TorBrowserLauncherStatus {
            installed: false,
            detail: format!("Not installed ({found})"),
        };
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        TorBrowserLauncherStatus {
            installed: false,
            detail: "Unsupported platform".into(),
        }
    }
}

fn tor_browser_env_exports(cookie: &Path) -> String {
    format!(
        "export TOR_SKIP_LAUNCH=1\n\
export TOR_SOCKS_HOST=\"{SOCKS_HOST}\"\n\
export TOR_SOCKS_PORT=\"{BROWSER_SOCKS_PORT}\"\n\
export TOR_CONTROL_HOST=\"{SOCKS_HOST}\"\n\
export TOR_CONTROL_PORT=\"{BROWSER_CONTROL_PORT}\"\n\
export TOR_CONTROL_COOKIE_AUTH_FILE=\"{}\"\n\
export TOR_NO_DISPLAY_NETWORK_SETTINGS=1\n",
        cookie.display()
    )
}

pub fn write_tor_browser_launcher() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return install_macos_tor_browser_launcher();
    }
    #[cfg(target_os = "linux")]
    {
        return install_linux_tor_browser_launcher();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Tor Browser launcher is not supported on this platform".into())
    }
}

pub fn remove_tor_browser_launcher() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        return remove_macos_tor_browser_launcher();
    }
    #[cfg(target_os = "linux")]
    {
        return remove_linux_tor_browser_launcher();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err("Tor Browser launcher remove is not supported on this platform".into())
    }
}

#[cfg(target_os = "macos")]
fn macos_tor_browser_launcher_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join("Applications")
        .join("Tor Browser via OnionGate.app")
}

#[cfg(target_os = "macos")]
fn find_tor_browser_app() -> Option<PathBuf> {
    let home = home_dir().ok()?;
    for candidate in [
        PathBuf::from("/Applications/Tor Browser.app"),
        home.join("Applications/Tor Browser.app"),
    ] {
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn tor_browser_macos_binary(app: &Path) -> Result<PathBuf, String> {
    for name in ["firefox", "Tor Browser"] {
        let bin = app.join("Contents/MacOS").join(name);
        if bin.is_file() {
            return Ok(bin);
        }
    }
    Err(format!(
        "Could not find Tor Browser binary inside {}",
        app.display()
    ))
}

#[cfg(target_os = "macos")]
fn install_macos_tor_browser_launcher() -> Result<String, String> {
    let tb_app = find_tor_browser_app().ok_or_else(|| {
        "Tor Browser.app not found in /Applications or ~/Applications. Install Tor Browser first."
            .to_string()
    })?;
    let tb_bin = tor_browser_macos_binary(&tb_app)?;
    let cookie = control_cookie_path()?;

    let app = macos_tor_browser_launcher_path();
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&macos).map_err(|e| format!("Failed to create app bundle: {e}"))?;
    fs::create_dir_all(&resources).map_err(|e| format!("Failed to create Resources: {e}"))?;

    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Tor Browser via OnionGate</string>
  <key>CFBundleIdentifier</key>
  <string>com.openhat.oniongate.tor-browser</string>
  <key>CFBundleName</key>
  <string>Tor Browser via OnionGate</string>
  <key>CFBundleDisplayName</key>
  <string>Tor Browser via OnionGate</string>
  <key>CFBundleIconFile</key>
  <string>app</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>11.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
"#;
    fs::write(contents.join("Info.plist"), plist)
        .map_err(|e| format!("Failed to write Info.plist: {e}"))?;

    let env = tor_browser_env_exports(&cookie);
    let exe = macos.join("Tor Browser via OnionGate");
    let script = format!(
        "#!/bin/zsh\n\
# Generated by OnionGate — skip TB's Tor, use OnionGate's SOCKS/control.\n\
# Do not open stock Tor Browser while OnionGate is Connected (9150/9151 are occupied).\n\
{env}\
if ! nc -z -w 1 \"{SOCKS_HOST}\" \"{BROWSER_SOCKS_PORT}\" >/dev/null 2>&1; then\n\
  osascript -e 'display alert \"OnionGate is not Connected\" message \"Connect OnionGate first, then open this launcher. Tor Browser will use OnionGate Tor on port {BROWSER_SOCKS_PORT}.\" as critical' >/dev/null 2>&1 || true\n\
  exit 1\n\
fi\n\
if [ ! -f \"$TOR_CONTROL_COOKIE_AUTH_FILE\" ]; then\n\
  osascript -e 'display alert \"OnionGate Tor cookie missing\" message \"Connect OnionGate so managed Tor writes its control cookie, then retry.\" as critical' >/dev/null 2>&1 || true\n\
  exit 1\n\
fi\n\
exec \"{}\" \"$@\"\n",
        tb_bin.display()
    );
    fs::write(&exe, script).map_err(|e| format!("Failed to write launcher: {e}"))?;
    chmod_exec(&exe)?;

    let icns_src = tb_app.join("Contents/Resources/firefox.icns");
    let icns_alt = tb_app.join("Contents/Resources/app.icns");
    let icns_dst = resources.join("app.icns");
    if icns_src.is_file() {
        let _ = fs::copy(&icns_src, &icns_dst);
    } else if icns_alt.is_file() {
        let _ = fs::copy(&icns_alt, &icns_dst);
    }

    let helper = app_dir()?.join("launch-tor-browser-oniongate.sh");
    fs::write(
        &helper,
        format!("#!/bin/zsh\nexec open -a \"{}\"\n", app.display()),
    )
    .map_err(|e| format!("Failed to write helper script: {e}"))?;
    chmod_exec(&helper)?;

    let _ = Command::new("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister")
        .args(["-f", &app.display().to_string()])
        .status();

    crate::logs::append(format!(
        "Installed Tor Browser via OnionGate launcher at {}",
        app.display()
    ));
    Ok(format!(
        "Installed launcher at {}. Connect OnionGate, then open it instead of stock Tor Browser.",
        app.display()
    ))
}

#[cfg(target_os = "macos")]
fn remove_macos_tor_browser_launcher() -> Result<String, String> {
    let app = macos_tor_browser_launcher_path();
    if app.is_dir() {
        fs::remove_dir_all(&app).map_err(|e| format!("Failed to remove {}: {e}", app.display()))?;
    }
    let helper = app_dir()?.join("launch-tor-browser-oniongate.sh");
    if helper.exists() {
        let _ = fs::remove_file(helper);
    }
    crate::logs::append("Removed Tor Browser via OnionGate launcher");
    Ok("Removed Tor Browser via OnionGate from ~/Applications".into())
}

#[cfg(target_os = "linux")]
fn linux_tor_browser_launcher_desktop_path() -> PathBuf {
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
        .join(".local/share/applications/tor-browser-oniongate.desktop")
}

#[cfg(target_os = "linux")]
fn find_linux_tor_browser_start() -> Option<PathBuf> {
    let home = home_dir().ok()?;
    let candidates = [
        home.join("tor-browser/Browser/start-tor-browser"),
        home.join("tor-browser_en-US/Browser/start-tor-browser"),
        home.join(".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser"),
        PathBuf::from("/usr/bin/torbrowser"),
        PathBuf::from("/usr/bin/tor-browser"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(target_os = "linux")]
fn install_linux_tor_browser_launcher() -> Result<String, String> {
    let start = find_linux_tor_browser_start().ok_or_else(|| {
        "Tor Browser not found. Install it (e.g. extract under ~/tor-browser) first.".to_string()
    })?;
    let cookie = control_cookie_path()?;
    let wrapper = app_dir()?.join("launch-tor-browser-oniongate.sh");
    let env = tor_browser_env_exports(&cookie);
    let script = format!(
        "#!/bin/bash\n\
# Generated by OnionGate — external Tor for Tor Browser.\n\
{env}\
if ! (command -v nc >/dev/null && nc -z -w 1 \"{SOCKS_HOST}\" \"{BROWSER_SOCKS_PORT}\") >/dev/null 2>&1; then\n\
  echo \"OnionGate is not Connected (nothing on {SOCKS_HOST}:{BROWSER_SOCKS_PORT})\" >&2\n\
  exit 1\n\
fi\n\
if [ ! -f \"$TOR_CONTROL_COOKIE_AUTH_FILE\" ]; then\n\
  echo \"OnionGate Tor control cookie missing — Connect OnionGate first\" >&2\n\
  exit 1\n\
fi\n\
exec \"{}\" \"$@\"\n",
        start.display()
    );
    fs::write(&wrapper, &script).map_err(|e| format!("Failed to write launcher: {e}"))?;
    chmod_exec(&wrapper)?;

    let desktop = linux_tor_browser_launcher_desktop_path();
    if let Some(parent) = desktop.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create applications dir: {e}"))?;
    }
    let desktop_body = format!(
        "[Desktop Entry]\n\
Type=Application\n\
Name=Tor Browser via OnionGate\n\
Comment=Tor Browser using OnionGate-managed Tor (no stacked Tor)\n\
Exec={}\n\
Terminal=false\n\
Categories=Network;WebBrowser;\n\
",
        wrapper.display()
    );
    fs::write(&desktop, desktop_body).map_err(|e| format!("Failed to write desktop entry: {e}"))?;

    crate::logs::append(format!(
        "Installed Tor Browser via OnionGate launcher at {}",
        desktop.display()
    ));
    Ok(format!(
        "Installed Tor Browser via OnionGate in your app menu ({})",
        desktop.display()
    ))
}

#[cfg(target_os = "linux")]
fn remove_linux_tor_browser_launcher() -> Result<String, String> {
    let desktop = linux_tor_browser_launcher_desktop_path();
    if desktop.is_file() {
        fs::remove_file(&desktop)
            .map_err(|e| format!("Failed to remove {}: {e}", desktop.display()))?;
    }
    let wrapper = app_dir()?.join("launch-tor-browser-oniongate.sh");
    if wrapper.exists() {
        let _ = fs::remove_file(wrapper);
    }
    crate::logs::append("Removed Tor Browser via OnionGate launcher");
    Ok("Removed Tor Browser via OnionGate from your app menu".into())
}
