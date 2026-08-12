use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use tokio::process::{Child, Command};
use which::which;

pub const SOCKS_HOST: &str = "127.0.0.1";
pub const SOCKS_PORT: u16 = 9050;
pub const ISOLATED_SOCKS_PORT: u16 = 9060;
/// Tor Browser's default SOCKS port. Bound with IsolateSOCKSAuth so TB keeps
/// per-first-party stream isolation when it uses OnionGate's Tor (Whonix-style).
pub const BROWSER_SOCKS_PORT: u16 = 9150;
pub const CONTROL_PORT: u16 = 9051;
/// Tor Browser's default control port (same cookie as CONTROL_PORT).
pub const BROWSER_CONTROL_PORT: u16 = 9151;
pub const DNS_PORT: u16 = 9053;

/// Path to the managed Tor control cookie (for Tor Browser / external controllers).
pub fn control_cookie_path() -> Result<PathBuf, String> {
    Ok(ensure_data_dir()?.join("tor-data").join("control_auth_cookie"))
}

fn host_triple() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return "aarch64-apple-darwin";
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return "x86_64-apple-darwin";
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return "x86_64-unknown-linux-gnu";
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return "aarch64-unknown-linux-gnu";
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return "x86_64-pc-windows-msvc";
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    {
        "unknown"
    }
}

/// Directories / files that may contain app-bundled runtimes (preferred over brew).
fn bundled_binary_candidates(name: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let triple = host_triple();
    let platform_name = if cfg!(target_os = "windows") {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let with_triple = if cfg!(target_os = "windows") {
        format!("{name}-{triple}.exe")
    } else {
        format!("{name}-{triple}")
    };

    let push_name = |dir: &Path, acc: &mut Vec<PathBuf>| {
        acc.push(dir.join(&platform_name));
        acc.push(dir.join(&with_triple));
    };

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            push_name(exe_dir, &mut out);
            // Tauri externalBin sometimes keeps a binaries/ prefix next to the exe.
            push_name(&exe_dir.join("binaries"), &mut out);
            // macOS .app: Contents/MacOS -> Contents/Resources/runtime/...
            if let Some(contents) = exe_dir.parent() {
                let res = contents.join("Resources");
                push_name(&res.join("binaries"), &mut out);
                push_name(&res.join("runtime").join("bin"), &mut out);
                if name == "tor" {
                    out.push(res.join("runtime").join("tor").join(&platform_name));
                } else {
                    out.push(
                        res.join("runtime")
                            .join("tor")
                            .join("pluggable_transports")
                            .join(name),
                    );
                }
            }
        }
    }

    // Dev / cargo: prefer the expert-bundle layout so Tor finds colocated dylibs.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let runtime = manifest.join("resources").join("runtime");
    if name == "tor" {
        out.insert(0, runtime.join("tor").join(&platform_name));
    } else {
        out.insert(
            0,
            runtime.join("tor").join("pluggable_transports").join(name),
        );
        out.insert(0, runtime.join("bin").join(name));
    }
    push_name(&manifest.join("binaries"), &mut out);
    push_name(&runtime.join("bin"), &mut out);

    out
}

pub fn find_tor_binary() -> Option<PathBuf> {
    static CACHED: Mutex<Option<PathBuf>> = Mutex::new(None);
    if let Ok(guard) = CACHED.lock() {
        if let Some(path) = guard.as_ref() {
            if is_executable(path) {
                return Some(path.clone());
            }
        }
    }
    let found = find_tor_binary_scan();
    if let Ok(mut guard) = CACHED.lock() {
        *guard = found.clone();
    }
    found
}

fn find_tor_binary_scan() -> Option<PathBuf> {
    // Always prefer expert-bundle tor (dylibs beside the binary) over a bare sidecar copy.
    for candidate in bundled_binary_candidates("tor") {
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    if let Ok(path) = which("tor") {
        return Some(path);
    }
    for dir in candidate_bin_dirs() {
        let candidate = dir.join("tor");
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// GUI apps on macOS often inherit a minimal PATH that omits Homebrew.
fn candidate_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        for part in path.split(':') {
            if !part.is_empty() {
                dirs.push(PathBuf::from(part));
            }
        }
    }
    for dir in [
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    ] {
        let p = PathBuf::from(dir);
        if !dirs.iter().any(|d| d == &p) {
            dirs.push(p);
        }
    }
    dirs
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .map(|meta| meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Prefer app-bundled binaries, then PATH / Homebrew.
pub(crate) fn find_binary(name: &str) -> Option<PathBuf> {
    for candidate in bundled_binary_candidates(name) {
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    if let Ok(path) = which(name) {
        return Some(path);
    }
    for dir in candidate_bin_dirs() {
        let candidate = dir.join(if cfg!(target_os = "windows") {
            format!("{name}.exe")
        } else {
            name.to_string()
        });
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Bundled Tor expert-bundle data dir (geoip, etc.), if present.
pub fn bundled_runtime_dir() -> Option<PathBuf> {
    let mut bases = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            if let Some(contents) = exe_dir.parent() {
                bases.push(contents.join("Resources").join("runtime"));
            }
            bases.push(exe_dir.join("resources").join("runtime"));
        }
    }
    bases.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("runtime"),
    );
    bases.into_iter().find(|p| {
        p.join("tor")
            .join(if cfg!(target_os = "windows") {
                "tor.exe"
            } else {
                "tor"
            })
            .is_file()
            || p.join("data").join("geoip").is_file()
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn apply_native_library_path(cmd: &mut Command, binary: &Path) {
    let Some(dir) = binary.parent() else {
        return;
    };
    #[cfg(target_os = "macos")]
    {
        let key = "DYLD_LIBRARY_PATH";
        let mut value = dir.display().to_string();
        if let Ok(existing) = std::env::var(key) {
            value = format!("{value}:{existing}");
        }
        cmd.env(key, value);
    }
    #[cfg(target_os = "linux")]
    {
        let key = "LD_LIBRARY_PATH";
        let mut value = dir.display().to_string();
        if let Ok(existing) = std::env::var(key) {
            value = format!("{value}:{existing}");
        }
        cmd.env(key, value);
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn apply_native_library_path(_cmd: &mut Command, _binary: &Path) {}

fn find_brew_binary() -> Option<PathBuf> {
    find_binary("brew")
}

fn port_reachable(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("{SOCKS_HOST}:{port}")
            .parse()
            .expect("valid socket addr"),
        Duration::from_millis(400),
    )
    .is_ok()
}

pub fn socks_reachable() -> bool {
    port_reachable(SOCKS_PORT)
}

pub fn control_reachable() -> bool {
    port_reachable(CONTROL_PORT)
}

/// Probe Tor DNSPort with a tiny UDP DNS query (DNSPort is UDP, not TCP).
pub fn dns_reachable() -> bool {
    use std::net::UdpSocket;

    let Ok(sock) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(500)));

    // Minimal DNS query for "." (root) — any response means DNSPort is alive.
    let query: [u8; 17] = [
        0x12, 0x34, // id
        0x01, 0x00, // standard query
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
        0x00, // root label
        0x00, 0x01, // type A
        0x00, 0x01, // class IN
    ];
    let addr = format!("{SOCKS_HOST}:{DNS_PORT}");
    if sock.send_to(&query, &addr).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    sock.recv_from(&mut buf).is_ok()
}

pub fn ensure_data_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "Could not resolve local data directory".to_string())?
        .join("tor-socks-gui");
    fs::create_dir_all(&base).map_err(|e| format!("Failed to create data dir: {e}"))?;
    let data_dir = base.join("tor-data");
    fs::create_dir_all(&data_dir).map_err(|e| format!("Failed to create tor data dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Failed to protect data dir: {e}"))?;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Failed to protect Tor data dir: {e}"))?;
    }
    Ok(base)
}

fn write_managed_torrc(app_dir: &Path) -> Result<PathBuf, String> {
    let data_dir = app_dir.join("tor-data");
    let torrc = app_dir.join("torrc");
    let settings = crate::settings::load();
    let log_path = crate::logs::ensure_log_file()?;
    let dns_block = if settings.remote_dns {
        format!("DNSPort {SOCKS_HOST}:{DNS_PORT}\nAutomapHostsOnResolve 1\n")
    } else {
        String::new()
    };

    let mut extra = String::new();

    let exit = settings.exit_country.trim();
    if exit.len() == 2 {
        extra.push_str(&format!("ExitNodes {{{exit}}}\nStrictNodes 1\n"));
    } else if !settings.exit_nodes_fp.trim().is_empty() {
        extra.push_str(&format!(
            "ExitNodes {}\nStrictNodes 1\n",
            settings.exit_nodes_fp.trim()
        ));
    }
    if !settings.entry_nodes.trim().is_empty() {
        extra.push_str(&format!("EntryNodes {}\n", settings.entry_nodes.trim()));
    }
    if !settings.middle_nodes.trim().is_empty() {
        extra.push_str(&format!("MiddleNodes {}\n", settings.middle_nodes.trim()));
    }

    let active_bridge_lines = if settings.last_connect_strategy == "builtin:snowflake" {
        super::bridges::bundled_defaults("snowflake")
    } else {
        settings.bridge_lines.clone()
    };
    if settings.bridges_enabled && !active_bridge_lines.is_empty() {
        let needed = super::pt::transports_from_bridge_lines(&active_bridge_lines);
        if !needed.is_empty() {
            let plugins = super::pt::client_transport_plugin_lines(&needed)?;
            for line in plugins {
                extra.push_str(&line);
                extra.push('\n');
            }
        }
        extra.push_str("UseBridges 1\n");
        for line in &active_bridge_lines {
            extra.push_str(line);
            extra.push('\n');
        }
    }

    if let Some(runtime) = bundled_runtime_dir() {
        let geoip = runtime.join("data").join("geoip");
        let geoip6 = runtime.join("data").join("geoip6");
        if geoip.is_file() {
            extra.push_str(&format!("GeoIPFile {}\n", geoip.display()));
        }
        if geoip6.is_file() {
            extra.push_str(&format!("GeoIPv6File {}\n", geoip6.display()));
        }
    }

    // Permanent Onion Host sites. Tor owns the keys in these directories; we
    // only point at them.
    extra.push_str(&crate::onion_service::persistent::torrc_block());

    let contents = format!(
        "\
SocksPort {SOCKS_HOST}:{SOCKS_PORT}
SocksPort {SOCKS_HOST}:{ISOLATED_SOCKS_PORT} IsolateSOCKSAuth
SocksPort {SOCKS_HOST}:{BROWSER_SOCKS_PORT} IsolateSOCKSAuth
ControlPort {SOCKS_HOST}:{CONTROL_PORT}
ControlPort {SOCKS_HOST}:{BROWSER_CONTROL_PORT}
CookieAuthentication 1
Log {} file {}
{dns_block}{extra}DataDirectory {}
",
        settings.log_level,
        log_path.display(),
        data_dir.display()
    );
    fs::write(&torrc, contents).map_err(|e| format!("Failed to write torrc: {e}"))?;
    Ok(torrc)
}

/// Regenerate torrc in place so a running Tor can pick changes up on reload.
pub fn rewrite_torrc() -> Result<PathBuf, String> {
    let app_dir = ensure_data_dir()?;
    write_managed_torrc(&app_dir)
}

async fn stop_system_tor_service() {
    #[cfg(target_os = "macos")]
    {
        if let Some(brew) = find_brew_binary() {
            let _ = Command::new(&brew)
                .args(["services", "stop", "tor"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if which("systemctl").is_ok() {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", "tor"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;
            let _ = Command::new("systemctl")
                .args(["stop", "tor"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("taskkill.exe")
            .args(["/IM", "tor.exe", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }

    // Give the OS a moment to release SOCKS/control ports.
    for _ in 0..20 {
        if !socks_reachable() && !control_reachable() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn spawn_managed_tor(managed: &mut Option<Child>) -> Result<(), String> {
    let tor_bin = find_tor_binary().ok_or_else(|| {
        "tor binary not found. Run `npm run deps` (or scripts/download-deps.sh) before building, or install tor on PATH.".to_string()
    })?;

    if let Some(child) = managed.as_mut() {
        if child.try_wait().map_err(|e| e.to_string())?.is_none() {
            // Already have a managed process; wait for ports.
            for _ in 0..40 {
                if socks_reachable() && control_reachable() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    let app_dir = ensure_data_dir()?;
    let torrc = write_managed_torrc(&app_dir)?;

    crate::logs::append(format!(
        "Spawning managed Tor ({}) with {}",
        tor_bin.display(),
        torrc.display()
    ));

    let mut cmd = Command::new(&tor_bin);
    apply_native_library_path(&mut cmd, &tor_bin);
    let child = cmd
        .arg("-f")
        .arg(&torrc)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn tor: {e}"))?;

    *managed = Some(child);

    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if socks_reachable() && control_reachable() {
            return Ok(());
        }
        if let Some(child) = managed.as_mut() {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!(
                    "Managed Tor exited early ({status}). Another tor may still own port 9050 — try Stop Tor, then Start Tor."
                ));
            }
        }
    }

    if socks_reachable() && !control_reachable() {
        return Err(
            "Tor SOCKS is up but ControlPort 9051 is not. Stop other Tor instances and Start Tor again."
                .into(),
        );
    }

    Err("Tor started but SOCKS/control ports did not become ready".into())
}

async fn apply_remote_dns_if_needed() -> Result<(), String> {
    let remote_dns = crate::settings::load().remote_dns;
    if !control_reachable() {
        return Ok(());
    }
    // Best-effort: live SETCONF so brew/managed Tor picks up DNSPort without full restart.
    let _ = super::control::apply_remote_dns(remote_dns).await;
    Ok(())
}

/// Ensure Tor is up with both SOCKS (9050) and ControlPort (9051).
/// Homebrew/system Tor often exposes SOCKS only; in that case we stop it and
/// start an app-managed Tor with ControlPort enabled for New Identity.
pub async fn ensure_tor_with_control(managed: &mut Option<Child>) -> Result<String, String> {
    if socks_reachable() && control_reachable() {
        apply_remote_dns_if_needed().await?;
        crate::logs::append("Tor already available (SOCKS + ControlPort)");
        return Ok("Tor SOCKS and ControlPort already available".into());
    }

    if socks_reachable() && !control_reachable() {
        // Typical brew/apt default: SOCKS without ControlPort.
        crate::logs::append("System Tor has SOCKS but no ControlPort — migrating to managed Tor");
        stop_system_tor_service().await;
        if let Some(mut child) = managed.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        // If something else still holds 9050, we cannot bind.
        if socks_reachable() {
            return Err(
                "Another Tor is using 9050 without ControlPort 9051. Run `brew services stop tor` (or stop your system tor), then Start Tor in the app."
                    .into(),
            );
        }
        spawn_managed_tor(managed).await?;
        apply_remote_dns_if_needed().await?;
        crate::logs::append("Managed Tor started (replaced system Tor)");
        return Ok(
            "Replaced system Tor with app-managed Tor (ControlPort 9051 enabled for New Identity)"
                .into(),
        );
    }

    // Nothing listening — prefer managed so New Identity works out of the box.
    spawn_managed_tor(managed).await?;
    apply_remote_dns_if_needed().await?;
    crate::logs::append("Managed Tor started");
    Ok("Started managed Tor with SOCKS 9050 and ControlPort 9051".into())
}

pub async fn start_tor(managed: &mut Option<Child>) -> Result<String, String> {
    ensure_tor_with_control(managed).await
}

/// Restart managed Tor so torrc changes (DNS, bridges, exit pin) take effect.
pub async fn restart_managed(managed: &mut Option<Child>) -> Result<String, String> {
    if let Some(mut child) = managed.take() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    } else {
        stop_system_tor_service().await;
    }
    for _ in 0..20 {
        if !socks_reachable() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    spawn_managed_tor(managed).await?;
    apply_remote_dns_if_needed().await?;
    Ok("Restarted Tor with updated configuration".into())
}

/// Restart managed Tor so torrc DNSPort changes take effect if SETCONF is unavailable.
pub async fn restart_managed_for_dns(managed: &mut Option<Child>) -> Result<String, String> {
    restart_managed(managed).await?;
    Ok("Restarted Tor with updated DNS settings".into())
}

pub async fn stop_tor(managed: &mut Option<Child>) -> Result<String, String> {
    let mut stopped = Vec::new();

    if let Some(mut child) = managed.take() {
        // Kill the process group-ish: tor first, then wait.
        let _ = child.kill().await;
        let _ = child.wait().await;
        stopped.push("managed process");
    }

    stop_system_tor_service().await;

    // Always attempt pkill for any leftover tor on our ports (brew/migrated).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let _ = Command::new("pkill")
            .args(["-x", "tor"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("taskkill.exe")
            .args(["/IM", "tor.exe", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    for _ in 0..20 {
        if !socks_reachable() && !control_reachable() && !dns_reachable() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    if socks_reachable() || control_reachable() {
        return Err(
            "Tor is still running after stop. Try `brew services stop tor` / `pkill -x tor`, then Disconnect again."
                .into(),
        );
    }

    if stopped.is_empty() {
        Ok("Stopped Tor".into())
    } else {
        Ok(format!("Stopped Tor ({})", stopped.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_torrc_binds_tor_browser_default_ports() {
        let app_dir = ensure_data_dir().expect("data dir");
        let torrc = write_managed_torrc(&app_dir).expect("write torrc");
        let text = fs::read_to_string(&torrc).expect("read torrc");
        assert!(
            text.contains(&format!("SocksPort {SOCKS_HOST}:{BROWSER_SOCKS_PORT} IsolateSOCKSAuth")),
            "Tor Browser SOCKS must keep IsolateSOCKSAuth: {text}"
        );
        assert!(
            text.contains(&format!("ControlPort {SOCKS_HOST}:{BROWSER_CONTROL_PORT}")),
            "Tor Browser control port missing: {text}"
        );
    }
}
