//! OnionGate privileged helper daemon.
//!
//! Runs with elevated privileges (installed once via launchd/systemd/SCM). It
//! performs ONLY the fixed, typed operations in `oniongate_lib::helper` —
//! never arbitrary shell — and the privileged rulesets are baked in here, not
//! supplied by the client. On Unix the connecting peer is authenticated by uid;
//! on macOS a signed helper also requires a matching code signature.
//!
//! NOTE (pre-ship hardening): this binary links the app library only for the
//! shared protocol types; before release it should be split into a minimal
//! crate so the privileged daemon does not carry the GUI dependency tree.

#[cfg(unix)]
fn main() {
    unix_daemon::run();
}

#[cfg(windows)]
fn main() {
    // Enter the Windows service control dispatcher; falls back to a console
    // run (for debugging) if not launched by the SCM.
    if windows_daemon::run_as_service().is_err() {
        windows_daemon::run_console();
    }
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("oniongate-helper is not supported on this platform");
    std::process::exit(1);
}

// ============================ Unix (macOS/Linux) ============================

#[cfg(unix)]
mod unix_daemon {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    use oniongate_lib::helper::{decode, encode, HelperRequest, HelperResponse, SOCKET_PATH};

    #[cfg(target_os = "macos")]
    extern "C" {
        fn getpeereid(fd: i32, euid: *mut u32, egid: *mut u32) -> i32;
    }

    #[cfg(target_os = "macos")]
    fn peer_uid(stream: &UnixStream) -> Option<u32> {
        let mut euid: u32 = u32::MAX;
        let mut egid: u32 = u32::MAX;
        let rc = unsafe { getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
        (rc == 0).then_some(euid)
    }

    #[cfg(target_os = "linux")]
    fn peer_uid(stream: &UnixStream) -> Option<u32> {
        let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if rc != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
            return None;
        }
        Some(unsafe { credentials.assume_init() }.uid)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn peer_uid(_stream: &UnixStream) -> Option<u32> {
        None
    }

    fn peer_identity_ok(stream: &UnixStream) -> bool {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = stream;
            return true;
        }
        #[cfg(target_os = "macos")]
        {
            let helper_path = std::env::current_exe().ok();
            let helper_signed = helper_path
                .as_deref()
                .and_then(oniongate_lib::helper::identity::codesign_info)
                .is_some();
            let Some(pid) = peer_pid(stream) else {
                return !helper_signed;
            };
            let Some(path) = pid_executable(pid) else {
                return !helper_signed;
            };
            match oniongate_lib::helper::identity::codesign_info(&path) {
                Some(info)
                    if oniongate_lib::helper::identity::app_identity_allowed(
                        &path,
                        &info.identifier,
                    ) =>
                {
                    if let (Some(helper), Some(peer_team)) = (
                        helper_path
                            .as_deref()
                            .and_then(oniongate_lib::helper::identity::codesign_info),
                        info.team.as_ref(),
                    ) {
                        if let Some(helper_team) = helper.team.as_ref() {
                            return helper_team == peer_team;
                        }
                    }
                    true
                }
                Some(_) => false,
                None => !helper_signed,
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn peer_pid(stream: &UnixStream) -> Option<u32> {
        const SOL_LOCAL: libc::c_int = 0;
        const LOCAL_PEERPID: libc::c_int = 0x002;
        let mut pid: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                SOL_LOCAL,
                LOCAL_PEERPID,
                &mut pid as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        (rc == 0 && pid > 1).then_some(pid as u32)
    }

    #[cfg(target_os = "macos")]
    fn pid_executable(pid: u32) -> Option<std::path::PathBuf> {
        let mut buf = [0u8; 4096];
        let n =
            unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        let path = std::str::from_utf8(&buf[..n as usize]).ok()?;
        Some(std::path::PathBuf::from(path))
    }

    fn allow_uid_from_args() -> Option<u32> {
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--allow-uid" {
                if let Some(uid) = args.next().and_then(|v| v.parse::<u32>().ok()) {
                    return Some(uid);
                }
            }
        }
        None
    }

    fn console_uid() -> Option<u32> {
        fs::metadata("/dev/console").ok().map(|m| m.uid())
    }

    /// Console owner is read per connection: a LaunchDaemon started at boot
    /// would otherwise snapshot uid 0 and reject the logged-in user forever.
    fn allowed_uid(override_uid: Option<u32>) -> Option<u32> {
        override_uid.or_else(console_uid)
    }

    pub fn run() {
        let allow_override = allow_uid_from_args();
        eprintln!(
            "oniongate-helper starting; allow-uid override = {allow_override:?}, console uid = {:?}",
            console_uid()
        );
        let _ = fs::remove_file(SOCKET_PATH);
        let listener = match UnixListener::bind(SOCKET_PATH) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("failed to bind {SOCKET_PATH}: {e}");
                std::process::exit(1);
            }
        };
        // World-connectable socket; the peer-uid check below is the real gate.
        let _ = fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o666));

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => handle(stream, allow_override),
                Err(e) => eprintln!("accept error: {e}"),
            }
        }
    }

    fn handle(stream: UnixStream, allow_override: Option<u32>) {
        let allow = allowed_uid(allow_override);
        let uid_ok = match (peer_uid(&stream), allow) {
            (Some(p), Some(a)) => p == a,
            (Some(p), None) => p != 0, // require a non-root user if console unknown
            _ => false,
        };
        if !uid_ok || !peer_identity_ok(&stream) {
            let _ = respond(&stream, &HelperResponse::err("unauthorized peer"));
            return;
        }
        let mut reader = match stream.try_clone() {
            Ok(s) => BufReader::new(s),
            Err(_) => return,
        };
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            return;
        }
        let response = match decode::<HelperRequest>(&line) {
            Ok(req) => dispatch(req, peer_executable(&stream)),
            Err(e) => HelperResponse::err(format!("bad request: {e}")),
        };
        let _ = respond(&stream, &response);
    }

    /// Kernel-attested path of the connecting process. Only used to locate files
    /// that belong to the already-authenticated app (never to exec anything the
    /// client named), so it is not a client-supplied path.
    #[cfg(target_os = "macos")]
    fn peer_executable(stream: &UnixStream) -> Option<std::path::PathBuf> {
        peer_pid(stream).and_then(pid_executable)
    }

    #[cfg(not(target_os = "macos"))]
    fn peer_executable(_stream: &UnixStream) -> Option<std::path::PathBuf> {
        None
    }

    fn respond(mut stream: &UnixStream, response: &HelperResponse) -> std::io::Result<()> {
        let bytes = encode(response)
            .unwrap_or_else(|_| b"{\"ok\":false,\"message\":\"encode error\"}\n".to_vec());
        stream.write_all(&bytes)?;
        stream.flush()
    }

    fn dispatch(req: HelperRequest, peer_exe: Option<std::path::PathBuf>) -> HelperResponse {
        let _ = &peer_exe;
        match req {
            HelperRequest::Ping => HelperResponse::ok("pong"),
            HelperRequest::KillSwitchEnable {
                tcp_endpoints,
                tcp_exceptions,
                allow_lan,
            } => super::executor::kill_switch_enable(&tcp_endpoints, &tcp_exceptions, allow_lan),
            HelperRequest::KillSwitchDisable => super::executor::kill_switch_disable(),
            HelperRequest::NetworkLockEnable {
                tor_path,
                tcp_endpoints,
                tcp_exceptions,
                allow_lan,
            } => super::executor::network_lock_enable(
                &tor_path,
                &tcp_endpoints,
                &tcp_exceptions,
                allow_lan,
            ),
            HelperRequest::NetworkLockDisable => super::executor::network_lock_disable(),
            HelperRequest::DenyLogHarvest => super::executor::deny_log_harvest(),
            HelperRequest::TerminatePid { pid } => {
                oniongate_lib::helper::execute_terminate_pid(pid)
            }
            HelperRequest::StopApplication { pid } => {
                oniongate_lib::helper::execute_stop_application(pid)
            }
            HelperRequest::TunStart { spec } => {
                super::executor::tun_start(&spec, peer_exe.as_deref())
            }
            HelperRequest::TunStop => super::executor::tun_stop(),
            HelperRequest::MacRandomize => super::executor::mac_randomize(),
            HelperRequest::WifiSetPower { on } => super::executor::wifi_set_power(on),
            HelperRequest::SocksEnable => oniongate_lib::helper::execute_socks_enable(),
            HelperRequest::SocksDisable => oniongate_lib::helper::execute_socks_disable(),
        }
    }
}

// ---------------------- Unix privileged executors ----------------------

#[cfg(target_os = "macos")]
mod executor {
    use oniongate_lib::helper::{HelperResponse, TunSpec};
    use oniongate_lib::tun::{HELPER_TUN_CONFIG, HELPER_TUN_DIR, HELPER_TUN_LOG, PINNED_SINGBOX};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const PFCTL: &str = "/sbin/pfctl";
    const NETWORKSETUP: &str = "/usr/sbin/networksetup";
    const IFCONFIG: &str = "/sbin/ifconfig";
    const PF_ANCHOR: &str = "com.apple/oniongate.ks";
    const PF_LOCK_ANCHOR: &str = "com.apple/oniongate.lock";
    const LEGACY_PF_ANCHOR: &str = "tor.socks.gui";
    const LEGACY_PF_LOCK_ANCHOR: &str = "tor.socks.gui.lock";
    const PF_RULES_PATH: &str = "/var/run/oniongate-pf.conf";
    const PF_LOCK_RULES_PATH: &str = "/var/run/oniongate-pf-lock.conf";

    fn synthesize(
        endpoints: &[String],
        exceptions: &[String],
        allow_lan: bool,
    ) -> Result<String, String> {
        if endpoints.is_empty() {
            if !exceptions.is_empty() {
                return Err("exceptions require Tor endpoints".into());
            }
            return Ok(oniongate_lib::firewall::strict::pf_udp_ipv6_rules());
        }
        let eps = oniongate_lib::firewall::strict::parse_ip_list(
            endpoints,
            oniongate_lib::firewall::strict::MAX_ENDPOINTS,
        )?;
        let exs = oniongate_lib::firewall::strict::parse_ip_list(
            exceptions,
            oniongate_lib::firewall::strict::MAX_EXCEPTIONS,
        )?;
        Ok(oniongate_lib::firewall::strict::pf_strict_rules(
            &eps, &exs, allow_lan,
        ))
    }

    fn ensure_pf_enabled(strict: bool) -> Result<(), String> {
        let out = Command::new(PFCTL).arg("-e").output();
        match out {
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                if out.status.success() || err.contains("already enabled") {
                    Ok(())
                } else if strict {
                    Err(format!("pfctl -e failed: {err}"))
                } else {
                    Ok(())
                }
            }
            Err(e) if strict => Err(format!("pfctl -e error: {e}")),
            Err(_) => Ok(()),
        }
    }

    fn ensure_pflog() {
        let _ = Command::new("/sbin/ifconfig")
            .args(["pflog0", "create"])
            .status();
        let _ = Command::new("/sbin/ifconfig")
            .args(["pflog0", "up"])
            .status();
        let _ = Command::new("/usr/sbin/sysctl")
            .args(["-w", "net.inet.ip.forwarding=0"])
            .status();
        let _ = Command::new("/usr/sbin/sysctl")
            .args(["-w", "net.inet6.ip6.forwarding=0"])
            .status();
    }

    fn load_anchor(anchor: &str, path: &str, rules: &str, strict: bool) -> HelperResponse {
        if !Path::new(PFCTL).exists() {
            return HelperResponse::err("pfctl not found");
        }
        if let Err(e) = fs::write(path, rules) {
            return HelperResponse::err(format!("write pf rules: {e}"));
        }
        match Command::new(PFCTL)
            .args(["-a", anchor, "-f", path])
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                let err = err.trim();
                return HelperResponse::err(if err.is_empty() {
                    format!("pfctl load failed: {}", out.status)
                } else {
                    format!("pfctl load failed: {err}")
                });
            }
            Err(e) => return HelperResponse::err(format!("pfctl load error: {e}")),
        }
        let _ = Command::new(PFCTL)
            .args(["-a", anchor, "-F", "states"])
            .status();
        if let Err(e) = ensure_pf_enabled(strict) {
            return HelperResponse::err(e);
        }
        if strict {
            ensure_pflog();
        }
        HelperResponse::ok("pf rules loaded")
    }

    fn flush_anchor(anchor: &str) -> HelperResponse {
        if !Path::new(PFCTL).exists() {
            return HelperResponse::err("pfctl not found");
        }
        match Command::new(PFCTL)
            .args(["-a", anchor, "-F", "all"])
            .status()
        {
            Ok(s) if s.success() => HelperResponse::ok("pf anchor flushed"),
            Ok(s) => HelperResponse::err(format!("pfctl flush failed: {s}")),
            Err(e) => HelperResponse::err(format!("pfctl flush error: {e}")),
        }
    }

    pub fn kill_switch_enable(
        endpoints: &[String],
        exceptions: &[String],
        allow_lan: bool,
    ) -> HelperResponse {
        let strict = !endpoints.is_empty();
        let rules = match synthesize(endpoints, exceptions, allow_lan) {
            Ok(r) => r,
            Err(e) => return HelperResponse::err(e),
        };
        match load_anchor(PF_ANCHOR, PF_RULES_PATH, &rules, strict) {
            HelperResponse { ok: true, .. } => HelperResponse::ok(if strict {
                "Kill switch enabled (pf default-deny except Tor endpoints)"
            } else {
                "Kill switch enabled (pf UDP/QUIC + IPv6 block)"
            }),
            other => other,
        }
    }

    pub fn kill_switch_disable() -> HelperResponse {
        let current = flush_anchor(PF_ANCHOR);
        let _ = flush_anchor(LEGACY_PF_ANCHOR);
        let _ = flush_anchor("oniongate.ks");
        match current {
            HelperResponse { ok: true, .. } => HelperResponse::ok("Kill switch disabled"),
            other => other,
        }
    }

    pub fn network_lock_enable(
        _tor_path: &str,
        endpoints: &[String],
        exceptions: &[String],
        allow_lan: bool,
    ) -> HelperResponse {
        let strict = !endpoints.is_empty();
        let rules = match synthesize(endpoints, exceptions, allow_lan) {
            Ok(r) => r,
            Err(e) => return HelperResponse::err(e),
        };
        match load_anchor(PF_LOCK_ANCHOR, PF_LOCK_RULES_PATH, &rules, strict) {
            HelperResponse { ok: true, .. } => HelperResponse::ok(if strict {
                "Network lock enabled (pf default-deny except Tor bootstrap endpoints)"
            } else {
                "Network lock enabled (pf UDP/QUIC + IPv6)"
            }),
            other => other,
        }
    }

    pub fn network_lock_disable() -> HelperResponse {
        let current = flush_anchor(PF_LOCK_ANCHOR);
        let _ = flush_anchor(LEGACY_PF_LOCK_ANCHOR);
        let _ = flush_anchor("oniongate.lock");
        match current {
            HelperResponse { ok: true, .. } => HelperResponse::ok("Network lock disabled"),
            other => other,
        }
    }

    pub fn deny_log_harvest() -> HelperResponse {
        use std::io::Read;
        let mut child = match Command::new("/usr/sbin/tcpdump")
            .args(["-n", "-l", "-i", "pflog0", "-c", "40", "-tt"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return HelperResponse::err(format!("tcpdump: {e}")),
        };
        std::thread::sleep(std::time::Duration::from_millis(800));
        let pid = child.id() as i32;
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let mut out = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_string(&mut out);
        }
        let _ = child.wait();
        let lines: Vec<String> = out.lines().map(|l| l.to_string()).collect();
        match serde_json::to_string(&lines) {
            Ok(json) => HelperResponse::ok(json),
            Err(e) => HelperResponse::err(e.to_string()),
        }
    }

    // ------------------------------ TUN ------------------------------

    /// Nothing we exec as root may live somewhere a non-root user could replace
    /// it, so the pinned binary and its directory are checked on every start.
    fn verify_root_owned(path: &Path, want_executable: bool) -> Result<(), String> {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("{} is not available: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} is a symlink", path.display()));
        }
        if want_executable {
            if !meta.is_file() {
                return Err(format!("{} is not a regular file", path.display()));
            }
            if meta.mode() & 0o111 == 0 {
                return Err(format!("{} is not executable", path.display()));
            }
        } else if !meta.is_dir() {
            return Err(format!("{} is not a directory", path.display()));
        }
        if meta.uid() != 0 {
            return Err(format!("{} is not owned by root", path.display()));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!("{} is group- or world-writable", path.display()));
        }
        Ok(())
    }

    fn pinned_singbox() -> Result<&'static Path, String> {
        let path = Path::new(PINNED_SINGBOX);
        let dir = path
            .parent()
            .ok_or_else(|| "pinned sing-box has no parent directory".to_string())?;
        verify_root_owned(dir, false)?;
        verify_root_owned(path, true)?;
        Ok(path)
    }

    /// Root-owned working directory for the generated config and the log. If it
    /// already exists but belongs to someone else, refuse rather than write into
    /// a directory a non-root user controls.
    fn ensure_tun_dir() -> Result<(), String> {
        let dir = Path::new(HELPER_TUN_DIR);
        if !dir.exists() {
            fs::create_dir_all(dir)
                .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("could not protect {}: {e}", dir.display()))?;
        }
        verify_root_owned(dir, false)
    }

    /// Create or truncate a root-only file. The mode is applied at creation so
    /// there is no window where the file is readable by anyone else.
    fn open_root_only(path: &Path) -> Result<fs::File, String> {
        if fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(format!("{} is a symlink", path.display()));
        }
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("could not open {}: {e}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("could not protect {}: {e}", path.display()))?;
        Ok(file)
    }

    /// Locate the Tor binary the app runs, so the generated config can exempt it
    /// from its own tunnel. Derived from the authenticated peer's bundle or from
    /// the pinned install location — the request never carries a path. Coming up
    /// empty costs Tor its direct route to a guard, which fails closed.
    fn resolve_tor_binary(peer_exe: Option<&Path>) -> Option<PathBuf> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        let from_bundle = |macos_dir: &Path, acc: &mut Vec<PathBuf>| {
            if let Some(contents) = macos_dir.parent() {
                let resources = contents.join("Resources");
                acc.push(resources.join("runtime").join("tor").join("tor"));
                acc.push(resources.join("runtime").join("bin").join("tor"));
                acc.push(resources.join("binaries").join("tor"));
            }
            acc.push(macos_dir.join("tor"));
            acc.push(macos_dir.join("binaries").join("tor"));
        };
        if let Some(dir) = peer_exe.and_then(|p| p.parent()) {
            from_bundle(dir, &mut candidates);
        }
        from_bundle(
            Path::new("/Applications/OnionGate.app/Contents/MacOS"),
            &mut candidates,
        );
        candidates.into_iter().find(|candidate| {
            fs::metadata(candidate)
                .map(|m| m.is_file() && m.mode() & 0o111 != 0)
                .unwrap_or(false)
        })
    }

    fn pid_executable(pid: i32) -> Option<PathBuf> {
        let mut buf = [0u8; 4096];
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        std::str::from_utf8(&buf[..n as usize])
            .ok()
            .map(PathBuf::from)
    }

    /// Every process whose *resolved* executable is the pinned sing-box. Matching
    /// on the executable rather than on a command-line pattern keeps the root
    /// kill narrow: an unrelated sing-box the user runs is never a target.
    fn pinned_singbox_pids() -> Vec<i32> {
        let Ok(out) = Command::new("/bin/ps").args(["-Ao", "pid="]).output() else {
            return Vec::new();
        };
        let pinned = Path::new(PINNED_SINGBOX);
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter_map(|token| token.parse::<i32>().ok())
            .filter(|pid| *pid > 1)
            .filter(|pid| pid_executable(*pid).as_deref() == Some(pinned))
            .collect()
    }

    fn log_tail() -> String {
        let Ok(raw) = fs::read_to_string(HELPER_TUN_LOG) else {
            return String::new();
        };
        let lines: Vec<&str> = raw.lines().rev().take(4).collect();
        lines.into_iter().rev().collect::<Vec<_>>().join(" | ")
    }

    pub fn tun_start(spec: &TunSpec, peer_exe: Option<&Path>) -> HelperResponse {
        if let Err(e) = spec.validate() {
            return HelperResponse::err(format!("TUN spec rejected: {e}"));
        }
        if !pinned_singbox_pids().is_empty() {
            return HelperResponse::ok("sing-box TUN already running");
        }
        let binary = match pinned_singbox() {
            Ok(path) => path,
            Err(e) => {
                return HelperResponse::err(format!(
                    "the pinned sing-box is not installed correctly ({e}); reinstall OnionGate from the macOS package"
                ))
            }
        };
        if let Err(e) = ensure_tun_dir() {
            return HelperResponse::err(e);
        }

        let config = oniongate_lib::tun::build_config_from_spec(
            spec,
            HELPER_TUN_LOG,
            resolve_tor_binary(peer_exe).as_deref(),
        );
        let raw = match serde_json::to_string_pretty(&config) {
            Ok(raw) => raw,
            Err(e) => return HelperResponse::err(format!("could not serialize the config: {e}")),
        };
        let config_path = Path::new(HELPER_TUN_CONFIG);
        match open_root_only(config_path) {
            Ok(mut file) => {
                use std::io::Write;
                if let Err(e) = file.write_all(raw.as_bytes()) {
                    return HelperResponse::err(format!("could not write the config: {e}"));
                }
            }
            Err(e) => return HelperResponse::err(e),
        }

        let log = match open_root_only(Path::new(HELPER_TUN_LOG)) {
            Ok(file) => file,
            Err(e) => return HelperResponse::err(e),
        };
        let log_err = match log.try_clone() {
            Ok(file) => file,
            Err(e) => return HelperResponse::err(format!("could not open the log: {e}")),
        };

        let mut command = Command::new(binary);
        command
            .arg("run")
            .arg("-c")
            .arg(config_path)
            .current_dir("/")
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
        // Its own session, so the tunnel does not die with a daemon restart.
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => return HelperResponse::err(format!("could not start sing-box: {e}")),
        };

        std::thread::sleep(Duration::from_millis(600));
        if let Ok(Some(status)) = child.try_wait() {
            let tail = log_tail();
            return HelperResponse::err(format!("sing-box exited immediately ({status}). {tail}"));
        }
        // Reap in the background; the daemon is long-lived and collects no zombies.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        HelperResponse::ok("sing-box TUN started from the pinned binary")
    }

    pub fn tun_stop() -> HelperResponse {
        let pids = pinned_singbox_pids();
        if pids.is_empty() {
            return HelperResponse::ok("no pinned sing-box process is running");
        }
        for pid in &pids {
            unsafe { libc::kill(*pid, libc::SIGTERM) };
        }
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(200));
            if pinned_singbox_pids().is_empty() {
                return HelperResponse::ok("sing-box TUN stopped");
            }
        }
        for pid in pinned_singbox_pids() {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        std::thread::sleep(Duration::from_millis(400));
        if pinned_singbox_pids().is_empty() {
            HelperResponse::ok("sing-box TUN stopped")
        } else {
            HelperResponse::err("sing-box did not stop")
        }
    }

    // -------------------------- Wi-Fi / MAC --------------------------

    fn run_tool(program: &str, args: &[&str]) -> Result<String, String> {
        let out = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("{program} failed: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "{program} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Interface names are matched, never accepted: the client sends no device
    /// and only a name this parser produced is ever handed to a command.
    fn valid_device_name(name: &str) -> bool {
        let bytes = name.as_bytes();
        (2..=10).contains(&bytes.len())
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && bytes[0].is_ascii_lowercase()
            && bytes[bytes.len() - 1].is_ascii_digit()
    }

    /// Pull the Wi-Fi device out of `networksetup -listallhardwareports`.
    fn wifi_device_from_ports(listing: &str) -> Option<String> {
        let mut wifi = false;
        for line in listing.lines() {
            let line = line.trim();
            if let Some(port) = line.strip_prefix("Hardware Port:") {
                let port = port.trim();
                wifi = port.eq_ignore_ascii_case("Wi-Fi") || port.eq_ignore_ascii_case("AirPort");
            } else if wifi {
                if let Some(device) = line.strip_prefix("Device:") {
                    let device = device.trim().to_string();
                    return valid_device_name(&device).then_some(device);
                }
            }
        }
        None
    }

    fn wifi_device() -> Result<String, String> {
        let listing = run_tool(NETWORKSETUP, &["-listallhardwareports"])?;
        wifi_device_from_ports(&listing).ok_or_else(|| "no Wi-Fi device on this Mac".to_string())
    }

    /// A random address is only valid locally if the locally-administered bit is
    /// set and the multicast bit is clear; without both the NIC rejects it or the
    /// link treats the frame as a group address.
    fn locally_administered(mut bytes: [u8; 6]) -> [u8; 6] {
        bytes[0] |= 0b0000_0010;
        bytes[0] &= !0b0000_0001;
        bytes
    }

    fn format_mac(bytes: [u8; 6]) -> String {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// The system CSPRNG. Read directly so the privileged daemon takes on no
    /// random-number dependency of its own.
    fn random_bytes() -> Result<[u8; 6], String> {
        use std::io::Read;
        let mut bytes = [0u8; 6];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .map_err(|e| format!("could not read the system CSPRNG: {e}"))?;
        Ok(bytes)
    }

    fn current_mac(device: &str) -> Option<String> {
        let out = run_tool(IFCONFIG, &[device]).ok()?;
        out.lines()
            .find_map(|line| line.trim().strip_prefix("ether "))
            .map(|mac| mac.trim().to_ascii_lowercase())
    }

    fn wifi_power_on(device: &str) -> bool {
        run_tool(NETWORKSETUP, &["-getairportpower", device])
            .map(|out| out.to_ascii_lowercase().contains(": on"))
            .unwrap_or(false)
    }

    fn set_wifi_power(device: &str, on: bool) -> Result<String, String> {
        run_tool(
            NETWORKSETUP,
            &["-setairportpower", device, if on { "on" } else { "off" }],
        )
    }

    pub fn mac_randomize() -> HelperResponse {
        let device = match wifi_device() {
            Ok(device) => device,
            Err(e) => return HelperResponse::err(e),
        };
        let mac = format_mac(match random_bytes() {
            Ok(bytes) => locally_administered(bytes),
            Err(e) => return HelperResponse::err(e),
        });
        let was_on = wifi_power_on(&device);

        // Cycling the radio is what forces dissociation now that Apple's
        // `airport` CLI is gone; the address only takes hold once the card
        // re-associates under it.
        let _ = set_wifi_power(&device, false);
        std::thread::sleep(Duration::from_millis(800));
        let applied_while_down = run_tool(IFCONFIG, &[&device, "ether", &mac]).is_ok();
        if was_on {
            let _ = set_wifi_power(&device, true);
            std::thread::sleep(Duration::from_millis(800));
        }
        if current_mac(&device).as_deref() == Some(mac.as_str()) {
            return HelperResponse::ok(mac);
        }

        // Some releases refuse the change while the radio is down. Set it with
        // the card powered, then cycle so association happens under the new one.
        if !applied_while_down || was_on {
            if let Err(e) = run_tool(IFCONFIG, &[&device, "ether", &mac]) {
                return HelperResponse::err(format!("could not set the MAC address: {e}"));
            }
            let _ = set_wifi_power(&device, false);
            std::thread::sleep(Duration::from_millis(800));
            let _ = set_wifi_power(&device, was_on);
            std::thread::sleep(Duration::from_millis(800));
        }
        match current_mac(&device) {
            Some(now) if now == mac => HelperResponse::ok(mac),
            _ => HelperResponse::err(
                "the MAC address did not change; this Mac or its Wi-Fi driver refused it",
            ),
        }
    }

    pub fn wifi_set_power(on: bool) -> HelperResponse {
        let device = match wifi_device() {
            Ok(device) => device,
            Err(e) => return HelperResponse::err(e),
        };
        match set_wifi_power(&device, on) {
            Ok(_) if on => HelperResponse::ok("Wi-Fi radio on"),
            Ok(_) => HelperResponse::ok("Wi-Fi radio off"),
            Err(e) => HelperResponse::err(e),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::synthesize;
        use super::{
            format_mac, locally_administered, valid_device_name, verify_root_owned,
            wifi_device_from_ports,
        };

        /// Nothing the root daemon execs may live where a non-root user could
        /// swap it. `verify_root_owned` is the gate the pinned sing-box and its
        /// directory pass through on every TUN start; exercise its refusals
        /// without needing to actually be root. The one branch that requires
        /// root to reach — a genuinely root-owned but group/world-writable file
        /// — cannot be forged here and is stated as an un-exercisable path.
        #[test]
        fn verify_root_owned_refuses_symlinks_wrong_types_and_non_root_paths() {
            use std::fs;
            use std::os::unix::fs::PermissionsExt;

            let root =
                std::env::temp_dir().join(format!("oniongate-verify-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("scratch dir");

            // A regular, test-user-owned executable: refused because it is not
            // root-owned (this is the check that stops a swapped-in sing-box).
            let file = root.join("sing-box");
            fs::write(&file, b"#!/bin/sh\n").expect("write");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).expect("chmod");
            let err = verify_root_owned(&file, true).expect_err("non-root");
            assert!(err.contains("root"), "{err}");

            // A symlink is refused first, even when it points at a real file —
            // following it is the cheapest way to redirect the root exec.
            let link = root.join("sing-box-link");
            std::os::unix::fs::symlink(&file, &link).expect("symlink");
            let err = verify_root_owned(&link, true).expect_err("symlink");
            assert!(err.contains("symlink"), "{err}");

            // Wrong file type in either direction is refused.
            let err = verify_root_owned(&root, true).expect_err("dir as exe");
            assert!(err.contains("regular file"), "{err}");
            let err = verify_root_owned(&file, false).expect_err("file as dir");
            assert!(err.contains("directory"), "{err}");

            // A missing path is refused, never treated as absent-and-acceptable.
            assert!(verify_root_owned(&root.join("gone"), true).is_err());

            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn loopback_exceptions_precede_the_quick_blocks() {
            let rules = synthesize(&[], &[], false).unwrap();
            let block = rules
                .lines()
                .position(|line| line.starts_with("block drop"))
                .unwrap();
            for pass in rules
                .lines()
                .enumerate()
                .filter_map(|(index, line)| line.starts_with("pass").then_some(index))
            {
                assert!(pass < block);
            }
            assert!(rules.contains("inet6"));
            assert!(rules.contains("::1"));
        }

        #[test]
        fn strict_rules_reject_pf_metacharacters() {
            assert!(synthesize(&["1.2.3.4; rm -rf /".into()], &[], false).is_err());
        }

        #[test]
        fn exceptions_without_endpoints_are_rejected() {
            assert!(synthesize(&[], &["203.0.113.9".into()], false).is_err());
        }

        /// An address without the locally-administered bit collides with real
        /// vendor space, and one with the multicast bit set is not a station
        /// address at all. Both must hold for every draw.
        #[test]
        fn randomized_addresses_are_always_locally_administered_unicast() {
            for _ in 0..4096 {
                let drawn = super::random_bytes().expect("system CSPRNG");
                let mac = locally_administered(drawn);
                assert_eq!(mac[0] & 0b0000_0010, 0b0000_0010, "{mac:?}");
                assert_eq!(mac[0] & 0b0000_0001, 0, "{mac:?}");
                assert_eq!(&mac[1..], &drawn[1..], "only the first octet may change");
            }
        }

        #[test]
        fn formatted_addresses_are_lowercase_colon_separated() {
            assert_eq!(
                format_mac([0x02, 0xab, 0x00, 0xff, 0x10, 0x9c]),
                "02:ab:00:ff:10:9c"
            );
        }

        #[test]
        fn the_wifi_device_comes_from_the_hardware_port_listing() {
            let listing = "\
Hardware Port: Ethernet
Device: en1
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: 11:22:33:44:55:66

Hardware Port: Thunderbolt Bridge
Device: bridge0
";
            assert_eq!(wifi_device_from_ports(listing).as_deref(), Some("en0"));
            assert!(wifi_device_from_ports("Hardware Port: Ethernet\nDevice: en1").is_none());
        }

        #[test]
        fn a_device_name_that_is_not_an_interface_is_refused() {
            assert!(valid_device_name("en0"));
            assert!(valid_device_name("utun3"));
            assert!(!valid_device_name("en0; rm -rf /"));
            assert!(!valid_device_name("../../en0"));
            assert!(!valid_device_name(""));
            assert!(!valid_device_name("en"));
        }
    }
}

#[cfg(target_os = "linux")]
mod executor {
    use oniongate_lib::helper::HelperResponse;
    use std::process::Command;

    const TABLE: &str = "oniongate_ks";
    const LOCK_TABLE: &str = "oniongate_lock";
    const LEGACY_TABLE: &str = "tor_socks_gui_ks";
    const LEGACY_LOCK_TABLE: &str = "tor_socks_gui_lock";

    fn run_script(script: &str) -> Result<(), String> {
        let status = Command::new("sh")
            .arg("-c")
            .arg(script)
            .status()
            .map_err(|e| e.to_string())?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("nft script failed: {status}"))
    }

    fn enable_table(table: &str) -> String {
        format!(
            "nft list table inet {table} >/dev/null 2>&1 && nft delete table inet {table} || true; \
             nft add table inet {table} && \
             nft 'add chain inet {table} output {{ type filter hook output priority 0; policy accept; }}' && \
             nft add rule inet {table} output oif lo accept && \
             nft add rule inet {table} output ip daddr 127.0.0.1 accept && \
             nft add rule inet {table} output ip6 daddr ::1 accept && \
             nft add rule inet {table} output ip6 daddr != ::1 drop && \
             nft add rule inet {table} output udp dport 53 drop && \
             nft add rule inet {table} output udp dport 443 drop && \
             nft add rule inet {table} output meta l4proto udp drop"
        )
    }

    pub fn kill_switch_enable(
        endpoints: &[String],
        _exceptions: &[String],
        _allow_lan: bool,
    ) -> HelperResponse {
        if !endpoints.is_empty() {
            return HelperResponse::err("strict NIC lock is macOS-only");
        }
        match run_script(&enable_table(TABLE)) {
            Ok(()) => HelperResponse::ok("Kill switch enabled (nftables UDP/QUIC + IPv6 block)"),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn kill_switch_disable() -> HelperResponse {
        match run_script(&format!(
            "nft delete table inet {TABLE} 2>/dev/null || true; nft delete table inet {LEGACY_TABLE} 2>/dev/null || true"
        )) {
            Ok(()) => HelperResponse::ok("Kill switch disabled"),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn network_lock_enable(
        _tor_path: &str,
        endpoints: &[String],
        _exceptions: &[String],
        _allow_lan: bool,
    ) -> HelperResponse {
        if !endpoints.is_empty() {
            return HelperResponse::err("strict NIC lock is macOS-only");
        }
        match run_script(&enable_table(LOCK_TABLE)) {
            Ok(()) => HelperResponse::ok("Network lock enabled (nftables UDP/QUIC + IPv6)"),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn deny_log_harvest() -> HelperResponse {
        HelperResponse::err("deny log harvest is macOS-only")
    }

    pub fn network_lock_disable() -> HelperResponse {
        match run_script(&format!(
            "nft delete table inet {LOCK_TABLE} 2>/dev/null || true; nft delete table inet {LEGACY_LOCK_TABLE} 2>/dev/null || true"
        )) {
            Ok(()) => HelperResponse::ok("Network lock disabled"),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn tun_start(
        _spec: &oniongate_lib::helper::TunSpec,
        _peer_exe: Option<&std::path::Path>,
    ) -> HelperResponse {
        HelperResponse::err("helper-backed TUN is macOS-only")
    }

    pub fn tun_stop() -> HelperResponse {
        HelperResponse::err("helper-backed TUN is macOS-only")
    }

    pub fn mac_randomize() -> HelperResponse {
        HelperResponse::err("MAC randomization is macOS-only")
    }

    pub fn wifi_set_power(_on: bool) -> HelperResponse {
        HelperResponse::err("Wi-Fi power control is macOS-only")
    }
}

// ============================ Windows ============================

#[cfg(windows)]
mod executor {
    use oniongate_lib::helper::HelperResponse;
    use std::path::Path;
    use std::process::Command;

    const RULE: &str = "OnionGate UDP Internet Guard";
    const RULE_V6: &str = "OnionGate IPv6 Internet Guard";
    const RULE_V6_LO: &str = "OnionGate IPv6 Loopback Allow";
    const LOCK_UDP: &str = "OnionGate Transition UDP Lock";
    const LOCK_V6: &str = "OnionGate Transition IPv6 Lock";
    const LOCK_V6_LO: &str = "OnionGate Transition IPv6 Loopback Allow";
    const LOCK_TCP: &str = "OnionGate Transition TCP Lock";
    const LOCK_TOR_ALLOW: &str = "OnionGate Transition Tor Allow";

    fn powershell(script: &str) -> Result<(), String> {
        use oniongate_lib::win_console::HideConsole;
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .hide_console()
            .status()
            .map_err(|e| e.to_string())?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("powershell failed: {status}"))
    }

    fn validate_tor_path(tor_path: &str) -> Result<&str, String> {
        if tor_path.is_empty() {
            return Ok("");
        }
        let path = Path::new(tor_path);
        if !path.is_absolute() {
            return Err("tor_path must be absolute".into());
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name != "tor.exe" && name != "tor" {
            return Err("tor_path must end with tor.exe".into());
        }
        if !path.is_file() {
            return Err("tor_path does not exist".into());
        }
        Ok(tor_path)
    }

    pub fn kill_switch_enable(
        endpoints: &[String],
        _exceptions: &[String],
        _allow_lan: bool,
    ) -> HelperResponse {
        if !endpoints.is_empty() {
            return HelperResponse::err("strict NIC lock is macOS-only");
        }
        let script = format!(
            "Get-NetFirewallRule -DisplayName '{RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{RULE_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{RULE_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             New-NetFirewallRule -DisplayName '{RULE}' -Direction Outbound -Action Block -Protocol UDP -RemoteAddress Internet -Profile Any | Out-Null; \
             New-NetFirewallRule -DisplayName '{RULE_V6_LO}' -Direction Outbound -Action Allow -Protocol Any -RemoteAddress '::1' -Profile Any | Out-Null; \
             New-NetFirewallRule -DisplayName '{RULE_V6}' -Direction Outbound -Action Block -Protocol Any -RemoteAddress '::/0' -Profile Any | Out-Null"
        );
        match powershell(&script) {
            Ok(()) => HelperResponse::ok("Windows UDP/QUIC and IPv6 Internet guard enabled"),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn kill_switch_disable() -> HelperResponse {
        let script = format!(
            "Get-NetFirewallRule -DisplayName '{RULE}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{RULE_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{RULE_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
        );
        match powershell(&script) {
            Ok(()) => HelperResponse::ok("Windows UDP/QUIC and IPv6 Internet guard disabled"),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn network_lock_enable(
        tor_path: &str,
        endpoints: &[String],
        _exceptions: &[String],
        _allow_lan: bool,
    ) -> HelperResponse {
        if !endpoints.is_empty() {
            return HelperResponse::err("strict NIC lock is macOS-only");
        }
        let tor_path = match validate_tor_path(tor_path) {
            Ok(p) => p,
            Err(e) => return HelperResponse::err(e),
        };
        let tor_allow = if tor_path.is_empty() {
            String::new()
        } else {
            let escaped = tor_path.replace('\'', "''");
            format!(
                "Get-NetFirewallRule -DisplayName '{LOCK_TOR_ALLOW}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
                 New-NetFirewallRule -DisplayName '{LOCK_TOR_ALLOW}' -Direction Outbound -Action Allow -Program '{escaped}' -RemoteAddress Any -Profile Any | Out-Null; "
            )
        };
        let script = format!(
            "{tor_allow}\
             Get-NetFirewallRule -DisplayName '{LOCK_UDP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{LOCK_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{LOCK_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{LOCK_TCP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             New-NetFirewallRule -DisplayName '{LOCK_UDP}' -Direction Outbound -Action Block -Protocol UDP -RemoteAddress Internet -Profile Any | Out-Null; \
             New-NetFirewallRule -DisplayName '{LOCK_V6_LO}' -Direction Outbound -Action Allow -Protocol Any -RemoteAddress '::1' -Profile Any | Out-Null; \
             New-NetFirewallRule -DisplayName '{LOCK_V6}' -Direction Outbound -Action Block -Protocol Any -RemoteAddress '::/0' -Profile Any | Out-Null; \
             New-NetFirewallRule -DisplayName '{LOCK_TCP}' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress Internet -Profile Any | Out-Null"
        );
        match powershell(&script) {
            Ok(()) => HelperResponse::ok(
                "Network lock enabled (UDP/IPv6/TCP blocked; Tor allowed when path provided)",
            ),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn network_lock_disable() -> HelperResponse {
        let script = format!(
            "Get-NetFirewallRule -DisplayName '{LOCK_UDP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{LOCK_V6}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{LOCK_V6_LO}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{LOCK_TCP}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
             Get-NetFirewallRule -DisplayName '{LOCK_TOR_ALLOW}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
        );
        match powershell(&script) {
            Ok(()) => HelperResponse::ok("Network lock disabled"),
            Err(e) => HelperResponse::err(e),
        }
    }

    pub fn deny_log_harvest() -> HelperResponse {
        HelperResponse::err("deny log harvest is macOS-only")
    }

    pub fn tun_start(_spec: &oniongate_lib::helper::TunSpec) -> HelperResponse {
        HelperResponse::err("helper-backed TUN is macOS-only")
    }

    pub fn tun_stop() -> HelperResponse {
        HelperResponse::err("helper-backed TUN is macOS-only")
    }

    pub fn mac_randomize() -> HelperResponse {
        HelperResponse::err("MAC randomization is macOS-only")
    }

    pub fn wifi_set_power(_on: bool) -> HelperResponse {
        HelperResponse::err("Wi-Fi power control is macOS-only")
    }
}

#[cfg(windows)]
mod windows_daemon {
    use std::ffi::OsString;
    use std::time::Duration;

    use oniongate_lib::helper::{decode, encode, HelperRequest, HelperResponse, PIPE_NAME};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    const SERVICE_NAME: &str = "OnionGateHelper";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_as_service() -> Result<(), windows_service::Error> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_args: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> Result<(), Box<dyn std::error::Error>> {
        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                ServiceControl::Stop | ServiceControl::Interrogate => {
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;
        let running = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };
        status_handle.set_service_status(running)?;
        serve_pipe();
        Ok(())
    }

    // Console fallback for debugging (not run under SCM).
    pub fn run_console() {
        serve_pipe();
    }

    fn serve_pipe() {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("failed to start runtime: {e}");
                return;
            }
        };
        rt.block_on(async {
            loop {
                let server = match ServerOptions::new().create(PIPE_NAME) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("pipe create error: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                if server.connect().await.is_err() {
                    continue;
                }
                let mut reader = BufReader::new(server);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                    continue;
                }
                let response = match decode::<HelperRequest>(&line) {
                    Ok(HelperRequest::Ping) => HelperResponse::ok("pong"),
                    Ok(HelperRequest::KillSwitchEnable {
                        tcp_endpoints,
                        tcp_exceptions,
                        allow_lan,
                    }) => super::executor::kill_switch_enable(
                        &tcp_endpoints,
                        &tcp_exceptions,
                        allow_lan,
                    ),
                    Ok(HelperRequest::KillSwitchDisable) => super::executor::kill_switch_disable(),
                    Ok(HelperRequest::NetworkLockEnable {
                        tor_path,
                        tcp_endpoints,
                        tcp_exceptions,
                        allow_lan,
                    }) => super::executor::network_lock_enable(
                        &tor_path,
                        &tcp_endpoints,
                        &tcp_exceptions,
                        allow_lan,
                    ),
                    Ok(HelperRequest::NetworkLockDisable) => {
                        super::executor::network_lock_disable()
                    }
                    Ok(HelperRequest::DenyLogHarvest) => super::executor::deny_log_harvest(),
                    Ok(HelperRequest::TerminatePid { pid }) => {
                        oniongate_lib::helper::execute_terminate_pid(pid)
                    }
                    Ok(HelperRequest::StopApplication { pid }) => {
                        oniongate_lib::helper::execute_stop_application(pid)
                    }
                    Ok(HelperRequest::TunStart { spec }) => super::executor::tun_start(&spec),
                    Ok(HelperRequest::TunStop) => super::executor::tun_stop(),
                    Ok(HelperRequest::MacRandomize) => super::executor::mac_randomize(),
                    Ok(HelperRequest::WifiSetPower { on }) => super::executor::wifi_set_power(on),
                    Ok(HelperRequest::SocksEnable) => oniongate_lib::helper::execute_socks_enable(),
                    Ok(HelperRequest::SocksDisable) => {
                        oniongate_lib::helper::execute_socks_disable()
                    }
                    Err(e) => HelperResponse::err(format!("bad request: {e}")),
                };
                let mut inner = reader.into_inner();
                if let Ok(bytes) = encode(&response) {
                    let _ = inner.write_all(&bytes).await;
                    let _ = inner.flush().await;
                }
            }
        });
    }
}
