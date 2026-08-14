//! OnionGate privileged helper daemon.
//!
//! Runs with elevated privileges (installed once via launchd/systemd/SCM). It
//! performs ONLY the fixed, typed operations in `tor_socks_gui_lib::helper` —
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

    use tor_socks_gui_lib::helper::{decode, encode, HelperRequest, HelperResponse, SOCKET_PATH};

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
                .and_then(tor_socks_gui_lib::helper::identity::codesign_info)
                .is_some();
            let Some(pid) = peer_pid(stream) else {
                return !helper_signed;
            };
            let Some(path) = pid_executable(pid) else {
                return !helper_signed;
            };
            match tor_socks_gui_lib::helper::identity::codesign_info(&path) {
                Some(info)
                    if tor_socks_gui_lib::helper::identity::allowed_app_identifier(
                        &info.identifier,
                    ) || info.identifier.contains("oniongate")
                        || info.identifier == "tor-socks-gui" =>
                {
                    if let (Some(helper), Some(peer_team)) = (
                        helper_path
                            .as_deref()
                            .and_then(tor_socks_gui_lib::helper::identity::codesign_info),
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

    fn allowed_uid() -> Option<u32> {
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--allow-uid" {
                if let Some(uid) = args.next().and_then(|v| v.parse::<u32>().ok()) {
                    return Some(uid);
                }
            }
        }
        // Fall back to the console owner (the logged-in GUI user).
        fs::metadata("/dev/console").ok().map(|m| m.uid())
    }

    pub fn run() {
        let allow = allowed_uid();
        eprintln!("oniongate-helper starting; allowed uid = {allow:?}");
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
                Ok(stream) => handle(stream, allow),
                Err(e) => eprintln!("accept error: {e}"),
            }
        }
    }

    fn handle(stream: UnixStream, allow: Option<u32>) {
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
            Ok(req) => dispatch(req),
            Err(e) => HelperResponse::err(format!("bad request: {e}")),
        };
        let _ = respond(&stream, &response);
    }

    fn respond(mut stream: &UnixStream, response: &HelperResponse) -> std::io::Result<()> {
        let bytes = encode(response)
            .unwrap_or_else(|_| b"{\"ok\":false,\"message\":\"encode error\"}\n".to_vec());
        stream.write_all(&bytes)?;
        stream.flush()
    }

    fn dispatch(req: HelperRequest) -> HelperResponse {
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
                tor_socks_gui_lib::helper::execute_terminate_pid(pid)
            }
            HelperRequest::StopApplication { pid } => {
                tor_socks_gui_lib::helper::execute_stop_application(pid)
            }
        }
    }
}

// ---------------------- Unix privileged executors ----------------------

#[cfg(target_os = "macos")]
mod executor {
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tor_socks_gui_lib::helper::HelperResponse;

    const PFCTL: &str = "/sbin/pfctl";
    const PF_ANCHOR: &str = "tor.socks.gui";
    const PF_LOCK_ANCHOR: &str = "tor.socks.gui.lock";
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
            return Ok(tor_socks_gui_lib::firewall::strict::pf_udp_ipv6_rules());
        }
        let eps = tor_socks_gui_lib::firewall::strict::parse_ip_list(
            endpoints,
            tor_socks_gui_lib::firewall::strict::MAX_ENDPOINTS,
        )?;
        let exs = tor_socks_gui_lib::firewall::strict::parse_ip_list(
            exceptions,
            tor_socks_gui_lib::firewall::strict::MAX_EXCEPTIONS,
        )?;
        Ok(tor_socks_gui_lib::firewall::strict::pf_strict_rules(
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
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => return HelperResponse::err(format!("pfctl load failed: {s}")),
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
        match flush_anchor(PF_ANCHOR) {
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
        match flush_anchor(PF_LOCK_ANCHOR) {
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

    #[cfg(test)]
    mod tests {
        use super::synthesize;

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
    }
}

#[cfg(target_os = "linux")]
mod executor {
    use std::process::Command;
    use tor_socks_gui_lib::helper::HelperResponse;

    const TABLE: &str = "tor_socks_gui_ks";
    const LOCK_TABLE: &str = "tor_socks_gui_lock";

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
            "nft delete table inet {TABLE} 2>/dev/null || true"
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
            "nft delete table inet {LOCK_TABLE} 2>/dev/null || true"
        )) {
            Ok(()) => HelperResponse::ok("Network lock disabled"),
            Err(e) => HelperResponse::err(e),
        }
    }
}

// ============================ Windows ============================

#[cfg(windows)]
mod executor {
    use std::path::Path;
    use std::process::Command;
    use tor_socks_gui_lib::helper::HelperResponse;

    const RULE: &str = "OnionGate UDP Internet Guard";
    const RULE_V6: &str = "OnionGate IPv6 Internet Guard";
    const RULE_V6_LO: &str = "OnionGate IPv6 Loopback Allow";
    const LOCK_UDP: &str = "OnionGate Transition UDP Lock";
    const LOCK_V6: &str = "OnionGate Transition IPv6 Lock";
    const LOCK_V6_LO: &str = "OnionGate Transition IPv6 Loopback Allow";
    const LOCK_TCP: &str = "OnionGate Transition TCP Lock";
    const LOCK_TOR_ALLOW: &str = "OnionGate Transition Tor Allow";

    fn powershell(script: &str) -> Result<(), String> {
        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
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
}

#[cfg(windows)]
mod windows_daemon {
    use std::ffi::OsString;
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;
    use tor_socks_gui_lib::helper::{decode, encode, HelperRequest, HelperResponse, PIPE_NAME};
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
                        tor_socks_gui_lib::helper::execute_terminate_pid(pid)
                    }
                    Ok(HelperRequest::StopApplication { pid }) => {
                        tor_socks_gui_lib::helper::execute_stop_application(pid)
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
