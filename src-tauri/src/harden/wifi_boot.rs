//! Turn Wi-Fi off at boot with a root LaunchDaemon, with `pmset` wake guards.
//!
//! MODIFICATION NOTICE (GPL-3.0 section 5(a)):
//! This file contains work derived from term7's
//! "MacOS-Privacy-and-Security-Enhancements" (GPL-3.0), specifically
//! `05_WiFi-OFF/network_daemon/01_disable_wifi.sh`,
//! `05_WiFi-OFF/network_daemon/02_enable_wifi.sh` and their LaunchDaemon
//! property lists. Modified by the OnionGate project on 2026-08-15:
//!   * the two upstream daemons are merged into one boot script that resolves
//!     the Wi-Fi device at runtime instead of assuming `en0`;
//!   * the script and its LaunchDaemon live in a root-owned directory under
//!     `/Library/Application Support`, not in world-writable `/Users/Shared`,
//!     so a root job never executes a user-writable file;
//!   * upstream's world-readable `chmod 666` log file is dropped entirely —
//!     the daemon writes no log;
//!   * upstream's call into the `spoof` npm tool is removed (see
//!     `harden::mac_random` for why), so no MAC address is assigned at boot;
//!   * uninstall restores the `pmset` values captured before install and puts
//!     the Wi-Fi network service back, which upstream does not do;
//!   * OnionGate can turn the radio back on once the session reports
//!     `Protected`, which has no upstream counterpart.
//!
//! Upstream: https://codeberg.org/term7/MacOS-Privacy-and-Security-Enhancements

use std::fs;
use std::process::{Command, Stdio};

pub const LABEL: &str = "com.adamsiwiec.oniongate.wifi-off-at-boot";
pub const SUPPORT_DIR: &str = "/Library/Application Support/OnionGate/wifi-off-at-boot";
pub const SCRIPT_PATH: &str =
    "/Library/Application Support/OnionGate/wifi-off-at-boot/disable-wifi-at-boot.sh";
pub const RESTORE_PATH: &str =
    "/Library/Application Support/OnionGate/wifi-off-at-boot/previous-power-settings.conf";
pub const PLIST_PATH: &str =
    "/Library/LaunchDaemons/com.adamsiwiec.oniongate.wifi-off-at-boot.plist";

#[derive(Debug, Clone)]
pub struct WifiBootStatus {
    /// Script + LaunchDaemon are both present, root-owned, and point at us.
    pub installed: bool,
    /// Everything else the check observed — wake guards, radio power, whether
    /// launchd has the job — in one line for the UI.
    pub detail: String,
}

fn run_out(bin: &str, args: &[&str]) -> String {
    Command::new(bin)
        .args(args)
        .output()
        .map(|o| {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            s
        })
        .unwrap_or_default()
}

/// Resolve the Wi-Fi device from `networksetup -listallhardwareports`. The same
/// listing the privileged helper uses; `airport(8)` is gone from recent macOS
/// and is never consulted here.
pub fn wifi_device_from_ports(listing: &str) -> Option<String> {
    let mut in_wifi = false;
    for line in listing.lines() {
        let line = line.trim();
        if let Some(port) = line.strip_prefix("Hardware Port:") {
            let port = port.trim();
            in_wifi = port.eq_ignore_ascii_case("Wi-Fi") || port.eq_ignore_ascii_case("AirPort");
        } else if in_wifi {
            if let Some(device) = line.strip_prefix("Device:") {
                let device = device.trim();
                if !device.is_empty() && device.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Some(device.to_string());
                }
            }
        }
    }
    None
}

pub fn wifi_device() -> Option<String> {
    wifi_device_from_ports(&run_out(
        "/usr/sbin/networksetup",
        &["-listallhardwareports"],
    ))
}

/// `networksetup -listallnetworkservices` prefixes a disabled service with `*`.
pub fn wifi_service_disabled(listing: &str) -> bool {
    listing.lines().any(|line| {
        let line = line.trim();
        line.starts_with('*')
            && line
                .trim_start_matches('*')
                .trim()
                .eq_ignore_ascii_case("Wi-Fi")
    })
}

/// `networksetup -getairportpower en0` → "Wi-Fi Power (en0): On".
pub fn parse_airport_power(out: &str) -> Option<bool> {
    let line = out
        .lines()
        .find(|l| l.to_ascii_lowercase().contains("power"))?;
    match line
        .rsplit_once(':')?
        .1
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// One `pmset -g custom` flag, e.g. `womp` or `networkoversleep`.
pub fn parse_pmset_flag(out: &str, key: &str) -> Option<i64> {
    out.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let name = parts.next()?;
        if name != key {
            return None;
        }
        parts.next()?.parse::<i64>().ok()
    })
}

pub fn restore_conf(womp: Option<i64>, network_oversleep: Option<i64>) -> String {
    let mut out = String::from("# OnionGate: pmset values recorded before wifi_off_at_boot\n");
    if let Some(v) = womp {
        out.push_str(&format!("womp={v}\n"));
    }
    if let Some(v) = network_oversleep {
        out.push_str(&format!("networkoversleep={v}\n"));
    }
    out
}

pub fn parse_restore_conf(text: &str) -> (Option<i64>, Option<i64>) {
    let read = |key: &str| {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find_map(|l| {
                let (name, value) = l.split_once('=')?;
                (name.trim() == key).then(|| value.trim().parse::<i64>().ok())?
            })
    };
    (read("womp"), read("networkoversleep"))
}

/// The boot script. Derived from term7 `05_WiFi-OFF` (see the file header).
pub fn boot_script() -> String {
    format!(
        r#"#!/bin/bash
# OnionGate — keep Wi-Fi off across boot.
# Derived from term7 MacOS-Privacy-and-Security-Enhancements 05_WiFi-OFF
# (GPL-3.0), modified: runtime device resolution, no logging, no MAC spoofing.
set -u

NETWORKSETUP=/usr/sbin/networksetup
PMSET=/usr/bin/pmset

wifi_device() {{
  "$NETWORKSETUP" -listallhardwareports | /usr/bin/awk '
    /^Hardware Port: Wi-Fi$/ {{ want = 1; next }}
    /^Hardware Port: AirPort$/ {{ want = 1; next }}
    want == 1 && /^Device: / {{ print $2; exit }}
  '
}}

# 1) Take the Wi-Fi service out of service before anything can auto-join a
#    remembered network or leak probe requests.
"$NETWORKSETUP" -setnetworkserviceenabled Wi-Fi off >/dev/null 2>&1

# 2) Wake guards. Without these the radio comes back on its own when the Mac
#    wakes, which would silently undo everything above.
"$PMSET" -a womp 0 >/dev/null 2>&1
"$PMSET" -a networkoversleep 0 >/dev/null 2>&1

# 3) Wait (bounded) for a console login, then power the radio down and put the
#    service back so Wi-Fi is visible-but-off and the user can switch it on.
WAITED=0
while [ "$WAITED" -lt {LOGIN_WAIT_SECS} ]; do
  CONSOLE_USER=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || echo root)
  if [ "$CONSOLE_USER" != "root" ] && [ -n "$CONSOLE_USER" ]; then
    break
  fi
  /bin/sleep 1
  WAITED=$((WAITED + 1))
done

DEVICE=$(wifi_device)
if [ -n "$DEVICE" ]; then
  ATTEMPT=0
  while [ "$ATTEMPT" -lt 5 ]; do
    if "$NETWORKSETUP" -setairportpower "$DEVICE" off >/dev/null 2>&1; then
      break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    /bin/sleep 2
  done
fi

/bin/sleep 3
"$NETWORKSETUP" -setnetworkserviceenabled Wi-Fi on >/dev/null 2>&1
exit 0
"#
    )
}

const LOGIN_WAIT_SECS: u32 = 120;

pub fn daemon_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{SCRIPT_PATH}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>Nice</key>
  <integer>-20</integer>
</dict>
</plist>
"#
    )
}

fn daemon_registered() -> bool {
    Command::new("/bin/launchctl")
        .args(["print", &format!("system/{LABEL}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A root job that executes a file anyone can rewrite is a way in, not a
/// hardening measure — so ownership is part of the status check.
fn root_owned(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).map(|m| m.uid() == 0).unwrap_or(false)
}

pub fn status() -> WifiBootStatus {
    let plist = fs::read_to_string(PLIST_PATH).unwrap_or_default();
    let script_present = std::path::Path::new(SCRIPT_PATH).is_file();
    // Inspect what the installed daemon actually runs rather than trusting that
    // we once wrote it: a stale or hand-edited plist must not read as active.
    let points_at_script = plist.contains(SCRIPT_PATH) && plist.contains(LABEL);
    let script_root_owned = script_present && root_owned(SCRIPT_PATH);
    let installed = script_present && points_at_script && script_root_owned;

    let pm = run_out("/usr/bin/pmset", &["-g", "custom"]);
    let womp = parse_pmset_flag(&pm, "womp");
    let network_oversleep = parse_pmset_flag(&pm, "networkoversleep");
    let service_disabled = wifi_service_disabled(&run_out(
        "/usr/sbin/networksetup",
        &["-listallnetworkservices"],
    ));
    let radio_on = wifi_device().and_then(|dev| {
        parse_airport_power(&run_out(
            "/usr/sbin/networksetup",
            &["-getairportpower", &dev],
        ))
    });
    let registered = daemon_registered();

    let mut detail = if installed {
        "Boot daemon installed".to_string()
    } else if script_present || !plist.is_empty() {
        "Boot daemon files are incomplete or not root-owned".to_string()
    } else {
        "Wi-Fi starts in whatever state macOS remembers".to_string()
    };
    if installed {
        detail.push_str(if registered {
            " · loaded in launchd"
        } else {
            " · takes effect at the next boot"
        });
    }
    match womp {
        Some(0) => detail.push_str(" · wake-on-LAN off"),
        Some(_) => detail.push_str(" · wake-on-LAN still on"),
        None => {}
    }
    if network_oversleep == Some(0) {
        detail.push_str(" · network not kept alive over sleep");
    }
    if let Some(on) = radio_on {
        detail.push_str(if on {
            " · radio on now"
        } else {
            " · radio off now"
        });
    }
    if service_disabled {
        detail.push_str(" · Wi-Fi service currently disabled");
    }

    WifiBootStatus { installed, detail }
}

fn heredoc(path: &str, marker: &str, body: &str) -> String {
    format!("/bin/cat > {path} <<'{marker}'\n{body}{marker}\n")
}

fn quote(path: &str) -> String {
    crate::elevate::shell_quote(path)
}

/// The script the administrator prompt runs. Everything it writes is
/// root-owned, and the plist is linted before the prompt returns success.
pub fn install_script(conf: &str) -> String {
    let dir = quote(SUPPORT_DIR);
    let script = quote(SCRIPT_PATH);
    let restore = quote(RESTORE_PATH);
    let plist = quote(PLIST_PATH);
    format!(
        "set -e\n\
         /bin/mkdir -p {dir}\n\
         {script_doc}\
         {restore_doc}\
         {plist_doc}\
         /usr/sbin/chown -R root:wheel {dir}\n\
         /bin/chmod 755 {dir}\n\
         /bin/chmod 755 {script}\n\
         /bin/chmod 644 {restore}\n\
         /usr/sbin/chown root:wheel {plist}\n\
         /bin/chmod 644 {plist}\n\
         /usr/bin/plutil -lint {plist}\n",
        script_doc = heredoc(&script, "OGWIFISCRIPT", &boot_script()),
        restore_doc = heredoc(&restore, "OGWIFICONF", conf),
        plist_doc = heredoc(&plist, "OGWIFIPLIST", &daemon_plist()),
    )
}

pub fn install() -> Result<String, String> {
    let pm = run_out("/usr/bin/pmset", &["-g", "custom"]);
    let conf = restore_conf(
        parse_pmset_flag(&pm, "womp"),
        parse_pmset_flag(&pm, "networkoversleep"),
    );
    crate::elevate::run_shell_with_prompt(
        &install_script(&conf),
        "OnionGate needs administrator access to install the Wi-Fi-off-at-boot daemon.",
    )?;

    // Deliberately not bootstrapped: the daemon has RunAtLoad, so loading it now
    // would drop the Wi-Fi link the user is sitting on. launchd picks it up from
    // /Library/LaunchDaemons at the next boot, which is when it is meant to run.
    crate::logs::append("Hardening: Wi-Fi-off-at-boot daemon installed");
    Ok("Wi-Fi will be off at boot from the next restart. Nothing changed on the current connection.".into())
}

/// Removal, including the `pmset` values recorded at install time. Only values
/// we wrote ourselves, and only `0`/`1`, are ever fed back to `pmset`.
pub fn uninstall_script(womp: Option<i64>, network_oversleep: Option<i64>) -> String {
    let dir = quote(SUPPORT_DIR);
    let plist = quote(PLIST_PATH);
    let mut commands = format!(
        "/bin/launchctl bootout system/{LABEL} 2>/dev/null || true\n\
         /bin/rm -f {plist}\n\
         /bin/rm -rf {dir}\n\
         /usr/sbin/networksetup -setnetworkserviceenabled Wi-Fi on 2>/dev/null || true\n"
    );
    if let Some(v) = womp.filter(|v| (0..=1).contains(v)) {
        commands.push_str(&format!("/usr/bin/pmset -a womp {v} 2>/dev/null || true\n"));
    }
    if let Some(v) = network_oversleep.filter(|v| (0..=1).contains(v)) {
        commands.push_str(&format!(
            "/usr/bin/pmset -a networkoversleep {v} 2>/dev/null || true\n"
        ));
    }
    commands
}

pub fn uninstall() -> Result<String, String> {
    let (womp, oversleep) = fs::read_to_string(RESTORE_PATH)
        .map(|text| parse_restore_conf(&text))
        .unwrap_or((None, None));
    crate::elevate::run_shell_with_prompt(
        &uninstall_script(womp, oversleep),
        "OnionGate needs administrator access to remove the Wi-Fi-off-at-boot daemon.",
    )?;
    crate::logs::append("Hardening: Wi-Fi-off-at-boot daemon removed");
    Ok("Wi-Fi-off-at-boot removed, power settings restored, Wi-Fi service re-enabled".into())
}

/// Turn the radio back on once the session is `Protected`, if the user asked
/// for that. Returns `Ok(None)` when there is simply nothing to do — never a
/// silent failure.
pub fn reenable_after_protected() -> Result<Option<String>, String> {
    if !status().installed {
        return Ok(None);
    }
    if !crate::settings::load().wifi_off_at_boot_auto_reenable {
        return Ok(None);
    }
    if crate::session::load().phase != crate::session::SessionPhase::Protected {
        return Ok(None);
    }
    let Some(device) = wifi_device() else {
        return Ok(None);
    };
    let powered = parse_airport_power(&run_out(
        "/usr/sbin/networksetup",
        &["-getairportpower", &device],
    ));
    if powered == Some(true) {
        return Ok(None);
    }

    if crate::helper::client::available() {
        match crate::helper::client::request(&crate::helper::HelperRequest::WifiSetPower {
            on: true,
        }) {
            Ok(resp) if resp.ok => {
                crate::logs::append(
                    "Hardening: Wi-Fi re-enabled after the session reported Protected",
                );
                return Ok(Some(
                    "Wi-Fi radio turned back on (session is Protected)".into(),
                ));
            }
            Ok(resp) => return Err(resp.message),
            Err(e) => return Err(e),
        }
    }
    // No helper: the radio switch itself does not need root, so try it directly
    // rather than throwing an administrator prompt at an unattended machine.
    let ok = Command::new("/usr/sbin/networksetup")
        .args(["-setairportpower", &device, "on"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        crate::logs::append("Hardening: Wi-Fi re-enabled after the session reported Protected");
        Ok(Some(
            "Wi-Fi radio turned back on (session is Protected)".into(),
        ))
    } else {
        Err("Could not turn the Wi-Fi radio back on; install the privileged helper or use the menu bar".into())
    }
}

/// Fired by the session module the moment the phase transitions into
/// `Protected`. This is the real call site the stopgap poller stood in for:
/// there is no timer, no polling, and it runs exactly once per transition.
///
/// The work runs on a detached thread so a phase change never blocks on
/// `networksetup`/helper IO, and it delegates to the fully guarded, idempotent
/// [`reenable_after_protected`] — which itself no-ops unless the daemon is
/// installed, the setting is on, the phase is still Protected, and the radio is
/// actually off. A failure is surfaced to the log, never swallowed silently.
pub fn on_session_protected() {
    std::thread::spawn(|| {
        if let Err(e) = reenable_after_protected() {
            crate::logs::append(format!("Hardening: Wi-Fi auto re-enable failed: {e}"));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wifi_device_comes_from_the_hardware_port_listing() {
        let listing = "\
Hardware Port: Ethernet
Device: en5
Ethernet Address: 00:11:22:33:44:55

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff
";
        assert_eq!(wifi_device_from_ports(listing).as_deref(), Some("en0"));
        assert_eq!(
            wifi_device_from_ports("Hardware Port: Ethernet\nDevice: en5"),
            None
        );
    }

    #[test]
    fn a_disabled_wifi_service_is_read_from_the_asterisk_marker() {
        let disabled = "An asterisk (*) denotes that a network service is disabled.\n*Wi-Fi\nThunderbolt Bridge\n";
        let enabled = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nThunderbolt Bridge\n";
        assert!(wifi_service_disabled(disabled));
        assert!(!wifi_service_disabled(enabled));
    }

    #[test]
    fn radio_power_is_parsed_from_networksetup() {
        assert_eq!(parse_airport_power("Wi-Fi Power (en0): On"), Some(true));
        assert_eq!(parse_airport_power("Wi-Fi Power (en0): Off\n"), Some(false));
        assert_eq!(parse_airport_power("en0 is not a Wi-Fi interface"), None);
    }

    #[test]
    fn pmset_flags_are_read_by_exact_name() {
        let out = " System-wide power settings:\nCurrently in use:\n standbydelaylow      10800\n womp                 1\n networkoversleep     0\n";
        assert_eq!(parse_pmset_flag(out, "womp"), Some(1));
        assert_eq!(parse_pmset_flag(out, "networkoversleep"), Some(0));
        assert_eq!(parse_pmset_flag(out, "hibernatemode"), None);
    }

    #[test]
    fn recorded_power_settings_round_trip() {
        let text = restore_conf(Some(1), Some(0));
        assert_eq!(parse_restore_conf(&text), (Some(1), Some(0)));
        assert_eq!(parse_restore_conf(&restore_conf(None, None)), (None, None));
    }

    /// The daemon must run the script we installed, and nothing else.
    #[test]
    fn the_daemon_plist_points_at_the_installed_script() {
        let plist = daemon_plist();
        assert!(plist.contains(&format!("<string>{LABEL}</string>")));
        assert!(plist.contains(&format!("<string>{SCRIPT_PATH}</string>")));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
    }

    /// The wake guards are the whole point of the item: without them the radio
    /// silently comes back on the first wake from sleep.
    #[test]
    fn the_boot_script_sets_both_wake_guards_and_never_calls_spoof() {
        let script = boot_script();
        assert!(script.contains("-a womp 0"));
        assert!(script.contains("-a networkoversleep 0"));
        assert!(script.contains("-setnetworkserviceenabled Wi-Fi off"));
        assert!(script.contains("-setairportpower"));
        // No MAC assignment at boot: upstream calls the `spoof` tool here, which
        // hands out real vendor OUIs. Randomization goes through the helper.
        assert!(
            !script.contains("/spoof") && !script.contains("ether "),
            "no MAC assignment at boot"
        );
        // Apple's `airport` utility was removed; only `networksetup` subcommands
        // may mention the word.
        assert!(
            !script.contains("/airport") && !script.contains("Apple80211"),
            "the airport utility is gone from macOS"
        );
        assert!(!script.contains("/Users/Shared"), "no world-writable paths");
    }

    #[test]
    fn generated_daemon_plist_passes_plutil_lint() {
        super::super::tests_support::assert_plutil_lint(&daemon_plist(), "wifi-off-at-boot.plist");
    }

    #[test]
    fn generated_boot_script_parses_as_bash() {
        super::super::tests_support::assert_bash_parses(&boot_script(), "disable-wifi-at-boot.sh");
    }

    /// The install script runs as root, so a quoting mistake in it is the worst
    /// bug this module could ship. Parse it — never execute it — in the tests.
    #[test]
    fn the_elevated_install_script_parses_and_writes_only_root_owned_paths() {
        let script = install_script(&restore_conf(Some(1), Some(0)));
        assert!(script.contains("chown -R root:wheel"));
        assert!(script.contains("plutil -lint"));
        assert!(!script.contains("launchctl bootstrap"), "must not load now");
        assert!(!script.contains("/Users/Shared"));
        super::super::tests_support::assert_bash_parses(&script, "wifi-off-install.sh");
    }

    #[test]
    fn the_elevated_uninstall_script_restores_only_recorded_values() {
        let script = uninstall_script(Some(1), Some(0));
        assert!(script.contains("pmset -a womp 1"));
        assert!(script.contains("pmset -a networkoversleep 0"));
        assert!(script.contains("-setnetworkserviceenabled Wi-Fi on"));
        super::super::tests_support::assert_bash_parses(&script, "wifi-off-uninstall.sh");

        // Nothing recorded, or a value we never write, means no pmset call.
        let empty = uninstall_script(None, None);
        assert!(!empty.contains("pmset"));
        assert!(!uninstall_script(Some(7), Some(-1)).contains("pmset"));
    }
}
