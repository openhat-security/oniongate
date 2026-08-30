//! Block every outbound NIC path at boot until OnionGate Connect replaces
//! the lock. Wi-Fi-off-at-boot does not cover Ethernet or USB LAN.
//!
//! Clean-room: written for OnionGate. The LaunchDaemon only execs a
//! root-owned script that loads a root-owned rules file synthesized at
//! install time from [`crate::firewall::strict::pf_strict_rules`] with an
//! empty allowlist. No client-authored pf text is consulted at boot.

use std::fs;
use std::process::{Command, Stdio};

pub const LABEL: &str = "com.adamsiwiec.oniongate.boot-lock";
pub const SUPPORT_DIR: &str = "/Library/Application Support/OnionGate/boot-lock";
pub const SCRIPT_PATH: &str = "/Library/Application Support/OnionGate/boot-lock/apply-boot-lock.sh";
pub const RULES_PATH: &str = "/Library/Application Support/OnionGate/boot-lock/pf.conf";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.adamsiwiec.oniongate.boot-lock.plist";

const LOCK_ANCHOR: &str = "com.apple/oniongate.lock";

#[derive(Debug, Clone)]
pub struct BootLockStatus {
    pub installed: bool,
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

fn root_owned(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).map(|m| m.uid() == 0).unwrap_or(false)
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

/// Default-deny with loopback and DHCP only. No Tor endpoints: Tor is not
/// running at boot. Connect replaces this anchor once it has an allowlist.
pub fn boot_rules() -> String {
    crate::firewall::strict::pf_strict_rules(&[], &[], false)
}

pub fn boot_script() -> String {
    format!(
        r#"#!/bin/bash
# OnionGate — default-deny outbound IP at boot until Connect replaces this lock.
set -euo pipefail
RULES='{RULES_PATH}'
ANCHOR='{LOCK_ANCHOR}'

if [ ! -f "$RULES" ] || [ -L "$RULES" ]; then
  exit 1
fi
if [ "$(/usr/bin/stat -f %u "$RULES")" != "0" ]; then
  exit 1
fi
mode="$(/usr/bin/stat -f %Lp "$RULES")"
case "$mode" in
  400|444|600|644) ;;
  *) exit 1 ;;
esac

/sbin/pfctl -e >/dev/null 2>&1 || true
/sbin/pfctl -a "$ANCHOR" -f "$RULES"
"#
    )
}

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
</dict>
</plist>
"#
    )
}

pub fn status() -> BootLockStatus {
    let plist = fs::read_to_string(PLIST_PATH).unwrap_or_default();
    let script_present = std::path::Path::new(SCRIPT_PATH).is_file();
    let rules_present = std::path::Path::new(RULES_PATH).is_file();
    let points_at_script = plist.contains(SCRIPT_PATH) && plist.contains(LABEL);
    let installed = script_present
        && rules_present
        && points_at_script
        && root_owned(SCRIPT_PATH)
        && root_owned(RULES_PATH);

    let live = run_out("/sbin/pfctl", &["-a", LOCK_ANCHOR, "-sr"]);
    let live_deny = live.contains("block") && live.contains("from any to any");
    let registered = daemon_registered();

    let mut detail = if installed {
        "Boot network lock installed".to_string()
    } else if script_present || rules_present || !plist.is_empty() {
        "Boot lock files are incomplete or not root-owned".to_string()
    } else {
        "This Mac has a clearnet window from power-on until you Connect".to_string()
    };
    if installed {
        detail.push_str(if registered {
            " · loaded in launchd"
        } else {
            " · takes effect at the next boot"
        });
    }
    if live_deny {
        detail.push_str(" · default-deny is live now");
    }

    BootLockStatus { installed, detail }
}

fn heredoc(path: &str, marker: &str, body: &str) -> String {
    format!("/bin/cat > {path} <<'{marker}'\n{body}{marker}\n")
}

fn quote(path: &str) -> String {
    crate::elevate::shell_quote(path)
}

pub fn install_script() -> String {
    let dir = quote(SUPPORT_DIR);
    let script = quote(SCRIPT_PATH);
    let rules = quote(RULES_PATH);
    let plist = quote(PLIST_PATH);
    format!(
        "set -e\n\
         /bin/mkdir -p {dir}\n\
         {script_doc}\
         {rules_doc}\
         {plist_doc}\
         /usr/sbin/chown -R root:wheel {dir}\n\
         /bin/chmod 755 {dir}\n\
         /bin/chmod 755 {script}\n\
         /bin/chmod 644 {rules}\n\
         /usr/sbin/chown root:wheel {plist}\n\
         /bin/chmod 644 {plist}\n\
         /usr/bin/plutil -lint {plist}\n",
        script_doc = heredoc(&script, "OGBOOTSCRIPT", &boot_script()),
        rules_doc = heredoc(&rules, "OGBOOTRULES", &boot_rules()),
        plist_doc = heredoc(&plist, "OGBOOTPLIST", &daemon_plist()),
    )
}

pub fn install() -> Result<String, String> {
    crate::elevate::run_shell_with_prompt(
        &install_script(),
        "OnionGate needs administrator access to install the boot network lock.",
    )?;
    // Do not load now: that would cut the current session, including this
    // install. launchd picks the daemon up at the next boot.
    crate::logs::append("Hardening: boot network lock installed");
    Ok("The network will be blocked at the next boot until you Connect. Nothing changed on the current connection.".into())
}

pub fn uninstall_script() -> String {
    let dir = quote(SUPPORT_DIR);
    let plist = quote(PLIST_PATH);
    format!(
        "/bin/launchctl bootout system/{LABEL} 2>/dev/null || true\n\
         /sbin/pfctl -a {LOCK_ANCHOR} -F all 2>/dev/null || true\n\
         /bin/rm -f {plist}\n\
         /bin/rm -rf {dir}\n"
    )
}

pub fn uninstall() -> Result<String, String> {
    crate::elevate::run_shell_with_prompt(
        &uninstall_script(),
        "OnionGate needs administrator access to remove the boot network lock.",
    )?;
    crate::logs::append("Hardening: boot network lock removed");
    Ok("Boot network lock removed. The next restart will not block the network.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_rules_are_default_deny_without_tor_endpoints() {
        let rules = boot_rules();
        assert!(rules.contains("pass out quick on lo0 all"));
        assert!(rules.contains("pass out log proto udp from any port 68 to any port 67"));
        assert!(rules.contains("block drop out log quick from any to any"));
        assert!(
            !rules.contains("pass out proto tcp to "),
            "boot lock must not pre-allow Tor endpoints"
        );
        assert!(!rules.contains("10.0.0.0/8"), "boot lock must not open LAN");
    }

    #[test]
    fn the_daemon_plist_points_at_the_installed_script() {
        let plist = daemon_plist();
        assert!(plist.contains(&format!("<string>{LABEL}</string>")));
        assert!(plist.contains(&format!("<string>{SCRIPT_PATH}</string>")));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
        assert!(!plist.contains("KeepAlive</key>\n  <true/>"));
    }

    #[test]
    fn the_boot_script_loads_only_the_root_owned_rules_file() {
        let script = boot_script();
        assert!(script.contains(RULES_PATH));
        assert!(script.contains(LOCK_ANCHOR));
        assert!(script.contains("pfctl -a"));
        assert!(script.contains("stat -f %u"));
        assert!(!script.contains("/Users/Shared"));
        assert!(!script.contains("networksetup"));
    }

    #[test]
    fn generated_daemon_plist_passes_plutil_lint() {
        super::super::tests_support::assert_plutil_lint(&daemon_plist(), "boot-lock.plist");
    }

    #[test]
    fn generated_boot_script_parses_as_bash() {
        super::super::tests_support::assert_bash_parses(&boot_script(), "apply-boot-lock.sh");
    }

    #[test]
    fn the_elevated_install_script_parses_and_does_not_load_now() {
        let script = install_script();
        assert!(script.contains("chown -R root:wheel"));
        assert!(script.contains("plutil -lint"));
        assert!(!script.contains("launchctl bootstrap"), "must not load now");
        super::super::tests_support::assert_bash_parses(&script, "boot-lock-install.sh");
    }

    #[test]
    fn the_elevated_uninstall_script_parses_and_flushes_the_lock() {
        let script = uninstall_script();
        assert!(script.contains("bootout"));
        assert!(script.contains("pfctl -a"));
        super::super::tests_support::assert_bash_parses(&script, "boot-lock-uninstall.sh");
    }
}
