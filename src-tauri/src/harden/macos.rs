//! macOS privacy/security toggles (term7 SETTINGS + privacy.sexy inspired, clean-room).

use std::process::{Command, Stdio};

use super::HardenItem;

fn item(
    id: &str,
    title: &str,
    description: &str,
    active: bool,
    supported: bool,
    detail: &str,
    group: &str,
    control: &str,
    risk: &str,
) -> HardenItem {
    HardenItem {
        id: id.into(),
        title: title.into(),
        description: description.into(),
        active,
        supported,
        detail: detail.into(),
        group: group.into(),
        control: control.into(),
        risk: risk.into(),
    }
}

fn run_out(bin: &str, args: &[&str]) -> String {
    Command::new(bin)
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            Some(s)
        })
        .unwrap_or_default()
}

fn defaults_read(domain: &str, key: &str) -> String {
    run_out("defaults", &["read", domain, key])
        .trim()
        .to_string()
}

fn defaults_bool(domain: &str, key: &str, default: bool) -> bool {
    let v = defaults_read(domain, key).to_ascii_lowercase();
    if v == "1" || v == "true" || v == "yes" {
        return true;
    }
    if v == "0" || v == "false" || v == "no" {
        return false;
    }
    default
}

fn is_apple_silicon() -> bool {
    run_out("uname", &["-m"]).trim() == "arm64"
}

fn firewall_enabled() -> bool {
    let t = run_out(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    )
    .to_ascii_lowercase();
    // Prefer State= — wording varies; avoid substring traps.
    if t.contains("state = 1") || t.contains("state=1") {
        return true;
    }
    if t.contains("state = 0") || t.contains("state=0") {
        return false;
    }
    let alf = defaults_read("/Library/Preferences/com.apple.alf", "globalstate");
    if alf == "1" || alf == "2" {
        return true;
    }
    if alf == "0" {
        return false;
    }
    t.contains("enabled") && !t.contains("disabled")
}

fn firewall_stealth() -> bool {
    // Actual output: "Firewall stealth mode is on" / "… is off" (not "enabled").
    let t = run_out(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getstealthmode"],
    )
    .to_ascii_lowercase();
    if t.contains("is on") {
        return true;
    }
    if t.contains("is off") {
        return false;
    }
    let alf = defaults_read("/Library/Preferences/com.apple.alf", "stealthenabled");
    alf == "1" || alf.eq_ignore_ascii_case("true")
}

fn macos_major() -> u32 {
    run_out("sw_vers", &["-productVersion"])
        .trim()
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Per-user Lockdown Mode (Ventura+). Key may be absent when never enabled.
fn lockdown_enabled() -> bool {
    let v = run_out("defaults", &["read", "-g", "LDMGlobalEnabled"])
        .trim()
        .to_ascii_lowercase();
    v == "1" || v == "true"
}

fn remote_login_on() -> bool {
    // `systemsetup -getremotelogin` requires root even to read status (it prints
    // "You need administrator access to run this tool... exiting!" otherwise).
    // Detect the SSH listener without elevation: is anything listening on :22?
    // The apply path still uses systemsetup via an admin prompt to change it.
    let out = run_out("netstat", &["-an"]);
    out.lines().any(|line| {
        line.contains("LISTEN") && line.split_whitespace().any(|col| col.ends_with(".22"))
    })
}

fn guest_enabled() -> bool {
    defaults_bool(
        "/Library/Preferences/com.apple.loginwindow",
        "GuestEnabled",
        false,
    )
}

fn filevault_on() -> bool {
    run_out("fdesetup", &["status"])
        .to_ascii_lowercase()
        .contains("on")
}

fn printer_sharing_on() -> bool {
    let t = run_out("cupsctl", &[]);
    t.contains("_share_printers=1") || t.contains("SharePrinters Yes")
}

/// Bonjour / mDNSResponder multicast advertisements (privacy.sexy-inspired).
fn bonjour_multicast_off() -> bool {
    let v = defaults_read(
        "/Library/Preferences/com.apple.mDNSResponder",
        "NoMulticastAdvertisements",
    )
    .to_ascii_lowercase();
    v == "1" || v == "true" || v == "yes"
}

/// Application firewall auto-allow for signed / downloaded signed apps.
fn firewall_auto_signed_on() -> bool {
    let signed = run_out(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getallowsigned"],
    )
    .to_ascii_lowercase();
    let downloaded = run_out(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getallowsignedapp"],
    )
    .to_ascii_lowercase();
    let signed_on = signed.contains("enabled") && !signed.contains("disabled");
    let dl_on = downloaded.contains("enabled") && !downloaded.contains("disabled");
    signed_on || dl_on
}

fn guest_smb_on() -> bool {
    defaults_bool(
        "/Library/Preferences/SystemConfiguration/com.apple.smb.server",
        "AllowGuestAccess",
        false,
    )
}

fn brew_installed() -> bool {
    Command::new("which")
        .arg("brew")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn homebrew_analytics_off() -> bool {
    if std::env::var_os("HOMEBREW_NO_ANALYTICS").is_some() {
        return true;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    for name in [".zprofile", ".bash_profile", ".zshrc", ".bashrc"] {
        let path = format!("{home}/{name}");
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if contents.lines().any(|l| {
                let t = l.trim();
                t.contains("HOMEBREW_NO_ANALYTICS=1") && !t.starts_with('#')
            }) {
                return true;
            }
        }
    }
    false
}

fn remote_management_on() -> bool {
    let pref = defaults_read(
        "/Library/Preferences/com.apple.RemoteManagement",
        "ARDAgentEnabled",
    )
    .to_ascii_lowercase();
    if pref == "1" || pref == "true" {
        return true;
    }
    Command::new("pgrep")
        .args(["-x", "ARDAgent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn remote_apple_events_on() -> bool {
    let t = run_out("systemsetup", &["-getremoteappleevents"]).to_ascii_lowercase();
    if t.contains("on") && !t.contains("off") {
        return true;
    }
    // ARD / screensharing agents
    Command::new("pgrep")
        .args(["-x", "AppleVNCServer"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn spotlight_indexing_on() -> bool {
    let t = run_out("mdutil", &["-s", "/"]);
    !t.to_ascii_lowercase().contains("disabled")
}

fn siri_enabled() -> bool {
    // Various keys across releases; treat as on unless clearly disabled.
    let ask = defaults_read("com.apple.assistant.support", "Assistant Enabled");
    if ask == "0" || ask.eq_ignore_ascii_case("false") {
        return false;
    }
    let status = defaults_read("com.apple.Siri", "StatusMenuVisible");
    if status == "0" {
        return false;
    }
    true
}

fn elevate(script: &str) -> Result<(), String> {
    crate::elevate::run_shell(script)
}

fn hardware_uuid() -> String {
    run_out("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])
        .lines()
        .find_map(|line| {
            if line.contains("IOPlatformUUID") {
                line.split('"').nth(3).map(|s| s.to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// Best-effort Location Services probe (may need prior admin auth for `sudo -n`).
fn location_services_on() -> Option<bool> {
    // STIG-style: read as _locationd without prompting.
    if let Ok(out) = Command::new("sudo")
        .args([
            "-n",
            "-u",
            "_locationd",
            "/usr/bin/defaults",
            "-currentHost",
            "read",
            "com.apple.locationd",
            "LocationServicesEnabled",
        ])
        .output()
    {
        if out.status.success() {
            let v = String::from_utf8_lossy(&out.stdout)
                .trim()
                .to_ascii_lowercase();
            if v == "1" || v == "true" {
                return Some(true);
            }
            if v == "0" || v == "false" {
                return Some(false);
            }
        }
    }
    let uuid = hardware_uuid();
    if !uuid.is_empty() {
        let path =
            format!("/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.{uuid}");
        if let Ok(out) = Command::new("sudo")
            .args(["-n", "defaults", "read", &path, "LocationServicesEnabled"])
            .output()
        {
            if out.status.success() {
                let v = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .to_ascii_lowercase();
                if v == "1" || v == "true" {
                    return Some(true);
                }
                if v == "0" || v == "false" {
                    return Some(false);
                }
            }
        }
    }
    None
}

fn set_location_services(enabled: bool) -> Result<(), String> {
    let val = if enabled { "true" } else { "false" };
    // Write both legacy and ByHost UUID paths; kickstart locationd.
    let script = format!(
        r#"UUID=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice | /usr/bin/awk -F'"' '/IOPlatformUUID/{{print $4}}')
/usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool {val}
if [ -n "$UUID" ]; then
  /usr/bin/defaults write "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.$UUID" LocationServicesEnabled -bool {val}
fi
/usr/sbin/chown -R _locationd:_locationd /var/db/locationd/Library/Preferences/ByHost 2>/dev/null || true
/bin/launchctl kickstart -k system/com.apple.locationd
"#
    );
    elevate(&script)
}

fn dock_show_recents() -> bool {
    defaults_bool("com.apple.dock", "show-recents", true)
}

/// Persist Dock recent-apps visibility and force Dock to reload prefs.
fn set_dock_show_recents(show: bool) -> Result<(), String> {
    // Do NOT kill cfprefsd — that races the write and often leaves Dock with the
    // old value (hide sticks, restore looks broken).
    // `defaults delete` + write true is the reliable “restore default shown” path.
    if show {
        let _ = Command::new("/usr/bin/defaults")
            .args(["delete", "com.apple.dock", "show-recents"])
            .status();
        let ok = Command::new("/usr/bin/defaults")
            .args(["write", "com.apple.dock", "show-recents", "-bool", "true"])
            .status()
            .map_err(|e| e.to_string())?
            .success();
        if !ok {
            return Err("defaults write show-recents true failed".into());
        }
        let _ = Command::new("/usr/bin/defaults")
            .args(["write", "com.apple.dock", "show-recent-count", "-int", "3"])
            .status();
    } else {
        let ok = Command::new("/usr/bin/defaults")
            .args(["write", "com.apple.dock", "show-recents", "-bool", "false"])
            .status()
            .map_err(|e| e.to_string())?
            .success();
        if !ok {
            return Err("defaults write show-recents false failed".into());
        }
    }

    // Give cfprefsd a moment to persist, then restart Dock only.
    std::thread::sleep(std::time::Duration::from_millis(250));
    let _ = Command::new("/usr/bin/killall")
        .arg("Dock")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let _ = Command::new("/usr/bin/open")
        .args(["-a", "Dock"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

pub fn list() -> Vec<HardenItem> {
    let kill = crate::harden::kill_siri::status();
    let ports = crate::harden::macports::status();
    let apple_si = is_apple_silicon();

    let kill_detail = if kill.running.is_empty() {
        kill.detail.clone()
    } else {
        format!("{} — active: {}", kill.detail, kill.running.join(", "))
    };

    let connection_filter = crate::ne_filter::status();

    let loc = location_services_on();
    let loc_active = matches!(loc, Some(false));
    let loc_detail = match loc {
        Some(true) => "Location Services appear on",
        Some(false) => "Location Services appear off",
        None => "Status unknown until toggled (needs admin to read locationd)",
    };

    vec![
        // —— Privacy (toggle ON = disable / harden the named feature) ——
        item(
            "remote_events",
            "Disable Remote Apple Events / Management",
            "Turns off Remote Apple Events and stops obvious ARD/VNC helpers when possible.",
            !remote_apple_events_on(),
            true,
            if remote_apple_events_on() {
                "Remote access still appears on"
            } else {
                "Remote Apple Events appear off"
            },
            "privacy",
            "toggle",
            "Remote management can expose your Mac on the LAN.",
        ),
        item(
            "siri_prefs",
            "Disable Siri (preferences)",
            "Turns off Ask Siri / Siri menu via defaults (best-effort).",
            !siri_enabled(),
            true,
            if siri_enabled() {
                "Siri preferences still look on"
            } else {
                "Siri preferences look off"
            },
            "privacy",
            "toggle",
            "Some Siri daemons may still run until Kill Siri is installed.",
        ),
        item(
            "kill_siri",
            "Kill Siri killswitch",
            "Install a LaunchAgent watchdog that kills Siri-related processes when Assistant activity is detected. SIP stays on.",
            kill.installed && kill.agent_loaded,
            true,
            &kill_detail,
            "privacy",
            "install",
            "Watchdog only — OS may respawn processes. This is outside OnionGate's core protection boundary.",
        ),
        item(
            "spotlight_index",
            "Disable Spotlight indexing",
            "Turns off Spotlight indexing on / via mdutil (admin).",
            !spotlight_indexing_on(),
            true,
            if spotlight_indexing_on() {
                "Indexing still enabled on /"
            } else {
                "Indexing disabled on /"
            },
            "privacy",
            "toggle",
            "Slows local search; reversible by toggling off.",
        ),
        item(
            "web_spell",
            "Disable internet spell correction",
            "Turns off continuous / web automatic spelling correction.",
            !defaults_bool("NSGlobalDomain", "WebAutomaticSpellingCorrectionEnabled", true)
                && !defaults_bool("NSGlobalDomain", "NSAutomaticSpellingCorrectionEnabled", true),
            true,
            "NSGlobalDomain spelling correction keys",
            "privacy",
            "toggle",
            "May send typing patterns to Apple depending on OS version.",
        ),
        item(
            "analytics",
            "Disable Analytics & diagnostics",
            "Opts out of sharing analytics / diagnostic data where defaults allow. Toggle on = analytics off.",
            {
                let auto = defaults_read("com.apple.SubmitDiagInfo", "AutoSubmit");
                auto == "0" || auto.eq_ignore_ascii_case("false")
            },
            true,
            "SubmitDiagInfo AutoSubmit",
            "privacy",
            "toggle",
            "Reduces outbound diagnostic traffic to Apple.",
        ),
        item(
            "personalized_ads",
            "Disable personalized ads & ad ID",
            "Turns off Apple personalized advertising and the advertising identifier.",
            {
                let personalized = defaults_bool(
                    "com.apple.AdLib",
                    "allowApplePersonalizedAdvertising",
                    true,
                ) == false;
                let ad_id = defaults_bool("com.apple.AdLib", "allowIdentifierForAdvertising", true)
                    == false;
                let limited = defaults_bool("com.apple.AdLib", "forceLimitAdTracking", false);
                personalized || ad_id || limited
            },
            true,
            "com.apple.AdLib advertising prefs",
            "privacy",
            "toggle",
            "Reduces ad identifier use; not a full tracker blocker.",
        ),
        item(
            "screenshot_dates",
            "Disable dates in screenshot names",
            "Omits date/time from screenshot filenames (metadata hygiene).",
            defaults_bool("com.apple.screencapture", "include-date", true) == false,
            true,
            "com.apple.screencapture include-date",
            "privacy",
            "toggle",
            "Filenames still reveal you took a screenshot; only strips the timestamp.",
        ),
        item(
            "homebrew_analytics",
            "Disable Homebrew analytics",
            "Sets HOMEBREW_NO_ANALYTICS=1 in your shell profile when Homebrew is installed.",
            homebrew_analytics_off(),
            brew_installed(),
            if brew_installed() {
                if homebrew_analytics_off() {
                    "HOMEBREW_NO_ANALYTICS configured"
                } else {
                    "Homebrew analytics still allowed"
                }
            } else {
                "Homebrew not found"
            },
            "privacy",
            "toggle",
            "Only affects Homebrew CLI telemetry; open a new terminal after changing.",
        ),
        item(
            "location_services",
            "Disable Location Services",
            "Turns off system Location Services via locationd (admin). May need a restart to fully apply.",
            loc_active,
            true,
            loc_detail,
            "privacy",
            "toggle",
            "Breaks Maps, Find My, weather location, and many apps. High impact — only if you accept that.",
        ),
        item(
            "icloud_docs",
            "Disable iCloud default for new documents",
            "Prefer local disk for new documents (NSDocumentSaveNewDocumentsToCloud=false).",
            !defaults_bool("NSGlobalDomain", "NSDocumentSaveNewDocumentsToCloud", true),
            true,
            "NSDocumentSaveNewDocumentsToCloud",
            "privacy",
            "toggle",
            "Stops accidental cloud uploads of new files.",
        ),
        item(
            "airdrop",
            "Disable AirDrop",
            "Sets AirDrop discoverability to Off.",
            defaults_read("com.apple.NetworkBrowser", "DisableAirDrop") == "1"
                || defaults_read("com.apple.sharingd", "DiscoverableMode")
                    .to_ascii_lowercase()
                    .contains("off"),
            true,
            "AirDrop discoverability",
            "privacy",
            "toggle",
            "AirDrop can expose your device name nearby.",
        ),
        item(
            "dock_recents",
            "Disable Dock recent apps",
            "Hides the recent-applications section in the Dock. Toggle off restores it.",
            !dock_show_recents(),
            true,
            if dock_show_recents() {
                "Recent apps section enabled (show-recents=true)"
            } else {
                "Recent apps section hidden (show-recents=false)"
            },
            "privacy",
            "toggle",
            "Hides recently used apps from shoulder-surfing.",
        ),
        // —— Security ——
        item(
            "captive_portal",
            "Disable Captive Portal assistant",
            "Stops the automatic captive-portal login helper.",
            defaults_read(
                "/Library/Preferences/SystemConfiguration/com.apple.captive.control",
                "Active",
            ) == "0",
            true,
            "com.apple.captive.control Active",
            "security",
            "toggle",
            "May break auto Wi‑Fi captive login pages; connect manually if needed.",
        ),
        item(
            "app_firewall",
            "Enable Application firewall",
            "Turns on the macOS application firewall (socketfilterfw).",
            firewall_enabled(),
            true,
            if firewall_enabled() {
                "Firewall is on"
            } else {
                "Firewall is off"
            },
            "security",
            "toggle",
            "Blocks unexpected inbound connections.",
        ),
        item(
            "firewall_stealth",
            "Enable Firewall stealth mode",
            "Ignores unexpected ICMP / closed-port probes.",
            firewall_stealth(),
            firewall_enabled(),
            if firewall_stealth() {
                "Stealth mode is on"
            } else {
                "Stealth mode is off (enable firewall first)"
            },
            "security",
            "toggle",
            "Makes the Mac less visible on untrusted networks.",
        ),
        item(
            "guest_account",
            "Disable Guest account",
            "Turns off the Guest user on the login window.",
            !guest_enabled(),
            true,
            if guest_enabled() {
                "Guest account is on"
            } else {
                "Guest account is off"
            },
            "security",
            "toggle",
            "Guest sessions can leave residual data on shared machines.",
        ),
        item(
            "remote_login",
            "Disable Remote Login (SSH)",
            "Turns off Remote Login via systemsetup.",
            !remote_login_on(),
            true,
            if remote_login_on() {
                "SSH / Remote Login is on"
            } else {
                "Remote Login is off"
            },
            "security",
            "toggle",
            "SSH is a common remote-attack surface when exposed.",
        ),
        item(
            "bonjour_ads",
            "Disable AirPlay receiver",
            "Limits AirPlay receiver advertising and related discoverability.",
            defaults_bool("com.apple.controlcenter", "AirplayRecieverEnabled", true) == false
                || defaults_read("com.apple.controlcenter", "AirplayRecieverEnabled") == "0",
            true,
            "AirPlay receiver prefs",
            "security",
            "toggle",
            "Reduces LAN discovery of your Mac.",
        ),
        item(
            "bonjour_mdns",
            "Disable Bonjour multicast ads",
            "Sets mDNSResponder NoMulticastAdvertisements (admin). Limits LAN service advertising.",
            bonjour_multicast_off(),
            true,
            if bonjour_multicast_off() {
                "NoMulticastAdvertisements=true"
            } else {
                "Multicast advertisements allowed"
            },
            "security",
            "toggle",
            "Can break some local device discovery (printers, AirPlay targets).",
        ),
        item(
            "fw_signed_auto",
            "Block auto-allow signed apps (firewall)",
            "Stops the application firewall from automatically allowing signed / downloaded signed apps.",
            firewall_enabled() && !firewall_auto_signed_on(),
            firewall_enabled(),
            if !firewall_enabled() {
                "Enable Application firewall first"
            } else if firewall_auto_signed_on() {
                "Signed apps still auto-allowed"
            } else {
                "Signed-app auto-allow disabled"
            },
            "security",
            "toggle",
            "You may need to approve inbound apps manually in Firewall options.",
        ),
        item(
            "guest_smb",
            "Disable Guest SMB sharing",
            "Turns off guest access to shared folders over SMB.",
            !guest_smb_on(),
            true,
            if guest_smb_on() {
                "Guest SMB access on"
            } else {
                "Guest SMB access off"
            },
            "security",
            "toggle",
            "Separate from the Guest login account toggle.",
        ),
        item(
            "remote_mgmt",
            "Disable Remote Management (ARD)",
            "Deactivates Apple Remote Desktop / Remote Management agent (admin).",
            !remote_management_on(),
            true,
            if remote_management_on() {
                "Remote Management appears active"
            } else {
                "Remote Management off / inactive"
            },
            "security",
            "toggle",
            "Stops ARDAgent remote control surface when it was enabled.",
        ),
        item(
            "printer_sharing",
            "Disable printer sharing",
            "cupsctl --no-share-printers",
            !printer_sharing_on(),
            which::which("cupsctl").is_ok(),
            if printer_sharing_on() {
                "Printer sharing is on"
            } else {
                "Printer sharing is off"
            },
            "security",
            "toggle",
            "Shared printers are reachable on the local network.",
        ),
        item(
            "screensaver_lock",
            "Enable password after screen saver",
            "Requires password immediately after idle lock.",
            defaults_bool("com.apple.screensaver", "askForPassword", false)
                && defaults_read("com.apple.screensaver", "askForPasswordDelay")
                    .trim()
                    .parse::<i64>()
                    .unwrap_or(999)
                    == 0,
            true,
            "Screen saver password delay",
            "security",
            "toggle",
            "Prevents walk-up access after the display sleeps.",
        ),
        item(
            "filevault",
            "FileVault status",
            "Reports disk encryption status. Enable FileVault in System Settings (not forced here).",
            filevault_on(),
            true,
            if filevault_on() {
                "FileVault is On"
            } else {
                "FileVault is Off — open Settings to enable"
            },
            "security",
            "guide",
            "Full-disk encryption protects data at rest if the Mac is stolen.",
        ),
        item(
            "firmware_password",
            "Firmware password (Intel)",
            "Guide only — setting a firmware password is interactive and Intel-only.",
            false,
            !apple_si,
            if apple_si {
                "Not applicable on Apple Silicon"
            } else {
                "Use Startup Security Utility / firmwarepasswd interactively"
            },
            "security",
            "guide",
            "Prevents booting from external media on Intel Macs.",
        ),
        {
            let filter = &connection_filter;
            item(
                "connection_filter",
                "Connection filter (Network Extension)",
                "LuLu-style hold-and-drop for outbound flows that are not already Tor. pf stays the packet lock. Apple can hide some of its own processes from this filter.",
                filter.installed && filter.running,
                true,
                &filter.detail,
                "security",
                "toggle",
                "Needs a signed build with a network-extension profile and your approval in System Settings. Default verdict is drop. Allow does not punch clearnet. If the filter is installed and this setting is on, a dead or bypassed filter marks the session Degraded. Blocked on Apple Developer Program enrollment.",
            )
        },
        item(
            "mac_random",
            "Private Wi‑Fi address (guide)",
            "Enable Private Wi‑Fi Address per network in System Settings.",
            false,
            true,
            "System Settings → Wi‑Fi → Details → Private Wi‑Fi Address",
            "security",
            "guide",
            "Reduces long-term Wi‑Fi tracking by BSSID.",
        ),
        // —— Tools ——
        item(
            "clear_dns_cache",
            "Flush DNS cache",
            "Clears the local DNS resolver cache (useful after changing Tor / proxy DNS).",
            false,
            true,
            "dscacheutil + mDNSResponder HUP",
            "tools",
            "action",
            "One-shot; does not change DNS settings.",
        ),
        item(
            "macports",
            "MacPorts",
            "Optional package manager. Detects MacPorts and opens the official installer if requested.",
            ports.installed,
            true,
            &ports.detail,
            "tools",
            "link",
            "Not required by OnionGate. Use only macports.org / official GitHub releases.",
        ),
        // —— Lockdown (separate, invasive) ——
        {
            let on = lockdown_enabled();
            let ventura_plus = macos_major() >= 13;
            item(
                "lockdown_mode",
                "Lockdown Mode",
                "Extreme hardening against sophisticated spyware (macOS 13+). Status from LDMGlobalEnabled; confirm in System Settings. A restart is usually required.",
                on,
                ventura_plus,
                if !ventura_plus {
                    "Requires macOS Ventura (13) or later"
                } else if on {
                    "On (LDMGlobalEnabled=1) — restart if you just changed this"
                } else {
                    "Off — enable only if you accept major feature breakage"
                },
                "lockdown",
                "toggle",
                "HIGHLY INVASIVE: blocks most message attachments, limits FaceTime and web features (fonts, JIT, complex CSS), disables configuration profiles / remote management, restricts USB accessories when locked, and breaks everyday convenience. For high-risk threat models only — not a casual privacy toggle.",
            )
        },
    ]
}

pub async fn apply(id: &str, enable: bool) -> Result<String, String> {
    match id {
        "remote_events" => {
            if enable {
                // enable=true means "hardening on" → disable remote events
                elevate("systemsetup -setremoteappleevents off; launchctl bootout system /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null || true")?;
                Ok("Remote Apple Events disabled (best-effort)".into())
            } else {
                elevate("systemsetup -setremoteappleevents on")?;
                Ok("Remote Apple Events enabled".into())
            }
        }
        "siri_prefs" => {
            if enable {
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.assistant.support",
                        "Assistant Enabled",
                        "-bool",
                        "false",
                    ])
                    .status();
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.Siri",
                        "StatusMenuVisible",
                        "-bool",
                        "false",
                    ])
                    .status();
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.Siri",
                        "LockscreenEnabled",
                        "-bool",
                        "false",
                    ])
                    .status();
                let _ = Command::new("launchctl")
                    .args(["disable", "gui/$(id -u)/com.apple.assistantd"])
                    .status();
                Ok("Siri preferences disabled (best-effort). Consider Kill Siri for process killswitch.".into())
            } else {
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.assistant.support",
                        "Assistant Enabled",
                        "-bool",
                        "true",
                    ])
                    .status();
                Ok("Siri preferences re-enabled (best-effort)".into())
            }
        }
        "kill_siri" => {
            if enable {
                crate::harden::kill_siri::install()
            } else {
                crate::harden::kill_siri::uninstall()
            }
        }
        "spotlight_index" => {
            if enable {
                elevate("mdutil -i off /")?;
                Ok("Spotlight indexing disabled on /".into())
            } else {
                elevate("mdutil -i on /")?;
                Ok("Spotlight indexing enabled on /".into())
            }
        }
        "web_spell" => {
            let val = if enable { "false" } else { "true" };
            let _ = Command::new("defaults")
                .args([
                    "write",
                    "NSGlobalDomain",
                    "WebAutomaticSpellingCorrectionEnabled",
                    "-bool",
                    val,
                ])
                .status();
            let _ = Command::new("defaults")
                .args([
                    "write",
                    "NSGlobalDomain",
                    "NSAutomaticSpellingCorrectionEnabled",
                    "-bool",
                    val,
                ])
                .status();
            Ok(if enable {
                "Internet / automatic spell correction disabled".into()
            } else {
                "Spell correction re-enabled".into()
            })
        }
        "analytics" => {
            if enable {
                elevate("defaults write /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit -bool false; defaults write com.apple.SubmitDiagInfo AutoSubmit -bool false")?;
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.assistant.support",
                        "Siri Data Sharing Opt-In Status",
                        "-int",
                        "0",
                    ])
                    .status();
                Ok("Analytics / diagnostic auto-submit disabled (best-effort)".into())
            } else {
                elevate("defaults write /Library/Preferences/com.apple.SubmitDiagInfo AutoSubmit -bool true")?;
                Ok("Analytics auto-submit re-enabled".into())
            }
        }
        "personalized_ads" => {
            if enable {
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.AdLib",
                        "allowApplePersonalizedAdvertising",
                        "-bool",
                        "false",
                    ])
                    .status();
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.AdLib",
                        "allowIdentifierForAdvertising",
                        "-bool",
                        "false",
                    ])
                    .status();
                let _ = elevate(
                    "defaults write /Library/Preferences/com.apple.AdLib forceLimitAdTracking -bool true",
                );
                Ok("Personalized ads and advertising identifier limited".into())
            } else {
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.AdLib",
                        "allowApplePersonalizedAdvertising",
                        "-bool",
                        "true",
                    ])
                    .status();
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.AdLib",
                        "allowIdentifierForAdvertising",
                        "-bool",
                        "true",
                    ])
                    .status();
                let _ = elevate(
                    "defaults delete /Library/Preferences/com.apple.AdLib forceLimitAdTracking 2>/dev/null || true",
                );
                Ok("Personalized ads preferences restored".into())
            }
        }
        "screenshot_dates" => {
            let val = if enable { "false" } else { "true" };
            let _ = Command::new("defaults")
                .args([
                    "write",
                    "com.apple.screencapture",
                    "include-date",
                    "-bool",
                    val,
                ])
                .status();
            let _ = Command::new("killall").arg("SystemUIServer").status();
            Ok(if enable {
                "Screenshot filenames no longer include date/time".into()
            } else {
                "Screenshot date/time in filenames restored".into()
            })
        }
        "homebrew_analytics" => {
            if !brew_installed() {
                return Err("Homebrew is not installed".into());
            }
            let home = std::env::var("HOME").map_err(|_| "HOME unset".to_string())?;
            let profile = format!("{home}/.zprofile");
            let marker = "export HOMEBREW_NO_ANALYTICS=1";
            if enable {
                let mut contents = std::fs::read_to_string(&profile).unwrap_or_default();
                if !contents.contains("HOMEBREW_NO_ANALYTICS=1") {
                    if !contents.is_empty() && !contents.ends_with('\n') {
                        contents.push('\n');
                    }
                    contents.push_str(marker);
                    contents.push('\n');
                    std::fs::write(&profile, contents)
                        .map_err(|e| format!("write {profile}: {e}"))?;
                }
                Ok("HOMEBREW_NO_ANALYTICS=1 added to ~/.zprofile — open a new terminal".into())
            } else {
                if let Ok(contents) = std::fs::read_to_string(&profile) {
                    let filtered: String = contents
                        .lines()
                        .filter(|l| !l.contains("HOMEBREW_NO_ANALYTICS=1"))
                        .fold(String::new(), |mut acc, l| {
                            acc.push_str(l);
                            acc.push('\n');
                            acc
                        });
                    std::fs::write(&profile, filtered)
                        .map_err(|e| format!("write {profile}: {e}"))?;
                }
                Ok("HOMEBREW_NO_ANALYTICS removed from ~/.zprofile".into())
            }
        }
        "location_services" | "location_guide" => {
            if enable {
                set_location_services(false)?;
                Ok(
                    "Location Services disabled (admin). Restart if Settings still shows On."
                        .into(),
                )
            } else {
                set_location_services(true)?;
                Ok(
                    "Location Services re-enabled (admin). Restart if Settings still shows Off."
                        .into(),
                )
            }
        }
        "icloud_docs" => {
            let val = if enable { "false" } else { "true" };
            let _ = Command::new("defaults")
                .args([
                    "write",
                    "NSGlobalDomain",
                    "NSDocumentSaveNewDocumentsToCloud",
                    "-bool",
                    val,
                ])
                .status();
            Ok(if enable {
                "New documents default to local disk".into()
            } else {
                "iCloud default for new docs restored".into()
            })
        }
        "airdrop" => {
            if enable {
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.NetworkBrowser",
                        "DisableAirDrop",
                        "-bool",
                        "true",
                    ])
                    .status();
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.sharingd",
                        "DiscoverableMode",
                        "-string",
                        "Off",
                    ])
                    .status();
                Ok("AirDrop discoverability set Off (best-effort)".into())
            } else {
                let _ = Command::new("defaults")
                    .args(["delete", "com.apple.NetworkBrowser", "DisableAirDrop"])
                    .status();
                Ok("AirDrop restriction cleared (set mode in Control Center if needed)".into())
            }
        }
        "dock_recents" => {
            // enable=true → disable (hide) recent apps; enable=false → restore section.
            set_dock_show_recents(!enable)?;
            std::thread::sleep(std::time::Duration::from_millis(300));
            let now = dock_show_recents();
            if enable && now {
                return Err(
                    "Preference write did not stick (show-recents still true). Use System Settings → Desktop & Dock → Show recent apps."
                        .into(),
                );
            }
            if !enable && !now {
                return Err(
                    "Could not restore recent apps (show-recents still false). Use System Settings → Desktop & Dock → Show recent apps."
                        .into(),
                );
            }
            Ok(if enable {
                "Dock recent apps hidden".into()
            } else {
                "Dock recent apps restored — section may stay empty until you open apps again"
                    .into()
            })
        }
        "captive_portal" => {
            if enable {
                elevate("defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -bool false")?;
                Ok("Captive portal helper disabled".into())
            } else {
                elevate("defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -bool true")?;
                Ok("Captive portal helper re-enabled".into())
            }
        }
        "app_firewall" => {
            if enable {
                elevate("/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")?;
                Ok("Application firewall enabled".into())
            } else {
                elevate("/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off")?;
                Ok("Application firewall disabled".into())
            }
        }
        "firewall_stealth" => {
            if enable {
                elevate("/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on")?;
                Ok("Firewall stealth mode enabled".into())
            } else {
                elevate("/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off")?;
                Ok("Firewall stealth mode disabled".into())
            }
        }
        "guest_account" => {
            if enable {
                elevate("defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false")?;
                Ok("Guest account disabled".into())
            } else {
                elevate("defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool true")?;
                Ok("Guest account enabled".into())
            }
        }
        "remote_login" => {
            if enable {
                elevate("systemsetup -setremotelogin off")?;
                Ok("Remote Login (SSH) disabled".into())
            } else {
                elevate("systemsetup -setremotelogin on")?;
                Ok("Remote Login (SSH) enabled".into())
            }
        }
        "bonjour_ads" => {
            let val = if enable { "false" } else { "true" };
            let _ = Command::new("defaults")
                .args([
                    "write",
                    "com.apple.controlcenter",
                    "AirplayRecieverEnabled",
                    "-bool",
                    val,
                ])
                .status();
            Ok(if enable {
                "AirPlay receiver advertising limited (best-effort)".into()
            } else {
                "AirPlay receiver preference restored".into()
            })
        }
        "bonjour_mdns" => {
            if enable {
                elevate(
                    "defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES",
                )?;
                Ok("Bonjour multicast advertisements disabled (admin)".into())
            } else {
                elevate(
                    "defaults delete /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements 2>/dev/null || true",
                )?;
                Ok("Bonjour multicast advertisements restored".into())
            }
        }
        "fw_signed_auto" => {
            if !firewall_enabled() {
                return Err("Enable Application firewall first".into());
            }
            if enable {
                elevate(
                    "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off; /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off",
                )?;
                Ok("Firewall no longer auto-allows signed apps".into())
            } else {
                elevate(
                    "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on; /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on",
                )?;
                Ok("Firewall auto-allow for signed apps restored".into())
            }
        }
        "guest_smb" => {
            if enable {
                elevate(
                    "defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool NO",
                )?;
                Ok("Guest SMB sharing disabled".into())
            } else {
                elevate(
                    "defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool YES",
                )?;
                Ok("Guest SMB sharing enabled".into())
            }
        }
        "remote_mgmt" => {
            let kick = "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart";
            if enable {
                elevate(&format!("{kick} -deactivate -stop 2>/dev/null || true"))?;
                Ok("Remote Management deactivated (best-effort)".into())
            } else {
                Err(
                    "Re-enable Remote Management from System Settings → General → Sharing if needed"
                        .into(),
                )
            }
        }
        "clear_dns_cache" => {
            elevate("dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null || true")?;
            Ok("DNS cache flushed".into())
        }
        "printer_sharing" => {
            if enable {
                elevate("cupsctl --no-share-printers")?;
                Ok("Printer sharing disabled".into())
            } else {
                elevate("cupsctl --share-printers")?;
                Ok("Printer sharing enabled".into())
            }
        }
        "screensaver_lock" => {
            if enable {
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.screensaver",
                        "askForPassword",
                        "-int",
                        "1",
                    ])
                    .status();
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.screensaver",
                        "askForPasswordDelay",
                        "-int",
                        "0",
                    ])
                    .status();
                Ok("Password required immediately after screen saver".into())
            } else {
                let _ = Command::new("defaults")
                    .args([
                        "write",
                        "com.apple.screensaver",
                        "askForPassword",
                        "-int",
                        "0",
                    ])
                    .status();
                Ok("Screen saver password requirement relaxed".into())
            }
        }
        "filevault" => {
            let _ = Command::new("open")
                .arg("x-apple.systempreferences:com.apple.preference.security?FileVault")
                .status();
            Ok("Opened FileVault settings — enable there if Off".into())
        }
        "lockdown_mode" => {
            if macos_major() < 13 {
                return Err("Lockdown Mode requires macOS 13 Ventura or later".into());
            }
            // Prefer Apple’s UI (password + restart). Also sync the preference key so
            // status reflects intent; full effect still needs a reboot.
            if enable {
                let _ = Command::new("defaults")
                    .args(["write", "-g", "LDMGlobalEnabled", "-bool", "true"])
                    .status();
            } else {
                let _ = Command::new("defaults")
                    .args(["write", "-g", "LDMGlobalEnabled", "-bool", "false"])
                    .status();
            }
            let _ = Command::new("open")
                .arg("x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_LockdownMode")
                .status();
            Ok(if enable {
                "Lockdown Mode preference set on and Settings opened. Confirm there and restart — this is invasive (attachments, FaceTime, web features, USB when locked, and more break)."
                    .into()
            } else {
                "Lockdown Mode preference set off and Settings opened. Restart to fully apply."
                    .into()
            })
        }
        "firmware_password" => {
            if is_apple_silicon() {
                return Err("Firmware password applies to Intel Macs only".into());
            }
            let _ = Command::new("open")
                .arg("https://support.apple.com/guide/mac-help/set-a-firmware-password-mchlp1570/mac")
                .status();
            Ok(
                "Opened Apple guide for firmware password (set interactively; never automated)"
                    .into(),
            )
        }
        "connection_filter" => {
            let _ = crate::settings::update(|s| s.connection_filter = enable);
            if enable {
                crate::ne_filter::activate()
            } else {
                crate::ne_filter::deactivate()
            }
        }
        "mac_random" => {
            let _ = Command::new("open")
                .arg("x-apple.systempreferences:com.apple.preference.network")
                .status();
            Ok("Opened Network settings — enable Private Wi‑Fi Address per SSID".into())
        }
        "macports" => crate::harden::macports::open_download(),
        _ => Err(format!("Unknown harden id: {id}")),
    }
}
