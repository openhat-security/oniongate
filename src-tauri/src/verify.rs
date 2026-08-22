#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub id: String,
    pub label: String,
    pub status: String,
    pub detail: String,
    /// How to fix a warn/fail result (shown in the UI when not passing).
    pub remediation: Option<String>,
}

/// Concrete "how to fix" guidance per check id, shown when the check warns/fails.
fn remediation_for(id: &str) -> Option<String> {
    let text = match id {
        "tor_ip" => {
            "Connect Tor from the Connect screen. If your network blocks Tor, enable a bridge \
             on the Bridges tab (Smart Connect will also try the bundled Snowflake transport)."
        }
        "ip_separation" => {
            "Make sure Tor is connected and your apps route through it (enable the system proxy \
             or TUN on the Routing tab), then run the verifier again."
        }
        "dns" => {
            "Turn on 'Resolve through Tor' in Settings, or use socks5h in proxy apps. In TUN mode \
             DNS is sent to Tor automatically."
        }
        "udp_quic" => {
            "Enable the kill switch on the Routing tab, or switch to TUN mode, to block clearnet \
             UDP/QUIC (this needs an administrator prompt)."
        }
        "ipv6" => {
            "Enable TUN with strict routing to contain IPv6, or disable IPv6 for this network in \
             System Settings."
        }
        "app_policy" => {
            "Enable TUN and add applications under the Apps tab. Isolated per-app routing requires \
             TUN to be active."
        }
        "session_guard" => {
            "Turn on Session Guard under Apps using the 'Only selected via Tor' policy so selected \
             apps are suspended if the Tor route drops."
        }
        "recovery" => {
            "Open the Connect screen and run Emergency Restore to reconcile firewall, TUN, and \
             proxy state with the crash-recovery journal."
        }
        "egress_watch" => {
            "Those processes have established TCP that is not OnionGate SOCKS, TUN, or OnionGate's \
             Tor. In Proxy mode enable TUN or point the app at SOCKS. In TUN mode, quit the app or \
             add it to selected-app routing. Destinations are not stored."
        }
        "nic_lock" => {
            "Turn the NIC lock off, or reconnect so pf can load the default-deny rules. \
             Snowflake/meek cannot use this lock."
        }
        "nic_lock_exceptions" => {
            "Remove destination exceptions on Routing. Each exception is a machine-wide hole."
        }
        "nic_lock_vpn" => "Disconnect the other VPN before using the NIC lock.",
        "connection_filter" => {
            "Approve the OnionGate connection filter in System Settings → Network Extensions. \
             Apple can hide some of its own processes from this filter; that is a residual, \
             not an Allow. pf remains the packet lock. A signed .pkg is required to load it."
        }
        _ => return None,
    };
    Some(text.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakReport {
    pub created_at_unix: u64,
    pub passed: bool,
    pub checks: Vec<VerificationCheck>,
}

fn check(id: &str, label: &str, passed: bool, detail: impl Into<String>) -> VerificationCheck {
    VerificationCheck {
        id: id.into(),
        label: label.into(),
        status: if passed { "pass" } else { "fail" }.into(),
        detail: detail.into(),
        remediation: if passed { None } else { remediation_for(id) },
    }
}

fn warn(id: &str, label: &str, detail: impl Into<String>) -> VerificationCheck {
    VerificationCheck {
        id: id.into(),
        label: label.into(),
        status: "warn".into(),
        detail: detail.into(),
        remediation: remediation_for(id),
    }
}

fn unverifiable(label: &str, detail: impl Into<String>) -> VerificationCheck {
    VerificationCheck {
        id: "ip_separation".into(),
        label: label.into(),
        status: "warn".into(),
        detail: detail.into(),
        remediation: None,
    }
}

fn ipv6_default_route() -> bool {
    #[cfg(target_os = "macos")]
    let result = Command::new("route")
        .args(["-n", "get", "-inet6", "default"])
        .output();
    #[cfg(target_os = "linux")]
    let result = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let result: std::io::Result<std::process::Output> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported",
    ));
    result
        .map(|output| output.status.success() && !output.stdout.is_empty())
        .unwrap_or(false)
}

pub async fn run() -> LeakReport {
    let settings = crate::settings::load();
    let firewall = crate::firewall::status();
    let tun = crate::tun::process_seems_running();
    let direct = crate::ip::fetch_direct_for_verification().await;
    let tor = crate::ip::fetch_via_tor().await;
    let mut checks = Vec::new();

    checks.push(check(
        "tor_ip",
        "Tor egress",
        tor.is_ok(),
        if tor.is_ok() {
            "A remote IP check succeeded through SOCKS hostname resolution"
        } else {
            "Tor egress could not reach the remote verifier"
        },
    ));
    match (&direct, &tor) {
        (Ok(default_path), Ok(tor_path)) if tun => checks.push(unverifiable(
            "Default/Tor egress under TUN",
            if default_path == tor_path {
                "The no-proxy request and explicit Tor request used the same exit. TUN intentionally prevents a safe direct-IP baseline."
            } else {
                "Both requests succeeded, but TUN captures the no-proxy path; different Tor circuits can use different exits, so direct-IP separation is not measurable safely."
            },
        )),
        (Ok(direct), Ok(tor)) => checks.push(check(
            "ip_separation",
            "Direct/Tor IP separation",
            direct != tor,
            if direct != tor {
                "Direct and Tor egress addresses differ (addresses are not stored)"
            } else {
                "Direct and Tor egress addresses unexpectedly match"
            },
        )),
        _ => checks.push(warn(
            "ip_separation",
            "Direct/Tor IP separation",
            "One path was unavailable, so separation could not be compared",
        )),
    }

    let dns_reachable = crate::tor::dns_reachable();
    checks.push(if settings.remote_dns {
        check(
            "dns",
            "Resolve through Tor",
            dns_reachable,
            if dns_reachable {
                "Tor's local UDP DNSPort responded"
            } else {
                "Resolve through Tor is enabled, but Tor's DNSPort did not respond"
            },
        )
    } else {
        warn(
            "dns",
            "Resolve through Tor",
            "Disabled by user; OnionGate cannot verify DNS containment for proxy applications",
        )
    });
    checks.push(if tun {
        check(
            "udp_quic",
            "UDP/QUIC containment",
            true,
            "The live TUN policy blocks UDP/QUIC",
        )
    } else if firewall.active && firewall.verified_live {
        check(
            "udp_quic",
            "UDP/QUIC containment",
            true,
            "Live OnionGate firewall rules were inspected",
        )
    } else if firewall.marker_active {
        warn(
            "udp_quic",
            "UDP/QUIC containment",
            "A kill-switch marker exists, but the live firewall rule could not be verified",
        )
    } else {
        check(
            "udp_quic",
            "UDP/QUIC containment",
            false,
            "No active TUN or verified firewall rule",
        )
    });

    let ipv6 = ipv6_default_route();
    checks.push(if !ipv6 || tun {
        check(
            "ipv6",
            "IPv6 route",
            true,
            if ipv6 {
                "An IPv6 default route exists and strict TUN routing is active"
            } else {
                "No IPv6 default route was detected"
            },
        )
    } else {
        warn(
            "ipv6",
            "IPv6 route",
            "IPv6 is available without active TUN containment",
        )
    });

    checks.push(check(
        "app_policy",
        "Selected-app policy",
        !settings.split_tunnel || (!settings.route_apps.is_empty() && tun),
        if settings.split_tunnel && tun {
            "Stable application identities are loaded into the active TUN policy"
        } else if settings.split_tunnel {
            "Application policy is configured but TUN is not active"
        } else {
            "No selected-app policy is enabled"
        },
    ));
    checks.push(
        if settings.session_guard && !settings.route_apps.is_empty() {
            check(
                "session_guard",
                "Session Guard",
                true,
                "Selected processes suspend if the Tor/TUN route disappears",
            )
        } else {
            warn(
                "session_guard",
                "Session Guard",
                "Fail-closed selected-app suspension is not enabled",
            )
        },
    );

    let recovery = crate::session::recovery_status();
    checks.push(check(
        "recovery",
        "Crash recovery state",
        !recovery.needed,
        "Live firewall/TUN/proxy state was compared with the crash-recovery journal",
    ));

    let filter = crate::ne_filter::status();
    if filter.supported {
        let session_live = matches!(
            crate::session::load().phase,
            crate::session::SessionPhase::Connecting
                | crate::session::SessionPhase::Protected
                | crate::session::SessionPhase::Degraded
        );
        checks.push(if !filter.bundled && !filter.installed {
            warn(
                "connection_filter",
                "Connection filter",
                filter.detail.clone(),
            )
        } else if filter.running && filter.unseen_bypass == 0 {
            check(
                "connection_filter",
                "Connection filter",
                true,
                filter.detail.clone(),
            )
        } else if session_live && settings.connection_filter {
            check(
                "connection_filter",
                "Connection filter",
                false,
                filter.detail.clone(),
            )
        } else {
            warn(
                "connection_filter",
                "Connection filter",
                filter.detail.clone(),
            )
        });
    }

    let watch = crate::egress_watch::current();
    let expected_direct = settings.connection_mode != "tun"
        || (settings.split_tunnel
            && settings.app_routing_policy == "only"
            && !settings.strict_tcp_lock);
    checks.push(if !watch.watching {
        warn(
            "egress_watch",
            "Live clearnet watch",
            "The connection daemon is idle until you Connect",
        )
    } else if watch.bypass == 0 {
        check(
            "egress_watch",
            "Live clearnet watch",
            true,
            "No established clearnet TCP outside OnionGate, Tor, or LAN",
        )
    } else if expected_direct {
        warn(
            "egress_watch",
            "Live clearnet watch",
            format!(
                "{} established clearnet TCP flow(s) are not through OnionGate (counts only; destinations are not stored)",
                watch.bypass
            ),
        )
    } else {
        check(
            "egress_watch",
            "Live clearnet watch",
            false,
            format!(
                "{} established clearnet TCP flow(s) are not through OnionGate while TUN is capturing the default path",
                watch.bypass
            ),
        )
    });

    if settings.strict_tcp_lock {
        let fw = crate::firewall::status();
        checks.push(check(
            "nic_lock",
            "NIC default-deny",
            fw.strict_deny_live,
            if fw.strict_deny_live {
                "Live pf default-deny is active (public IP blocked except Tor endpoints)"
            } else {
                "NIC lock is requested but live pf default-deny was not verified"
            },
        ));
        checks.push(check(
            "nic_lock_exceptions",
            "NIC lock exceptions",
            settings.strict_tcp_exceptions.is_empty(),
            if settings.strict_tcp_exceptions.is_empty() {
                "No destination exceptions"
            } else {
                "Destination exceptions are loaded (machine-wide leak; session should be Degraded)"
            },
        ));
        let vpn = crate::vpn_detect::detect();
        checks.push(check(
            "nic_lock_vpn",
            "Competing VPN",
            !vpn.active,
            if vpn.active {
                vpn.detail
            } else {
                "No competing VPN detected".into()
            },
        ));
    }

    let passed = checks.iter().all(|item| item.status != "fail");
    let report = LeakReport {
        created_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        passed,
        checks,
    };
    let _ = crate::db::save_leak_report(&report);
    report
}
