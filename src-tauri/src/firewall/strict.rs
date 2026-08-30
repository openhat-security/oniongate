//! Shared NIC-lock policy: validate IPs and synthesize macOS pf rules.
//!
//! The helper daemon calls this so the client never supplies pf text.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_EXCEPTIONS: usize = 8;

pub fn parse_ip(raw: &str) -> Result<IpAddr, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty address".into());
    }
    if trimmed
        .chars()
        .any(|c| !c.is_ascii_hexdigit() && c != '.' && c != ':')
    {
        return Err("address contains invalid characters".into());
    }
    let ip: IpAddr = trimmed
        .parse()
        .map_err(|_| "not an IP address".to_string())?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return Err("address must be a unicast public or LAN IP".into());
    }
    Ok(ip)
}

pub fn parse_ip_list(raw: &[String], cap: usize) -> Result<Vec<IpAddr>, String> {
    if raw.len() > cap {
        return Err(format!("too many addresses (max {cap})"));
    }
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let ip = parse_ip(item)?;
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(out)
}

pub fn ips_to_strings(ips: &[IpAddr]) -> Vec<String> {
    ips.iter().map(ToString::to_string).collect()
}

/// Everyday kill switch: UDP/QUIC + IPv6 only. Loopback stays open for Tor.
pub fn pf_udp_ipv6_rules() -> String {
    "\
# OnionGate — steady-state UDP/QUIC + IPv6 leak protection
pass out quick on lo0 all
pass out quick to 127.0.0.1
pass out quick to ::1
block drop out log quick inet6 from any to any
block drop out log quick proto udp from any to any
"
    .into()
}

/// Default-deny every outbound IP packet except loopback, DHCP, Tor allowlist,
/// optional LAN, and warned user exceptions.
pub fn pf_strict_rules(endpoints: &[IpAddr], exceptions: &[IpAddr], allow_lan: bool) -> String {
    let mut rules = String::from(
        "# OnionGate — default-deny NIC lock\n\
pass out quick on lo0 all\n\
pass out quick to 127.0.0.1\n\
pass out quick to ::1\n\
pass out log proto udp from any port 68 to any port 67\n",
    );
    if allow_lan {
        rules.push_str(
            "pass out quick to 10.0.0.0/8\n\
pass out quick to 172.16.0.0/12\n\
pass out quick to 192.168.0.0/16\n\
pass out quick to 169.254.0.0/16\n\
pass out quick to fc00::/7\n\
pass out quick to fe80::/10\n",
        );
    }
    for ip in endpoints.iter().chain(exceptions.iter()) {
        rules.push_str(&format!("pass out proto tcp to {ip}\n"));
    }
    rules.push_str("block drop out log quick from any to any\n");
    rules
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PflogDeny {
    pub proto: String,
    pub dest: IpAddr,
    pub port: u16,
}

/// Parse a tcpdump/pflog header line. Payloads are ignored; allowlist IPs are
/// filtered by the caller so pass traffic is never stored.
pub fn parse_pflog_line(line: &str) -> Option<PflogDeny> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("pass ") && !lower.contains("block") {
        return None;
    }
    let proto = if lower.contains("udp") {
        "udp"
    } else if lower.contains("icmp") {
        "icmp"
    } else {
        "tcp"
    };
    let dest_part = line.split('>').nth(1)?;
    let token = dest_part.split_whitespace().next()?.trim_end_matches(':');
    let (host, port) = split_host_port(token)?;
    let dest: IpAddr = host.parse().ok()?;
    if dest.is_loopback() || dest.is_unspecified() || dest.is_multicast() {
        return None;
    }
    Some(PflogDeny {
        proto: proto.into(),
        dest,
        port,
    })
}

fn split_host_port(token: &str) -> Option<(String, u16)> {
    if let Some(rest) = token.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        let port = port.parse().ok()?;
        return Some((host.to_string(), port));
    }
    if let Some((host, port)) = token.rsplit_once('.') {
        if host.parse::<Ipv4Addr>().is_ok() {
            let port = port.parse().ok()?;
            return Some((host.to_string(), port));
        }
    }
    if let Some((host, port)) = token.rsplit_once('.') {
        if host.parse::<Ipv6Addr>().is_ok() {
            let port = port.parse().ok()?;
            return Some((host.to_string(), port));
        }
    }
    if let Some((host, port)) = token.rsplit_once(':') {
        if host.parse::<IpAddr>().is_ok() {
            let port = port.parse().ok()?;
            return Some((host.to_string(), port));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_metacharacters_and_loopback() {
        assert!(parse_ip("1.2.3.4; pfctl").is_err());
        assert!(parse_ip("127.0.0.1").is_err());
        assert!(parse_ip("0.0.0.0").is_err());
        assert!(parse_ip("::1").is_err());
        assert_eq!(
            parse_ip("198.51.100.10").unwrap().to_string(),
            "198.51.100.10"
        );
    }

    #[test]
    fn strict_template_default_denies_all_and_allows_dhcp() {
        let ip: IpAddr = "198.51.100.10".parse().unwrap();
        let rules = pf_strict_rules(&[ip], &[], false);
        assert!(rules.contains("pass out quick on lo0 all"));
        assert!(rules.contains("pass out log proto udp from any port 68 to any port 67"));
        assert!(rules.contains("pass out proto tcp to 198.51.100.10"));
        assert!(rules.contains("block drop out log quick from any to any"));
        assert!(!rules.contains("10.0.0.0/8"));
        let first_block = rules
            .lines()
            .position(|l| l.starts_with("block drop"))
            .unwrap();
        for pass in rules
            .lines()
            .enumerate()
            .filter_map(|(i, l)| l.starts_with("pass").then_some(i))
        {
            assert!(pass < first_block);
        }
    }

    #[test]
    fn lan_pass_is_opt_in() {
        let rules = pf_strict_rules(&[], &[], true);
        assert!(rules.contains("pass out quick to 192.168.0.0/16"));
    }

    #[test]
    fn pflog_parser_reads_tcpdump_style() {
        let line = "00:00:00.1 rule 5/(match) block out on en0: 192.168.1.5.54321 > 17.248.10.20.5223: Flags [S]";
        let parsed = parse_pflog_line(line).unwrap();
        assert_eq!(parsed.dest.to_string(), "17.248.10.20");
        assert_eq!(parsed.port, 5223);
        assert_eq!(parsed.proto, "tcp");
    }

    #[test]
    fn cap_rejects_oversized_lists() {
        let many: Vec<String> = (0..MAX_ENDPOINTS + 1)
            .map(|i| format!("198.51.100.{}", i % 250 + 1))
            .collect();
        assert!(parse_ip_list(&many, MAX_ENDPOINTS).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generated_rules_are_valid_pfctl_syntax() {
        let ip: IpAddr = "198.51.100.10".parse().unwrap();
        for (label, rules) in [
            ("udp/ipv6", pf_udp_ipv6_rules()),
            ("strict", pf_strict_rules(&[ip], &[], false)),
            ("strict+lan", pf_strict_rules(&[ip], &[], true)),
            ("boot-lock", pf_strict_rules(&[], &[], false)),
        ] {
            let path = std::env::temp_dir().join(format!(
                "oniongate-pf-syntax-{}-{}",
                std::process::id(),
                label.replace('/', "-")
            ));
            std::fs::write(&path, &rules).unwrap();
            let out = std::process::Command::new("/sbin/pfctl")
                .args(["-nf", &path.to_string_lossy()])
                .output()
                .expect("pfctl");
            let err = String::from_utf8_lossy(&out.stderr);
            let _ = std::fs::remove_file(&path);
            assert!(
                !err.contains("syntax error"),
                "{label} rejected by pfctl:\n{err}\n{rules}"
            );
        }
    }
}
