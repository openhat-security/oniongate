use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
use crate::win_console::HideConsole;

/// What `audit` needs to know about a site, regardless of whether it is a
/// temporary control-port service or a permanent `HiddenServiceDir` site.
pub struct AuditTarget<'a> {
    pub service_id: &'a str,
    pub hostname: &'a str,
    pub local_port: u16,
    pub virtual_port: u16,
    /// Present only when OnionGate still holds the credential in memory, which
    /// is the case for temporary private sites and never for permanent ones.
    pub client_credential: Option<&'a str>,
    /// True when the service requires authorization we cannot supply.
    pub auth_required_without_credential: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerAudit {
    pub reachable: bool,
    pub loopback_only: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionAudit {
    pub listener: ListenerAudit,
    pub published: bool,
    pub latency_ms: Option<u64>,
    pub http_status: Option<u16>,
    pub security_headers: Vec<String>,
    pub warnings: Vec<String>,
}

/// Detect a listener bound to every interface in `lsof`/`ss`/`netstat` output.
///
/// Publishing an onion service for a wildcard-bound port would expose the same
/// service on the clearnet, so this must never miss a wildcard bind.
fn binds_wildcard(listing: &str, port: u16) -> bool {
    listing.lines().any(|line| {
        line.contains(&format!("*:{port}"))
            || line.contains(&format!("0.0.0.0:{port}"))
            || line.contains(&format!("[::]:{port}"))
            || line.contains(&format!(":::{port}"))
    })
}

pub fn inspect_listener(port: u16) -> ListenerAudit {
    let reachable = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(500),
    )
    .is_ok();
    if !reachable {
        return ListenerAudit {
            reachable: false,
            loopback_only: false,
            detail: format!("Nothing is accepting TCP connections on 127.0.0.1:{port}"),
        };
    }

    #[cfg(target_os = "macos")]
    let output = Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .output();
    #[cfg(target_os = "linux")]
    let output = Command::new("ss")
        .args(["-ltn", &format!("sport = :{port}")])
        .output();
    #[cfg(target_os = "windows")]
    let output = Command::new("netstat.exe")
        .args(["-ano", "-p", "tcp"])
        .hide_console()
        .output();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let output: std::io::Result<std::process::Output> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "listener inspection unsupported",
    ));

    let Ok(output) = output else {
        return ListenerAudit {
            reachable: true,
            loopback_only: false,
            detail: "Listener is reachable, but its bind address could not be inspected".into(),
        };
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let wildcard = binds_wildcard(&text, port);
    ListenerAudit {
        reachable: true,
        loopback_only: !wildcard,
        detail: if wildcard {
            "Listener is exposed on a wildcard interface; bind it to 127.0.0.1 first".into()
        } else {
            format!("Listener appears restricted to loopback on port {port}")
        },
    }
}

pub async fn audit(target: &AuditTarget<'_>) -> Result<OnionAudit, String> {
    let mut warnings = Vec::new();

    // A site whose authorization keys we never held cannot be self-tested: Tor
    // cannot even fetch the descriptor without a client credential.
    if target.auth_required_without_credential {
        warnings.push(
            "Client authorization is on and OnionGate does not keep credentials, so the \
             descriptor cannot be fetched from here. Test with a client that holds one."
                .into(),
        );
        return Ok(OnionAudit {
            listener: inspect_listener(target.local_port),
            published: false,
            latency_ms: None,
            http_status: None,
            security_headers: Vec::new(),
            warnings,
        });
    }

    if let Some(credential) = target.client_credential {
        super::control::authorize_client(target.service_id, credential).await?;
    }
    let connectivity =
        crate::tor::onion::test_connectivity(target.hostname, target.virtual_port).await?;
    let mut status = None;
    let mut security_headers = Vec::new();
    if connectivity.reachable {
        let proxy = reqwest::Proxy::all(format!(
            "socks5h://{}:{}",
            crate::tor::SOCKS_HOST,
            crate::tor::SOCKS_PORT
        ))
        .map_err(|e| e.to_string())?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        if let Ok(response) = client
            .get(format!("http://{}", target.hostname))
            .send()
            .await
        {
            status = Some(response.status().as_u16());
            for header in [
                "content-security-policy",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            ] {
                if response.headers().contains_key(header) {
                    security_headers.push(header.into());
                }
            }
            if security_headers.is_empty() {
                warnings.push("No common HTTP security headers were observed".into());
            }
        }
    } else {
        warnings.push("Onion descriptor may still be publishing; retry shortly".into());
    }
    Ok(OnionAudit {
        listener: inspect_listener(target.local_port),
        published: connectivity.reachable,
        latency_ms: connectivity.latency_ms,
        http_status: status,
        security_headers,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_listener_is_not_flagged() {
        let lsof = "COMMAND   PID USER   FD TYPE DEVICE SIZE/OFF NODE NAME\n\
                    python  4321 me     3u IPv4  0x1234      0t0  TCP 127.0.0.1:8080 (LISTEN)\n";
        assert!(!binds_wildcard(lsof, 8080));
    }

    #[test]
    fn wildcard_binds_are_detected_in_lsof_output() {
        let ipv4 = "python 1 me 3u IPv4 0x1 0t0 TCP *:8080 (LISTEN)\n";
        let any = "python 1 me 3u IPv4 0x1 0t0 TCP 0.0.0.0:8080 (LISTEN)\n";
        let ipv6 = "python 1 me 3u IPv6 0x1 0t0 TCP [::]:8080 (LISTEN)\n";
        assert!(binds_wildcard(ipv4, 8080));
        assert!(binds_wildcard(any, 8080));
        assert!(binds_wildcard(ipv6, 8080));
    }

    #[test]
    fn wildcard_binds_are_detected_in_ss_output() {
        let ss = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n\
                  LISTEN 0      4096         0.0.0.0:8080       0.0.0.0:*\n";
        assert!(binds_wildcard(ss, 8080));

        let ipv6 = "LISTEN 0 4096 :::8080 :::*\n";
        assert!(binds_wildcard(ipv6, 8080));
    }

    /// A wildcard bind on a different port must not condemn our port.
    #[test]
    fn unrelated_ports_do_not_trigger_a_warning() {
        let lsof = "nginx 1 me 3u IPv4 0x1 0t0 TCP *:80 (LISTEN)\n\
                    python 2 me 3u IPv4 0x2 0t0 TCP 127.0.0.1:8080 (LISTEN)\n";
        assert!(!binds_wildcard(lsof, 8080));
        assert!(binds_wildcard(lsof, 80));
    }
}
