use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::tor::process::ISOLATED_SOCKS_PORT;
use crate::tor::{SOCKS_HOST, SOCKS_PORT};

const IP_URL: &str = "https://api.ipify.org?format=json";
const POLL_IDLE: Duration = Duration::from_secs(30);
const POLL_NEED_TOR: Duration = Duration::from_secs(5);
const POLL_SLICE: Duration = Duration::from_secs(2);

static SNAPSHOT: LazyLock<Mutex<IpReport>> =
    LazyLock::new(|| Mutex::new(IpReport::default()));

#[derive(Debug, Serialize, Deserialize)]
struct IpifyResponse {
    ip: String,
}

#[derive(Debug, Deserialize)]
struct IpWhoResponse {
    success: Option<bool>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoLocation {
    pub label: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpReport {
    pub direct_ip: Option<String>,
    pub tor_ip: Option<String>,
    pub direct_location: Option<GeoLocation>,
    pub tor_location: Option<GeoLocation>,
    pub direct_error: Option<String>,
    pub tor_error: Option<String>,
}

fn direct_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())
}

async fn fetch_direct() -> Result<String, String> {
    let client = direct_client()?;
    let resp = client
        .get(IP_URL)
        .send()
        .await
        .map_err(|e| format!("Direct IP request failed: {e}"))?;
    let body: IpifyResponse = resp
        .json()
        .await
        .map_err(|e| format!("Direct IP parse failed: {e}"))?;
    Ok(body.ip)
}

pub async fn fetch_direct_for_verification() -> Result<String, String> {
    fetch_direct().await
}

pub async fn fetch_via_tor() -> Result<String, String> {
    let proxy = reqwest::Proxy::all(format!("socks5h://{SOCKS_HOST}:{SOCKS_PORT}"))
        .map_err(|e| format!("Invalid SOCKS proxy: {e}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(IP_URL)
        .send()
        .await
        .map_err(|e| format!("Tor IP request failed: {e}"))?;
    let body: IpifyResponse = resp
        .json()
        .await
        .map_err(|e| format!("Tor IP parse failed: {e}"))?;
    Ok(body.ip)
}

pub async fn fetch_via_isolated(index: usize, epoch: u64) -> Result<String, String> {
    let proxy = reqwest::Proxy::all(format!(
        "socks5h://oniongate-{index}:{epoch}@{SOCKS_HOST}:{ISOLATED_SOCKS_PORT}"
    ))
    .map_err(|e| format!("Invalid isolated SOCKS proxy: {e}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get(IP_URL)
        .send()
        .await
        .map_err(|e| format!("Isolated Tor IP request failed: {e}"))?;
    let body: IpifyResponse = response
        .json()
        .await
        .map_err(|e| format!("Isolated Tor IP parse failed: {e}"))?;
    Ok(body.ip)
}

/// Fetch Tor IP with retries — circuits are often not ready right after NEWNYM.
pub async fn fetch_via_tor_with_retry(attempts: u32, delay: Duration) -> Result<String, String> {
    let attempts = attempts.max(1);
    let mut last_err = String::new();
    for i in 0..attempts {
        match fetch_via_tor().await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                last_err = e;
                if i + 1 < attempts {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    Err(last_err)
}

fn format_location(geo: &IpWhoResponse) -> Option<GeoLocation> {
    if geo.success == Some(false) {
        return None;
    }

    let mut parts = Vec::new();
    if let Some(city) = geo.city.as_ref().filter(|s| !s.is_empty()) {
        parts.push(city.clone());
    }
    if let Some(region) = geo.region.as_ref().filter(|s| !s.is_empty()) {
        if !parts.iter().any(|p| p.eq_ignore_ascii_case(region)) {
            parts.push(region.clone());
        }
    }
    if let Some(country) = geo.country.as_ref().filter(|s| !s.is_empty()) {
        parts.push(country.clone());
    }

    if parts.is_empty() {
        return None;
    }

    Some(GeoLocation {
        label: parts.join(", "),
        city: geo.city.clone(),
        region: geo.region.clone(),
        country: geo.country.clone(),
        country_code: geo.country_code.clone(),
    })
}

async fn lookup_location(ip: &str, via_tor: bool) -> Result<GeoLocation, String> {
    let client = if via_tor {
        let proxy = reqwest::Proxy::all(format!("socks5h://{SOCKS_HOST}:{SOCKS_PORT}"))
            .map_err(|e| format!("Invalid SOCKS proxy: {e}"))?;
        reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?
    } else {
        direct_client()?
    };
    let url = format!("https://ipwho.is/{ip}");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Location lookup failed: {e}"))?;
    let body: IpWhoResponse = resp
        .json()
        .await
        .map_err(|e| format!("Location parse failed: {e}"))?;

    if body.success == Some(false) {
        return Err(body
            .message
            .unwrap_or_else(|| "Location lookup unsuccessful".into()));
    }

    format_location(&body).ok_or_else(|| "No location data for IP".into())
}

async fn enrich(report: IpReport) -> IpReport {
    let (direct_location, tor_location) = tokio::join!(
        async {
            match &report.direct_ip {
                Some(ip) => lookup_location(ip, false).await.ok(),
                None => None,
            }
        },
        async {
            match &report.tor_ip {
                // Keep the Tor-exit lookup on the Tor path. Sending both
                // addresses from the direct connection would let the
                // geolocation provider correlate them.
                Some(ip) => lookup_location(ip, true).await.ok(),
                None => None,
            }
        }
    );

    IpReport {
        direct_location,
        tor_location,
        ..report
    }
}

fn store(report: IpReport) -> IpReport {
    if let Ok(mut guard) = SNAPSHOT.lock() {
        *guard = report.clone();
    }
    report
}

/// Latest sample. Never fetches on the caller thread — the daemon owns ipify.
pub fn current() -> IpReport {
    SNAPSHOT
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

pub fn start_monitor() {
    tauri::async_runtime::spawn(async {
        loop {
            let _ = refresh_ips().await;
            let socks = crate::tor::socks_reachable();
            let need_tor = socks && current().tor_ip.is_none();
            let target = if need_tor { POLL_NEED_TOR } else { POLL_IDLE };
            let mut waited = Duration::ZERO;
            while waited < target {
                tokio::time::sleep(POLL_SLICE).await;
                waited += POLL_SLICE;
                if crate::tor::socks_reachable() != socks {
                    break;
                }
            }
        }
    });
}

pub async fn refresh_ips() -> IpReport {
    let socks_up = crate::tor::socks_reachable();
    let direct_fut = fetch_direct();
    let tor_fut = async {
        if socks_up {
            fetch_via_tor().await
        } else {
            Err("Tor SOCKS is not up".into())
        }
    };
    let (direct, tor) = tokio::join!(direct_fut, tor_fut);
    let report = IpReport {
        direct_ip: direct.as_ref().ok().cloned(),
        tor_ip: tor.as_ref().ok().cloned(),
        direct_location: None,
        tor_location: None,
        direct_error: direct.err(),
        tor_error: tor.err(),
    };
    store(enrich(report).await)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTestResult {
    pub success: bool,
    pub message: String,
    pub direct_ip: Option<String>,
    pub tor_ip: Option<String>,
}

/// Connectivity test that always checks direct IP; Tor IP only if SOCKS is up.
pub async fn test_network() -> NetworkTestResult {
    let socks_up = crate::tor::socks_reachable();
    let direct = fetch_direct().await;
    let tor = if socks_up {
        Some(fetch_via_tor().await)
    } else {
        None
    };

    let direct_ip = direct.as_ref().ok().cloned();
    let tor_ip = tor.as_ref().and_then(|r| r.as_ref().ok().cloned());

    let success = if socks_up {
        tor_ip.is_some()
    } else {
        direct_ip.is_some()
    };

    let message = if let (Some(d), Some(t)) = (&direct_ip, &tor_ip) {
        format!("Success — Direct {d} · Tor {t}")
    } else if let Some(d) = &direct_ip {
        if socks_up {
            format!("Failure — Direct {d} · Tor unreachable")
        } else {
            format!("Success — Direct {d}")
        }
    } else if let Some(t) = &tor_ip {
        format!("Success — Tor {t}")
    } else {
        format!("Failure — could not reach the network")
    };

    NetworkTestResult {
        success,
        message,
        direct_ip,
        tor_ip,
    }
}

/// Like refresh_ips, but patiently retries the Tor path (used after New Identity).
pub async fn refresh_ips_after_newnym() -> IpReport {
    // Brief settle time before the first attempt; NEWNYM tears down circuits.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let direct_fut = fetch_direct();
    let tor_fut = fetch_via_tor_with_retry(8, Duration::from_millis(1500));
    let (direct, tor) = tokio::join!(direct_fut, tor_fut);

    let report = IpReport {
        direct_ip: direct.as_ref().ok().cloned(),
        tor_ip: tor.as_ref().ok().cloned(),
        direct_location: None,
        tor_location: None,
        direct_error: direct.err(),
        tor_error: tor.err(),
    };
    store(enrich(report).await)
}
