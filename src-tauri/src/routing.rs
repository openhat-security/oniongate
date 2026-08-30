use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub nickname: String,
    pub fingerprint: String,
    pub country: Option<String>,
    pub as_name: Option<String>,
    pub flags: Vec<String>,
    pub or_addresses: Vec<String>,
    pub observed_bandwidth: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OnionooResponse {
    relays: Vec<OnionooRelay>,
}

#[derive(Debug, Deserialize)]
struct OnionooRelay {
    nickname: Option<String>,
    fingerprint: Option<String>,
    country: Option<String>,
    #[serde(rename = "as_name")]
    as_name: Option<String>,
    flags: Option<Vec<String>>,
    #[serde(rename = "or_addresses")]
    or_addresses: Option<Vec<String>>,
    #[serde(rename = "observed_bandwidth")]
    observed_bandwidth: Option<u64>,
}

/// Search live Tor relays via Onionoo.
pub async fn search_relays(query: &str, limit: usize) -> Result<Vec<RelayInfo>, String> {
    let q = query.trim();
    if q.is_empty() {
        return Err("Enter a search query (nickname, country code, or fingerprint)".into());
    }
    let lim = limit.clamp(1, 50);
    let url = format!(
        "https://onionoo.torproject.org/details?search={}&limit={lim}",
        urlencoding_encode(q)
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("oniongate/0.2")
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Onionoo request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Onionoo HTTP {}", resp.status()));
    }
    let body: OnionooResponse = resp
        .json()
        .await
        .map_err(|e| format!("Onionoo parse failed: {e}"))?;
    Ok(body
        .relays
        .into_iter()
        .filter_map(|r| {
            Some(RelayInfo {
                nickname: r.nickname.unwrap_or_else(|| "Unnamed".into()),
                fingerprint: r.fingerprint?,
                country: r.country,
                as_name: r.as_name,
                flags: r.flags.unwrap_or_default(),
                or_addresses: r.or_addresses.unwrap_or_default(),
                observed_bandwidth: r.observed_bandwidth,
            })
        })
        .collect())
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
