//! Local deny journal for the macOS NIC lock.
//!
//! Destinations of *blocked* attempts are stored here (capped). Tor allowlist
//! IPs, command lines, and secrets never enter this file.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::firewall::strict::PflogDeny;

const MAX_ROWS: usize = 4000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyEvent {
    pub process: String,
    pub pid: u32,
    pub path: String,
    pub dest: String,
    pub port: u16,
    pub proto: String,
    pub count: u64,
    pub last_seen_unix: u64,
    pub needs_popup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DenyLogSnapshot {
    pub events: Vec<DenyEvent>,
}

fn state() -> &'static Mutex<HashMap<String, DenyEvent>> {
    static STATE: OnceLock<Mutex<HashMap<String, DenyEvent>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn journal_path() -> Result<std::path::PathBuf, String> {
    Ok(crate::tor::process::ensure_data_dir()?.join("deny-journal.jsonl"))
}

fn key(process: &str, dest: &str, port: u16, proto: &str) -> String {
    format!("{process}|{dest}|{port}|{proto}")
}

fn correlate(deny: &PflogDeny) -> (String, u32, String) {
    let watch = crate::egress_watch::current();
    let needle = format!("{}:{}", deny.dest, deny.port);
    for flow in &watch.flows {
        if flow.remote == needle || flow.remote.starts_with(&format!("{}:", deny.dest)) {
            return (flow.process.clone(), flow.pid, flow.path.clone());
        }
    }
    ("unknown".into(), 0, String::new())
}

pub fn ingest(denies: &[PflogDeny], allowlist: &[IpAddr]) {
    if denies.is_empty() {
        return;
    }
    let Ok(mut map) = state().lock() else {
        return;
    };
    let ts = now_unix();
    for deny in denies {
        if allowlist.contains(&deny.dest) {
            continue;
        }
        let (process, pid, path) = correlate(deny);
        let dest = deny.dest.to_string();
        let k = key(&process, &dest, deny.port, &deny.proto);
        if let Some(existing) = map.get_mut(&k) {
            existing.count += 1;
            existing.last_seen_unix = ts;
            existing.pid = pid;
            if !path.is_empty() {
                existing.path = path;
            }
        } else {
            if map.len() >= MAX_ROWS {
                if let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, e)| e.last_seen_unix)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&oldest);
                }
            }
            map.insert(
                k,
                DenyEvent {
                    process: process.clone(),
                    pid,
                    path,
                    dest: dest.clone(),
                    port: deny.port,
                    proto: deny.proto.clone(),
                    count: 1,
                    last_seen_unix: ts,
                    needs_popup: true,
                },
            );
            crate::logs::append(format!(
                "Denied {} from {process} pid {pid} to public dest (count 1)",
                deny.proto
            ));
            let _ = append_journal_line(&DenyEvent {
                process,
                pid,
                path: String::new(),
                dest,
                port: deny.port,
                proto: deny.proto.clone(),
                count: 1,
                last_seen_unix: ts,
                needs_popup: true,
            });
        }
    }
}

fn append_journal_line(event: &DenyEvent) -> Result<(), String> {
    let path = journal_path()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    let mut line = serde_json::to_string(event).map_err(|e| e.to_string())?;
    line.push('\n');
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn snapshot() -> DenyLogSnapshot {
    let Ok(map) = state().lock() else {
        return DenyLogSnapshot::default();
    };
    let mut events: Vec<DenyEvent> = map.values().cloned().collect();
    events.sort_by(|a, b| b.last_seen_unix.cmp(&a.last_seen_unix));
    DenyLogSnapshot { events }
}

pub fn acknowledge(process: &str, dest: &str, port: u16, proto: &str) {
    let Ok(mut map) = state().lock() else {
        return;
    };
    if let Some(event) = map.get_mut(&key(process, dest, port, proto)) {
        event.needs_popup = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::strict::PflogDeny;

    #[test]
    fn aggregates_duplicate_tuples_and_skips_allowlist() {
        let dest: IpAddr = "203.0.113.9".parse().unwrap();
        let allow: IpAddr = "198.51.100.10".parse().unwrap();
        ingest(
            &[
                PflogDeny {
                    proto: "tcp".into(),
                    dest,
                    port: 443,
                },
                PflogDeny {
                    proto: "tcp".into(),
                    dest,
                    port: 443,
                },
                PflogDeny {
                    proto: "tcp".into(),
                    dest: allow,
                    port: 9001,
                },
            ],
            &[allow],
        );
        let snap = snapshot();
        let hit = snap
            .events
            .iter()
            .find(|e| e.dest == "203.0.113.9")
            .expect("deny stored");
        assert!(hit.count >= 2);
        assert!(!snap.events.iter().any(|e| e.dest == "198.51.100.10"));
    }
}
