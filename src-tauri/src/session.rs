use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::proxy::SavedProxyState;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    #[default]
    Disconnected,
    Connecting,
    Protected,
    Degraded,
    Recovering,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SessionJournal {
    pub phase: SessionPhase,
    pub original_proxy: Option<SavedProxyState>,
    pub proxy_changed: bool,
    pub tun_expected: bool,
    pub firewall_expected: bool,
    pub network_lock_expected: bool,
    pub tor_expected: bool,
    pub active_transports: Vec<String>,
    pub last_error: Option<String>,
    pub owner_pid: u32,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub needed: bool,
    pub phase: SessionPhase,
    pub proxy_live: bool,
    pub tun_live: bool,
    pub firewall_live: bool,
    pub network_lock_live: bool,
    pub tor_live: bool,
    pub detail: String,
}

fn path() -> Result<PathBuf, String> {
    Ok(crate::tor::process::ensure_data_dir()?.join("session-journal.json"))
}

pub fn load() -> SessionJournal {
    let Ok(path) = path() else {
        return SessionJournal::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return SessionJournal::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save(journal: &SessionJournal) -> Result<(), String> {
    let path = path()?;
    let temp = path.with_extension("json.tmp");
    let mut next = journal.clone();
    next.updated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let raw = serde_json::to_vec_pretty(&next)
        .map_err(|e| format!("Failed to serialize session journal: {e}"))?;
    fs::write(&temp, raw).map_err(|e| format!("Failed to write session journal: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to protect session journal: {e}"))?;
    }
    fs::rename(&temp, &path).map_err(|e| format!("Failed to commit session journal: {e}"))
}

pub fn update(mutator: impl FnOnce(&mut SessionJournal)) -> Result<SessionJournal, String> {
    let mut journal = load();
    mutator(&mut journal);
    save(&journal)?;
    Ok(journal)
}

pub fn begin_connect() -> Result<(), String> {
    update(|j| {
        j.phase = SessionPhase::Connecting;
        j.tor_expected = true;
        j.owner_pid = std::process::id();
        j.last_error = None;
    })?;
    Ok(())
}

pub fn record_proxy_before(snapshot: SavedProxyState) -> Result<(), String> {
    update(|j| {
        j.original_proxy = Some(snapshot);
        j.proxy_changed = true;
    })?;
    Ok(())
}

pub fn expect_tun(expected: bool) -> Result<(), String> {
    update(|j| j.tun_expected = expected)?;
    Ok(())
}

pub fn expect_firewall(expected: bool) -> Result<(), String> {
    update(|j| j.firewall_expected = expected)?;
    Ok(())
}

pub fn expect_network_lock(expected: bool) -> Result<(), String> {
    update(|j| j.network_lock_expected = expected)?;
    Ok(())
}

pub fn expect_transports(transports: Vec<String>) -> Result<(), String> {
    update(|j| j.active_transports = transports)?;
    Ok(())
}

pub fn set_phase(phase: SessionPhase, error: Option<String>) -> Result<(), String> {
    update(|j| {
        j.phase = phase;
        j.last_error = error;
    })?;
    Ok(())
}

pub fn clear() -> Result<(), String> {
    save(&SessionJournal::default())
}

pub fn recovery_status() -> RecoveryStatus {
    let journal = load();
    let proxy_live = crate::proxy::get_status().enabled;
    let tun_live = crate::tun::process_seems_running();
    let firewall_live = crate::firewall::status().active;
    let network_lock_live = crate::firewall::network_lock_status().active;
    let tor_live = crate::tor::socks_reachable() || crate::tor::control_reachable();
    let journal_dirty = journal.phase != SessionPhase::Disconnected
        || journal.proxy_changed
        || journal.tun_expected
        || journal.firewall_expected
        || journal.network_lock_expected
        || journal.tor_expected;
    let live_dirty = proxy_live || tun_live || firewall_live || network_lock_live || tor_live;
    let interrupted =
        journal_dirty && journal.owner_pid != 0 && journal.owner_pid != std::process::id();
    let needed = interrupted && live_dirty;
    RecoveryStatus {
        needed,
        phase: journal.phase,
        proxy_live,
        tun_live,
        firewall_live,
        network_lock_live,
        tor_live,
        detail: if needed {
            "A previous protected session did not finish cleanup. Run Emergency Restore.".into()
        } else if journal_dirty {
            "A stale session journal was found, but no OnionGate network state is live.".into()
        } else {
            "No interrupted session detected.".into()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_journal_is_disconnected_and_clean() {
        let journal = SessionJournal::default();
        assert_eq!(journal.phase, SessionPhase::Disconnected);
        assert!(!journal.proxy_changed);
        assert!(!journal.tun_expected);
        assert!(!journal.firewall_expected);
    }
}
