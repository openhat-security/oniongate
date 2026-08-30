use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use serde::{Deserialize, Serialize};

const MAX_APP_LINES: usize = 400;
const MAX_FILE_TAIL: usize = 500;

static APP_LOG: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorLogs {
    pub lines: Vec<String>,
    pub source: String,
    pub log_path: Option<String>,
}

fn app_dir() -> Result<PathBuf, String> {
    crate::paths::data_dir()
}

pub fn tor_log_path() -> Result<PathBuf, String> {
    Ok(app_dir()?.join("tor.log"))
}

pub fn append(line: impl AsRef<str>) {
    let ts = now_hms();
    let entry = format!("[{ts}] {}", line.as_ref());
    if let Ok(mut guard) = APP_LOG.lock() {
        guard.push(entry);
        let overflow = guard.len().saturating_sub(MAX_APP_LINES);
        if overflow > 0 {
            guard.drain(0..overflow);
        }
    }
}

fn now_hms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 86400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

pub fn clear() -> Result<(), String> {
    if let Ok(mut guard) = APP_LOG.lock() {
        guard.clear();
    }
    if let Ok(path) = tor_log_path() {
        let _ = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path);
    }
    append("Log cleared");
    Ok(())
}

fn tail_file(path: &PathBuf, max_lines: usize) -> Vec<String> {
    let Ok(file) = fs::File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let mut lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    if lines.len() > max_lines {
        lines = lines.split_off(lines.len() - max_lines);
    }
    lines
}

pub fn get_logs() -> TorLogs {
    let log_path = tor_log_path().ok();
    let mut file_lines = log_path
        .as_ref()
        .map(|p| tail_file(p, MAX_FILE_TAIL))
        .unwrap_or_default();

    let app_lines = APP_LOG.lock().map(|g| g.clone()).unwrap_or_default();

    let source = if !file_lines.is_empty() {
        "tor.log + app".into()
    } else if !app_lines.is_empty() {
        "app".into()
    } else {
        "empty".into()
    };

    if !app_lines.is_empty() {
        if !file_lines.is_empty() {
            file_lines.push("--- app ---".into());
        }
        file_lines.extend(app_lines);
    }

    if file_lines.is_empty() {
        file_lines.push(
            "No Tor log output yet. Start Tor from the app to capture managed Tor logs.".into(),
        );
    }

    TorLogs {
        lines: file_lines,
        source,
        log_path: log_path.map(|p| p.display().to_string()),
    }
}

/// Ensure the log file exists so Tor can append.
pub fn ensure_log_file() -> Result<PathBuf, String> {
    let path = tor_log_path()?;
    if !path.exists() {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("Failed to create log file: {e}"))?;
        writeln!(f, "# OnionGate log").ok();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to protect log file: {e}"))?;
    }
    Ok(path)
}
