//! SQLite persistence for bridge cache and session metrics.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

static DB: Mutex<Option<Connection>> = Mutex::new(None);

fn db_path() -> Result<PathBuf, String> {
    Ok(crate::paths::data_dir()?.join("session.db"))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn init() -> Result<(), String> {
    let path = db_path()?;
    let conn = Connection::open(&path).map_err(|e| format!("SQLite open failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to protect SQLite database: {e}"))?;
    }
    conn.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS bridge_cache (
            transport TEXT NOT NULL,
            lines_json TEXT NOT NULL,
            source TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            PRIMARY KEY (transport)
        );
        CREATE TABLE IF NOT EXISTS bridge_library (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            line TEXT NOT NULL UNIQUE,
            transport TEXT NOT NULL,
            saved_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at INTEGER NOT NULL,
            ended_at INTEGER,
            strategy TEXT,
            mode TEXT
        );
        CREATE TABLE IF NOT EXISTS session_live (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            session_id INTEGER,
            bytes_read INTEGER NOT NULL DEFAULT 0,
            bytes_written INTEGER NOT NULL DEFAULT 0,
            circuits INTEGER NOT NULL DEFAULT 0,
            identity_changes INTEGER NOT NULL DEFAULT 0,
            rate_down_bps REAL NOT NULL DEFAULT 0,
            rate_up_bps REAL NOT NULL DEFAULT 0,
            started_at INTEGER,
            last_sample_at INTEGER,
            last_read INTEGER NOT NULL DEFAULT 0,
            last_written INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS leak_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at INTEGER NOT NULL,
            report_json TEXT NOT NULL
        );
        INSERT OR IGNORE INTO session_live (id) VALUES (1);
        "#,
    )
    .map_err(|e| format!("SQLite migrate failed: {e}"))?;

    let mut guard = DB.lock().map_err(|e| e.to_string())?;
    *guard = Some(conn);
    Ok(())
}

fn with_db<T>(f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
    let guard = DB.lock().map_err(|e| e.to_string())?;
    let conn = guard
        .as_ref()
        .ok_or_else(|| "Database not initialized".to_string())?;
    f(conn)
}

pub fn cache_bridges(transport: &str, lines: &[String], source: &str) -> Result<(), String> {
    let json = serde_json::to_string(lines).map_err(|e| e.to_string())?;
    let at = now_unix();
    with_db(|conn| {
        conn.execute(
            "INSERT INTO bridge_cache(transport, lines_json, source, fetched_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(transport) DO UPDATE SET
               lines_json=excluded.lines_json,
               source=excluded.source,
               fetched_at=excluded.fetched_at",
            params![transport, json, source, at],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn load_bridge_cache(transport: &str) -> Option<(Vec<String>, String, i64)> {
    with_db(|conn| {
        let mut stmt = conn
            .prepare("SELECT lines_json, source, fetched_at FROM bridge_cache WHERE transport=?1")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query(params![transport]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let json: String = row.get(0).map_err(|e| e.to_string())?;
            let source: String = row.get(1).map_err(|e| e.to_string())?;
            let at: i64 = row.get(2).map_err(|e| e.to_string())?;
            let lines: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
            return Ok(Some((lines, source, at)));
        }
        Ok(None)
    })
    .ok()
    .flatten()
}

pub fn save_library_lines(lines: &[String]) -> Result<usize, String> {
    let at = now_unix();
    with_db(|conn| {
        let mut n = 0usize;
        for line in lines {
            let transport = crate::tor::bridges::describe_bridge(line).transport;
            let changed = conn
                .execute(
                    "INSERT OR IGNORE INTO bridge_library(line, transport, saved_at) VALUES (?1, ?2, ?3)",
                    params![line, transport, at],
                )
                .map_err(|e| e.to_string())?;
            n += changed as usize;
        }
        Ok(n)
    })
}

pub fn list_library() -> Result<Vec<String>, String> {
    with_db(|conn| {
        let mut stmt = conn
            .prepare("SELECT line FROM bridge_library ORDER BY saved_at DESC")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionOverview {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub bytes_total: u64,
    pub circuits: u32,
    pub identity_changes: u32,
    pub rate_down_bps: f64,
    pub rate_up_bps: f64,
    pub uptime_secs: u64,
    pub started_at: Option<i64>,
    pub connected: bool,
}

pub fn start_session(strategy: &str, mode: &str) -> Result<(), String> {
    let at = now_unix();
    with_db(|conn| {
        conn.execute(
            "INSERT INTO sessions(started_at, strategy, mode) VALUES (?1, ?2, ?3)",
            params![at, strategy, mode],
        )
        .map_err(|e| e.to_string())?;
        let sid = conn.last_insert_rowid();
        conn.execute(
            "UPDATE session_live SET
                session_id=?1,
                bytes_read=0, bytes_written=0, circuits=0, identity_changes=0,
                rate_down_bps=0, rate_up_bps=0,
                started_at=?2, last_sample_at=?2,
                last_read=0, last_written=0
             WHERE id=1",
            params![sid, at],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn end_session() -> Result<(), String> {
    let at = now_unix();
    with_db(|conn| {
        let sid: Option<i64> = conn
            .query_row("SELECT session_id FROM session_live WHERE id=1", [], |r| {
                r.get(0)
            })
            .ok()
            .flatten();
        if let Some(sid) = sid {
            let _ = conn.execute(
                "UPDATE sessions SET ended_at=?1 WHERE id=?2",
                params![at, sid],
            );
        }
        Ok(())
    })
}

pub fn bump_identity() -> Result<(), String> {
    with_db(|conn| {
        conn.execute(
            "UPDATE session_live SET identity_changes = identity_changes + 1 WHERE id=1",
            [],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn sample_traffic(bytes_read: u64, bytes_written: u64, circuits: u32) -> Result<(), String> {
    let at = now_unix();
    with_db(|conn| {
        let (last_read, last_written, last_at, started): (i64, i64, Option<i64>, Option<i64>) =
            conn.query_row(
                "SELECT last_read, last_written, last_sample_at, started_at FROM session_live WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|e| e.to_string())?;

        let mut rate_down = 0.0;
        let mut rate_up = 0.0;
        if let Some(prev) = last_at {
            let dt = (at - prev).max(1) as f64;
            let lr = last_read.max(0) as u64;
            let lw = last_written.max(0) as u64;
            if bytes_read >= lr {
                rate_down = (bytes_read - lr) as f64 / dt;
            }
            if bytes_written >= lw {
                rate_up = (bytes_written - lw) as f64 / dt;
            }
        }
        let started_at = started.unwrap_or(at);
        conn.execute(
            "UPDATE session_live SET
                bytes_read=?1, bytes_written=?2, circuits=?3,
                rate_down_bps=?4, rate_up_bps=?5,
                last_sample_at=?6, last_read=?1, last_written=?2,
                started_at=COALESCE(started_at, ?7)
             WHERE id=1",
            params![
                bytes_read as i64,
                bytes_written as i64,
                circuits,
                rate_down,
                rate_up,
                at,
                started_at
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn overview(connected: bool) -> SessionOverview {
    with_db(|conn| {
        let row = conn.query_row(
            "SELECT bytes_read, bytes_written, circuits, identity_changes,
                    rate_down_bps, rate_up_bps, started_at
             FROM session_live WHERE id=1",
            [],
            |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, u32>(2)?,
                    r.get::<_, u32>(3)?,
                    r.get::<_, f64>(4)?,
                    r.get::<_, f64>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                ))
            },
        );
        match row {
            Ok((br, bw, circ, idc, rd, ru, started)) => {
                let uptime = started.map(|s| (now_unix() - s).max(0) as u64).unwrap_or(0);
                Ok(SessionOverview {
                    bytes_read: br,
                    bytes_written: bw,
                    bytes_total: br.saturating_add(bw),
                    circuits: circ,
                    identity_changes: idc,
                    rate_down_bps: rd,
                    rate_up_bps: ru,
                    uptime_secs: if connected { uptime } else { 0 },
                    started_at: started,
                    connected,
                })
            }
            Err(_) => Ok(SessionOverview {
                connected,
                ..Default::default()
            }),
        }
    })
    .unwrap_or_default()
}

pub fn save_leak_report(report: &crate::verify::LeakReport) -> Result<(), String> {
    let json = serde_json::to_string(report).map_err(|e| e.to_string())?;
    with_db(|conn| {
        conn.execute(
            "INSERT INTO leak_reports(created_at, report_json) VALUES (?1, ?2)",
            params![report.created_at_unix as i64, json],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "DELETE FROM leak_reports WHERE id NOT IN (SELECT id FROM leak_reports ORDER BY id DESC LIMIT 20)",
            [],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })
}

pub fn latest_leak_report() -> Result<Option<crate::verify::LeakReport>, String> {
    with_db(|conn| {
        let mut stmt = conn
            .prepare("SELECT report_json FROM leak_reports ORDER BY id DESC LIMIT 1")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        let Some(row) = rows.next().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let json: String = row.get(0).map_err(|e| e.to_string())?;
        serde_json::from_str(&json)
            .map(Some)
            .map_err(|e| e.to_string())
    })
}
