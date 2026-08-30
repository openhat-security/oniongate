//! On-disk locations owned by OnionGate.
//!
//! Older builds stored state under the internal name `tor-socks-gui`. Every
//! [`data_dir`] call absorbs that leftover folder into `oniongate`: a rename
//! when the new name is absent, or a merge (current wins on conflict) when
//! both exist. OnionGate never writes the leftover name. An old binary still
//! can; the next launch of this binary picks those writes up.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::{Map, Value};

pub const DATA_DIR_NAME: &str = "oniongate";
const LEGACY_DATA_DIR_NAME: &str = "tor-socks-gui";

/// Files that may be moved into place when current is missing them. Never
/// includes HiddenServiceDir trees (those are renamed as whole site dirs).
const ABSORB_FILES: &[&str] = &[
    "session.db",
    "persistence-baseline.json",
    "deny-journal.jsonl",
    "helper.plist",
    "oniongate-helper.service",
];

const ABSORB_EMPTY_DIRS: &[&str] = &["kill-siri"];

const LIST_KEYS: &[&str] = &[
    "bridge_lines",
    "route_apps",
    "split_tunnel_apps",
    "strict_tcp_exceptions",
];

/// Application data directory (`~/Library/Application Support/oniongate` on macOS).
pub fn data_dir() -> Result<PathBuf, String> {
    let parent = dirs::data_local_dir()
        .ok_or_else(|| "Could not resolve local data directory".to_string())?;
    let current = parent.join(DATA_DIR_NAME);
    let legacy = parent.join(LEGACY_DATA_DIR_NAME);
    absorb_legacy_dir(&legacy, &current)?;
    fs::create_dir_all(&current).map_err(|e| format!("Failed to create data dir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Failed to protect data dir: {e}"))?;
    }
    Ok(current)
}

fn absorb_legacy_dir(legacy: &Path, current: &Path) -> Result<(), String> {
    if !legacy.exists() {
        return Ok(());
    }
    if !current.exists() {
        return fs::rename(legacy, current).map_err(|e| {
            format!("Failed to migrate data directory from the previous name: {e}")
        });
    }
    merge_json_file(legacy, current, "settings.json")?;
    merge_sites_registry(legacy, current)?;
    absorb_missing_files(legacy, current)?;
    absorb_unique_child_dirs(&legacy.join("onion-sites"), &current.join("onion-sites"))?;
    absorb_unique_child_dirs(
        &legacy.join("onion-sites-parked"),
        &current.join("onion-sites-parked"),
    )?;
    let current_tor = current.join("tor-data");
    let legacy_tor = legacy.join("tor-data");
    if !current_tor.exists() && legacy_tor.exists() {
        let _ = fs::rename(&legacy_tor, &current_tor);
    }
    Ok(())
}

fn merge_json_file(legacy: &Path, current: &Path, name: &str) -> Result<(), String> {
    let leftover_path = legacy.join(name);
    let current_path = current.join(name);
    if !leftover_path.exists() {
        return Ok(());
    }
    if !current_path.exists() {
        return move_file(&leftover_path, &current_path);
    }
    let leftover_raw = fs::read_to_string(&leftover_path)
        .map_err(|e| format!("Failed to read leftover {name}: {e}"))?;
    let current_raw = fs::read_to_string(&current_path)
        .map_err(|e| format!("Failed to read {name}: {e}"))?;
    let Ok(leftover) = serde_json::from_str::<Value>(&leftover_raw) else {
        return Ok(());
    };
    let Ok(current_val) = serde_json::from_str::<Value>(&current_raw) else {
        return Ok(());
    };
    let leftover_newer = mtime(&leftover_path) > mtime(&current_path);
    let merged = merge_settings_values(&current_val, &leftover, leftover_newer);
    if merged == current_val {
        return Ok(());
    }
    write_private_json(&current_path, &merged)
}

fn merge_sites_registry(legacy: &Path, current: &Path) -> Result<(), String> {
    let leftover_path = legacy.join("onion-sites.json");
    let current_path = current.join("onion-sites.json");
    if !leftover_path.exists() {
        return Ok(());
    }
    if !current_path.exists() {
        return move_file(&leftover_path, &current_path);
    }
    let leftover_raw = fs::read_to_string(&leftover_path)
        .map_err(|e| format!("Failed to read leftover onion-sites registry: {e}"))?;
    let current_raw = fs::read_to_string(&current_path)
        .map_err(|e| format!("Failed to read onion-sites registry: {e}"))?;
    let Ok(leftover) = serde_json::from_str::<Value>(&leftover_raw) else {
        return Ok(());
    };
    let Ok(mut current_val) = serde_json::from_str::<Value>(&current_raw) else {
        return Ok(());
    };
    let Some(merged_sites) = union_site_arrays(current_val.get("sites"), leftover.get("sites"))
    else {
        return Ok(());
    };
    if let Some(obj) = current_val.as_object_mut() {
        obj.insert("sites".into(), merged_sites);
    }
    write_private_json(&current_path, &current_val)
}

fn absorb_missing_files(legacy: &Path, current: &Path) -> Result<(), String> {
    for name in ABSORB_FILES {
        let dest = current.join(name);
        let src = legacy.join(name);
        if !dest.exists() && src.exists() {
            move_file(&src, &dest)?;
        }
    }
    for name in ABSORB_EMPTY_DIRS {
        let dest = current.join(name);
        let src = legacy.join(name);
        if !dest.exists() && src.exists() {
            let _ = fs::rename(&src, &dest);
        }
    }
    Ok(())
}

/// Move a leftover child directory that current does not already have.
/// Rename only — never read or copy HiddenServiceDir contents.
fn absorb_unique_child_dirs(legacy_parent: &Path, current_parent: &Path) -> Result<(), String> {
    if !legacy_parent.exists() {
        return Ok(());
    }
    let entries = match fs::read_dir(legacy_parent) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let src = entry.path();
        if !src.is_dir() {
            continue;
        }
        let Some(name) = src.file_name() else {
            continue;
        };
        let dest = current_parent.join(name);
        if dest.exists() {
            continue;
        }
        if !current_parent.exists() {
            fs::create_dir_all(current_parent)
                .map_err(|e| format!("Failed to create site directory: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(current_parent, fs::Permissions::from_mode(0o700));
            }
        }
        let _ = fs::rename(&src, &dest);
    }
    Ok(())
}

fn move_file(src: &Path, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create data dir: {e}"))?;
    }
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Cross-device rename is not a key copy of HiddenServiceDir; these
            // callers are settings/registry/db only.
            fs::copy(src, dest).map_err(|e| format!("Failed to absorb leftover file: {e}"))?;
            let _ = fs::remove_file(src);
            Ok(())
        }
    }
}

fn write_private_json(path: &Path, value: &Value) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(value)
        .map_err(|e| format!("Failed to serialize merged settings: {e}"))?;
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, raw).map_err(|e| format!("Failed to write merged settings: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to protect merged settings: {e}"))?;
    }
    fs::rename(&temp, path).map_err(|e| format!("Failed to commit merged settings: {e}"))
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn merge_settings_values(current: &Value, leftover: &Value, leftover_newer: bool) -> Value {
    let (Some(cur), Some(leg)) = (current.as_object(), leftover.as_object()) else {
        return current.clone();
    };
    Value::Object(merge_settings_objects(cur, leg, leftover_newer))
}

fn merge_settings_objects(
    current: &Map<String, Value>,
    leftover: &Map<String, Value>,
    leftover_newer: bool,
) -> Map<String, Value> {
    let mut out = leftover.clone();
    for (key, value) in current {
        let leftover_val = leftover.get(key);
        if keep_leftover_collection(value, leftover_val) {
            continue;
        }
        if leftover_newer && LIST_KEYS.contains(&key.as_str()) {
            if let Some(merged) = union_json_arrays(value, leftover_val.unwrap_or(&Value::Null)) {
                out.insert(key.clone(), merged);
                continue;
            }
        }
        out.insert(key.clone(), value.clone());
    }
    out
}

fn keep_leftover_collection(current: &Value, leftover: Option<&Value>) -> bool {
    let Some(leftover) = leftover else {
        return false;
    };
    match (current, leftover) {
        (Value::Array(c), Value::Array(l)) if c.is_empty() && !l.is_empty() => true,
        (Value::String(c), Value::String(l)) if c.is_empty() && !l.is_empty() => true,
        _ => false,
    }
}

fn union_json_arrays(current: &Value, leftover: &Value) -> Option<Value> {
    let cur = current.as_array()?;
    let leg = leftover.as_array()?;
    let mut out = cur.clone();
    for item in leg {
        if !out.contains(item) {
            out.push(item.clone());
        }
    }
    Some(Value::Array(out))
}

fn union_site_arrays(current: Option<&Value>, leftover: Option<&Value>) -> Option<Value> {
    let mut out = current.and_then(Value::as_array).cloned().unwrap_or_default();
    let leftover = leftover.and_then(Value::as_array).cloned().unwrap_or_default();
    for site in leftover {
        let Some(id) = site.get("id").and_then(Value::as_str) else {
            continue;
        };
        let exists = out.iter().any(|row| row.get("id").and_then(Value::as_str) == Some(id));
        if !exists {
            out.push(site);
        }
    }
    Some(Value::Array(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "oniongate-paths-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn migrates_legacy_directory_when_new_name_is_absent() {
        let root = scratch("rename");
        let legacy = root.join(LEGACY_DATA_DIR_NAME);
        let current = root.join(DATA_DIR_NAME);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("settings.json"), "{\"ok\":true}").unwrap();
        absorb_legacy_dir(&legacy, &current).unwrap();
        assert!(current.join("settings.json").is_file());
        assert!(!legacy.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn merges_leftover_settings_when_both_exist() {
        let root = scratch("merge");
        let legacy = root.join(LEGACY_DATA_DIR_NAME);
        let current = root.join(DATA_DIR_NAME);
        fs::create_dir_all(&legacy).unwrap();
        fs::create_dir_all(&current).unwrap();
        fs::write(
            legacy.join("settings.json"),
            r#"{"bridge_lines":["Bridge obfs4 203.0.113.5:443 ABC"],"exit_country":"se","log_level":"info"}"#,
        )
        .unwrap();
        fs::write(
            current.join("settings.json"),
            r#"{"bridge_lines":[],"exit_country":"","log_level":"notice","connection_mode":"tun"}"#,
        )
        .unwrap();
        let leftover_before = fs::read_to_string(legacy.join("settings.json")).unwrap();
        absorb_legacy_dir(&legacy, &current).unwrap();
        let merged: Value =
            serde_json::from_str(&fs::read_to_string(current.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(merged["connection_mode"], "tun");
        assert_eq!(merged["log_level"], "notice");
        assert_eq!(merged["exit_country"], "se");
        assert_eq!(
            merged["bridge_lines"],
            serde_json::json!(["Bridge obfs4 203.0.113.5:443 ABC"])
        );
        assert_eq!(
            fs::read_to_string(legacy.join("settings.json")).unwrap(),
            leftover_before,
            "absorb must not write the leftover directory"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn current_scalar_wins_on_conflict() {
        let current = serde_json::json!({"log_level":"notice","exit_country":"de"});
        let leftover = serde_json::json!({"log_level":"info","exit_country":"se"});
        let merged = merge_settings_values(&current, &leftover, false);
        assert_eq!(merged["log_level"], "notice");
        assert_eq!(merged["exit_country"], "de");
    }

    #[test]
    fn leftover_only_keys_are_kept() {
        let current = serde_json::json!({"log_level":"notice"});
        let leftover = serde_json::json!({"log_level":"info","theme":"dark"});
        let merged = merge_settings_values(&current, &leftover, false);
        assert_eq!(merged["log_level"], "notice");
        assert_eq!(merged["theme"], "dark");
    }

    #[test]
    fn newer_leftover_unions_bridge_lines() {
        let current = serde_json::json!({"bridge_lines":["Bridge a"]});
        let leftover = serde_json::json!({"bridge_lines":["Bridge a","Bridge b"]});
        let merged = merge_settings_values(&current, &leftover, true);
        assert_eq!(
            merged["bridge_lines"],
            serde_json::json!(["Bridge a", "Bridge b"])
        );
    }

    #[test]
    fn moves_unique_onion_site_dir_without_touching_a_conflicting_one() {
        let root = scratch("sites");
        let legacy = root.join(LEGACY_DATA_DIR_NAME);
        let current = root.join(DATA_DIR_NAME);
        fs::create_dir_all(legacy.join("onion-sites/old-site")).unwrap();
        fs::create_dir_all(current.join("onion-sites/new-site")).unwrap();
        fs::write(legacy.join("onion-sites/old-site/hostname"), "old.onion").unwrap();
        fs::write(current.join("onion-sites/new-site/hostname"), "new.onion").unwrap();
        fs::write(
            legacy.join("onion-sites.json"),
            r#"{"sites":[{"id":"old-site","nickname":"old"}]}"#,
        )
        .unwrap();
        fs::write(
            current.join("onion-sites.json"),
            r#"{"sites":[{"id":"new-site","nickname":"new"}]}"#,
        )
        .unwrap();
        absorb_legacy_dir(&legacy, &current).unwrap();
        assert!(current.join("onion-sites/old-site/hostname").is_file());
        assert!(current.join("onion-sites/new-site/hostname").is_file());
        let registry: Value =
            serde_json::from_str(&fs::read_to_string(current.join("onion-sites.json")).unwrap())
                .unwrap();
        let ids: Vec<&str> = registry["sites"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["id"].as_str())
            .collect();
        assert!(ids.contains(&"old-site"));
        assert!(ids.contains(&"new-site"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn leaves_conflicting_leftover_site_in_place() {
        let root = scratch("conflict");
        let legacy = root.join(LEGACY_DATA_DIR_NAME);
        let current = root.join(DATA_DIR_NAME);
        fs::create_dir_all(legacy.join("onion-sites/same")).unwrap();
        fs::create_dir_all(current.join("onion-sites/same")).unwrap();
        fs::write(legacy.join("onion-sites/same/hostname"), "legacy.onion").unwrap();
        fs::write(current.join("onion-sites/same/hostname"), "current.onion").unwrap();
        absorb_legacy_dir(&legacy, &current).unwrap();
        assert_eq!(
            fs::read_to_string(current.join("onion-sites/same/hostname")).unwrap(),
            "current.onion"
        );
        assert_eq!(
            fs::read_to_string(legacy.join("onion-sites/same/hostname")).unwrap(),
            "legacy.onion"
        );
        let _ = fs::remove_dir_all(root);
    }
}
