//! macOS code-signature helpers for the privileged helper.
//!
//! Unsigned debug builds (`make dev`) skip these checks. A signed helper
//! refuses unsigned or foreign-signed peers; install refuses an unsigned
//! helper next to a signed app.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodesignInfo {
    pub identifier: String,
    pub team: Option<String>,
}

#[cfg(target_os = "macos")]
pub fn codesign_info(path: &Path) -> Option<CodesignInfo> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stderr);
    let mut identifier = None;
    let mut team = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Identifier=") {
            identifier = Some(value.trim().to_string());
        }
        if let Some(value) = line.strip_prefix("TeamIdentifier=") {
            let value = value.trim();
            if !value.is_empty() && value != "not set" {
                team = Some(value.to_string());
            }
        }
    }
    Some(CodesignInfo {
        identifier: identifier.filter(|id| !id.is_empty())?,
        team,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn codesign_info(_path: &Path) -> Option<CodesignInfo> {
    None
}

pub fn allowed_app_identifier(id: &str) -> bool {
    id == "com.adamsiwiec.oniongate" || id.starts_with("com.adamsiwiec.oniongate.")
}

/// When the app next to the helper is signed, the helper must be signed with
/// the same Team ID (or both ad-hoc with an allowed identifier).
pub fn verify_helper_for_install(helper: &Path, app: &Path) -> Result<(), String> {
    let Some(app_info) = codesign_info(app) else {
        return Ok(());
    };
    let helper_info = codesign_info(helper).ok_or_else(|| {
        "refusing to install an unsigned helper next to a signed OnionGate".to_string()
    })?;
    if !allowed_app_identifier(&app_info.identifier)
        && app_info.identifier != "oniongate"
        && app_info.identifier != "tor-socks-gui"
    {
        return Err("refusing to install a helper for an unexpected signed app".into());
    }
    match (&app_info.team, &helper_info.team) {
        (Some(app_team), Some(helper_team)) if app_team == helper_team => Ok(()),
        (None, None)
            if allowed_app_identifier(&helper_info.identifier)
                || helper_info.identifier.contains("oniongate") =>
        {
            Ok(())
        }
        _ => Err("helper code signature does not match the OnionGate app".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oniongate_bundle_id_is_allowed() {
        assert!(allowed_app_identifier("com.adamsiwiec.oniongate"));
        assert!(allowed_app_identifier("com.adamsiwiec.oniongate.helper"));
        assert!(!allowed_app_identifier("com.apple.finder"));
        assert!(!allowed_app_identifier("com.expressvpn.ExpressVPN"));
    }
}
