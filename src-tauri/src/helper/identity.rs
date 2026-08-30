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

/// rustc/ld64 ad-hoc linker signatures look like `oniongate-ed8101b581b559cc`
/// — crate or bin name, then a hyphen and 16 hex chars. Strip that suffix so
/// the allowlist can match the product, not the per-build hash.
///
/// `tor-socks-gui` / `tor_socks_gui-<hash>` remain accepted so already-installed
/// unsigned builds can still talk to a replacement helper.
fn linker_signed_stem(id: &str) -> &str {
    const SUFFIX: usize = 17; // '-' + 16 hex digits
    if id.len() > SUFFIX {
        let split = id.len() - SUFFIX;
        if id.as_bytes()[split] == b'-' && id[split + 1..].bytes().all(|b| b.is_ascii_hexdigit()) {
            return &id[..split];
        }
    }
    id
}

fn identifier_stem(id: &str) -> String {
    linker_signed_stem(id.trim())
        .to_ascii_lowercase()
        .replace('_', "-")
}

pub fn allowed_app_identifier(id: &str) -> bool {
    let stem = identifier_stem(id);
    matches!(
        stem.as_str(),
        "com.adamsiwiec.oniongate"
            | "oniongate"
            | "oniongate-cli"
            | "oniongate-helper"
            | "tor-socks-gui"
    ) || stem.starts_with("com.adamsiwiec.oniongate.")
}

/// True when the signed identifier is an OnionGate binary, or when the process
/// lives inside an OnionGate.app whose Info.plist CFBundleIdentifier is ours.
/// Used both at helper install and on every privileged IPC connection.
pub fn app_identity_allowed(app: &Path, signed_id: &str) -> bool {
    if allowed_app_identifier(signed_id) {
        return true;
    }
    enclosing_app_bundle(app)
        .and_then(bundle_identifier_from_plist)
        .is_some_and(|id| allowed_app_identifier(&id))
}

fn enclosing_app_bundle(path: &Path) -> Option<&Path> {
    path.ancestors()
        .find(|candidate| candidate.extension().is_some_and(|ext| ext == "app"))
}

fn bundle_identifier_from_plist(app_bundle: &Path) -> Option<String> {
    let text = std::fs::read_to_string(app_bundle.join("Contents/Info.plist")).ok()?;
    let key = text.find("<key>CFBundleIdentifier</key>")?;
    let after = &text[key..];
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")?;
    let value = after[start..start + end].trim();
    (!value.is_empty()).then(|| value.to_string())
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
    if !app_identity_allowed(app, &app_info.identifier) {
        return Err("refusing to install a helper for an unexpected signed app".into());
    }
    match (&app_info.team, &helper_info.team) {
        (Some(app_team), Some(helper_team)) if app_team == helper_team => Ok(()),
        (None, None) if allowed_app_identifier(&helper_info.identifier) => Ok(()),
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
        assert!(allowed_app_identifier("oniongate"));
        assert!(allowed_app_identifier("oniongate-cli"));
        assert!(allowed_app_identifier("OnionGate"));
        assert!(allowed_app_identifier("tor-socks-gui"));
        assert!(allowed_app_identifier("tor_socks_gui-41fc8c7bff308390"));
        assert!(allowed_app_identifier("oniongate-ed8101b581b559cc"));
        assert!(allowed_app_identifier("oniongate_helper-4939cbb0a38623fb"));
        assert!(allowed_app_identifier("oniongate-helper"));
        assert!(!allowed_app_identifier("com.apple.finder"));
        assert!(!allowed_app_identifier("com.expressvpn.ExpressVPN"));
        assert!(!allowed_app_identifier("com.evil.oniongate"));
        assert!(!allowed_app_identifier("oniongate-stealer"));
        assert!(!allowed_app_identifier("not-oniongate-aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn plist_bundle_id_allows_adhoc_product_name() {
        let root = tempfile_bundle(
            "OnionGate.app",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.adamsiwiec.oniongate</string>
</dict>
</plist>
"#,
        );
        let exe = root.join("OnionGate.app/Contents/MacOS/oniongate");
        assert!(app_identity_allowed(&exe, "OnionGate"));
        assert!(app_identity_allowed(&exe, "a-foreign-id"));
    }

    #[test]
    fn foreign_bundle_id_is_rejected() {
        let root = tempfile_bundle(
            "Other.app",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.expressvpn.ExpressVPN</string>
</dict>
</plist>
"#,
        );
        let exe = root.join("Other.app/Contents/MacOS/Other");
        assert!(!app_identity_allowed(&exe, "Other"));
    }

    fn tempfile_bundle(name: &str, plist: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "oniongate-identity-{}-{}",
            std::process::id(),
            name
        ));
        let macos = root.join(name).join("Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::write(root.join(name).join("Contents/Info.plist"), plist).unwrap();
        std::fs::write(macos.join("oniongate"), []).unwrap();
        std::fs::write(macos.join("Other"), []).unwrap();
        root
    }
}
