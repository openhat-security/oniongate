//! Permanent Onion Host sites.
//!
//! A permanent site keeps the same `.onion` address across restarts, which is
//! only possible if its service key survives. That key is generated and owned by
//! **Tor**, inside a `HiddenServiceDir` under Tor's data directory with
//! owner-only permissions. OnionGate never reads, copies, logs, or exports key
//! material; it only reads the public `hostname` file to learn the address.
//!
//! What OnionGate does persist is non-secret: a nickname, the port mapping, and
//! the *public* half of each authorized client key.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// A discarded-private-key client that keeps a newly created "private" site
/// closed before the user issues the first usable credential.
const AUTH_LOCK_CLIENT: &str = "oniongate-lock";

/// Non-secret record of a permanent site. The `.onion` address is deliberately
/// absent: it is read back from Tor's `hostname` file so that this registry
/// never becomes a second source of truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermanentSite {
    pub id: String,
    pub nickname: String,
    pub local_port: u16,
    pub virtual_port: u16,
    pub created_at_unix: u64,
}

/// A site plus the live state read from disk at call time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermanentSiteView {
    pub id: String,
    pub nickname: String,
    pub local_port: u16,
    pub virtual_port: u16,
    pub created_at_unix: u64,
    /// `None` until Tor has created the service and written `hostname`.
    pub hostname: Option<String>,
    pub auth_enabled: bool,
    pub clients: Vec<String>,
}

/// A freshly issued client credential. The private half exists only in this
/// value and is never written to disk by OnionGate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCredential {
    pub site_id: String,
    pub client_name: String,
    /// `descriptor:x25519:<base32 private key>`
    pub credential: String,
    /// Ready-to-paste contents of the client's `.auth_private` file, once the
    /// address is known.
    pub auth_private_line: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Registry {
    #[serde(default)]
    sites: Vec<PermanentSite>,
}

fn base_dir() -> Result<PathBuf, String> {
    let base = crate::paths::data_dir()?;
    restrict(&base)?;
    Ok(base)
}

fn sites_root() -> Result<PathBuf, String> {
    let root = base_dir()?.join("onion-sites");
    fs::create_dir_all(&root).map_err(|e| format!("Failed to create onion site dir: {e}"))?;
    restrict(&root)?;
    Ok(root)
}

/// Authorized-client files are parked here while authorization is switched off,
/// so that turning it back on does not invalidate credentials already handed
/// out. Kept outside the `HiddenServiceDir` so Tor never sees it.
fn parked_root() -> Result<PathBuf, String> {
    let root = base_dir()?.join("onion-sites-parked");
    fs::create_dir_all(&root).map_err(|e| format!("Failed to create parked client dir: {e}"))?;
    restrict(&root)?;
    Ok(root)
}

fn registry_path() -> Result<PathBuf, String> {
    Ok(base_dir()?.join("onion-sites.json"))
}

pub fn site_dir(id: &str) -> Result<PathBuf, String> {
    Ok(sites_root()?.join(id))
}

fn parked_dir(id: &str) -> Result<PathBuf, String> {
    Ok(parked_root()?.join(id))
}

fn clients_dir(id: &str) -> Result<PathBuf, String> {
    Ok(site_dir(id)?.join("authorized_clients"))
}

/// Tor refuses to use a `HiddenServiceDir` that is group- or world-accessible.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("Failed to restrict permissions on {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_registry() -> Registry {
    let Ok(path) = registry_path() else {
        return Registry::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return Registry::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_registry(registry: &Registry) -> Result<(), String> {
    let path = registry_path()?;
    let raw = serde_json::to_string_pretty(registry)
        .map_err(|e| format!("Failed to serialize onion site registry: {e}"))?;
    fs::write(&path, raw).map_err(|e| format!("Failed to write onion site registry: {e}"))
}

/// Reduce a nickname to a filesystem- and torrc-safe directory name.
pub fn slugify(nickname: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = true;
    for ch in nickname.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "site".into()
    } else {
        slug.chars().take(48).collect()
    }
}

fn unique_id(registry: &Registry, base: &str) -> String {
    if !registry.sites.iter().any(|s| s.id == base) {
        return base.to_string();
    }
    for n in 2..1000 {
        let candidate = format!("{base}-{n}");
        if !registry.sites.iter().any(|s| s.id == candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", now_unix())
}

/// Public address for a site, or `None` before Tor has published it.
fn read_hostname(id: &str) -> Option<String> {
    let path = site_dir(id).ok()?.join("hostname");
    let raw = fs::read_to_string(path).ok()?;
    let host = raw.trim().to_ascii_lowercase();
    if host.ends_with(".onion") {
        Some(host)
    } else {
        None
    }
}

fn list_auth_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.strip_suffix(".auth").map(str::to_string)
        })
        .collect();
    names.sort();
    names
}

fn list_client_files(dir: &Path) -> Vec<String> {
    list_auth_files(dir)
        .into_iter()
        .filter(|name| name != AUTH_LOCK_CLIENT)
        .collect()
}

fn revokes_final_active_client(active: &[String], name: &str) -> bool {
    active.len() == 1 && active.iter().any(|client| client == name)
}

fn view(site: &PermanentSite) -> PermanentSiteView {
    let active_dir = clients_dir(&site.id).ok();
    let auth_enabled = active_dir
        .as_ref()
        .is_some_and(|dir| !list_auth_files(dir).is_empty());
    let active = active_dir
        .as_ref()
        .map(|dir| list_client_files(dir))
        .unwrap_or_default();
    PermanentSiteView {
        id: site.id.clone(),
        nickname: site.nickname.clone(),
        local_port: site.local_port,
        virtual_port: site.virtual_port,
        created_at_unix: site.created_at_unix,
        hostname: read_hostname(&site.id),
        auth_enabled,
        clients: if !auth_enabled {
            parked_dir(&site.id)
                .map(|dir| list_client_files(&dir))
                .unwrap_or_default()
        } else {
            active
        },
    }
}

pub fn list() -> Vec<PermanentSiteView> {
    let mut sites = load_registry().sites;
    sites.sort_by(|a, b| a.id.cmp(&b.id));
    sites.iter().map(view).collect()
}

pub fn get(id: &str) -> Option<PermanentSiteView> {
    load_registry().sites.iter().find(|s| s.id == id).map(view)
}

/// torrc fragment for every permanent site, in a stable order.
///
/// Tor treats `HiddenServiceDir`/`HiddenServicePort` as one ordered group, so
/// these must always be emitted together and in the same sequence.
pub fn torrc_block() -> String {
    let Ok(root) = sites_root() else {
        return String::new();
    };
    torrc_block_for(&load_registry().sites, &root)
}

fn torrc_block_for(sites: &[PermanentSite], root: &Path) -> String {
    let mut sorted: Vec<&PermanentSite> = sites.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let mut out = String::new();
    for site in sorted {
        let dir = root.join(&site.id);
        out.push_str(&format!("HiddenServiceDir {}\n", dir.display()));
        out.push_str(&format!(
            "HiddenServicePort {} 127.0.0.1:{}\n",
            site.virtual_port, site.local_port
        ));
    }
    out
}

/// Rewrite torrc and ask a running Tor to pick the change up.
///
/// A reload re-reads the configuration without re-bootstrapping, dropping
/// circuits, or disturbing temporary services. When Tor is not running there is
/// nothing to do: torrc is regenerated from this registry at next start.
pub async fn apply() -> Result<(), String> {
    if !crate::tor::control_reachable() {
        return Ok(());
    }
    crate::tor::process::rewrite_torrc()?;
    crate::tor::control::run_authenticated(&["SIGNAL RELOAD"]).await?;
    Ok(())
}

/// Wait briefly for Tor to create a newly added service directory.
async fn await_hostname(id: &str) -> Option<String> {
    for _ in 0..20 {
        if let Some(host) = read_hostname(id) {
            return Some(host);
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    None
}

fn write_auth_lock(dir: &Path) -> Result<(), String> {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    let path = dir.join(format!("{AUTH_LOCK_CLIENT}.auth"));
    fs::write(
        &path,
        format!(
            "descriptor:x25519:{}\n",
            BASE32_NOPAD.encode(public.as_bytes())
        ),
    )
    .map_err(|e| format!("Failed to create private-site authorization lock: {e}"))?;
    restrict_file(&path)
}

pub async fn add(
    nickname: &str,
    local_port: u16,
    virtual_port: u16,
    enable_auth: bool,
) -> Result<PermanentSiteView, String> {
    if local_port == 0 || virtual_port == 0 {
        return Err("Ports must be between 1 and 65535".into());
    }
    let nickname = nickname.trim();
    if nickname.is_empty() {
        return Err("Give the site a name so you can tell it apart later".into());
    }

    // A listener that is already reachable on every interface must never be
    // published as an onion service. A listener that is simply not running yet
    // is allowed: permanent sites are commonly set up before the server behind
    // them starts.
    let listener = super::audit::inspect_listener(local_port);
    if listener.reachable && !listener.loopback_only {
        return Err(listener.detail);
    }

    let mut registry = load_registry();
    let id = unique_id(&registry, &slugify(nickname));

    let dir = site_dir(&id)?;
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create site directory: {e}"))?;
    restrict(&dir)?;

    registry.sites.push(PermanentSite {
        id: id.clone(),
        nickname: nickname.to_string(),
        local_port,
        virtual_port,
        created_at_unix: now_unix(),
    });
    save_registry(&registry)?;

    if enable_auth {
        let clients = clients_dir(&id)?;
        fs::create_dir_all(&clients)
            .map_err(|e| format!("Failed to create authorized_clients directory: {e}"))?;
        restrict(&clients)?;
        // An empty authorized_clients directory makes a Tor onion service
        // public. Install an unusable lock credential first, then remove it
        // when the user issues their first real credential.
        write_auth_lock(&clients)?;
    }

    // Roll the whole thing back if Tor will not take the change, rather than
    // leaving a half-created site behind. Nobody holds its address yet, so
    // discarding it is safe.
    if let Err(e) = apply().await {
        rollback_add(&id);
        return Err(format!(
            "Tor rejected the new site, so nothing was created: {e}"
        ));
    }

    // Only worth waiting when a running Tor could actually write `hostname`.
    if crate::tor::control_reachable() {
        await_hostname(&id).await;
    }

    crate::logs::append(format!(
        "Created permanent onion site '{id}' for loopback port {local_port}"
    ));

    get(&id).ok_or_else(|| "Site was created but could not be read back".into())
}

fn rollback_add(id: &str) {
    let mut registry = load_registry();
    registry.sites.retain(|s| s.id != id);
    let _ = save_registry(&registry);
    if let Ok(dir) = site_dir(id) {
        let _ = fs::remove_dir_all(dir);
    }
    let _ = crate::tor::process::rewrite_torrc();
}

pub async fn remove(id: &str) -> Result<String, String> {
    let mut registry = load_registry();
    let Some(index) = registry.sites.iter().position(|s| s.id == id) else {
        return Err("No permanent site with that id".into());
    };
    let site = registry.sites.remove(index);
    save_registry(&registry)?;

    // Removing the directory destroys Tor's copy of the key, which is what
    // makes the address unrecoverable.
    if let Ok(dir) = site_dir(id) {
        let _ = fs::remove_dir_all(dir);
    }
    if let Ok(dir) = parked_dir(id) {
        let _ = fs::remove_dir_all(dir);
    }

    crate::logs::append(format!("Deleted permanent onion site '{}'", site.id));

    // The key is already gone, so this cannot be undone. If Tor would not
    // reload, say so plainly: the running instance keeps serving the site from
    // memory until it restarts.
    if let Err(e) = apply().await {
        return Ok(format!(
            "Deleted permanent site '{}' and destroyed its key, but Tor did not reload ({e}). \
             It stays reachable until Tor restarts.",
            site.nickname
        ));
    }

    Ok(format!(
        "Deleted permanent site '{}'. Its address cannot be recovered.",
        site.nickname
    ))
}

pub async fn rename(id: &str, nickname: &str) -> Result<PermanentSiteView, String> {
    let nickname = nickname.trim();
    if nickname.is_empty() {
        return Err("Site name cannot be empty".into());
    }
    let mut registry = load_registry();
    let site = registry
        .sites
        .iter_mut()
        .find(|s| s.id == id)
        .ok_or_else(|| "No permanent site with that id".to_string())?;
    site.nickname = nickname.to_string();
    save_registry(&registry)?;
    get(id).ok_or_else(|| "Site could not be read back".into())
}

fn valid_client_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Give the credential a name so you can revoke it later".into());
    }
    if trimmed.chars().count() > 48 {
        return Err("Credential name is too long (48 characters maximum)".into());
    }
    Ok(slugify(trimmed))
}

/// Issue a new client credential. The private half is returned once and is not
/// stored; only the public half is written into `authorized_clients/`.
pub async fn add_client(id: &str, name: &str) -> Result<IssuedCredential, String> {
    let site = get(id).ok_or_else(|| "No permanent site with that id".to_string())?;
    let client_name = valid_client_name(name)?;

    let auth_enabled = site.auth_enabled;
    let dir = if auth_enabled {
        clients_dir(id)?
    } else {
        parked_dir(id)?
    };
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create authorized_clients directory: {e}"))?;
    restrict(&dir)?;

    let file = dir.join(format!("{client_name}.auth"));
    if file.exists() {
        return Err(format!("A credential named '{client_name}' already exists"));
    }

    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    fs::write(
        &file,
        format!(
            "descriptor:x25519:{}\n",
            BASE32_NOPAD.encode(public.as_bytes())
        ),
    )
    .map_err(|e| format!("Failed to write client authorization: {e}"))?;
    restrict_file(&file)?;
    let lock = dir.join(format!("{AUTH_LOCK_CLIENT}.auth"));
    let had_lock = lock.exists();
    if had_lock {
        if let Err(e) = fs::remove_file(&lock) {
            let _ = fs::remove_file(&file);
            return Err(format!(
                "Failed to replace private-site authorization lock: {e}"
            ));
        }
    }

    let credential = format!(
        "descriptor:x25519:{}",
        BASE32_NOPAD.encode(secret.as_bytes())
    );
    let auth_private_line = site
        .hostname
        .as_ref()
        .and_then(|host| host.strip_suffix(".onion"))
        .map(|addr| format!("{addr}:{credential}"));

    if auth_enabled {
        if let Err(e) = apply().await {
            // The private half has not been returned yet. Remove the unusable
            // public key and restore the fail-closed lock if this was the first
            // credential.
            let _ = fs::remove_file(&file);
            if had_lock {
                let _ = write_auth_lock(&dir);
            }
            let _ = apply().await;
            return Err(format!(
                "Tor did not accept the client authorization change, so no credential was issued: {e}"
            ));
        }
    }
    crate::logs::append(format!(
        "Issued client credential '{client_name}' for permanent onion site '{id}'"
    ));

    Ok(IssuedCredential {
        site_id: id.to_string(),
        client_name,
        credential,
        auth_private_line,
    })
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to restrict permissions on {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub async fn revoke_client(id: &str, name: &str) -> Result<String, String> {
    if get(id).is_none() {
        return Err("No permanent site with that id".into());
    }
    let active = clients_dir(id)?;
    let parked = parked_dir(id)?;
    let active_names = list_client_files(&active);
    if revokes_final_active_client(&active_names, name) {
        return Err(
            "Cannot revoke the final active credential because that would make the site public. \
             Add another credential first, or turn authorization off explicitly."
                .into(),
        );
    }
    let mut removed = false;
    for dir in [active, parked] {
        let file = dir.join(format!("{name}.auth"));
        if file.exists() {
            fs::remove_file(&file).map_err(|e| format!("Failed to revoke credential: {e}"))?;
            removed = true;
        }
    }
    if !removed {
        return Err(format!("No credential named '{name}' on this site"));
    }
    apply().await?;
    crate::logs::append(format!(
        "Revoked client credential '{name}' on permanent onion site '{id}'"
    ));
    Ok(format!(
        "Revoked '{name}'. It can no longer reach this site."
    ))
}

/// Switch client authorization on or off.
///
/// Turning it off parks the authorized-client files outside the service
/// directory rather than deleting them, so credentials already handed out keep
/// working when authorization is switched back on.
pub async fn set_auth_enabled(id: &str, enabled: bool) -> Result<PermanentSiteView, String> {
    if get(id).is_none() {
        return Err("No permanent site with that id".into());
    }
    let active = clients_dir(id)?;
    let parked = parked_dir(id)?;

    if enabled {
        let names = list_auth_files(&parked);
        if names.is_empty() && list_auth_files(&active).is_empty() {
            return Err(
                "Issue at least one client credential before turning authorization on".into(),
            );
        }
        fs::create_dir_all(&active)
            .map_err(|e| format!("Failed to create authorized_clients directory: {e}"))?;
        restrict(&active)?;
        for name in names {
            let file = format!("{name}.auth");
            fs::rename(parked.join(&file), active.join(&file))
                .map_err(|e| format!("Failed to restore client authorization: {e}"))?;
        }
    } else {
        let names = list_auth_files(&active);
        fs::create_dir_all(&parked)
            .map_err(|e| format!("Failed to create parked client directory: {e}"))?;
        restrict(&parked)?;
        for name in names {
            let file = format!("{name}.auth");
            fs::rename(active.join(&file), parked.join(&file))
                .map_err(|e| format!("Failed to park client authorization: {e}"))?;
        }
    }

    apply().await?;
    crate::logs::append(format!(
        "Client authorization {} for permanent onion site '{id}'",
        if enabled { "enabled" } else { "disabled" }
    ));
    get(id).ok_or_else(|| "Site could not be read back".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_produces_safe_directory_names() {
        assert_eq!(slugify("My Blog"), "my-blog");
        assert_eq!(slugify("  spaced  out  "), "spaced-out");
        assert_eq!(slugify("weird!!!chars???"), "weird-chars");
        assert_eq!(slugify("--leading-and-trailing--"), "leading-and-trailing");
        assert_eq!(slugify(""), "site");
        assert_eq!(slugify("!!!"), "site");
    }

    #[test]
    fn slugify_never_escapes_its_directory() {
        for probe in ["../../etc/passwd", "..", "a/../../b", "C:\\Windows"] {
            let slug = slugify(probe);
            assert!(!slug.contains('/'), "{slug} contains a path separator");
            assert!(!slug.contains('\\'), "{slug} contains a path separator");
            assert!(!slug.contains(".."), "{slug} can traverse upwards");
        }
    }

    #[test]
    fn unique_id_avoids_collisions() {
        let registry = Registry {
            sites: vec![
                PermanentSite {
                    id: "blog".into(),
                    nickname: "Blog".into(),
                    local_port: 3000,
                    virtual_port: 80,
                    created_at_unix: 0,
                },
                PermanentSite {
                    id: "blog-2".into(),
                    nickname: "Blog".into(),
                    local_port: 3001,
                    virtual_port: 80,
                    created_at_unix: 0,
                },
            ],
        };
        assert_eq!(unique_id(&registry, "blog"), "blog-3");
        assert_eq!(unique_id(&registry, "notes"), "notes");
    }

    #[test]
    fn registry_round_trips_without_secrets() {
        let registry = Registry {
            sites: vec![PermanentSite {
                id: "blog".into(),
                nickname: "My Blog".into(),
                local_port: 3000,
                virtual_port: 80,
                created_at_unix: 1_700_000_000,
            }],
        };
        let json = serde_json::to_string(&registry).unwrap();
        // The registry must never gain a key or credential field.
        assert!(!json.contains("key"));
        assert!(!json.contains("credential"));
        assert!(!json.contains("secret"));
        let back: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sites, registry.sites);
    }

    #[test]
    fn client_auth_file_uses_the_documented_format() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);
        let line = format!(
            "descriptor:x25519:{}",
            BASE32_NOPAD.encode(public.as_bytes())
        );
        let encoded = line.strip_prefix("descriptor:x25519:").unwrap();
        // 32 raw bytes base32-encoded without padding is 52 characters.
        assert_eq!(encoded.len(), 52);
        assert!(!encoded.contains('='));
        assert!(encoded
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn discarded_private_auth_lock_is_active_but_hidden_from_client_list() {
        let dir = std::env::temp_dir().join(format!(
            "oniongate-auth-lock-{}-{}",
            std::process::id(),
            now_unix()
        ));
        fs::create_dir_all(&dir).unwrap();
        write_auth_lock(&dir).unwrap();
        fs::write(
            dir.join("alice.auth"),
            "descriptor:x25519:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST\n",
        )
        .unwrap();

        assert_eq!(
            list_auth_files(&dir),
            vec!["alice".to_string(), AUTH_LOCK_CLIENT.to_string()]
        );
        assert_eq!(list_client_files(&dir), vec!["alice".to_string()]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn final_active_client_cannot_be_revoked_implicitly() {
        let clients = vec!["alice".to_string()];
        assert!(revokes_final_active_client(&clients, "alice"));
        assert!(!revokes_final_active_client(&clients, "bob"));
        assert!(!revokes_final_active_client(
            &["alice".to_string(), "bob".to_string()],
            "alice"
        ));
    }

    #[test]
    fn a_missing_hostname_file_is_not_an_address() {
        assert_eq!(read_hostname("definitely-not-a-real-site-id-xyz"), None);
    }

    fn site(id: &str, local: u16, virt: u16) -> PermanentSite {
        PermanentSite {
            id: id.into(),
            nickname: id.into(),
            local_port: local,
            virtual_port: virt,
            created_at_unix: 0,
        }
    }

    #[test]
    fn torrc_block_pairs_each_directory_with_its_port() {
        let root = Path::new("/data/onion-sites");
        let block = torrc_block_for(&[site("blog", 3000, 80)], root);
        // Tor expects the platform's own separator, so derive the expected
        // directory rather than hard-coding a Unix path.
        let dir = root.join("blog");
        assert_eq!(
            block,
            format!(
                "HiddenServiceDir {}\nHiddenServicePort 80 127.0.0.1:3000\n",
                dir.display()
            )
        );
    }

    /// Tor reads HiddenServiceDir/HiddenServicePort as one ordered group, so an
    /// unstable order would silently repoint sites at each other's keys.
    #[test]
    fn torrc_block_order_is_stable_regardless_of_registry_order() {
        let root = Path::new("/data/onion-sites");
        let forward = [site("alpha", 3000, 80), site("beta", 3001, 8080)];
        let reversed = [site("beta", 3001, 8080), site("alpha", 3000, 80)];
        assert_eq!(
            torrc_block_for(&forward, root),
            torrc_block_for(&reversed, root)
        );
        let block = torrc_block_for(&reversed, root);
        assert!(block.find("alpha").unwrap() < block.find("beta").unwrap());
    }

    #[test]
    fn torrc_block_is_empty_without_permanent_sites() {
        assert!(torrc_block_for(&[], Path::new("/data/onion-sites")).is_empty());
    }

    /// Deleting a site is the only way to revoke it, so it must vanish from the
    /// configuration Tor reads.
    #[test]
    fn a_removed_site_leaves_no_trace_in_torrc() {
        let root = Path::new("/data/onion-sites");
        let remaining = [site("keep", 3000, 80)];
        let block = torrc_block_for(&remaining, root);
        assert!(block.contains("keep"));
        assert!(!block.contains("gone"));
    }

    /// Permanent sites are represented only in torrc, never in the in-memory
    /// store that session teardown drains, so `stop_all_temporary` cannot reach
    /// them.
    #[test]
    fn permanent_sites_are_absent_from_the_temporary_store() {
        let root = Path::new("/data/onion-sites");
        assert!(!torrc_block_for(&[site("blog", 3000, 80)], root).is_empty());
        assert!(crate::onion_service::list()
            .iter()
            .all(|project| project.service_id != "blog"));
    }
}
