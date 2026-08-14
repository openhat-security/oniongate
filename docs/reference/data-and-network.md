# Local data and network activity

OnionGate has no analytics, advertising SDK, remote logging, or diagnostic
upload. It still makes network requests for the features you ask it to perform.
This page is the concrete inventory.

## Local data directory

The current internal directory name predates the OnionGate name:

- macOS: `~/Library/Application Support/tor-socks-gui/`
- Linux: `~/.local/share/tor-socks-gui/`
- Windows: `%LOCALAPPDATA%\tor-socks-gui\`

Do not sync this directory to cloud storage. It can contain permanent onion-site
keys owned by Tor. On Unix, OnionGate enforces mode `0700` on the directory and
mode `0600` on settings, the session database, logs, recovery journal, and
client-authorization files where it creates them. Operating-system compromise
or another process running as your user remains in scope.

## Files and retention

| Data | Location / retention | Sensitivity |
| --- | --- | --- |
| Settings, selected app identities, and bridge lines | `settings.json`, until changed or removed | Bridge lines and local paths are sensitive |
| Tor data and permanent onion keys | `tor-data/` and `onion-sites/`, until a site is deleted | Permanent private keys are critical secrets |
| Permanent-site registry | `onion-sites.json` | Names, ports, public onion addresses, client names |
| Client authorization public keys | each site's `authorized_clients/` | Public halves only |
| Recovery journal | `session-journal.json`, rewritten per session, mode 600 on Unix | Proxy snapshot and live-state expectations |
| Tor log | `tor.log`, until cleared or removed | May contain sensitive operational context |
| TUN config and log | `sing-box-tun.json`, `sing-box.log` | App paths, process names, route policy |
| Session database | `session.db` | Bridge cache/library, session times and modes, counters |
| Verification reports | newest 20 rows in `session.db` | Results and remediation, no public IP values |
| Startup baseline | `persistence-baseline.json`, until replaced/removed | Local startup paths and signature metadata |
| Generated helper service files | local data plus platform service paths | Allowed UID and service configuration |
| App bypass helpers | target app settings, `~/.tor-socks-gui/`, `/etc/tor-socks-gui/`, and user launcher locations | Proxy configuration and local paths |

The session database keeps session start/end times, selected strategy and mode,
live byte totals/rates, circuit counts, and identity-change counts. It does not
store destination history. The Verify page's live connection census is process-memory only. Full
addresses may appear in the UI; saved leak reports store a bypass count only.

App-specific helpers deliberately write outside the main data directory:
Firefox `user.js`, Cursor/VS Code settings, Claude Code settings, shell startup
files, and separate Chrome/Discord/Slack launchers. The Apps page shows and
removes the known OnionGate-managed configuration; see
[Route applications](/guide/apps).

## Onion Host secrets

Temporary service keys are never written: Tor receives `DiscardPK` when the
service is created.

Permanent service keys are generated and read by Tor inside each
`HiddenServiceDir`. OnionGate reads only the public `hostname`. Deleting a
permanent site deletes that directory and irreversibly destroys the address.

For client authorization, OnionGate stores only the public client key. The
private credential is displayed once. Redirecting CLI output, copying it to the
clipboard, taking a screenshot, or saving the QR code moves that secret outside
OnionGate's storage guarantees.

## Network requests

### Tor and pluggable transports

Connecting contacts the Tor network. If bridges are active, the selected bridge
or transport infrastructure sees the client connection. Snowflake, meek, and
Conjure also contact their broker, front, or registration infrastructure.

### IP and location display

A background task refreshes them after connect, after New Identity, and about
every 30 seconds otherwise:

- `api.ipify.org` receives one request with application proxies disabled; in
  Proxy mode this supplies the direct baseline, while active TUN captures it;
- the same service receives a separate request through Tor for the Tor exit;
- `ipwho.is/<address>` receives the first address lookup over the same default
  path;
- the Tor-exit lookup is sent through Tor.

This routing prevents the location provider from receiving both lookups over a
direct connection. In TUN mode OnionGate does not bypass the tunnel to discover
a clearnet address, so the verifier marks direct/Tor separation unverifiable.
Timing correlation by network observers or the providers is still possible.
Public addresses remain in UI memory only and are not written to verification
reports.

### Relay search

Searching or filtering relays sends the query to the Tor Project's
`onionoo.torproject.org` service over the ordinary network path. Queries can
contain a country code, nickname, or relay fingerprint.

### Bridge catalog scanning

Bridge scanning makes direct TCP connection attempts to selected bridge
endpoints or, for fronted transports, their configured broker/front on port
443. This reveals the probe to the destination and local network. It does not
perform a Tor bootstrap.

### Updates

The updater requests the signed release manifest and artifacts from GitHub
Releases when you select **Check for updates**. Tauri verifies the manifest
signature before installation.

### Onion audits

Testing an onion address sends a SOCKS domain request through managed Tor.
Onion Host's HTTP audit also requests the site through Tor to read the status and
selected response headers. A permanent private site cannot be fetched because
OnionGate does not retain a client credential.

### Development and builds

`make setup` / `make deps` downloads pinned Tor and sidecar archives from their
documented upstream release locations. The script rejects any archive whose
SHA-256 is absent from or does not match `scripts/dependencies.sha256`.

Installing MacPorts or opening external operating-system help uses the system
browser and is outside OnionGate's network boundary.

## What is never uploaded automatically

- application logs or verification reports;
- settings, local paths, selected app identities, or startup baselines;
- bridge lines;
- onion addresses or client credentials;
- the recovery journal;
- browsing or destination history.

## Removing local data

Use OnionGate's controls first:

1. delete permanent sites you intentionally want to destroy;
2. turn off app bypass and shell helpers so their external files are removed;
3. revoke client credentials and remove bridge lines;
4. disconnect and confirm cleanup;
5. remove the privileged helper, if installed;
6. clear logs and quit OnionGate.

Only then remove the local data directory if you want a complete reset.
Removing it destroys all remaining permanent onion identities and local
history. An application uninstall may leave this data behind so that a reinstall
does not silently destroy keys.

See [Privacy](/reference/privacy) for policy-level commitments and the
[threat model](/reference/threat-model) for adversaries and exclusions.
