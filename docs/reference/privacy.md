# Privacy

OnionGate is local-first software. It has no analytics, advertising identifier,
remote logging, crash-report upload, account system, or diagnostic telemetry.

This policy describes the application in this repository. Tor, bridge
operators, websites, GitHub, and the explicit third-party services listed under
[Local data and network activity](/reference/data-and-network) have their own
privacy policies.

## Stored locally

OnionGate stores only what is needed to operate requested features:

- settings, including selected bridge lines and relay preferences;
- selected application identities: labels, executable paths, bundle/signing
  identifiers, process names, and circuit epochs;
- session start/end times, selected connection strategy and mode, byte/circuit
  counters, and identity-change counts;
- the crash-recovery mutation journal and previous proxy snapshot;
- up to 20 redacted verification reports;
- Tor and TUN logs;
- an optional startup/persistence baseline;
- bridge catalog cache/library entries;
- app-specific proxy settings and launcher files when you enable a bypass
  helper;
- permanent Onion Host metadata: nickname, ports, public hostname,
  authorization state, and client names/public keys.

The application does not maintain destination or browsing history. The live
connection census on Verify may show full local and remote addresses in the UI
because only you can see that window; those values stay in process memory and
are never logged, saved, or uploaded.

## Public-address checks

The Connect dashboard, network test, and leak verifier may fetch the machine's
direct public address and a Tor-exit address. Those values exist in process
memory and can be displayed in the UI, but are omitted from saved verification
reports and are not written to the session database.

The requests necessarily disclose an address to the IP-check provider. Direct
baseline lookups disable application proxies but remain subject to active TUN;
explicit Tor lookups use Tor. Location lookups follow the same corresponding
path so the provider does not receive both addresses from a direct connection.
Timing correlation remains possible.

## Onion Host keys

Temporary service keys are never stored. OnionGate creates those services with
Tor's `DiscardPK` flag, so even OnionGate cannot recreate an address after the
service or Tor stops.

Permanent sites are the deliberate exception. Keeping the same `.onion`
address requires the key to survive. Tor generates and holds that key in its own
`HiddenServiceDir` with owner-only permissions. OnionGate does not read, copy,
log, or export it; it reads only the public `hostname` file. Deleting the site
deletes the directory and makes the address unrecoverable.

The private half of a v3 client-authorization credential is shown once and is
not written by OnionGate. Only the public half is retained. Clipboard managers,
screenshots, redirected CLI output, and files you create are outside that
guarantee.

## Tor control authentication

Managed Tor uses cookie authentication. Tor writes its runtime
`control_auth_cookie` inside its protected data directory; OnionGate reads it
only to authenticate local control commands. OnionGate never logs, exports, or
copies the cookie into settings or reports.

## Logs and reports

Logs remain local until you explicitly share them. The UI can clear managed
Tor's log, but higher log levels may contain more operational context. Redact
bridge lines, onion addresses, app identifiers, and paths before sharing.

Verification exports contain check names, status, detail, remediation, and
timestamp. They intentionally exclude public addresses, bridge lines, full
process command lines, and onion/client secrets.

## Network activity

Network access occurs only for a requested product function:

- Tor bootstrap and routed traffic;
- selected bridges and pluggable transports;
- public-address and location display;
- Onionoo relay search;
- bridge reachability scans;
- onion-service audits through Tor;
- signed update checks;
- Snowflake volunteering when explicitly started;
- official dependency downloads during source builds.

There is no third-party bridge-feed download and no automatic upload of local
state. The exact endpoints and paths are documented in
[Local data and network activity](/reference/data-and-network).

## Deletion

Removing the application may leave its local data so an uninstall does not
silently destroy permanent onion keys. To erase data safely, first delete any
permanent sites you intend to destroy, disconnect cleanly, remove the privileged
helper, and then remove the local data directory. This cannot be undone.
