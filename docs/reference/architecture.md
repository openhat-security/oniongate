# Architecture

OnionGate is a Tauri 2 desktop application: a React/TypeScript webview presents
state owned by a Rust core. A separate Rust binary exposes headless CLI
operations. Tor, sing-box, and pluggable transports run as local sidecars.

## Trust and privilege boundaries

1. **React UI (`src/`)** renders state and sends typed Tauri commands. It does
   not receive onion private keys, control cookies, or raw privileged rules.
2. **Rust core (`src-tauri/src/`)** owns configuration, orchestration, Tor
   control, recovery, diagnostics, and policy generation.
3. **Platform adapters** read and mutate proxy, TUN, firewall, process, and
   workstation state. Mutations must be observable and reversible.
4. **Managed sidecars** are separate processes: Tor, sing-box, lyrebird,
   obfs4proxy, and Conjure components where bundled. Downloaded archives are
   pinned in `scripts/dependencies.sha256`.
5. **Privileged helper** is an optional root service reached over a local Unix
   socket or Windows named pipe. Its request enum is typed only: ping, kill
   switch, transition lock, macOS deny harvest, terminate pid, and stop
   application. It cannot accept command text, paths, or caller-supplied rules.
   On macOS a signed helper also checks the peer's code signature.
6. **Operating system / administrator** remains outside OnionGate's trust
   boundary. Without the helper, platform elevation mechanisms perform each
   privileged mutation.

The webview CSP permits local assets and Tauri IPC, not arbitrary remote
scripts, frames, objects, or fetch destinations. Network requests originate in
the Rust core.

The main-window capability grants only core window controls, native dialogs,
signed updater access, and process restart. It does not grant Tauri shell,
filesystem, HTTP, or arbitrary URL-opener permissions.

## Frontend organization

The primary navigation follows capability boundaries:

- **Connect:** live session, routing, bridge configuration;
- **Apps:** app-specific proxy helpers and selected-app TUN policy;
- **Host:** temporary and permanent onion-service lifecycle;
- **Verify:** live diagnostic checks and redacted exports;
- **System:** macOS Checkup, Harden controls, and Startup Items;
- **Settings:** application preferences, helper/update controls, and logs.

`useTorApp.ts` centralizes shared state and Tauri invocations. Page components
do not directly construct Tor, firewall, or TUN configuration.

## Core modules

- `tor/process.rs`: sidecar discovery, managed `torrc`, fixed loopback ports,
  process lifecycle, bootstrap readiness, and restart/reload.
- `tor/control.rs`: cookie-authenticated control protocol, `NEWNYM`, DNS,
  bootstrap, circuit, and traffic queries.
- `tor/bridges.rs`, `tor/pt.rs`, `tor/smart_connect.rs`: trusted bridge
  catalogs, reachability probes, pluggable-transport configuration, and
  direct/bridge/Snowflake selection.
- `tun/`: generated sing-box TUN policy, DNS selection, UDP blocking,
  private-LAN bypass, and per-app SOCKS isolation.
- `proxy/`: reversible macOS, GNOME, and Windows SOCKS configuration.
- `firewall/`: OnionGate-owned UDP/QUIC rules and live-state verification.
- `session.rs`, `cleanup.rs`: persisted mutation journal, ordered teardown, and
  interrupted-session recovery.
- `session_guard.rs`: selected-process suspension when an active Tor/TUN route
  disappears.
- `onion_service/`: temporary control-port services and permanent
  `HiddenServiceDir` lifecycle, client authorization, and audits.
- `verify.rs`: egress comparison plus configuration/live-state diagnostics.
- `workstation/`, `harden/`: read-only posture/persistence checks and explicit
  host mutations outside the routing guarantee.
- `helper/`: typed privileged protocol, client, installer, and service.
- `tray.rs`: native macOS/Linux/Windows status menu backed by the same
  connect/disconnect, identity, and recovery orchestration.
- `db.rs`: local bridge cache/library, session metrics, and redacted reports.
- `bypass.rs`, `detect.rs`: app discovery and reversible app-specific helpers.

## Managed Tor

Managed Tor listens only on loopback:

```text
127.0.0.1:9050  normal SOCKS
127.0.0.1:9060  SOCKS with IsolateSOCKSAuth for per-app contexts
127.0.0.1:9051  cookie-authenticated control port
127.0.0.1:9053  DNSPort when remote DNS is enabled
```

The generated `torrc` includes selected exits/relays, bridges and transport
plugins, GeoIP data, and permanent onion-site blocks. Configuration changes
restart managed Tor when necessary; permanent-site changes rewrite `torrc` and
signal a reload.

OnionGate does not report a successful start until SOCKS and control are both
reachable. A conflicting system Tor that exposes SOCKS without the required
control port is not accepted as equivalent.

## Routing model

Proxy mode advertises Tor SOCKS through platform settings but cannot contain an
application that ignores those settings.

TUN mode generates a sing-box configuration with:

- TCP routed to the isolated-auth Tor SOCKS listener;
- UDP/QUIC blocked;
- private-address traffic bypassed directly;
- strict routing enabled;
- optional process path/name rules.

Under **Only selected via Tor**, each selected app receives a distinct SOCKS
username and circuit epoch while unmatched traffic is direct. Under **All except
selected**, selected apps are direct and the remainder uses the default shared
Tor context.

The firewall layer supplements TUN by blocking clearnet UDP/QUIC. It is not a
general TCP firewall.

## Mutation journal and recovery

Before a protected session mutates host state, `session.rs` records expected
components and the prior proxy snapshot in an atomically replaced, owner-only
journal. Normal disconnect and Emergency Restore use the same teardown order:

1. release Session Guard processes;
2. stop TUN;
3. remove OnionGate firewall rules;
4. restore proxy state;
5. stop the volunteer Snowflake process;
6. destroy temporary onion services;
7. stop Tor and orphaned transports;
8. verify ports are released, then clear the journal.

Permanent onion sites are configuration, not a session resource: their keys
survive teardown, but they are offline while Tor is stopped.

## Onion Host key model

Temporary services use `ADD_ONION ... DiscardPK`; the key never enters app
storage.

Permanent services use one Tor-owned `HiddenServiceDir` per site. The
non-secret registry stores IDs, labels, ports, auth state, client names, and the
public hostname. Tor creates the private key. OnionGate writes public client
authorization files but never reads the service key or retains private client
credentials.

## CLI

The `oniongate` binary links the same Rust core modules used by Tauri commands.
It does not automate the GUI. Runtime failures return exit code 1 and usage
errors return 2, making commands suitable for scripts.

Full orchestration parity is not complete: CLI `start` currently starts managed
Tor but does not apply the saved TUN, kill-switch, or operating-system proxy
boundary, and standalone invocations do not share temporary-site memory. These
are stable-release blockers; the desktop command path remains the authoritative
protected-session orchestrator.

## Build and release boundaries

`scripts/download-deps.sh` stages only archives present in the SHA-256 manifest.
Tauri's `externalBin` configuration names sidecars by base name; the build system
selects the target-triple binary. Tor-runtime components such as
`conjure-client` may instead ship under the bundled `resources/runtime/` tree;
the transport status is authoritative for a given platform.

Development excludes the privileged helper from `externalBin`. `make dev` builds
and starts `oniongate-helper` (see [Daemons](/guide/daemons)).
Release CI builds the helper for each target and merges `tauri.release.conf.json`,
placing the helper beside the app executable so the platform bundler signs it as
nested code.

The updater public key in `tauri.conf.json` is a trust root. Release signing keys
stay outside the repository. CI serializes platform builds while merging updater
metadata, then publishes signed checksums, Cargo/npm/sidecar SBOMs, and GitHub
provenance to a draft. See [Release process](/reference/release) and
[Platform support](/reference/platform-support).

## Invariants

- No direct-route fallback when a requested protected boundary fails.
- No protected status before required live components are observed.
- Protected-session proxy, TUN, firewall, Tor, and transport mutations are
  journaled and reversible.
- GUI and CLI must converge on the same protected-state orchestration before a
  stable release; current CLI limitations are documented above.
- Secret key material, bridge lines, control cookies, public verification
  addresses, and full process command lines are excluded from logs and exports.
