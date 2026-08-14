# OnionGate threat model

## Goals

OnionGate aims to:

1. route selected TCP applications through Tor without DNS or UDP leaks when
   the required TUN/app policy is active and verified;
2. fail closed for applications explicitly placed under Session Guard;
3. restore network state after disconnect, crash, or interrupted elevation;
4. host temporary and permanent v3 onion services for loopback listeners;
5. make the active protection boundary observable and testable.

## Adversaries considered

- A local network or ISP observing destinations and blocking Tor.
- A remote service attempting to learn the client's public IP.
- A malicious or unreliable Tor exit observing unencrypted application data.
- An application accidentally bypassing proxy settings.
- An attacker who learns an onion address but lacks its client credential.
- A local reader of a permanent site's key directory (backup, synced folder, or
  another process running as the same user).
- A crash that leaves proxy, TUN, firewall, or helper state behind.
- A compromised dependency or release artifact.
- A third-party IP, geolocation, update, or relay-directory service observing
  the request OnionGate explicitly sends to it.

## Out of scope

- A compromised operating-system kernel, root account, firmware, or hardware.
- Browser fingerprinting and state isolation equivalent to Tor Browser.
- Global passive traffic correlation.
- Making unsafe application protocols anonymous.
- Malware prevention, exploit containment, or a general endpoint-security
  product.
- Paths listed in [Residual leaks](/reference/residual-leaks), including NECP
  flows that never hit `pf` and the same-host Tor-endpoint allowlist hole.
- UDP tunnelling, torrenting, streaming, gaming, or stable geolocation.
- Protecting a local onion service that is itself vulnerable.
- Guaranteeing that a moved, renamed, helper, or child process still matches a
  stored selected-application identity.
- Session Guard process suspension on Windows. Windows still uses TUN,
  selected-app rules, and the Defender Firewall kill switch.

## Modes

### SOCKS proxy

Only applications that use `socks5h` or otherwise delegate hostname resolution
to Tor are protected. The operating-system proxy is a compatibility feature,
not a complete containment boundary.

### TUN

The TUN captures system traffic, sends supported TCP through Tor SOCKS, and
blocks unsupported UDP/QUIC. Private-LAN bypasses, split policies, IPv6, DNS,
and route changes must be covered by automated leak tests.

The current sing-box policy intentionally routes private-address destinations
directly. Local services therefore remain reachable and are outside the Tor
boundary. Under **Only selected via Tor**, unmatched applications are also
deliberately direct. Under **All except selected**, selected applications are
deliberately direct and the Tor-routed remainder shares a default isolation
context.

### Session Guard

Guarded applications receive isolated SOCKS credentials and must not use a
direct fallback if Tor, TUN, or the route policy becomes unavailable.

On macOS and Linux, the current enforcement layer checks Tor SOCKS and the TUN
process each second, then suspends processes matching the stored executable
path or process name. It resumes only PIDs it suspended. This cannot guarantee
coverage for a child/helper with a different identity, and it is not implemented
on Windows.

### Onion Host

Services bind only to loopback, and a wildcard-bound listener is refused rather
than published. Sites may be public or require v3 client authorization; private
is the default.

Onion Host has two tiers with different key handling, and the difference is
security-relevant:

**Temporary sites** are created over the control port with `DiscardPK`. Tor
discards the service key immediately, so the address cannot be recreated by
anyone. Desktop-owned sites are deleted during disconnect/quit. A standalone
CLI-created site remains loaded until Tor stops because later CLI processes do
not share its in-memory registry.

**Permanent sites** keep their address across restarts, which requires the key
to survive. The key is generated and owned by Tor in a `HiddenServiceDir` inside
Tor's data directory at owner-only permissions; OnionGate never reads, copies,
logs, or exports key material and learns the address only from the public
`hostname` file. This shifts the risk: anyone who can read that directory — a
local attacker with your user's privileges, an unencrypted disk backup, or a
synced folder — can impersonate the site. Full-disk encryption and an
appropriately protected user account are assumed. Permanent sites deliberately
survive session teardown, so stopping Tor does not revoke exposure; deleting the
site does.

Client authorization stores only the **public** half of each client key in
`authorized_clients/`. The private half is shown once at creation and never
written to disk, so a lost credential is reissued rather than recovered.
Revoking one client does not affect the others. OnionGate refuses to revoke the
final active credential because an empty authorization directory would make the
site public; making a site public requires the explicit authorization-off
action.

## Verification boundary

The leak verifier is a live diagnostic, not a packet capture or formal proof. It:

- makes separate direct and Tor HTTPS requests and compares the returned
  addresses in memory;
- probes Tor's local DNSPort;
- inspects whether TUN is running or an OnionGate UDP firewall rule is live;
- checks for an IPv6 default route;
- reconciles selected-app settings with active TUN;
- checks Session Guard preconditions and the recovery journal.

It does not observe every application's DNS or packets, send a UDP/IPv6 leak
probe, force a Session Guard failure, or prove a running process matched its
stored identity. Warnings mean a condition could not be established even when
the report has no failures.

## Privileged helper

The optional helper is a root service and therefore a high-value local target.
Its protocol is newline-delimited typed JSON over a local IPC endpoint. It
accepts only typed operations: ping, kill-switch and transition-lock
enable/disable, macOS deny-log harvest, terminate an allowed pid, and stop an
`.app` bundle. There is no arbitrary command, path, or caller-supplied rule
operation.

On Unix the service is configured for the installing user's UID. On macOS a
**signed** helper also requires the peer's code signature (Team ID /
`com.adamsiwiec.oniongate`). Unsigned debug builds stay UID-only. Windows pipe
client authentication and splitting the helper into a minimal crate remain
pre-stable debt.

Same-user malware can still request those fixed operations against an unsigned
debug helper. A signed release helper refuses unsigned or foreign-signed peers.

## Sensitive data

Never include bridge lines, onion private keys, client credentials, local file
paths, destination history, or full process command lines in telemetry or
diagnostic exports. OnionGate has no analytics by default.

Managed Tor necessarily writes a control-authentication cookie in its protected
data directory. OnionGate may read it for local control authentication but must
never copy, log, persist elsewhere, or export it.

IP and geolocation providers observe explicit verification/display requests.
Baseline lookups disable application proxies but remain subject to active TUN;
Tor lookups explicitly use Tor. OnionGate does not bypass active TUN merely to
discover a clearnet address. Timing correlation remains possible.

## Release assurances

Stable release artifacts must be built by CI from a tag, signed, checksummed,
supplied with an SBOM, and created from sidecars verified against the pinned
dependency manifest. A notarized build is not a substitute for a security
review. The project has not yet published a stable release; missing signatures
or provenance are release blockers, not optional warnings.
