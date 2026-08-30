<p align="center">
  <img src="public/logo.png" alt="OnionGate" width="120" height="120" />
</p>

<h1 align="center">OnionGate</h1>

<p align="center">
  <b>A Tor workstation toolkit for macOS, Linux, and Windows.</b>
</p>

<p align="center">
  <a href="https://github.com/openhat-security/oniongate/releases">
    <img src="https://img.shields.io/github/downloads/openhat-security/oniongate/total?label=downloads" alt="Total release downloads" />
  </a>
  <a href="https://github.com/openhat-security/oniongate">
    <img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fopenhat-security.github.io%2Foniongate%2Fmetrics%2Fclones.json" alt="Repository clones in the last 14 days" />
  </a>
</p>

OnionGate is a desktop app that routes individual applications through isolated
Tor circuits, turns a local port into an onion site, and inspects the live
routing and leak-prevention boundary. It bundles and manages Tor for you — no
terminal required — and ships a headless CLI for servers and scripts.

**[Read the documentation →](https://openhat-security.github.io/oniongate/)**

> This project is **alpha**. It is **not** a VPN, Tor Browser, Tails, or a
> two-machine Tor gateway, and it must not be the sole control for high-risk
> work. It does not stop browser fingerprinting or global traffic correlation.
> Read the [threat model](docs/reference/threat-model.md) and
> [residual leaks](docs/reference/residual-leaks.md) first.

## Potential leaks

Same-host routing cannot match a workstation that has no clearnet NIC. Even with
the macOS NIC default-deny on, these remain:

- kernel / NECP paths that never hit `pf`
- any local process TCP’ing to a listed Tor endpoint IP
- DHCP, optional LAN, and user destination exceptions
- Linux/Windows (this lock is macOS-only)
- Snowflake/meek (lock refused)

Full list: [Residual leaks](docs/reference/residual-leaks.md).

## Routing modes: SOCKS vs TUN vs two-machine isolation

OnionGate can feel like a small “Tor VPN” app, but the protection boundary
depends on which mode you use. A two-machine gateway keeps the workstation off
the clearnet NIC. OnionGate is a same-host app that manages Tor and optionally a
TUN.

| | System SOCKS (proxy mode) | TUN mode | Two-machine gateway |
| --- | --- | --- | --- |
| Who must opt in | Each app that honors SOCKS | Most TCP on the machine | Everything in the workstation |
| Ordinary browsers (Chrome, Firefox, Safari, …) | Only if configured for SOCKS + remote DNS | Yes — captured by the tunnel | Yes — no clearnet path |
| Tor Browser | Ignores OS proxy; runs its own Tor | Stock TB stacks Tor-over-Tor unless redirected | Gateway Tor + no stacked Tor |
| DNS | App must use `socks5h` / remote DNS | Tor `DNSPort` when Resolve through Tor is on | Forced through the gateway |
| UDP / QUIC | Can leak | Blocked | Blocked / unavailable |
| Fail closed if Tor dies | Weak (apps may go direct) | Stronger (`strict_route` + Session Guard + optional NIC lock) | Strong (workstation has no clearnet) |
| Isolation | Process / OS trust boundary | Process / OS trust boundary | Separate machines + filtered control port |

**You do not need “Tor Browser via OnionGate” for arbitrary browsers.**  
Connect in **TUN** mode (all traffic via Tor, or your split-tunnel policy). Chrome,
Firefox, Safari, and most apps then reach the network through OnionGate’s Tor.

**When you do need the Tor Browser launcher:** only if you want **Tor Browser**
itself. Tor Browser always expects its own Tor on `127.0.0.1:9150`. OnionGate
already binds those Tor Browser ports on its managed Tor; the
**Apps → Tor Browser via OnionGate** launcher sets `TOR_SKIP_LAUNCH` and points
SOCKS/control at OnionGate so about:tor treats Tor as externally managed.
Open that launcher, not the stock Tor Browser icon, while OnionGate is
Connected. Details: [Route applications](docs/guide/apps.md) and
[Connect](docs/guide/connection.md).

**SOCKS proxy alone** is a convenience path: easy, but any app can ignore it.
Prefer TUN when you want “any browser / most apps” containment on one machine.
On macOS, Maximum Isolation adds a kernel `pf` default-deny so leftover public
IP (including Apple daemons) cannot leave the NIC except to Tor’s allowlisted
endpoints.

## What you can do

- **Route apps through Tor** — give each app its own isolated circuit, with a
  macOS/Linux Session Guard that suspends matching selected processes if their
  Tor/TUN route drops.
- **Host an onion site** — expose `127.0.0.1:<port>` as a v3 onion service with
  client authorization and a QR handoff. Make it **temporary** (key discarded at
  stop, address gone for good) or **permanent** (same address across restarts,
  with named client credentials you can revoke individually). See the
  [hosting guide](docs/guide/hosting.md).
- **Inspect the live boundary** — a background watch lists processes with
  clearnet TCP that is not going through OnionGate (ephemeral, not stored).
  Run on-demand diagnostics for egress separation, DNS, IPv6, UDP/QUIC, and
  per-app policy, then export a redacted report. Public IPs are compared in
  memory, never stored. Verification is not packet capture or formal proof.
- **Stay in control from the tray** — inspect live status, connect/disconnect,
  rotate identity, or run Emergency Restore from the native macOS, Linux, or
  Windows widget.

## Install

OnionGate is pre-1.0. Every published build is alpha software and must not be
relied on for high-risk activity.

Download only from the
[GitHub Releases page](https://github.com/openhat-security/oniongate/releases),
and verify the checksum, SBOM, and provenance before running anything.

Pre-1.0 macOS and Windows builds are **not** signed with an OS vendor
certificate, so Gatekeeper and SmartScreen will warn on first launch. Release CI
blocks any `1.0.0` or later stable release that is not fully signed.

Full instructions, including building from source, are in the
[install guide](docs/guide/install.md).

## Command line

`oniongate-cli` is the headless companion. It hosts onion sites on machines with no
GUI:

```bash
oniongate-cli start
oniongate-cli host add blog --local-port 3000
oniongate-cli host auth add blog alice
```

See the [CLI guide](docs/guide/cli.md).

## Develop

Requires Node.js (see `.nvmrc`), Rust stable, Make, and the Tauri prerequisites
for your OS. Prefer the Makefile targets (`make help` lists them all).

```bash
make setup          # npm ci + download/verify Tor / sing-box sidecars
make start          # start daemons, then tauri dev
```

Daemons (privileged helper install, status, and what is *not* a daemon) are
documented in [docs/guide/daemons.md](docs/guide/daemons.md).

Build a release bundle from source:

```bash
make build
```

Quality checks before a PR:

```bash
make check
make lint
```

Work on the documentation site:

```bash
make docs           # hot-reloading preview at http://localhost:5173
```

## Contributing

Contributions are welcome under GPL-3.0. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) and our
[Code of Conduct](CODE_OF_CONDUCT.md) first. Report security issues privately per
[SECURITY.md](SECURITY.md) — never in a public issue.

## Documentation

The full site is at
**[openhat-security.github.io/oniongate](https://openhat-security.github.io/oniongate/)**.

- [Getting started](docs/guide/index.md)
- [Quick start](docs/guide/quick-start.md)
- [Local installers and updates](docs/guide/updates.md)
- [Connect and route traffic](docs/guide/connection.md)
- [Use bridges](docs/guide/bridges.md)
- [Route applications](docs/guide/apps.md)
- [Host an onion site](docs/guide/hosting.md)
- [Verify the live boundary](docs/guide/verify.md)
- [Check and harden this machine](docs/guide/system.md)
- [Settings and logs](docs/guide/settings.md)
- [Recovery and troubleshooting](docs/guide/troubleshooting.md)
- [Command line](docs/guide/cli.md)
- [Architecture](docs/reference/architecture.md)
- [Platform support](docs/reference/platform-support.md)
- [Local data and network activity](docs/reference/data-and-network.md)
- [Threat model](docs/reference/threat-model.md)
- [Privacy](docs/reference/privacy.md)
- [Third-party software](docs/reference/third-party.md)
- [Release process](docs/reference/release.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## License & trademark

Copyright (C) 2026 OpenHat Security.

OnionGate is licensed under [GPL-3.0](LICENSE). It comes with ABSOLUTELY NO
WARRANTY, to the extent permitted by applicable law; you are welcome to
redistribute it under the terms of the GNU General Public License, version 3.
Bundled component notices and corresponding-source links are in
[`THIRD_PARTY.md`](src-tauri/resources/licenses/THIRD_PARTY.md).

Parts of the macOS hardening features are derived from term7's *MacOS Privacy
and Security Enhancements*, Copyright (C) 2025 term7, licensed under GPL-3.0.
Canonical repository:
<https://codeberg.org/term7/MacOS-Privacy-and-Security-Enhancements> (GitHub
mirror: <https://github.com/term7/MacOS-Privacy-and-Security-Enhancements>).
Derived files carry their own modification notices; see
[third-party software](docs/reference/third-party.md).

OnionGate is an independent project — not affiliated with or endorsed by The Tor
Project. "Tor" and the onion logo are trademarks of The Tor Project; OnionGate
uses its own logo, not the official Tor onion logo.
