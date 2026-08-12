<p align="center">
  <img src="public/logo.png" alt="OnionGate" width="120" height="120" />
</p>

<h1 align="center">OnionGate</h1>

<p align="center">
  <b>A Tor workstation toolkit for macOS, Linux, and Windows.</b>
</p>

<p align="center">
  <a href="https://github.com/irruptio-security/oniongate/releases">
    <img src="https://img.shields.io/github/downloads/irruptio-security/oniongate/total?label=downloads" alt="Total release downloads" />
  </a>
  <a href="https://github.com/irruptio-security/oniongate">
    <img src="https://img.shields.io/endpoint?url=https%3A%2F%2Firruptio-security.github.io%2Foniongate%2Fmetrics%2Fclones.json" alt="Repository clones in the last 14 days" />
  </a>
</p>

OnionGate is a desktop app that routes individual applications through isolated
Tor circuits, turns a local port into an onion site, and inspects the live
routing and leak-prevention boundary. It bundles and manages Tor for you — no
terminal required — and ships a headless CLI for servers and scripts.

**[Read the documentation →](https://irruptio-security.github.io/oniongate/)**

> OnionGate is **not** a VPN, Tor Browser, Tails, or Whonix. It does not stop
> browser fingerprinting or global traffic correlation. Read the
> [threat model](docs/reference/threat-model.md) before relying on it for
> sensitive work.

## Routing modes: SOCKS vs TUN vs Whonix

OnionGate can feel like a small “Tor VPN” app, but the protection boundary
depends on which mode you use. Whonix is a two-VM design (Workstation +
Gateway). OnionGate is a same-host app that manages Tor and optionally a TUN.

| | System SOCKS (proxy mode) | TUN mode | Whonix |
| --- | --- | --- | --- |
| Who must opt in | Each app that honors SOCKS | Most TCP on the machine | Everything in the Workstation VM |
| Ordinary browsers (Chrome, Firefox, Safari, …) | Only if configured for SOCKS + remote DNS | Yes — captured by the tunnel | Yes — no clearnet path |
| Tor Browser | Ignores OS proxy; runs its own Tor | Stock TB stacks Tor-over-Tor unless redirected | Gateway Tor + no stacked Tor |
| DNS | App must use `socks5h` / remote DNS | Tor `DNSPort` when Resolve through Tor is on | Forced through Gateway |
| UDP / QUIC | Can leak | Blocked | Blocked / unavailable |
| Fail closed if Tor dies | Weak (apps may go direct) | Stronger (`strict_route` + Session Guard for selected apps) | Strong (Workstation has no clearnet) |
| Isolation | Process / OS trust boundary | Process / OS trust boundary | Separate VMs + filtered control port |

**You do not need “Tor Browser via OnionGate” for arbitrary browsers.**  
Connect in **TUN** mode (all traffic via Tor, or your split-tunnel policy). Chrome,
Firefox, Safari, and most apps then reach the network through OnionGate’s Tor —
same *idea* as Whonix’s “everything goes through the gateway,” without VMs.

**When you do need the Tor Browser launcher:** only if you want **Tor Browser**
itself. Tor Browser always expects its own Tor on `127.0.0.1:9150`. OnionGate
already binds those Tor Browser ports on its managed Tor; the
**Apps → Tor Browser via OnionGate** launcher sets `TOR_SKIP_LAUNCH` and points
SOCKS/control at OnionGate so about:tor treats Tor as externally managed
(Whonix-style). Open that launcher, not the stock Tor Browser icon, while
OnionGate is Connected. Details:
[Route applications](docs/guide/apps.md) and
[Connect](docs/guide/connection.md).

**SOCKS proxy alone** is a convenience path: easy, but any app can ignore it.
Prefer TUN when you want “any browser / most apps” containment on one machine.

### Making OnionGate more like Whonix

OnionGate already shares Whonix’s *routing* idea in TUN mode (force TCP through
Tor, block UDP). It does **not** share Whonix’s *security* idea (air-gapped
Workstation, onion-grater control filter, no host clearnet). Closer next steps:

1. **TUN as the default “workstation” preset** — proxy mode stays for
   compatibility; everyday use assumes tunnel + Resolve through Tor + kill
   switch.
2. **Stock Tor Browser without a special app** — keep occupying `9150`/`9151`
   and add a thin local redirect so the normal Tor Browser icon works (or
   document a one-time `TOR_SKIP_LAUNCH` wrapper only).
3. **Harder fail-closed TCP** — extend the network lock / kill switch so
   clearnet TCP cannot bypass TUN if the tunnel drops (Whonix Workstation has
   nowhere else to go).
4. **Control-port filtering** — Whonix’s onion-grater stops the browser from
   learning entry guards / `GETINFO address`. OnionGate currently shares the
   real control cookie with the Tor Browser launcher.
5. **What we will not claim without VMs** — malware breakout, global
   fingerprinting parity with Tor Browser, or “as safe as Whonix.” Same-host
   TUN can never match two-machine isolation; use Whonix/Qubes when that is the
   requirement.

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
[GitHub Releases page](https://github.com/irruptio-security/oniongate/releases),
and verify the checksum, SBOM, and provenance before running anything.

Pre-1.0 macOS and Windows builds are **not** signed with an OS vendor
certificate, so Gatekeeper and SmartScreen will warn on first launch. Release CI
blocks any `1.0.0` or later stable release that is not fully signed.

Full instructions, including building from source, are in the
[install guide](docs/guide/install.md).

## Command line

`oniongate` is the headless companion. It hosts onion sites on machines with no
GUI:

```bash
oniongate start
oniongate host add blog --local-port 3000
oniongate host auth add blog alice
```

See the [CLI guide](docs/guide/cli.md).

## Develop

Requires Node.js (see `.nvmrc`), Rust stable, Make, and the Tauri prerequisites
for your OS. Prefer the Makefile targets (`make help` lists them all).

```bash
make setup          # npm ci + download/verify Tor / sing-box sidecars
make start          # tauri dev
```

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
**[irruptio-security.github.io/oniongate](https://irruptio-security.github.io/oniongate/)**.

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

OnionGate is licensed under [GPL-3.0](LICENSE). Bundled component notices and
corresponding-source links are in
[`THIRD_PARTY.md`](src-tauri/resources/licenses/THIRD_PARTY.md).

OnionGate is an independent project — not affiliated with or endorsed by The Tor
Project. "Tor" and the onion logo are trademarks of The Tor Project; OnionGate
uses its own logo, not the official Tor onion logo.
