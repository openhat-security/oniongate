# What OnionGate is

OnionGate is a desktop app that routes individual applications through isolated
Tor circuits, turns a local port into an onion site, and checks whether its live
routing controls and egress are behaving as expected. It bundles and manages
Tor for you, so no terminal work is required.

OnionGate supports macOS, Linux x86_64, and Windows x86_64, plus Apple Silicon
and Intel Macs. Platform-specific system integrations are listed in the
[platform matrix](/reference/platform-support). The headless
[command-line companion](/guide/cli) focuses on managed Tor and permanent onion
hosting.

## What you can do with it

**Route apps through Tor.** Selected TUN-routed applications receive distinct
Tor circuit contexts. On macOS and Linux, Session Guard can also suspend matched
processes if that route drops.

See [Connect and route traffic](/guide/connection) and
[Route applications](/guide/apps) for the boundary and platform limitations.

**Host an onion site.** Expose `127.0.0.1:<port>` as a v3 onion service with
client authorization and a QR handoff. Choose a temporary site that disappears
for good when it stops, or a permanent one that keeps the same address across
restarts. See [Host an onion site](/guide/hosting).

**Inspect the live boundary.** While connected, a background watch lists
processes with clearnet TCP that is not going through OnionGate. Run on-demand
diagnostics covering DNS, IPv6, UDP/QUIC, and per-app policy, then export a
redacted report. Verification is a live configuration and egress diagnostic,
not a packet capture or formal proof.

**Check and harden the machine itself.** Read your macOS security state, apply
reversible privacy and security changes, and watch what runs at startup. See
[Check and harden this machine](/guide/system).

## What it is not

OnionGate is not a VPN, Tor Browser, Tails, a two-machine Tor gateway, an antivirus, or a general
application firewall. Specifically, it does **not**:

- protect against browser fingerprinting — use Tor Browser for that;
- defend against a global adversary correlating traffic;
- make an unsafe application protocol anonymous;
- contain malware or replace endpoint security;
- tunnel UDP, which is blocked rather than leaked.
- prove that every process or packet followed the intended route.

Read the [threat model](/reference/threat-model) before relying on it for
anything sensitive.

## Next steps

- [Install OnionGate](/guide/install)
- [Quick start](/guide/quick-start)
- [Connect and route traffic](/guide/connection)
- [Use bridges](/guide/bridges)
- [Route applications](/guide/apps)
- [Host an onion site](/guide/hosting)
- [Verify the live boundary](/guide/verify)
- [Settings and logs](/guide/settings)
- [Recovery and troubleshooting](/guide/troubleshooting)
- [Use the command line](/guide/cli)
