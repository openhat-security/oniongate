# Security policy

OnionGate changes network routing and may run Tor and sing-box with elevated
permissions. Treat every security report as sensitive.

## Supported versions

Only the latest tagged release receives security fixes. Until the project
publishes its first audited stable release, all builds are alpha software and
must not be relied on for high-risk activity.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities. Use the repository's private
GitHub Security Advisory form and include:

- the affected version and operating system;
- reproduction steps and expected impact;
- relevant logs with addresses, bridge lines, paths, and identifiers removed;
- whether coordinated disclosure requires an embargo.

We aim to acknowledge reports within 72 hours, provide an initial assessment
within 7 days, and coordinate publication after a fix is available.

## Security boundaries

- OnionGate is not Tor Browser and does not provide browser fingerprinting
  defenses.
- Tor carries TCP streams and DNS; OnionGate blocks unsupported UDP in guarded
  modes rather than tunnelling it.
- Proxy mode only protects applications that honor SOCKS and remote DNS.
- Bridges help with censorship but see the client connection.
- Onion services expose the selected local listener to authorized Tor clients;
  they do not sandbox that service.
- Host hardening is optional and does not replace macOS, Linux, or Windows
  security updates.
- The Verify report inspects egress and live configuration/state; it is not a
  packet capture or proof that every application followed policy.
- Session Guard process suspension is available on macOS/Linux; Windows uses
  the same TUN/app policy without that additional suspension layer.
- The optional root helper accepts only typed operations (kill switch,
  transition lock, deny harvest, pid/bundle stop). A signed macOS helper
  checks the peer's code signature; unsigned debug builds and Windows pipe
  ACLs remain pre-stable.

See the [threat model](docs/reference/threat-model.md) for the detailed model,
the [platform matrix](docs/reference/platform-support.md), and the
[data/network inventory](docs/reference/data-and-network.md).
