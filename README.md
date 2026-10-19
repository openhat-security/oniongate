<p align="center">
  <img src="public/logo.png" alt="OnionGate" width="120" height="120" />
</p>

<h1 align="center">OnionGate</h1>

<p align="center">
  A Tor workstation toolkit for macOS, Linux, and Windows.
</p>

<p align="center">
  <a href="https://github.com/openhat-security/oniongate/releases">
    <img src="https://img.shields.io/github/downloads/openhat-security/oniongate/total?label=downloads" alt="Total release downloads" />
  </a>
  <a href="https://github.com/openhat-security/oniongate">
    <img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fopenhat-security.github.io%2Foniongate%2Fmetrics%2Fclones.json" alt="Repository clones in the last 14 days" />
  </a>
</p>

OnionGate is a desktop app that runs Tor for you and sends your traffic through
it. It can route single apps over their own Tor circuits, publish a local port
as a v3 onion site, and show you which processes on the machine are still
talking to the internet directly. It bundles Tor, so you don't need a terminal
or Homebrew, and it comes with `oniongate-cli` for servers and scripts.

Full documentation: <https://openhat-security.github.io/oniongate/>

> [!WARNING]
> OnionGate is alpha software. It is not a VPN, Tor Browser, Tails, or a
> two-machine Tor gateway, and it should not be your only protection for
> high-risk work. It does nothing about browser fingerprinting or global traffic
> correlation. Read the [threat model](docs/reference/threat-model.md) and the
> list of [residual leaks](docs/reference/residual-leaks.md) before you rely on
> it.

## What it does

- Routes apps through Tor. Each selected app gets its own isolated circuit. On
  macOS and Linux, Session Guard suspends a selected app if its Tor or TUN route
  drops.
- Hosts onion sites. OnionGate publishes `127.0.0.1:<port>` as a v3 onion
  service and refuses servers bound to `0.0.0.0`. A temporary site throws its
  key away at creation, so the address is gone for good once Tor stops. A
  permanent site keeps its address across restarts and can require named
  client credentials, which you can revoke one at a time. See the
  [hosting guide](docs/guide/hosting.md).
- Shows the live boundary. A background watch lists processes with clearnet TCP
  connections that bypass OnionGate. The list lives in memory and is never
  saved. On-demand checks cover egress, DNS, IPv6, UDP/QUIC and per-app policy,
  and you can export a redacted report. Public IPs are compared in memory and
  never stored. None of this is packet capture or a formal proof.
- Lives in the tray. From the macOS, Linux or Windows tray icon you can see
  status, connect or disconnect, get a new identity, or run Emergency Restore.

## Pick a routing mode

How much OnionGate can protect you depends on the mode. It runs on the same
machine as your apps, so it can't match a gateway setup where the workstation
has no clearnet network card at all.

| | System SOCKS (proxy mode) | TUN mode | Two-machine gateway |
| --- | --- | --- | --- |
| Who must opt in | Each app that honors SOCKS | Most TCP on the machine | Everything in the workstation |
| Ordinary browsers (Chrome, Firefox, Safari) | Only if set to SOCKS with remote DNS | Yes, captured by the tunnel | Yes, there is no clearnet path |
| Tor Browser | Ignores the OS proxy and runs its own Tor | Stock Tor Browser stacks Tor over Tor unless redirected | Gateway Tor, no stacked Tor |
| DNS | App must use `socks5h` or remote DNS | Tor `DNSPort` when Resolve through Tor is on | Forced through the gateway |
| UDP / QUIC | Can leak | Blocked | Blocked or unavailable |
| If Tor dies | Weak; apps may go direct | Stronger: `strict_route`, Session Guard, optional NIC lock | Strong; the workstation has no clearnet |
| Isolation | Process / OS trust boundary | Process / OS trust boundary | Separate machines and a filtered control port |

Proxy mode is the easy option, and any app can ignore it. If you want ordinary
browsers and most apps to go through Tor on one machine, connect in TUN mode
(all traffic, or your split-tunnel policy).

You only need the Tor Browser launcher if you want Tor Browser itself. Tor
Browser expects its own Tor on `127.0.0.1:9150`, and OnionGate's managed Tor
already listens there. Use **Apps → Tor Browser via OnionGate** while
OnionGate is connected, not the stock Tor Browser icon. The launcher sets
`TOR_SKIP_LAUNCH` and points Tor Browser's SOCKS and control ports at
OnionGate. Details are in [Route applications](docs/guide/apps.md) and
[Connect](docs/guide/connection.md).

On macOS, Maximum Isolation adds a `pf` default-deny rule, so leftover public
IP traffic (Apple daemons included) can only reach Tor's allowlisted endpoints.

### What can still leak

Even with the macOS NIC default-deny on, these paths remain:

- kernel and NECP paths that never reach `pf`;
- any local process that opens TCP to a listed Tor endpoint IP;
- DHCP, optional LAN access, and destination exceptions you add;
- everything on Linux and Windows, where that lock doesn't exist yet;
- Snowflake and meek, which the lock refuses.

The full list is in [Residual leaks](docs/reference/residual-leaks.md).

## Install a release

Every published build is alpha (`x.y.z-alpha.N`). Install the newest `*-alpha*`
prerelease from the
[releases page](https://github.com/openhat-security/oniongate/releases). The
older plain `v0.2.0` to `v0.2.4` releases are superseded; don't install them.

| Platform | File |
| --- | --- |
| macOS Apple Silicon | `OnionGate_<version>_aarch64.pkg` |
| macOS Intel | `OnionGate_<version>_x64.pkg` |
| Windows x86_64 | NSIS `-setup.exe` |
| Linux x86_64 | `.AppImage`, `.deb` or `.rpm` |

Check the download before you run it:

```bash
sha256sum -c SHA256SUMS --ignore-missing        # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing    # macOS
```

`SHA256SUMS.sig` is a minisign signature over that file. The public key is the
updater `pubkey` in `src-tauri/tauri.conf.json`.

Pre-1.0 macOS and Windows builds aren't signed by Apple or Microsoft, so
Gatekeeper and SmartScreen warn on first launch. On macOS, right-click the
`.pkg`, choose Open, and confirm. Release CI refuses to publish 1.0.0 or later
unless every platform is signed. The [install guide](docs/guide/install.md)
covers signatures, provenance, the macOS `.pkg` and uninstalling.

## Build and run from source

You need:

- Node.js 24.18 or newer, but below 25 (see `.nvmrc`). Debian and Ubuntu
  packages are too old; use nvm or the nodejs.org tarball.
- Rust stable from rustup. Distro Rust (for example 1.85 on Debian 13) is too
  old, so check that `~/.cargo/bin` comes first on your `PATH`.
- Make, plus the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
  for your OS. On Debian or Ubuntu, `bash scripts/install-linux-build-deps.sh`
  installs them, including `libevent-2.1-7`, which the bundled Linux Tor needs
  to start.

Then:

```bash
make setup     # npm ci, then download and SHA-256-check Tor, lyrebird and sing-box
make start     # build the helper and CLI, start the helper, then run tauri dev
```

`make help` lists every target. `make start` asks for administrator rights once
to install the privileged helper. [Daemons](docs/guide/daemons.md) explains
what runs as root and what doesn't.

If `make setup` stops with `curl: (22) ... 404` while downloading the Tor
expert bundle, the Tor Project has moved that version off `dist.torproject.org`.
Fetch the same file from the archive into the cache and run setup again. The
pinned SHA-256 still checks it:

```bash
v=15.0.20   # TOR_BROWSER_VERSION in scripts/download-deps.sh
f=tor-expert-bundle-linux-x86_64-$v.tar.gz   # use your platform's name
mkdir -p .deps-cache
curl -fL -o .deps-cache/$f \
  https://archive.torproject.org/tor-package-archive/torbrowser/$v/$f
make setup
```

To build installers for the OS you're on (unsigned, for local testing):

```bash
make build        # Tauri bundle
make downloads    # installer files, including the macOS .pkg
```

Before opening a PR, run:

```bash
make check    # TypeScript typecheck, Rust tests, changelog trail
make lint     # clippy and rustfmt
```

`make docs` serves the documentation site at <http://localhost:5173>.

## Command line

`oniongate-cli` uses the same Rust core as the app. Build it with:

```bash
cargo build --release --manifest-path src-tauri/Cargo.toml --bin oniongate-cli
```

A short session that publishes a private site for a server on port 3000:

```bash
oniongate-cli start                          # Tor, then the saved proxy/TUN settings
oniongate-cli host add blog --local-port 3000
oniongate-cli host ls                        # id, name, address, port mapping, auth
oniongate-cli host auth add blog alice > alice.auth_private
oniongate-cli status                         # read socks_up, control_up, dns_up
oniongate-cli stop                           # stop Tor and restore network settings
```

Give `alice.auth_private` to the client. It goes in their Tor's
`ClientOnionAuthDir`, and the credential can't be shown again. Use
`--public` on `host add` for a site anyone can open, or `host temp` for a
temporary one. Exit codes are `0` for success, `1` for a runtime failure, and
`2` for a usage error.

On Linux, keep in mind:

- On a machine with no desktop session, `start` connects Tor but then exits
  with code 1, because it can't set the GNOME system proxy. Check `socks_up=true`
  in `status` instead of relying on the exit code.
- While a session is active, and also after a failed `start`, OnionGate keeps
  an nftables lock that blocks all UDP and IPv6 on the host, system DNS
  included. Run `oniongate-cli stop` to remove it. `sudo nft list tables`
  shows `inet oniongate_lock` while it's on.
- `host audit` can't confirm `published=true` for a site that requires client
  auth, because OnionGate doesn't keep credentials. Test those sites from a
  client that holds one.

All commands are in the [CLI guide](docs/guide/cli.md).

## Where things are stored

On Linux, OnionGate keeps its state in `~/.local/share/oniongate/`:
`settings.json`, the generated `torrc`, `tor.log`, the Tor data directory, and
`onion-sites/` with each permanent site's keys. The directories are `0700` and
key files `0600`. Permanent onion keys aren't backed up anywhere. If you delete
`onion-sites/<id>/`, that address is gone for good.
[Local data and network activity](docs/reference/data-and-network.md) lists
every file and every outbound request, macOS and Windows paths included.

## Troubleshooting

- `status` shows `recovery_needed=true`, or the app says "Interrupted session
  detected": a previous owner exited and left state behind. Run
  `oniongate-cli stop` (or Emergency Restore in the app), then check `status`.
  `make cleanup` does the same thing during development. A session started
  from the CLI also shows this flag, because the CLI process exits after
  `start`.
- "Another tor may still own port 9050": something else is listening on 9050.
  Stop it (for example `sudo systemctl stop tor` or `brew services stop tor`).
  `ss -ltnp | grep 9050` shows the owner on Linux.
- Tor stalls during "Loading relay descriptors" the first time: the first
  connection downloads the full directory and can be slow. Run `start` again;
  later starts reuse the cache.
- `tor: error while loading shared libraries: libevent-2.1.so.7`: install
  `libevent-2.1-7` (Debian/Ubuntu) or `libevent` (Fedora).

[Recovery and troubleshooting](docs/guide/troubleshooting.md) has more.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md),
never in a public issue.

Things to know before you rely on OnionGate:

- Tor's SOCKS, control and DNS ports listen on `127.0.0.1` only (9050, 9060,
  9150, 9051, 9151, 9053). The control ports use cookie authentication, but any
  process running as your user can read the cookie.
- Some features use the normal network on purpose: the update check (GitHub),
  relay search (Onionoo), bridge scanning, and the first IP and location check
  (api.ipify.org and ipwho.is). The data-and-network page lists all of them.
- `oniongate-cli bridges` and `oniongate-cli settings` print bridge lines and
  app paths. Don't paste their output into public issues.

## Documentation

- [Getting started](docs/guide/index.md) and [Quick start](docs/guide/quick-start.md)
- [Install](docs/guide/install.md) and [Local installers and updates](docs/guide/updates.md)
- [Connect and route traffic](docs/guide/connection.md), [Use bridges](docs/guide/bridges.md), [Route applications](docs/guide/apps.md)
- [Host an onion site](docs/guide/hosting.md) and [Verify the live boundary](docs/guide/verify.md)
- [Check and harden this machine](docs/guide/system.md), [Settings and logs](docs/guide/settings.md)
- [Recovery and troubleshooting](docs/guide/troubleshooting.md), [Command line](docs/guide/cli.md)
- [Architecture](docs/reference/architecture.md), [Platform support](docs/reference/platform-support.md)
- [Local data and network activity](docs/reference/data-and-network.md), [Threat model](docs/reference/threat-model.md), [Privacy](docs/reference/privacy.md)
- [Third-party software](docs/reference/third-party.md), [Release process](docs/reference/release.md), [Changelog](CHANGELOG.md)

## Contributing

Contributions are welcome under GPL-3.0. Read [CONTRIBUTING.md](CONTRIBUTING.md)
and the [Code of Conduct](CODE_OF_CONDUCT.md) first.

## License and trademark

Copyright (C) 2026 OpenHat Security.

OnionGate is licensed under [GPL-3.0](LICENSE). It comes with ABSOLUTELY NO
WARRANTY, to the extent permitted by applicable law; you are welcome to
redistribute it under the terms of the GNU General Public License, version 3.
Notices and corresponding-source links for bundled components are in
[`THIRD_PARTY.md`](src-tauri/resources/licenses/THIRD_PARTY.md).

Parts of the macOS hardening features are derived from term7's *MacOS Privacy
and Security Enhancements*, Copyright (C) 2025 term7, licensed under GPL-3.0.
Canonical repository:
<https://codeberg.org/term7/MacOS-Privacy-and-Security-Enhancements> (GitHub
mirror: <https://github.com/term7/MacOS-Privacy-and-Security-Enhancements>).
Derived files carry their own modification notices; see
[third-party software](docs/reference/third-party.md).

OnionGate is an independent project and is not affiliated with or endorsed by
The Tor Project. "Tor" and the onion logo are trademarks of The Tor Project.
OnionGate uses its own logo, not the official Tor onion logo.
