# Install

## Current release status

OnionGate is pre-1.0. Treat every published artifact as **alpha** software
(`x.y.z-alpha.N` going forward) and do
not rely on it for high-risk activity.

Download only from the
[official releases page](https://github.com/openhat-security/oniongate/releases).
A release bundles Tor, sing-box, lyrebird, obfs4proxy, and the required runtime
resources.

Primary downloads:

| Platform | Install asset |
| --- | --- |
| macOS Apple Silicon | `OnionGate_<version>_aarch64.pkg` |
| macOS Intel | `OnionGate_<version>_x64.pkg` |
| Windows x86_64 | NSIS `-setup.exe` installer |
| Linux x86_64 | `.AppImage`, with `.deb` and `.rpm` packages for supported distributions |

The macOS `.dmg` is still published as a secondary download for anyone who
wants to inspect or place the app by hand. Prefer the `.pkg`; see
[why the .pkg is the macOS default](#why-the-pkg-is-the-macos-default).

Files such as `OnionGate.app.tar.gz`, `.sig`, and `latest.json` are signed
in-app-updater support assets, not the normal manual installer.

## Why the .pkg is the macOS default

Dragging an app out of a `.dmg` carries its `com.apple.quarantine` attribute
with it. On an unsigned build macOS then reports the copy as "damaged", which
looks like corruption but is only the missing vendor signature. A drag-install
also has no install-time hook, so OnionGate's privileged helper is not
registered and every privileged action — the kill switch, the network lock,
TUN — falls back to an administrator prompt.

The `.pkg` fixes both. Its payload is placed by the system installer and is
never quarantined, and its postinstall script runs as root, so it can:

- register the privileged launchd daemon, which makes the app prompt-free from
  its first launch;
- install a root-owned copy of the `sing-box` sidecar at a fixed path, so the
  privileged helper never executes a user-writable binary;
- clear any leftover quarantine attribute from an earlier drag-install.

The install location is pinned to `/Applications` and cannot be changed.

Be clear about what this does **not** fix: the `.pkg` itself is unsigned, so
Gatekeeper still refuses the **first** double-click. Right-click the `.pkg`,
choose **Open**, and confirm. Everything after that first prompt is the win —
no "damaged app" error, and a helper that is live before you open the app.

## Pre-1.0 builds are not OS-vendor signed

Apple notarization and Windows Authenticode require paid vendor programs that
this project has not yet enrolled in. Until then:

- **macOS** builds are unsigned and un-notarized. Gatekeeper blocks the first
  launch.
- **Windows** builds are unsigned. SmartScreen warns on first run.
- **Linux** packages are unaffected, because the distribution model does not
  depend on a vendor certificate.

Release CI refuses to publish a `1.0.0` or later stable release unless every
platform is properly signed, so this gap cannot silently outlive 0.x.

Because the OS will not vouch for these builds, the checksum and provenance
checks below are the real trust anchor. Do not skip them.

## Verify before you run

```bash
# macOS
shasum -a 256 -c SHA256SUMS --ignore-missing

# Linux
sha256sum -c SHA256SUMS --ignore-missing
```

`SHA256SUMS.sig` is a minisign signature over that manifest, made with the same
key that signs updater payloads. The matching public key is the `pubkey` value
in `src-tauri/tauri.conf.json`.

On a signed release, also verify the platform signature:

- macOS:
  ```bash
  codesign --verify --deep --strict --verbose=2 /Applications/OnionGate.app
  spctl --assess --type execute --verbose=4 /Applications/OnionGate.app
  xcrun stapler validate /Applications/OnionGate.app
  ```
- Windows PowerShell:
  ```powershell
  Get-AuthenticodeSignature .\OnionGate.exe | Format-List
  ```
  Require a valid status and the publisher named in the release notes.
- Linux: published checksum/signature and matching release provenance.

If a checksum, signature, SBOM, or provenance promised by the release notes is
missing, stop rather than bypassing the check.

## First launch on an unsigned build

Verify the checksum and attestation first. Only then:

- **macOS**: right-click the downloaded `.pkg`, choose **Open**, then confirm
  the Gatekeeper prompt. The installer takes it from there; the installed app
  opens normally.

  If you installed from the `.dmg` instead, right-click `OnionGate.app` in
  Applications and choose **Open**. If macOS still calls it damaged, clear the
  download quarantine flag for that one app rather than weakening Gatekeeper
  globally:
  ```bash
  xattr -dr com.apple.quarantine /Applications/OnionGate.app
  ```
- **Windows**: on the SmartScreen prompt choose **More info → Run anyway**.

When GitHub CLI is available, verify the build attestation too:

```bash
gh attestation verify <downloaded-artifact> \
  --repo openhat-security/oniongate
```

## From source

You need Node.js (see `.nvmrc`), Rust stable, Make, and the
[Tauri prerequisites](https://tauri.app/start/prerequisites/) for your platform.

```bash
git clone --depth 1 https://github.com/openhat-security/oniongate.git
cd oniongate
make setup          # npm ci + download and verify the bundled Tor / sing-box runtimes
make start          # run the app in development mode
```

`make setup` downloads executable sidecars. Read the hash manifest and script
before running it if you are evaluating the supply chain.

To build a release bundle locally:

```bash
make build
```

On macOS, to wipe a previous install and put a fresh `.pkg` on the machine
(privileged helper + pinned sing-box, the prompt-free Connect path):

```bash
make macos-reinstall
```

That asks for administrator rights twice: once to uninstall, once for
`installer`. The rebuild does not make a DMG (`create-dmg` often fails in a
local terminal and the `.pkg` does not need it). Open
`/Applications/OnionGate.app` afterward — not `make start`.
`PURGE_DATA=1` also deletes settings and permanent onion keys.
`SKIP_BUILD=1` reuses the last built package. `make macos-uninstall` only
removes the installed copy.

Local bundles are not automatically signed, notarized, or trusted by the
updater. A successful local build is not equivalent to an official release.

Run `make help` for the full list of targets.

### Why `make setup` downloads binaries

OnionGate bundles known Tor and transport versions rather than trusting whatever
is on the host. `make setup` fetches archives and checks each one against a
pinned SHA-256 in `scripts/dependencies.sha256`. A mismatched or unpinned archive
is refused, so the build fails loudly instead of staging an unverified binary.

The fetched runtime directories are ignored by Git. Never commit them manually.

## Platform notes

### macOS

Install Apple's command-line build tools and the Tauri prerequisites. TUN,
firewall, proxy, helper installation, and many hardening controls may ask for
administrator approval.

A `.pkg` install registers the privileged helper up front, so those prompts
mostly disappear. A build installed any other way — from the `.dmg`, or from
source — installs the helper on first use instead, which costs one
administrator prompt.

Gatekeeper warnings are expected for an unsigned local build. Do not disable
Gatekeeper globally; use a signed official release when one exists.

### Linux

The Tauri build needs WebKitGTK and distribution build packages. The system
proxy backend currently supports GNOME `gsettings`. TUN needs host TUN support,
and the kill switch requires `nftables` plus an elevation path (`pkexec` or
appropriate sudo policy).

### Windows

Windows supports managed Tor, Onion Host, TUN routing, selected-app rules, and
the Defender Firewall kill switch. The system proxy covers WinINet-aware
applications; use TUN for broader coverage. Session Guard process suspension is
a macOS/Linux-only extra. Stable Windows installers require Authenticode.

See the complete [platform support matrix](/reference/platform-support).

## First launch

1. Read the [threat model](/reference/threat-model).
2. Complete the setup wizard or choose a preset under Settings.
3. Connect Tor and wait for 100% bootstrap.
4. Select Proxy or TUN based on the boundary you need.
5. Run **Verify** and read every warning.

OnionGate stores application state under `oniongate` in the platform data
directory. Older builds used `tor-socks-gui`; each launch renames that folder
in place when `oniongate` is absent, or merges leftover settings and unique
site directories when both exist. Do not place it in a synced folder; it
can contain permanent onion keys.

## Uninstall (macOS)

OnionGate ships its own uninstaller, because dragging the app to the Trash
would leave the privileged helper, the pinned sidecar, and the pf anchors
behind.

The in-bundle uninstaller is injected by the `.pkg` installer, so it exists
**only in `.pkg` installs**. From the app, use **Settings → Uninstall
OnionGate**. Or open `OnionGate.app`, right-click it in Finder, choose **Show
Package Contents**, and open `Contents/Resources/uninstall.command`, or run it
from a terminal:

```bash
/Applications/OnionGate.app/Contents/Resources/uninstall.command
```

It asks for an administrator password, then removes the launchd daemon and
helper binary, the pinned `sing-box`, the pf anchors, the connection filter,
the boot network lock and Wi-Fi-off-at-boot daemons, OnionGate's system SOCKS
proxy settings, the `/etc`
shell hooks, the app bundle, and the installer receipt.

::: tip Your data is kept by default
The uninstaller does **not** delete OnionGate's data directory. Your settings,
logs, and — most importantly — the private keys for any permanent Onion Host
site stay where they are, so reinstalling keeps the same `.onion` addresses.

Delete them only if you mean to:

```bash
/Applications/OnionGate.app/Contents/Resources/uninstall.command --purge-data
```

That prompts for confirmation before it removes anything. Permanent onion keys
are not backed up anywhere and cannot be regenerated; once they are gone, the
addresses derived from them are gone with them.
:::

The same script lives at `scripts/macos-pkg/uninstall-oniongate.sh` in the
repository, so you can read it before you run it, and use it to clean up after
a build from source.

## The command line

The CLI is built alongside the app as the `oniongate` binary:

```bash
cargo build --release --manifest-path src-tauri/Cargo.toml --bin oniongate
```

See the [CLI guide](/guide/cli) for what it can do.
