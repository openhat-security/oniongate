# Platform support

OnionGate supports its core Tor routing, hosting, verification, recovery, and
tray workflows on macOS, Linux x86_64, and Windows x86_64. Some operating-system
utilities are naturally platform-specific; the table shows feature availability
without treating an entire supported OS as incomplete.

| Capability | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Managed Tor and control port | Yes | Yes | Yes |
| Temporary/permanent Onion Host | Yes | Yes | Yes |
| System SOCKS proxy | Yes | GNOME desktops | WinINet-aware apps |
| sing-box TUN | Yes | Yes | Yes |
| UDP/QUIC kill switch | `pf` | `nftables` | Defender Firewall |
| Selected-app TUN rules | Yes | Yes | Yes |
| Session Guard process suspension | Yes | Yes | — |
| App detection and bypass helpers | Yes | Yes | — |
| Workstation Checkup / Startup Items | Yes | — | — |
| OS hardening | Yes | — | — |
| Privileged-helper service | Yes | Yes | Yes |
| CI compile/test | macOS 15 ARM/Intel | Ubuntu 22.04 | Windows 2022 |

## macOS

On macOS:

- System proxy changes use `networksetup` and capture up to three active network
  services for restoration.
- TUN uses elevated sing-box and may appear as a `utun` interface even though
  the generated interface name is `torsocks0`.
- The kill switch uses a dedicated `pf` anchor and blocks outbound UDP except
  loopback.
- Session Guard uses process stop/continue signals.
- Checkup, persistence baselines, Background/Login Items scanning, and all
  current hardening controls are macOS-specific.
- Background/Login Items scanning is explicit and requires Full Disk Access; it
  is never run automatically.

Normal downloadable builds also need Developer ID signing, hardened runtime,
notarization, and stapling. Until those artifacts are published, source builds
should be treated as development software.

## Linux

On Linux:

- System proxy integration supports GNOME `gsettings`; other desktop
  environments report it unavailable.
- TUN needs the host's TUN support and an elevation path.
- The kill switch requires `nft`. Without the helper, elevation uses `pkexec` or
  non-interactive/passwordless `sudo`.
- App detection searches common binaries and `.desktop` locations.
- Session Guard needs `pgrep` and `kill`.
- Workstation Checkup, persistence baselines, login-item scanning, and OS
  hardening are not implemented.

The CI target is Ubuntu, not every distribution. Package names, PolicyKit,
systemd, firewall tooling, and WebKit availability vary by distribution.

The Tor Project's 15.0.x expert bundle does not publish a Linux AArch64 archive.
`make deps` therefore fails closed on `aarch64-unknown-linux-gnu` unless a
developer explicitly sets `ALLOW_MISSING_TOR=1`; that override produces no
usable bundled Tor and is not a release path.

## Windows

On Windows:

- The system proxy changes WinINet registry values. Software that uses WinHTTP,
  custom DNS, or its own network stack may ignore them.
- TUN and selected-app policy use sing-box, but Session Guard process suspension
  is not implemented.
- The kill switch creates a named outbound UDP rule in Windows Defender
  Firewall.
- Workstation Checkup, app bypass helpers, and OS hardening are not implemented.
- Stable release artifacts require Authenticode. Unsigned Windows artifacts are
  limited to clearly labeled prereleases.

## Privileged helper packaging status

The repository contains install/service code for `oniongate-helper`. The typed
protocol covers ping, kill switch, transition lock, macOS deny harvest, pid
terminate, and `.app` stop. The helper must be built, placed beside the app, and
signed with the same identity as the app. A signed helper refuses unsigned
peers; unsigned debug builds authenticate by UID only.

Release CI now builds the helper per target and applies a release-only Tauri
sidecar overlay so development builds do not depend on a staged helper. The
draft must still be inspected to confirm the helper is present and shares the
application's platform signature. If absent, installation fails explicitly and
OnionGate uses interactive elevation instead.

Before stable release, the helper must also move to a minimal crate, verify the
macOS client code signature/audit token rather than UID alone, and enforce a
reviewed Windows pipe ACL and client identity.

## Support policy

Only the latest tagged release is eligible for security fixes. There is
currently no stable tagged release. Until the stable release gates pass, builds
on every platform are prerelease software and should not be the sole control for
high-risk activity.

See the [security policy](https://github.com/irruptio-security/oniongate/blob/main/SECURITY.md)
and [threat model](/reference/threat-model).
