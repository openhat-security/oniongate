# Changelog

All notable user-facing changes to OnionGate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
OnionGate uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] - 2026-08-14

### Fixed

- npm CycloneDX SBOM generation reads the lockfile and ignores `npm ls` peer
  noise, so the Actions metadata job can publish checksums and updater
  metadata.

### Changed

- GitHub Actions publishes the four-platform installers (macOS Apple Silicon,
  macOS Intel, Linux x86_64, Windows x86_64). 0.2.2 built them but did not
  publish after the SBOM step failed.

### Known limitations

- This remains a 0.x alpha. Apple notarization and Authenticode are still
  optional. Do not treat it as a sole control for high-risk work.

## [0.2.2] - 2026-08-13

### Changed

- GitHub Actions now builds the four-platform draft (macOS Apple Silicon, macOS
  Intel, Linux x86_64, Windows x86_64) with updater metadata, checksums, and
  SBOMs. The 0.2.1 drop was a local unsigned Apple Silicon installer only.

### Fixed

- Rust formatting so release verification and CI can run on the tag.

### Known limitations

- This remains a 0.x alpha. Apple notarization and Authenticode are still
  optional. Do not treat it as a sole control for high-risk work.

## [0.2.1] - 2026-08-13

### Added

- macOS NIC default-deny lock (Maximum Isolation) with a local deny journal and
  destination-exception consent (`LEAK`).
- Verify **Kill** stops an `.app` bundle (quit GUI, `launchctl bootout`, leftover
  pids), not a single pid.
- `make dev` builds and starts `oniongate-helper`. CLI: `oniongate helper
  status|start|stop`.
- Docs changelog page and commit-subject release audit trail, enforced by
  `make changelog-check` on every PR.

### Security

- CLI `start` no longer reports Protected; managed Tor only leaves the session
  Degraded.
- Disconnect aborts if the transition lock cannot arm, instead of dropping
  TUN/proxy onto clearnet.
- Tray Protected label matches the window (live NIC lock and no destination
  exceptions).
- Signed macOS helper requires a matching peer code signature; unsigned debug
  builds stay UID-only.
- Preset copy no longer claims a NIC lock on Linux/Windows.
- Product and docs label this line as alpha.

### Known limitations

- This is an unsigned 0.x alpha. The NIC default-deny is macOS-only. CLI start
  does not apply TUN, kill switch, or proxy. Helper crate split and Windows
  pipe identity remain open.

## [0.2.0] - 2026-07-30

### Added

- Managed Tor connection with Smart Connect, trusted bridge transports, exit
  selection, relay pinning, and live bootstrap/session status.
- Proxy and sing-box TUN routing modes with Tor DNS, UDP/QUIC containment,
  per-application circuit isolation, and macOS/Linux Session Guard.
- Temporary and permanent Onion Host sites, named v3 client credentials,
  authorization toggling, audits, QR handoff, and permanent-address lifecycle.
- Headless `oniongate` CLI for managed Tor and permanent onion-site operations.
- Live verification for Tor egress, DNSPort, IPv6 exposure, UDP/QUIC policy,
  app-policy prerequisites, and interrupted-session recovery.
- macOS Checkup, hardening controls, and startup-item baselines.
- Optional typed privileged helper for fixed kill-switch operations.
- Native menu-bar/system-tray controls on macOS, Linux, and Windows.
- Tray shortcuts for Verify, Onion Host, and Logs, plus a `make downloads`
  command for native local installer bundles.
- VitePress documentation site, platform matrix, threat model, privacy/data
  inventory, release process, and GitHub Pages deployment.
- Cursor-assisted release changelog preparation with enforced version and
  changelog gates.
- Draft GitHub distribution for macOS ARM64/Intel, Linux x86_64, and Windows
  x86_64 with updater metadata, helper packaging, signed checksums, SBOMs, and
  provenance.

### Changed

- Renamed Onion Lab to Onion Host and separated temporary from permanent sites.
- Reorganized operating-system checks and hardening under System; application
  preferences and logs now live under Settings.
- Added dedicated transparent app icons and compact platform-specific tray
  icons.
- Updated the updater endpoint and public project metadata to
  `irruptio-security/oniongate`.
- Standardized release downloads as macOS DMGs containing the app, a Windows
  NSIS setup EXE, and Linux AppImage/DEB/RPM packages.

### Security

- Protected status now requires the requested live proxy/TUN, DNS, control, and
  firewall boundary; incomplete startup is shown as degraded or unverified.
- Private permanent sites start with an unusable authorization lock so they are
  never briefly public, and the last active client cannot be revoked implicitly.
- Tor-exit location lookup travels through Tor rather than linking both address
  lookups over the direct connection.
- Local settings, logs, databases, journals, and onion-service state use
  owner-only Unix permissions.
- Corrected macOS `pf` rule ordering so loopback DNS remains available while
  clearnet UDP is blocked.
- Removed third-party Objective-See integration recommendations and the broad
  frontend URL-opener permission.

### Known limitations

- There is no stable audited release yet. Windows does not include Session Guard
  process suspension, and CLI protected-session orchestration remains limited.
- The privileged helper still requires minimal-crate and client-identity
  hardening before a stable release.
- Linux AArch64 cannot bundle Tor until an official expert bundle is available.
