# Release process

OnionGate has not published a stable release. Every downloadable build is
**alpha** until the [stable-release gate](#stable-release-gate) passes.

## Version naming

Use semantic versions with an explicit prerelease identifier while the product
is alpha:

| Kind | Example tag | GitHub | Updater (`/releases/latest/`) |
| --- | --- | --- | --- |
| Alpha (current policy) | `v0.2.5-alpha.1` | Prerelease, never Latest | Not followed |
| Beta / RC | `v0.3.0-beta.1`, `v1.0.0-rc.1` | Prerelease, never Latest | Not followed |
| Stable (gates only) | `v1.0.0` | Latest | In-app updater |

Rules:

- Prefer **`0.y.z-alpha.N`** until the [stable-release gate](#stable-release-gate)
  passes. SemVer `0.x` means initial development; bump `y` for meaningful
  incompatible work and `z` / `-alpha.N` for smaller cuts. Do **not** jump to
  `1.0.0-alpha.N` while notarization and Authenticode are still optional —
  that version line is reserved for stabilizing toward the signed `1.0.0`
  milestone and confuses the project's 1.0 signing gates.
- Prefer **forward-looking** tags such as `0.2.5-alpha.1` or `0.3.0-alpha.1`.
  Do **not** retag or rewrite already-published `v0.2.0`…`v0.2.4` (or any older
  plain `0.x`) — that breaks checksums, attestations, and installed updaters.
- Release CI marks any hyphenated version (`*-alpha*`, `*-beta*`, `*-rc*`, or
  other `*-` suffix) and every `staging`-origin tag as a GitHub **prerelease**.
- Alpha testers install from the Releases page (or a pinned asset URL). In-app
  **Check for updates** follows GitHub Latest only. While every published build
  is a prerelease, Latest is empty on purpose — the updater must not treat a
  plain `0.2.x` as stable.
- A plain `1.0.0+` from `main` may become Latest only after the stable gate
  below. Do not describe any `0.x` or `-alpha` / `-beta` / `-rc` build as
  production-ready.

## Deprecating older releases

GitHub has no first-class “deprecated” flag on Releases. For OnionGate:

1. Mark superseded builds as **prerelease** (so they cannot be Latest).
2. Ensure only one release is Latest — and during alpha, **none** should be
   (Latest stays empty until a stable tag).
3. Prefix the release title with a clear superseded marker and prepend a
   caution banner in the body that points installers at the current alpha on
   the [Releases page](https://github.com/openhat-security/oniongate/releases).
4. Keep README / install docs pointing only at the current alpha channel.
5. Do **not** delete tags or assets that checksums, attestations, or installed
   clients may still reference, unless there is an explicit migration plan.

Example maintainer edit (published tags only; leave assets in place):

```bash
gh release edit v0.2.4 \
  --prerelease \
  --title "OnionGate v0.2.4 (superseded)" \
  -F path/to/notes-with-superseded-banner.md
```

Do not pass `--latest=false` as a separate token on older `gh` builds — the
literal `false` can be parsed as a second positional argument. Marking the
release as a prerelease is enough to clear Latest.

The workflow intentionally creates a **draft** first so artifacts can be
inspected before publication.

## Cursor changelog gate

Before creating a tag, invoke the project `release-changelog` Cursor skill with
the intended semantic version. Cursor reviews every commit and full diff since
the previous tag, updates `CHANGELOG.md`, synchronizes package/Cargo/Tauri
versions, and runs the release preflight.

Review and merge that change before tagging. Release CI rejects:

- a tag whose commit is not reachable from `main` or `staging`;
- a tag that differs from the application version;
- mismatched versions across package, lockfile, Cargo, or Tauri config;
- a missing dated `CHANGELOG.md` section for that version;
- a stale `docs/reference/changelog.md` or missing release audit page
  (`make changelog-sync`).

Every PR runs `make changelog-check`. User-visible changes must add an
`## [Unreleased]` bullet. The docs site publishes the same changelog and a
commit-subject [audit trail](/reference/release-audit).

Cursor prepares text; a maintainer remains responsible for accuracy. AI output
must never contain secrets, bridge lines, onion/client credentials, public IPs,
local paths, or private report content.

`main` and `staging` are the only branches allowed to run normal CI or produce
downloadable artifacts. A tag reachable only from `staging` always creates a
prerelease. If the commit is reachable from both branches, it is treated as a
`main` release.

## Current automation

Pushing a tag matching `v*` first runs typecheck, format, Clippy, Rust tests,
docs build, npm production audit, Cargo audit, and the version/changelog gate.
Only then does it create or refresh a draft release and build:

- Apple Silicon on `macos-15` (`aarch64-apple-darwin`);
- Intel on `macos-15-intel` (`x86_64-apple-darwin`);
- Ubuntu 22.04;
- Windows Server 2022.

The manual-install assets are two architecture-specific macOS DMGs containing
`OnionGate.app`, a Windows NSIS setup EXE, and Linux AppImage/DEB/RPM packages.
Tauri also uploads signed platform updater payloads; those support in-app
updates and are not substitutes for the primary installers.

Each target downloads verified sidecars, builds and stages `oniongate-helper`,
creates updater signatures, and uploads installers to the same draft. Targets
build in parallel: none of them writes `latest.json`, so there is no shared
manifest for them to race over.

The metadata job then assembles `latest.json` from the uploaded payloads and
their detached signatures, failing the release if any of the four platform keys
is missing or unsigned. It also:

- generates Cargo, npm, and pinned-sidecar CycloneDX SBOMs;
- creates `SHA256SUMS` and signs it with the updater trust root;
- publishes GitHub build-provenance attestations;
- uploads all evidence as release assets and a retained workflow artifact.

The draft is published only after every artifact, checksum, SBOM, and
attestation is uploaded, so a tag is never briefly downloadable without its
verification material.

## Signing posture by version

The Tauri updater key is always mandatory: it costs nothing to generate and it
is what signs `latest.json` and `SHA256SUMS`. OS-vendor signing is gated on the
version instead, because Apple notarization and Authenticode both require paid
enrollment:

| Tag | Apple signing | Authenticode | Result |
| --- | --- | --- | --- |
| `0.x` (including `-alpha.N`) | optional | optional | Publishes; unsigned platforms get a warning banner in the release notes |
| `1.0.0`+ stable (no prerelease suffix) | required | required | Release CI fails the tag if either is missing |
| any `-suffix`, or a `staging` tag | optional | optional | Marked prerelease, never Latest |

When a platform is unsigned, CI prepends an explicit warning to the release
notes, skips the notarization and Authenticode assertions for that platform, and
still enforces bundle contents, checksums, SBOMs, and provenance.

Publishing a non-prerelease triggers a separate post-publish check of the public
`releases/latest/download/latest.json` endpoint, release checksums, and GitHub
attestations. A failed post-publish check is a release incident.

## Known release blockers

The workflow still does **not**:

- run quarantined-install smoke tests on fresh VMs;
- apply Apple notarization or Authenticode, which 1.0 will require;
- give CLI `start` the same verified TUN/firewall/proxy orchestration and
  long-running session ownership as the desktop app;
- provide manageable cross-process lifecycle for CLI-created temporary sites.
- complete the helper's minimal-crate and client code-signature hardening.

Consequently, 0.x artifacts must not be described as stable or
production-ready.

## Updater trust root

The Tauri updater public key is embedded in `src-tauri/tauri.conf.json`. Its
private key and password must exist only in offline backup and GitHub Actions
secrets:

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`

Losing the private key prevents installed clients from trusting future updates.
Replacing the public key casually breaks the update chain. Never commit either
the private key or password.

## Platform credentials

These are optional for `0.x` and mandatory from `1.0.0` onward.

The optional macOS **connection filter** is a Network System Extension
(`content-filter-provider-systemextension`). It will not load on unsigned or
ad-hoc Debug the way the privileged helper can. Shipping it needs an Apple
Developer ID **network-extension** provisioning profile, the host-app
entitlements in `scripts/macos-pkg/OnionGate.entitlements`, and user approval
in System Settings → General → Login Items & Extensions → Network Extensions.
Do not attach those entitlements to
unsigned `tauri.conf.json` builds: they would fail to launch. Unsigned `.pkg`
and `make dev` stay on `pf` plus the after-the-fact socket watch — they do
not embed the system extension (set `EMBED_FILTER=1` or a Developer ID
identity to ship it).

macOS requires:

- `APPLE_CERTIFICATE`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_SIGNING_IDENTITY`
- `APPLE_TEAM_ID`
- `APPLE_API_KEY`
- `APPLE_API_ISSUER`
- `APPLE_API_KEY_BASE64`

Windows signing uses:

- `WINDOWS_CERTIFICATE`
- `WINDOWS_CERTIFICATE_PASSWORD`

The full setup procedure lives in
[`.github/RELEASE_SECRETS.md`](https://github.com/openhat-security/oniongate/blob/main/.github/RELEASE_SECRETS.md).
That file documents names and procedures only; values stay in repository
secrets.

## Sidecar update procedure

1. Update one dependency/version at a time.
2. Download the immutable upstream archive from its official source.
3. For Tor, verify the Tor Project's signed checksum manifest.
4. Independently reproduce or verify the archive hash.
5. Update `scripts/dependencies.sha256`.
6. Run `make clean-deps && make deps` on every affected architecture.
7. Confirm staged filenames match Tauri's target-triple `externalBin` names.
8. Update third-party notices and corresponding-source links.
9. Review the sidecar's release notes for protocol, configuration, and license
   changes.

Never make the dependency script accept an unpinned archive.

## Stable-release gate

Before publishing a stable tag:

1. Run `make check`, `make lint`, `make audit`, `make build-frontend`, and
   `make docs-build` from a clean checkout.
2. Ensure CI passes on macOS, Linux, and Windows.
3. Review the threat model, privacy inventory, platform matrix, and installer
   docs in the same commit.
4. Build every artifact from the tag in GitHub Actions.
5. Package and sign the helper and all nested executable sidecars.
6. Sign/notarize/staple macOS; Authenticode-sign Windows.
7. Generate SHA-256 checksums, detached signatures, SBOMs, licenses, and build
   provenance.
8. Verify every uploaded artifact against the checksums.
9. Test a quarantined download and uninstall/recovery on clean macOS, Linux, and
   Windows VMs.
10. Exercise Connect, TUN, kill switch, Emergency Restore, temporary/permanent
    Onion Host, client authorization, and updater behavior.
11. Verify `latest.json` contains macOS ARM64/Intel, Linux x86_64, and Windows
    x86_64 entries with valid signatures.
12. Confirm CI published the release and marked it Latest, then re-verify the
    public download endpoints.

GitHub's `macos-15-intel` runner is scheduled to retire in August 2027. Intel
macOS releases need a replacement build runner or an explicit end-of-support
decision before then.

## Documentation deployment

Documentation is independent of application releases. A push to `main` that
changes `docs/`, package manifests, or the docs workflow builds VitePress and
deploys it to GitHub Pages. Pull requests build the site without deploying it.

Pages must be enabled once by a repository admin, because the workflow token
cannot perform that owner-level setup:

```bash
gh api -X POST repos/openhat-security/oniongate/pages -f build_type=workflow
```

The equivalent UI path is **Settings → Pages → Source: GitHub Actions**. Only
the canonical repository deploys; forks and staging builds validate the docs
without publishing them.

The README download badge uses GitHub's public release-asset totals. The clone
badge is refreshed daily from GitHub's private 14-day Traffic API and publishes
only the aggregate count through Pages. It requires a fine-grained
`TRAFFIC_TOKEN` Actions secret scoped to this repository with
**Administration: Read**. The default workflow token cannot read traffic data.
