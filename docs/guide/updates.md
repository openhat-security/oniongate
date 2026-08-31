# Local installers and updates

## Build download files locally

Run this on the operating system you want to package:

```bash
make setup       # first time
make downloads
```

The build is unsigned and intended for local testing. The command prints the
exact output paths:

- macOS: `src-tauri/target/<target>/release/bundle/pkg/*.pkg` (primary) and
  `src-tauri/target/<target>/release/bundle/dmg/*.dmg`
- Windows: `src-tauri/target/<target>/release/bundle/nsis/*-setup.exe`
- Linux: AppImage, DEB, and RPM directories under
  `src-tauri/target/<target>/release/bundle/`

On macOS the local target uses non-interactive DMG layout mode. It does not need
Cursor/Terminal automation permission to control Finder.

The DMG contains `OnionGate.app`. A macOS machine builds its own architecture;
Windows and Linux installers should be built natively on those systems. GitHub
release CI builds every supported target with signing and provenance.

### The macOS installer package

Tauri has no `pkg` bundle target, so the installer is a post-bundle step:
`scripts/build-macos-pkg.sh` takes the `.app` that Tauri produced and drives
Apple's `pkgbuild` and `productbuild`. `make downloads` runs it automatically,
and CI runs the same script on both macOS targets, so a local `.pkg` is built
the same way a released one is.

To rebuild only the installer after a bundle already exists:

```bash
make macos-pkg
```

The package installs to `/Applications` with no option to change that, and its
postinstall script registers the privileged helper and pins the `sing-box`
sidecar to a root-owned path. It also injects the uninstaller into the bundle
as `Contents/Resources/uninstall.command`, which is why the `.dmg` — built by
Tauri, untouched by this script — does not carry one.

Local packages are unsigned. Set `PKG_SIGNING_IDENTITY` to a Developer ID
Installer identity if you have one; without it `productbuild` still succeeds
and Gatekeeper prompts on the first double-click.

The updater is unaffected. macOS updates continue to ship as `.app.tar.gz`
payloads, and `scripts/build-updater-manifest.mjs` matches on that suffix, so
adding a `.pkg` to a release changes nothing about **Check for updates**.

::: warning Local bundles are unsigned
`make downloads` deliberately passes `--no-sign`. Gatekeeper, Authenticode, and
the Tauri updater trust chain apply only to official CI artifacts.
:::

## When to create an update

The first published version is an installation, not an update. Create an update
when users already have an older signed OnionGate release and you are ready to
publish a newer version.

Before tagging:

1. invoke the project `release-changelog` Cursor skill with the next semantic
   version;
2. review and merge its version/changelog change on `main` or `staging`;
3. run `make release-check VERSION=<version>`;
4. tag that exact commit as `v<version>` and push the tag.

Release CI creates a draft. Test the installers, checksums, SBOMs, and
attestations before publishing.

## How automatic updates work

The installed app contains only the updater **public** key. The matching private
key stays offline and in GitHub Actions secrets.

When the user selects **Settings → Check for updates**:

1. OnionGate requests
   `https://github.com/openhat-security/oniongate/releases/latest/download/latest.json`;
2. the manifest selects the current OS and architecture;
3. Tauri downloads the updater payload;
4. the embedded public key verifies its signature;
5. OnionGate installs it and relaunches.

A missing or invalid signature fails the update. OnionGate never bypasses the
check.

## Alpha, staging, and stable channels

Tags must point to commits on `main` or `staging`.

- While the product is alpha, `main` tags use semver prereleases such as
  `v0.2.5-alpha.1` (stay on `0.y.z-alpha.N`; do not jump to `1.0.0-alpha`
  until the signing gates are the active goal). Release CI marks them GitHub
  prereleases (never Latest).
- `staging` always produces a prerelease for manual testing.
- A plain stable tag (for example `v1.0.0`) may become Latest only after the
  [stable-release gate](/reference/release#stable-release-gate).

GitHub's `/releases/latest/` endpoint excludes drafts and prereleases. Therefore
the built-in updater follows published non-prerelease releases only. While every
downloadable build is a prerelease, `/releases/latest/` (and thus
`latest.json`) is empty on purpose — older plain `v0.2.x` releases are marked
superseded/prerelease so they cannot become Latest again. Alpha and staging
installers are downloaded from the Releases page (and verified against
`SHA256SUMS`). Do not retag already-published plain `v0.2.x` tags.

## Trust-root warning

Losing `TAURI_SIGNING_PRIVATE_KEY` or its password prevents existing
installations from accepting future updates. Rotating the public key in
`tauri.conf.json` also breaks that trust chain. Keep an encrypted offline backup
and never commit either secret.
