# Contributing

OnionGate is GPL-3.0 software. By contributing, you agree that your contribution
is distributed under GPL-3.0. Participation is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Development

```bash
make setup
make check
make lint
```

(`make help` lists setup, dev, build, clean, and other targets.)

Do not add downloaded executables, onion keys, bridge lines, logs, or local
security reports to commits.

Regenerate app/tray icons on macOS after changing `public/logo.png`:

```bash
make icons
```

The icon task removes only the edge-connected black matte, writes dedicated
tray assets, and regenerates Tauri's macOS/Windows/Linux icon bundles.

## Documentation

The site in `docs/` is VitePress and is published to GitHub Pages from `main`.

```bash
make docs           # hot-reloading preview
make docs-build     # what the docs workflow builds; rejects unresolved internal links
```

`docs/guide/` is task-oriented material. `docs/reference/` covers architecture,
platform support, local data/network activity, threat model, privacy, and the
release process. Only the GitHub-conventional files
(`README`, `SECURITY`, `CONTRIBUTING`, `CODE_OF_CONDUCT`) stay at the repository
root. Update the docs in the same pull request as the behavior they describe.

When a change adds or alters a network request, persisted field, elevated
operation, platform guarantee, sidecar, CLI flag, recovery path, or user-visible
control, update all affected guide and reference pages—not only the README.
Claims about verification must state what is observed and what remains
unproven.

## Changelog

Every user-visible change needs a Keep a Changelog bullet under
`## [Unreleased]` in `CHANGELOG.md` in the same PR. `make check` and CI run
`make changelog-check`. That fails if behavior files changed with an empty
Unreleased section, or if [docs/reference/changelog.md](docs/reference/changelog.md)
is stale.

Before a release, move Unreleased into a dated `## [x.y.z] - YYYY-MM-DD`
section and run `make changelog-sync` so the docs site and
[release audit trail](docs/reference/release-audit.md) (commit subjects since
the previous tag) match. GitHub release notes are extracted from that dated
section. Do not put secrets, bridge lines, keys, or public IPs in changelog
text or commit subjects.

## Pull requests

- Keep network mutations behind a typed platform API.
- Add rollback and startup-recovery behavior for every privileged mutation.
- Add tests for torrc, control-protocol, routing, firewall, and persistence
  changes.
- Describe privacy/security impact and failure behavior.
- Update platform support, data/network inventory, and threat-model limitations
  when the protection boundary changes.
- Preserve attribution and verify license compatibility for reused code.
- Never weaken Tor circuits or silently fall back to a direct route.
- Never read, log, or export onion service key material. Permanent sites are
  deliberately owned by Tor inside its own data directory; OnionGate may read
  only the public `hostname` file.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not public
issues.

## Preparing a release

Invoke the project `release-changelog` Cursor skill with the intended version.
Run it only from a clean `main` or `staging` checkout. Review its
complete-history changelog and version diff, then run:

```bash
make release-check VERSION=0.2.1
make release-bundle-local   # unsigned host-platform packaging smoke test
```

Merge that preparation before creating `v0.2.1`. Tag-triggered release CI
refuses mismatched versions or a missing dated changelog section and creates
only a draft for maintainer review. Tags outside `main`/`staging` are rejected;
staging-origin drafts are always prereleases.
