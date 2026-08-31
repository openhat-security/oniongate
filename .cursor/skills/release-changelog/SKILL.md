---
name: release-changelog
description: Prepares an OnionGate release version and AI-written changelog from the complete Git history since the previous tag. Use only when explicitly invoked before creating a release tag.
disable-model-invocation: true
---

# Prepare OnionGate release changelog

The user must provide a semantic version such as `0.2.5-alpha.1` (preferred
while alpha) or `0.2.1`. Do not create a tag, commit, push, publish a release,
or alter release credentials. Do not retag already-published releases.

## Workflow

1. Read `CHANGELOG.md`, `docs/reference/release.md`, and
   `.cursor/rules/release-ci.mdc`.
2. Require the current branch to be `main` or `staging` and require a clean
   starting tree. If either condition fails, stop; releases from feature
   branches are forbidden.
3. Find the newest reachable `v*` tag. Inspect every commit and full diff from
   that tag to `HEAD`; if no tag exists, inspect all history.
4. Write release notes for users, not a commit dump:
   - group under Added, Changed, Fixed, Security, Deprecated, Removed, or Known
     limitations only when populated;
   - explain behavior and impact in concise bullets;
   - call out platform support and fail-closed/security boundary changes;
   - omit internal refactors unless they change reliability, packaging, or
     security.
5. Never include bridge lines, onion addresses or keys, client credentials,
   public IPs, local paths, full command lines, secret names with values, or
   private issue/report content.
6. Keep `## [Unreleased]` at the top. Add
   `## [<version>] - YYYY-MM-DD` immediately below it. Do not duplicate an
   existing version section.
7. Synchronize the requested version in:
   - `package.json`
   - the root package entries in `package-lock.json`
   - `src-tauri/Cargo.toml`
   - `src-tauri/tauri.conf.json`
8. Run:

   ```bash
   node scripts/check-release.mjs v<version>
   node scripts/extract-release-notes.mjs v<version> /tmp/oniongate-release-notes.md
   make check
   make docs-build
   ```

9. Review the resulting changelog and version-only diff. Report release
   blockers separately; do not hide them inside marketing language.
10. Hand control back to the user for review and commit. The release tag may be
    created only after this change is merged to the release commit.

## Style

- Follow Keep a Changelog and Semantic Versioning.
- Use present-perfect user-facing bullets: “Added…”, “Fixed…”, “Changed…”.
- Be factual and conservative. Do not call a release stable, audited, signed,
  notarized, or production-ready unless the release gates prove it.
- Preserve manually written notes that remain accurate; edit rather than
  replacing them blindly.
