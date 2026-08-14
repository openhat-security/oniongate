<!-- Thanks for contributing to OnionGate. Contributions are licensed under GPL-3.0. -->

## Summary

<!-- What does this change do, and why? -->

## Privacy / security impact

<!-- Describe the effect on routing, leak behavior, and failure modes.
     State "none" only if truly none. -->

## Checklist

- [ ] `make check` passes (typecheck + Rust tests)
- [ ] `make lint` passes (`cargo clippy --all-targets` and `cargo fmt --check`)
- [ ] `make docs-build` passes
- [ ] `CHANGELOG.md` `## [Unreleased]` has a bullet for user-visible behavior (or this PR is docs/chore-only)
- [ ] User-visible behavior, platform limits, persisted data, network requests, CLI, and recovery docs are updated where affected
- [ ] Network mutations stay behind a typed platform API with rollback + startup recovery
- [ ] Added tests for torrc / control-protocol / routing / firewall / persistence changes
- [ ] No secrets, onion keys, bridge lines, logs, or local reports committed
- [ ] Onion key material is neither read, logged, nor exported (permanent sites stay owned by Tor)
- [ ] Does not weaken Tor circuits or add a silent direct-route fallback
- [ ] Attribution preserved and license compatibility verified for reused code

<!-- Report security vulnerabilities privately per SECURITY.md, not in a public PR. -->
