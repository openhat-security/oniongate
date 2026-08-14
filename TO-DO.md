# Follow-ups

Not in the macOS NIC default-deny pass. Do not treat these as silent holes in
that lock; they are tracked work.

- Linux: nftables equivalent of default-deny all outbound IP except live Tor
  endpoints, with a deny log and no bootstrap window.
- Windows: extend the transition TCP allow-Tor rule to the steady-state kill
  switch; default-deny other protocols if the platform allows.
- CLI: full protected-session orchestration (TUN / kill switch / proxy) and
  `emergency-restore`.
- Helper: split `oniongate-helper` into a minimal crate. Signed macOS builds
  already require a matching peer code signature; unsigned debug stays UID-only.
  Windows named-pipe ACL / client identity still needs review.
- Snowflake / meek vs the NIC lock: no honest IP allowlist; leave unsupported.
- Do not add a Network Extension as the enforcement path (Apple daemons bypass
  it; it can fail open).
