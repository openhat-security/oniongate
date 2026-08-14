#!/usr/bin/env bash
# Restore host network defaults after a killed OnionGate / `make dev` session.
# Flushes pf/nft/WFP anchors, TUN, system proxy, managed Tor, and transports.
# Does not rewrite OnionGate settings.json (bridges, locale, presets stay).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/src-tauri/Cargo.toml"

run_stop() {
  local bin="$1"
  if [[ -x "$bin" ]]; then
    echo "OnionGate: restoring host network defaults via $bin stop"
    "$bin" stop
    return $?
  fi
  return 1
}

if run_stop "$ROOT/src-tauri/target/debug/oniongate"; then
  exit $?
fi
if run_stop "$ROOT/src-tauri/target/release/oniongate"; then
  exit $?
fi

echo "OnionGate: restoring host network defaults via cargo oniongate stop"
exec cargo run --manifest-path "$MANIFEST" --bin oniongate --quiet -- stop
