#!/usr/bin/env bash
# `make dev` / `make start` entry: start daemons, run Tauri, then restore host defaults.
# See docs/guide/daemons.md. The helper is not a Tauri sidecar in development.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
MANIFEST="$ROOT/src-tauri/Cargo.toml"
CLI="$ROOT/src-tauri/target/debug/oniongate-cli"
if [[ -x "${CLI}.exe" ]]; then
  CLI="${CLI}.exe"
fi

echo "OnionGate: building daemons"
if ! cargo build --manifest-path "$MANIFEST" --bin oniongate-helper --bin oniongate-cli; then
  echo "OnionGate: could not build oniongate-helper / oniongate-cli" >&2
  exit 1
fi

echo "OnionGate: starting privileged helper"
if ! "$CLI" helper start; then
  echo "OnionGate: helper did not start; approve the administrator prompt or run: $CLI helper start" >&2
fi

CLEANED=0
cleanup() {
  if [[ "$CLEANED" -eq 1 ]]; then
    return
  fi
  CLEANED=1
  echo
  bash "$ROOT/scripts/dev-cleanup.sh" || true
}

trap cleanup EXIT
npm run tauri dev
status=$?
exit "$status"
