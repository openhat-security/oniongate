#!/usr/bin/env bash
# Copy a built OnionGateFilter.systemextension and oniongate-filter-ctl into
# an OnionGate.app. Missing artifacts are skipped so unsigned debug builds
# still package; the filter simply will not load.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="${1:-}"

if [[ -z "$APP" || ! -d "$APP" ]]; then
  echo "Usage: embed-oniongate-filter.sh /path/to/OnionGate.app" >&2
  exit 2
fi

FILTER_DIR="$ROOT/macos/OnionGateFilter"
SYSEX="$FILTER_DIR/build/com.adamsiwiec.oniongate.filter.systemextension"
CTL="$FILTER_DIR/build/oniongate-filter-ctl"

if [[ ! -d "$SYSEX" ]]; then
  echo "OnionGate filter system extension is not built; skipping embed."
  exit 0
fi

DEST_SYSEX="$APP/Contents/Library/SystemExtensions/com.adamsiwiec.oniongate.filter.systemextension"
mkdir -p "$(dirname "$DEST_SYSEX")"
rm -rf "$DEST_SYSEX"
cp -R "$SYSEX" "$DEST_SYSEX"

if [[ -x "$CTL" ]]; then
  cp "$CTL" "$APP/Contents/MacOS/oniongate-filter-ctl"
  chmod 755 "$APP/Contents/MacOS/oniongate-filter-ctl"
fi

echo "Embedded the connection filter into $APP"
