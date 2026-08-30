#!/usr/bin/env bash
# Wipe a previous macOS OnionGate install, rebuild the local .pkg, and install
# it with the system installer. That is the path that registers the privileged
# helper and pins sing-box as root — Connect should then stop asking for a
# password on every privileged step.
#
# Usage:
#   make macos-reinstall
#   make macos-reinstall SKIP_BUILD=1          # reuse the last built .pkg
#   make macos-reinstall PURGE_DATA=1          # also delete app data / onion keys
#   bash scripts/macos-pkg-reinstall.sh --help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PURGE_DATA="${PURGE_DATA:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
UNINSTALL_ONLY=0

usage() {
    cat <<'USAGE'
Usage: macos-pkg-reinstall.sh [options]

  --purge-data      Also delete the OnionGate data directory (permanent
                    Onion Host keys cannot be recovered). Off by default.
  --skip-build      Do not rebuild; install the newest existing local .pkg.
  --uninstall-only  Only remove the installed app / helper / pin. No rebuild.
  --help            Show this message.

Environment (used by the Makefile):
  PURGE_DATA=1   SKIP_BUILD=1
USAGE
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --purge-data) PURGE_DATA=1 ;;
        --skip-build) SKIP_BUILD=1 ;;
        --uninstall-only) UNINSTALL_ONLY=1 ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "macos-pkg-reinstall.sh only runs on macOS" >&2
    exit 1
fi

uninstall() {
    local args=()
    if [[ "$PURGE_DATA" == "1" ]]; then
        args+=(--purge-data --yes)
        echo "==> Uninstalling OnionGate and deleting its data directory"
    else
        echo "==> Uninstalling OnionGate (settings and onion keys kept)"
    fi
    bash "$ROOT/scripts/macos-pkg/uninstall-oniongate.sh" ${args[@]+"${args[@]}"}
}

verify_live_install() {
    local helper="/Library/PrivilegedHelperTools/com.adamsiwiec.oniongate.helper"
    local singbox="/Library/PrivilegedHelperTools/oniongate-sing-box"
    local failed=0

    echo
    echo "==> Verifying the installed helper"
    if [[ -f "$helper" ]]; then
        ls -l "$helper"
    else
        echo "    missing $helper" >&2
        failed=1
    fi
    if [[ -f "$singbox" ]]; then
        ls -l "$singbox"
    else
        echo "    missing $singbox — TUN will still prompt" >&2
        failed=1
    fi
    if launchctl print system/com.adamsiwiec.oniongate.helper >/dev/null 2>&1; then
        echo "    launchd job is loaded"
    else
        echo "    helper is not loaded — postinstall failed or was skipped" >&2
        failed=1
    fi
    if [[ ! -d /Applications/OnionGate.app ]]; then
        echo "    /Applications/OnionGate.app is missing" >&2
        failed=1
    fi
    return "$failed"
}

if [[ "$UNINSTALL_ONLY" == "1" ]]; then
    uninstall
    exit $?
fi

pkg=""
if [[ "$SKIP_BUILD" != "1" ]]; then
    echo "==> Building a release .app + .pkg (no DMG — that step is unrelated and often fails locally)"
    # Same helper sidecar + tauri.release.conf.json path as `make downloads`,
    # but --bundles app only. `make build` also tries a DMG and dies there
    # even after OnionGate.app is already on disk.
    BUNDLES=app bash "$ROOT/scripts/build-release-local.sh"
fi

pkg="$(ls -t \
    "$ROOT"/src-tauri/target/release/bundle/pkg/OnionGate_*.pkg \
    "$ROOT"/src-tauri/target/*/release/bundle/pkg/OnionGate_*.pkg \
    2>/dev/null | head -1 || true)"
if [[ -z "$pkg" ]]; then
    echo "No local .pkg found. Run without --skip-build, or: make build && make macos-pkg" >&2
    exit 1
fi
echo "==> Using $pkg"

uninstall

echo
echo "==> Installing $pkg onto /"
# The GUI Installer.app is for walking the welcome/license panes. This path is
# the developer reinstall: one administrator prompt, same postinstall.
sudo /usr/sbin/installer -pkg "$pkg" -target /

if verify_live_install; then
    echo
    echo "OnionGate is installed. Open /Applications/OnionGate.app (not make start)."
    echo "Connect / Disconnect should not ask for a password. Harden toggles still may."
    echo
    echo "    PKG: $pkg"
    exit 0
fi

echo
echo "Install finished, but the helper or pinned sing-box is not live." >&2
echo "Check /var/log/install.log for 'OnionGate postinstall'." >&2
exit 1
