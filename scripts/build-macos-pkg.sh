#!/usr/bin/env bash
# Build the macOS .pkg installer from an already-bundled OnionGate.app.
#
# Tauri 2 has no pkg bundle target, so this runs after `tauri build --bundles
# app,dmg` in both CI and `make downloads`. The .pkg is the primary macOS
# download: its payload is not quarantined, and its postinstall script installs
# the privileged helper as root so the app is prompt-free from first launch.
#
# Works unsigned. Signing is a later addition: pass PKG_SIGNING_IDENTITY once a
# Developer ID Installer certificate exists.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PKG_DIR="scripts/macos-pkg"
IDENTIFIER="com.adamsiwiec.oniongate"
INSTALL_LOCATION="/Applications"
LICENSE_SOURCE="src-tauri/resources/licenses/GPL-3.0.txt"

app=""
target=""
version=""
output_dir=""

usage() {
    cat <<'USAGE'
Usage: build-macos-pkg.sh [options]

  --app PATH           Built OnionGate.app (default: the bundle for --target)
  --target TRIPLE      Rust target triple (default: the rustc host)
  --version VERSION    Package version (default: src-tauri/tauri.conf.json)
  --output-dir DIR     Where to write the .pkg (default: next to the bundle)
  --help               Show this message

Set PKG_SIGNING_IDENTITY to sign with a Developer ID Installer certificate.
USAGE
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --app) app="$2"; shift 2 ;;
        --target) target="$2"; shift 2 ;;
        --version) version="$2"; shift 2 ;;
        --output-dir) output_dir="$2"; shift 2 ;;
        --help | -h) usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "build-macos-pkg.sh only runs on macOS" >&2
    exit 1
fi

if [[ -z "$target" ]]; then
    target="$(rustc -vV | awk '/^host:/{print $2}')"
fi
case "$target" in
    aarch64-apple-darwin) host_architectures="arm64"; arch_label="aarch64" ;;
    x86_64-apple-darwin) host_architectures="x86_64"; arch_label="x64" ;;
    *)
        echo "Not a macOS target: $target" >&2
        exit 1
        ;;
esac

if [[ -z "$version" ]]; then
    # plutil reads JSON and ships with macOS, so this works before npm install.
    version="$(plutil -extract version raw -o - src-tauri/tauri.conf.json)"
fi
if [[ -z "$version" ]]; then
    echo "Could not resolve the version" >&2
    exit 1
fi

bundle_root="src-tauri/target/$target/release/bundle"
host_bundle_root="src-tauri/target/release/bundle"
if [[ -z "$app" ]]; then
    # `tauri build` without --target writes to target/release/bundle.
    # A cross-triple build writes to target/<triple>/release/bundle.
    # Prefer a bundle that already has the OnionGate GUI binary.
    candidates=()
    for root in "$host_bundle_root" "$bundle_root"; do
        for candidate in "$root"/macos/*.app; do
            [[ -d "$candidate" ]] && candidates+=("$candidate")
        done
    done
    for candidate in "${candidates[@]+"${candidates[@]}"}"; do
        if [[ -x "$candidate/Contents/MacOS/OnionGate" ]]; then
            app="$candidate"
            bundle_root="$(cd "$(dirname "$candidate")/.." && pwd)"
            break
        fi
    done
    if [[ -z "$app" && ${#candidates[@]} -gt 0 ]]; then
        app="${candidates[0]}"
        bundle_root="$(cd "$(dirname "$app")/.." && pwd)"
    fi
fi
if [[ ! -d "$app" ]]; then
    echo "No .app bundle found under $host_bundle_root/macos or $bundle_root/macos." >&2
    echo "Run the Tauri build first (make build)." >&2
    exit 1
fi

if [[ -z "$output_dir" ]]; then
    output_dir="$bundle_root/pkg"
fi
mkdir -p "$output_dir"
output="$output_dir/OnionGate_${version}_${arch_label}.pkg"

work="$(mktemp -d "${TMPDIR:-/tmp}/oniongate-pkg.XXXXXX")"
trap 'rm -rf "$work"' EXIT
payload="$work/payload"
mkdir -p "$payload" "$work/component" "$work/resources"

echo "==> Staging $app"
# ditto preserves symlinks, resource forks, and the executable bits that a
# recursive cp would flatten.
ditto "$app" "$payload/OnionGate.app"

macos_dir="$payload/OnionGate.app/Contents/MacOS"
if [[ ! -x "$macos_dir/OnionGate" ]]; then
    echo "This .app has no GUI binary at Contents/MacOS/OnionGate." >&2
    if [[ -x "$macos_dir/tor-socks-gui" ]]; then
        echo "It still ships the pre-rename host (tor-socks-gui). Rebuild the app:" >&2
        echo "    make build && make macos-pkg-install" >&2
    else
        echo "Contents/MacOS contains:" >&2
        ls -1 "$macos_dir" >&2 || true
    fi
    exit 1
fi
if [[ ! -x "$macos_dir/oniongate-helper" ]]; then
    echo "This .app has no helper at Contents/MacOS/oniongate-helper." >&2
    exit 1
fi
# APFS is case-insensitive: a cargo bin named `oniongate` overwrites `OnionGate`
# and the .app "opens" as the CLI (prints status, exits). Refuse that payload.
if grep -a -q "headless companion for Tor routing" "$macos_dir/OnionGate"; then
    echo "Contents/MacOS/OnionGate is the CLI, not the GUI." >&2
    echo "The cargo bins OnionGate and oniongate collide on macOS. The CLI bin must be oniongate-cli." >&2
    exit 1
fi

# An unsigned / ad-hoc bundle cannot load a Network Extension. Embedding one
# still makes LaunchServices scan the sysex on open and lets filter-ctl wait
# up to three minutes on activate/deactivate — the app looks dead and Quit
# beachballs the Mac. Only signed trees (or EMBED_FILTER=1) ship it.
if [[ -n "${PKG_SIGNING_IDENTITY:-}" || -n "${APPLE_SIGNING_IDENTITY:-}" || "${EMBED_FILTER:-}" == "1" ]]; then
    echo "==> Embedding the connection filter"
    if make -C macos/OnionGateFilter; then
        bash scripts/embed-oniongate-filter.sh "$payload/OnionGate.app"
    else
        echo "    Swift filter did not compile; the .pkg stays on pf + egress watch."
    fi
else
    echo "==> Skipping the connection filter (unsigned local .pkg stays on pf)"
    echo "    Set EMBED_FILTER=1 or a Developer ID identity to ship it."
fi

# The uninstaller ships inside the bundle so it is double-clickable from
# Finder. The .app that Tauri builds does not carry it, so inject it here.
# Ensure Resources exists: some CI targets have omitted it and `install`
# then fails with set -e before pkgbuild.
mkdir -p "$payload/OnionGate.app/Contents/Resources"
install -m 0755 "$PKG_DIR/uninstall-oniongate.sh" \
    "$payload/OnionGate.app/Contents/Resources/uninstall.command"

# Linker-signed executables inside an unsigned .app make LaunchServices refuse
# to open it ("code has no resources but signature indicates they must be
# present"). Ad-hoc sign the staged bundle so a local .pkg can `open`.
# `TeamIdentifier=not set` is the linker stub, not a Developer ID.
# codesign -dv can exit non-zero while still printing TeamIdentifier; do not
# let pipefail abort the .pkg build on GitHub's Intel runners.
team="$(
    { codesign -dv --verbose=4 "$payload/OnionGate.app" 2>&1 || true; } |
        awk -F= '/^TeamIdentifier=/{print $2; exit}'
)"
if [[ -z "$team" || "$team" == "not set" ]]; then
    echo "==> Ad-hoc codesigning the staged app (no Developer ID on this build)"
    codesign --force --deep --sign - "$payload/OnionGate.app"
fi

for script in preinstall postinstall; do
    if [[ ! -x "$PKG_DIR/scripts/$script" ]]; then
        echo "$PKG_DIR/scripts/$script is not executable" >&2
        exit 1
    fi
done

echo "==> pkgbuild ($IDENTIFIER $version)"
component_plist="$work/component/OnionGate.plist"
pkgbuild --analyze --root "$payload" "$component_plist" >/dev/null
# Relocatable is the pkgbuild default: it would install over a copy of
# OnionGate.app found anywhere on disk. The postinstall script and the helper
# both assume /Applications, so pin it.
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$component_plist"

pkgbuild \
    --root "$payload" \
    --component-plist "$component_plist" \
    --identifier "$IDENTIFIER" \
    --version "$version" \
    --scripts "$PKG_DIR/scripts" \
    --install-location "$INSTALL_LOCATION" \
    "$work/OnionGate.pkg"

echo "==> productbuild"
test -f "$LICENSE_SOURCE"
install -m 0644 "$LICENSE_SOURCE" "$work/resources/LICENSE.txt"
install -m 0644 "$PKG_DIR/welcome.html" "$work/resources/welcome.html"
install -m 0644 "$PKG_DIR/conclusion.html" "$work/resources/conclusion.html"

distribution="$work/distribution.xml"
sed \
    -e "s/__HOST_ARCHITECTURES__/$host_architectures/g" \
    -e "s/__VERSION__/$version/g" \
    "$PKG_DIR/distribution.xml" > "$distribution"

productbuild_args=(
    --distribution "$distribution"
    --package-path "$work"
    --resources "$work/resources"
)
if [[ -n "${PKG_SIGNING_IDENTITY:-}" ]]; then
    productbuild_args+=(--sign "$PKG_SIGNING_IDENTITY")
else
    echo "    (unsigned: set PKG_SIGNING_IDENTITY to sign)"
fi
productbuild "${productbuild_args[@]}" "$output"

echo "==> Verifying"
test -f "$output"
# A payload without these is a silently broken installer: the app would still
# install, but Connect would run the old host or have no helper/uninstaller.
payload_files="$(pkgutil --payload-files "$work/OnionGate.pkg")"
require_payload() {
    local path="$1"
    if ! printf '%s\n' "$payload_files" | grep -qx "$path"; then
        echo "Package payload is missing $path" >&2
        echo "$payload_files" | grep -E 'MacOS/|uninstall' >&2 || true
        exit 1
    fi
}
require_payload './OnionGate.app/Contents/MacOS/OnionGate'
require_payload './OnionGate.app/Contents/MacOS/oniongate-helper'
require_payload './OnionGate.app/Contents/Resources/uninstall.command'

echo "==> macOS installer package built"
printf '    PKG: %s\n' "$output"
