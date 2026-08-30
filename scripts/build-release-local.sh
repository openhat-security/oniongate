#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

target="$(rustc -vV | awk '/^host:/{print $2}')"
extension=""
if [[ "$target" == *windows* ]]; then extension=".exe"; fi
# BUNDLES=app skips the macOS DMG. create-dmg / hdiutil often fail in a
# local terminal and the .pkg does not need that image.
if [[ -z "${BUNDLES:-}" ]]; then
  case "$target" in
    *apple-darwin) bundles="app,dmg" ;;
    *windows*) bundles="nsis" ;;
    *linux*) bundles="appimage,deb,rpm" ;;
    *)
      echo "Unsupported release host: $target" >&2
      exit 1
      ;;
  esac
else
  bundles="$BUNDLES"
fi

echo "==> Building unsigned local release bundle for $target"
npm run deps
cargo build \
  --manifest-path src-tauri/Cargo.toml \
  --release \
  --bin oniongate-helper \
  --target "$target"

source_path="src-tauri/target/$target/release/oniongate-helper$extension"
destination="src-tauri/binaries/oniongate-helper-$target$extension"
test -f "$source_path"
cp "$source_path" "$destination"
if [[ "$target" != *windows* ]]; then chmod 755 "$destination"; fi

CI=true npm run tauri -- build \
  --target "$target" \
  --bundles "$bundles" \
  --config src-tauri/tauri.release.conf.json \
  --no-sign

if [[ "$target" == *apple-darwin ]]; then
  app_bundle="$(printf '%s\n' src-tauri/target/"$target"/release/bundle/macos/*.app | head -n 1)"
  test -x "$app_bundle/Contents/MacOS/oniongate-helper"
  test -x "$app_bundle/Contents/MacOS/OnionGate"
  # `oniongate` is not a second file on macOS: APFS treats it as OnionGate.
  # The CLI cargo bin is oniongate-cli so it cannot overwrite the GUI.

  # Tauri has no pkg target, so the installer is a post-bundle step. Keep this
  # in step with the release workflow so `make downloads` matches CI.
  bash scripts/build-macos-pkg.sh --app "$app_bundle" --target "$target"
fi

echo "==> Local release bundle verified (unsigned)"
case "$target" in
  *apple-darwin)
    printf '    PKG: %s\n' src-tauri/target/"$target"/release/bundle/pkg/*.pkg
    printf '    DMG: %s\n' src-tauri/target/"$target"/release/bundle/dmg/*.dmg
    ;;
  *windows*)
    printf '    EXE: %s\n' src-tauri/target/"$target"/release/bundle/nsis/*.exe
    ;;
  *linux*)
    printf '    AppImage: %s\n' src-tauri/target/"$target"/release/bundle/appimage/*.AppImage
    printf '    DEB: %s\n' src-tauri/target/"$target"/release/bundle/deb/*.deb
    printf '    RPM: %s\n' src-tauri/target/"$target"/release/bundle/rpm/*.rpm
    ;;
esac
