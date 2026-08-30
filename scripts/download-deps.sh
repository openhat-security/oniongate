#!/usr/bin/env bash
# Download Tor (expert bundle), pluggable transports, and sing-box into
# src-tauri/ for bundling with the app. Users of a release build do not need brew.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_TAURI="$ROOT/src-tauri"
BIN_DIR="$SRC_TAURI/binaries"
RUNTIME_DIR="$SRC_TAURI/resources/runtime"
LICENSES_DIR="$SRC_TAURI/resources/licenses"
CACHE_DIR="${TOR_SOCKS_DEPS_CACHE:-$ROOT/.deps-cache}"

TOR_BROWSER_VERSION="${TOR_BROWSER_VERSION:-15.0.20}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.13.14}"
HASH_MANIFEST="$ROOT/scripts/dependencies.sha256"

mkdir -p "$BIN_DIR" "$RUNTIME_DIR" "$LICENSES_DIR" "$CACHE_DIR"

host_triple() {
  if command -v rustc >/dev/null 2>&1; then
    rustc -vV | sed -n 's/^host: //p'
    return
  fi
  local arch os
  arch="$(uname -m)"
  os="$(uname -s)"
  case "$os-$arch" in
    Darwin-arm64) echo "aarch64-apple-darwin" ;;
    Darwin-x86_64) echo "x86_64-apple-darwin" ;;
    Linux-x86_64) echo "x86_64-unknown-linux-gnu" ;;
    Linux-aarch64|Linux-arm64) echo "aarch64-unknown-linux-gnu" ;;
    MINGW64_NT*-x86_64|MSYS_NT*-x86_64) echo "x86_64-pc-windows-msvc" ;;
    *) echo "unsupported"; return 1 ;;
  esac
}

TRIPLE="$(host_triple)"
echo "==> Host triple: $TRIPLE"

case "$TRIPLE" in
  aarch64-apple-darwin)
    TOR_OS=macos; TOR_ARCH=aarch64
    SING_ASSET="sing-box-${SINGBOX_VERSION}-darwin-arm64.tar.gz"
    ;;
  x86_64-apple-darwin)
    TOR_OS=macos; TOR_ARCH=x86_64
    SING_ASSET="sing-box-${SINGBOX_VERSION}-darwin-amd64.tar.gz"
    ;;
  x86_64-unknown-linux-gnu)
    TOR_OS=linux; TOR_ARCH=x86_64
    SING_ASSET="sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz"
    ;;
  aarch64-unknown-linux-gnu)
    # Tor Browser expert bundle has no linux-aarch64 package as of 15.0.x.
    if [[ "${ALLOW_MISSING_TOR:-}" != "1" ]]; then
      echo "ERROR: Tor expert bundle is not published for linux-aarch64."
      echo "       Build on x86_64 Linux/macOS, or set ALLOW_MISSING_TOR=1 to fetch sing-box only."
      exit 1
    fi
    TOR_OS=linux; TOR_ARCH=""
    SING_ASSET="sing-box-${SINGBOX_VERSION}-linux-arm64.tar.gz"
    echo "WARN: Skipping Tor; only sing-box will be fetched (ALLOW_MISSING_TOR=1)."
    ;;
  x86_64-pc-windows-msvc)
    TOR_OS=windows; TOR_ARCH=x86_64
    SING_ASSET="sing-box-${SINGBOX_VERSION}-windows-amd64.zip"
    EXE=".exe"
    ;;
  *)
    echo "Unsupported host triple: $TRIPLE"
    exit 1
    ;;
esac

download() {
  local url="$1" dest="$2"
  if [[ -f "$dest" ]]; then
    echo "    cached $(basename "$dest")"
    return
  fi
  echo "    downloading $url"
  curl -fsSL --retry 3 -o "$dest.partial" "$url"
  mv "$dest.partial" "$dest"
}

verify_archive() {
  local archive="$1" name expected actual
  name="$(basename "$archive")"
  if [[ ! -f "$HASH_MANIFEST" ]]; then
    echo "ERROR: dependency hash manifest missing: $HASH_MANIFEST"
    exit 1
  fi
  expected="$(awk -v n="$name" '$2 == n { print $1 }' "$HASH_MANIFEST")"
  if [[ -z "$expected" ]]; then
    echo "ERROR: no pinned SHA-256 for $name"
    exit 1
  fi
  if command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
  else
    actual="$(sha256sum "$archive" | awk '{print $1}')"
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "ERROR: SHA-256 mismatch for $name"
    echo "       expected $expected"
    echo "       actual   $actual"
    rm -f "$archive"
    exit 1
  fi
  echo "    verified SHA-256 $name"
}

stage_sidecar() {
  # Copy executable to binaries/<name>-<triple> for Tauri externalBin.
  local src="$1" name="$2"
  local ext="${EXE:-}"
  local dest="$BIN_DIR/${name}-${TRIPLE}${ext}"
  cp -f "$src" "$dest"
  chmod +x "$dest"
  # Convenience copy without triple for local cargo runs / find_binary.
  cp -f "$src" "$BIN_DIR/${name}${ext}"
  chmod +x "$BIN_DIR/${name}${ext}"
  echo "    staged $name"
}

# --- Tor expert bundle -------------------------------------------------------
rm -rf "$RUNTIME_DIR/tor" "$RUNTIME_DIR/data" "$RUNTIME_DIR/docs"
mkdir -p "$RUNTIME_DIR"

if [[ -n "${TOR_ARCH}" ]]; then
  TOR_TGZ="tor-expert-bundle-${TOR_OS}-${TOR_ARCH}-${TOR_BROWSER_VERSION}.tar.gz"
  TOR_URL="https://dist.torproject.org/torbrowser/${TOR_BROWSER_VERSION}/${TOR_TGZ}"
  TOR_CACHE="$CACHE_DIR/$TOR_TGZ"
  echo "==> Tor expert bundle ${TOR_BROWSER_VERSION} (${TOR_OS}-${TOR_ARCH})"
  download "$TOR_URL" "$TOR_CACHE"
  verify_archive "$TOR_CACHE"
  tar -xzf "$TOR_CACHE" -C "$RUNTIME_DIR"
  # Expected layout: runtime/tor/tor, runtime/tor/pluggable_transports/*, runtime/data/geoip*
  if [[ ! -x "$RUNTIME_DIR/tor/tor${EXE:-}" ]]; then
    echo "ERROR: tor binary missing after extract"
    exit 1
  fi
  stage_sidecar "$RUNTIME_DIR/tor/tor${EXE:-}" "tor"
  if [[ -x "$RUNTIME_DIR/tor/pluggable_transports/lyrebird${EXE:-}" ]]; then
    stage_sidecar "$RUNTIME_DIR/tor/pluggable_transports/lyrebird${EXE:-}" "lyrebird"
    # Alias for code that looks for obfs4proxy
    cp -f "$BIN_DIR/lyrebird-${TRIPLE}${EXE:-}" "$BIN_DIR/obfs4proxy-${TRIPLE}${EXE:-}"
    cp -f "$BIN_DIR/lyrebird${EXE:-}" "$BIN_DIR/obfs4proxy${EXE:-}"
    chmod +x "$BIN_DIR/obfs4proxy-${TRIPLE}${EXE:-}" "$BIN_DIR/obfs4proxy${EXE:-}"
  fi
  if [[ -x "$RUNTIME_DIR/tor/pluggable_transports/conjure-client${EXE:-}" ]]; then
    stage_sidecar "$RUNTIME_DIR/tor/pluggable_transports/conjure-client${EXE:-}" "conjure-client"
  fi
  # Tor Browser's pt_config registers Snowflake through the bundled lyrebird.
  if [[ ! -x "$RUNTIME_DIR/tor/pluggable_transports/snowflake-client" ]]; then
    echo "==> Snowflake provided by verified Tor expert-bundle lyrebird"
  else
    stage_sidecar "$RUNTIME_DIR/tor/pluggable_transports/snowflake-client" "snowflake-client"
  fi
else
  echo "==> Skipping Tor expert bundle (unsupported arch)"
  # externalBin still expects these names on supported CI — create markers only when allowed.
  if [[ "${ALLOW_MISSING_TOR:-}" == "1" ]]; then
    echo "WARN: Not staging tor/lyrebird sidecars"
  fi
fi

# Ensure required sidecars exist for Tauri externalBin (supported hosts).
if [[ -n "${TOR_ARCH}" ]]; then
  for req in tor lyrebird obfs4proxy; do
    if [[ ! -f "$BIN_DIR/${req}-${TRIPLE}${EXE:-}" ]]; then
      echo "ERROR: missing required sidecar $BIN_DIR/${req}-${TRIPLE}${EXE:-}"
      exit 1
    fi
  done
fi

# --- sing-box ----------------------------------------------------------------
SING_URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${SING_ASSET}"
SING_CACHE="$CACHE_DIR/$SING_ASSET"
echo "==> sing-box v${SINGBOX_VERSION}"
download "$SING_URL" "$SING_CACHE"
verify_archive "$SING_CACHE"
SING_EXTRACT="$CACHE_DIR/sing-box-extract-$$"
rm -rf "$SING_EXTRACT"
mkdir -p "$SING_EXTRACT"
if [[ "$SING_ASSET" == *.zip ]]; then
  unzip -q "$SING_CACHE" -d "$SING_EXTRACT"
else
  tar -xzf "$SING_CACHE" -C "$SING_EXTRACT"
fi
SING_BIN="$(find "$SING_EXTRACT" -type f -name "sing-box${EXE:-}" -print -quit)"
if [[ -z "$SING_BIN" ]]; then
  echo "ERROR: sing-box binary not found in archive"
  exit 1
fi
mkdir -p "$RUNTIME_DIR/bin"
cp -f "$SING_BIN" "$RUNTIME_DIR/bin/sing-box${EXE:-}"
chmod +x "$RUNTIME_DIR/bin/sing-box${EXE:-}"
stage_sidecar "$RUNTIME_DIR/bin/sing-box${EXE:-}" "sing-box"
rm -rf "$SING_EXTRACT"

# --- License notices ---------------------------------------------------------
cat > "$LICENSES_DIR/THIRD_PARTY.md" <<EOF
# Third-party runtimes bundled with OnionGate

This application may bundle the following third-party programs. Their licenses
apply to those components; see upstream projects for full terms and source.

## Tor (Classic) and pluggable transports

- Source / downloads: https://www.torproject.org/ / https://dist.torproject.org/
- Expert bundle version used by \`scripts/download-deps.sh\`: ${TOR_BROWSER_VERSION}
- License: Tor is typically distributed under a BSD-style license; pluggable
  transports (lyrebird, conjure, etc.) have their own licenses in the expert
  bundle \`docs/\` folder (copied under \`resources/runtime/docs/\` when present).

## sing-box

- Source: https://github.com/SagerNet/sing-box
- Version: ${SINGBOX_VERSION}
- License: **GPL-3.0-or-later**
- Corresponding source: https://github.com/SagerNet/sing-box/tree/v${SINGBOX_VERSION}

When redistributing this app with sing-box included, you must provide the
sing-box license text and offer access to the corresponding source (the link
above to the exact tag is sufficient for unmodified upstream binaries).
EOF

if [[ -d "$RUNTIME_DIR/docs" ]]; then
  cp -f "$RUNTIME_DIR/docs/"*.txt "$LICENSES_DIR/" 2>/dev/null || true
fi

# Placeholder so empty binaries/ is never committed without a readme
cat > "$BIN_DIR/README.md" <<EOF
# Bundled binaries

Populated by \`scripts/download-deps.sh\`.

Tauri \`externalBin\` expects names like:

- \`tor-${TRIPLE}\`
- \`sing-box-${TRIPLE}\`
- \`lyrebird-${TRIPLE}\`
- \`obfs4proxy-${TRIPLE}\` (alias of lyrebird)
- \`conjure-client-${TRIPLE}\` (when present)

Do not commit large binaries; CI/release builders run the download script.
EOF

# Copy Tor's colocated dylibs next to the sidecar so @executable_path resolves
# when Tauri launches binaries/tor-<triple>.
if [[ "$(uname -s)" == "Darwin" && -d "$RUNTIME_DIR/tor" ]]; then
  find "$RUNTIME_DIR/tor" -maxdepth 1 -name '*.dylib' -exec cp -f {} "$BIN_DIR/" \;
fi

# macOS: clear quarantine and ad-hoc sign so Gatekeeper/dyld accept local copies.
if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "==> Clearing quarantine + ad-hoc codesign (macOS)"
  xattr -cr "$RUNTIME_DIR" "$BIN_DIR" 2>/dev/null || true
  # Sign dylibs first, then known executables.
  find "$RUNTIME_DIR" "$BIN_DIR" -name '*.dylib' -exec codesign --force --sign - {} \;
  find "$RUNTIME_DIR" "$BIN_DIR" -type f \( \
      -name 'tor' -o -name 'tor-*' \
      -o -name 'sing-box' -o -name 'sing-box-*' \
      -o -name 'lyrebird' -o -name 'lyrebird-*' \
      -o -name 'obfs4proxy' -o -name 'obfs4proxy-*' \
      -o -name 'conjure-client' -o -name 'conjure-client-*' \
      -o -name 'snowflake-client' -o -name 'snowflake-client-*' \
    \) -exec codesign --force --sign - {} \;
fi

echo "==> Done"
echo "    runtime: $RUNTIME_DIR"
echo "    sidecars: $BIN_DIR"
echo "    licenses: $LICENSES_DIR"
ls -la "$BIN_DIR" | sed 's/^/    /'
