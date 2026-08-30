#!/bin/bash
# OnionGate uninstaller for macOS.
#
# Shipped inside the app as Contents/Resources/uninstall.command so it can be
# double-clicked, and usable directly from a source checkout.
#
# It removes everything OnionGate installs outside its own data directory:
# the privileged helper and its launch daemon, the pinned sing-box, the pf
# anchors, the connection filter, the boot network lock and Wi-Fi-off-at-boot
# daemons, the system SOCKS proxy settings, the /etc shell hooks, the app
# bundle, and the installer receipt.
#
# YOUR DATA IS KEPT BY DEFAULT. The application data directory holds permanent
# Onion Host site keys, which Tor owns and which cannot be regenerated. They are
# removed only when you pass --purge-data and confirm.
#
# Never prints keys, bridge lines, onion addresses, or process command lines.

set -uo pipefail

LABEL="com.adamsiwiec.oniongate.helper"
PKG_IDENTIFIER="com.adamsiwiec.oniongate"
HELPER_DEST="/Library/PrivilegedHelperTools/${LABEL}"
PLIST_DEST="/Library/LaunchDaemons/${LABEL}.plist"
SINGBOX_DEST="/Library/PrivilegedHelperTools/oniongate-sing-box"
HELPER_SOCKET="/var/run/oniongate-helper.sock"
APP="/Applications/OnionGate.app"
APP_EXECUTABLE="${APP}/Contents/MacOS/OnionGate"

KS_ANCHOR="com.apple/oniongate.ks"
LOCK_ANCHOR="com.apple/oniongate.lock"
LEGACY_KS_ANCHOR="tor.socks.gui"
LEGACY_LOCK_ANCHOR="tor.socks.gui.lock"
LEGACY_BARE_KS_ANCHOR="oniongate.ks"
LEGACY_BARE_LOCK_ANCHOR="oniongate.lock"

ETC_DIR="/etc/oniongate"
LEGACY_ETC_DIR="/etc/tor-socks-gui"
HOOK_MARKER_BEGIN="# >>> oniongate >>>"
HOOK_MARKER_END="# <<< oniongate <<<"
LEGACY_HOOK_MARKER_BEGIN="# >>> tor-socks-gui >>>"
LEGACY_HOOK_MARKER_END="# <<< tor-socks-gui <<<"

DATA_DIR_NAME="oniongate"
LEGACY_DATA_DIR_NAME="tor-socks-gui"

PURGE_DATA=0
ASSUME_YES=0

# Kept verbatim so the sudo and self-relocation re-execs carry the same flags.
ORIGINAL_ARGS=("$@")

failures=0

info() { printf '  %s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() {
    printf '  WARNING: %s\n' "$*" >&2
    failures=$((failures + 1))
}

usage() {
    cat <<'USAGE'
Usage: uninstall-oniongate.sh [--purge-data] [--yes] [--help]

  --purge-data  Also delete the OnionGate data directory. This destroys
                permanent Onion Host site keys, which cannot be recovered.
                Off by default; requires confirmation.
  --yes         Do not prompt. Only meaningful with --purge-data.
  --help        Show this message.

Without --purge-data your settings, logs, and onion keys are kept, so a
reinstall picks up exactly where you left off.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --purge-data) PURGE_DATA=1 ;;
        --yes | -y) ASSUME_YES=1 ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Self-relocation
# ---------------------------------------------------------------------------

# When launched as Contents/Resources/uninstall.command this script lives inside
# the bundle it is about to delete. Run from a copy instead of relying on the
# filesystem keeping an unlinked file readable.
SELF="$0"
case "$SELF" in
    "${APP}"/*)
        relocated="$(/usr/bin/mktemp -t oniongate-uninstall)" || {
            printf 'Could not stage the uninstaller.\n' >&2
            exit 1
        }
        if ! /bin/cp "$SELF" "$relocated"; then
            printf 'Could not stage the uninstaller.\n' >&2
            exit 1
        fi
        /bin/chmod 755 "$relocated"
        exec /bin/bash "$relocated" ${ORIGINAL_ARGS[@]+"${ORIGINAL_ARGS[@]}"}
        ;;
esac

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

# Resolve the human before elevating, so `sudo` does not make every user path
# point at root's home.
if [ "${SUDO_USER:-}" != "" ] && [ "${SUDO_USER}" != "root" ]; then
    TARGET_USER="$SUDO_USER"
elif [ "$(id -u)" -ne 0 ]; then
    TARGET_USER="$(id -un)"
else
    TARGET_USER="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || echo root)"
fi
TARGET_HOME="$(/usr/bin/dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}')"
[ -n "${TARGET_HOME:-}" ] || TARGET_HOME="/Users/${TARGET_USER}"

if [ "$(id -u)" -ne 0 ]; then
    printf 'OnionGate uninstaller needs administrator rights to remove its system components.\n'
    exec /usr/bin/sudo -p 'Password for %u: ' /bin/bash "$0" ${ORIGINAL_ARGS[@]+"${ORIGINAL_ARGS[@]}"}
fi

printf 'OnionGate uninstaller\n'
info "Acting for user: ${TARGET_USER}"
if [ "$PURGE_DATA" -eq 1 ]; then
    info "Mode: remove OnionGate AND delete its data directory"
else
    info "Mode: remove OnionGate, keep its data directory (settings and onion keys)"
fi

# ---------------------------------------------------------------------------
# Confirmation for the destructive path
# ---------------------------------------------------------------------------

if [ "$PURGE_DATA" -eq 1 ] && [ "$ASSUME_YES" -eq 0 ]; then
    cat <<'CONFIRM'

  --purge-data deletes the OnionGate data directory. That directory holds the
  private keys for any permanent Onion Host site you created. They are not
  backed up anywhere and cannot be regenerated: the .onion addresses derived
  from them are lost for good.

CONFIRM
    reply=""
    if [ -r /dev/tty ]; then
        printf '  Type DELETE to confirm, anything else to keep your data: '
        read -r reply < /dev/tty
    else
        warn "no terminal available to confirm; keeping your data"
    fi
    if [ "$reply" != "DELETE" ]; then
        PURGE_DATA=0
        info "Keeping the data directory."
    fi
fi

# ---------------------------------------------------------------------------
# 1. Quit the app
# ---------------------------------------------------------------------------

step "Quitting OnionGate"
if [ -x "$APP_EXECUTABLE" ] && /usr/bin/pgrep -f "^${APP_EXECUTABLE}$" >/dev/null 2>&1; then
    uid="$(/usr/bin/stat -f %u /dev/console 2>/dev/null || echo 0)"
    if [ "${uid:-0}" -gt 0 ] 2>/dev/null; then
        # A graceful quit lets the app run its own teardown, which restores
        # host network state through the journal rather than leaving it to us.
        /bin/launchctl asuser "$uid" /usr/bin/osascript \
            -e 'tell application "OnionGate" to quit' >/dev/null 2>&1 || true
    fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        /usr/bin/pgrep -f "^${APP_EXECUTABLE}$" >/dev/null 2>&1 || break
        sleep 1
    done
    /usr/bin/pkill -f "^${APP_EXECUTABLE}$" >/dev/null 2>&1 || true
    info "Stopped the app."
else
    info "Not running."
fi

# ---------------------------------------------------------------------------
# 1b. Connection filter (Network Extension)
# ---------------------------------------------------------------------------

FILTER_ID="com.adamsiwiec.oniongate.filter"
FILTER_CTL="${APP}/Contents/MacOS/oniongate-filter-ctl"
FILTER_DIR="/Library/Application Support/OnionGate/filter"

step "Deactivating the connection filter"
if [ -x "$FILTER_CTL" ]; then
    uid="$(/usr/bin/stat -f %u /dev/console 2>/dev/null || echo 0)"
    # Older filter-ctl waits up to three minutes for a System Settings prompt
    # that never appears on unsigned builds. Cap it so uninstall cannot hang.
    if [ "${uid:-0}" -gt 0 ] 2>/dev/null; then
        /usr/bin/perl -e 'alarm 8; exec @ARGV' -- \
            /bin/launchctl asuser "$uid" "$FILTER_CTL" deactivate >/dev/null 2>&1 || true
    else
        /usr/bin/perl -e 'alarm 8; exec @ARGV' -- \
            "$FILTER_CTL" deactivate >/dev/null 2>&1 || true
    fi
    info "Asked the filter to deactivate. Approve the prompt in System Settings if macOS shows one."
else
    info "Filter activator is not in this bundle."
fi
if [ -d "$FILTER_DIR" ]; then
    /bin/rm -rf "$FILTER_DIR" || warn "could not remove ${FILTER_DIR}"
    info "Removed filter heartbeat state."
fi

# ---------------------------------------------------------------------------
# 2. Privileged helper and launch daemon
# ---------------------------------------------------------------------------

step "Removing the privileged helper"
if [ -f "$PLIST_DEST" ] || [ -f "$HELPER_DEST" ]; then
    /bin/launchctl bootout system "$PLIST_DEST" >/dev/null 2>&1 || true
    /bin/launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true
    /bin/rm -f "$PLIST_DEST" || warn "could not remove the launch daemon"
    /bin/rm -f "$HELPER_DEST" || warn "could not remove the helper binary"
    /bin/rm -f "$HELPER_SOCKET" || true
    info "Removed the launch daemon and helper binary."
else
    info "Not installed."
fi

# ---------------------------------------------------------------------------
# 2b. Host hardening LaunchDaemons
# ---------------------------------------------------------------------------

WIFI_BOOT_LABEL="com.adamsiwiec.oniongate.wifi-off-at-boot"
WIFI_BOOT_PLIST="/Library/LaunchDaemons/${WIFI_BOOT_LABEL}.plist"
WIFI_BOOT_DIR="/Library/Application Support/OnionGate/wifi-off-at-boot"
BOOT_LOCK_LABEL="com.adamsiwiec.oniongate.boot-lock"
BOOT_LOCK_PLIST="/Library/LaunchDaemons/${BOOT_LOCK_LABEL}.plist"
BOOT_LOCK_DIR="/Library/Application Support/OnionGate/boot-lock"

step "Removing host-hardening daemons"
removed_harden=0
for plist in "$WIFI_BOOT_PLIST" "$BOOT_LOCK_PLIST"; do
    label="${plist##*/}"
    label="${label%.plist}"
    if [ -f "$plist" ]; then
        /bin/launchctl bootout "system/${label}" >/dev/null 2>&1 || true
        /bin/launchctl bootout system "$plist" >/dev/null 2>&1 || true
        /bin/rm -f "$plist" || warn "could not remove ${plist}"
        removed_harden=1
    fi
done
for dir in "$WIFI_BOOT_DIR" "$BOOT_LOCK_DIR"; do
    if [ -d "$dir" ]; then
        /bin/rm -rf "$dir" || warn "could not remove ${dir}"
        removed_harden=1
    fi
done
if [ "$removed_harden" -eq 1 ]; then
    info "Removed the boot network lock and Wi-Fi-off-at-boot jobs."
else
    info "Not installed."
fi

# Root-owned TUN config / filter heartbeat / leftover helper state. User data
# lives under ~/Library/Application Support/oniongate and is not touched here.
HELPER_SUPPORT="/Library/Application Support/OnionGate"
step "Removing helper support files"
if [ -d "$HELPER_SUPPORT" ]; then
    /bin/rm -rf "$HELPER_SUPPORT" || warn "could not remove ${HELPER_SUPPORT}"
    info "Removed ${HELPER_SUPPORT}."
else
    info "None."
fi

# ---------------------------------------------------------------------------
# 3. Pinned sing-box
# ---------------------------------------------------------------------------

step "Removing the pinned sing-box"
if [ -f "$SINGBOX_DEST" ]; then
    # Anything still routing through the tunnel must stop before the binary
    # goes, so no orphaned process keeps a TUN interface alive.
    /usr/bin/pkill -f "^${SINGBOX_DEST}" >/dev/null 2>&1 || true
    sleep 1
    /usr/bin/pkill -9 -f "^${SINGBOX_DEST}" >/dev/null 2>&1 || true
    /bin/rm -f "$SINGBOX_DEST" || warn "could not remove the pinned sing-box"
    info "Removed."
else
    info "Not installed."
fi

# ---------------------------------------------------------------------------
# 4. pf anchors
# ---------------------------------------------------------------------------

step "Flushing the pf anchors"
for anchor in "$KS_ANCHOR" "$LOCK_ANCHOR" "$LEGACY_KS_ANCHOR" "$LEGACY_LOCK_ANCHOR" \
    "$LEGACY_BARE_KS_ANCHOR" "$LEGACY_BARE_LOCK_ANCHOR"; do
    /sbin/pfctl -a "$anchor" -F all >/dev/null 2>&1 || true
done
if /sbin/pfctl -a "$KS_ANCHOR" -sr 2>/dev/null | /usr/bin/grep -q . \
    || /sbin/pfctl -a "$LEGACY_KS_ANCHOR" -sr 2>/dev/null | /usr/bin/grep -q .; then
    warn "the kill-switch anchor still holds rules; run: sudo pfctl -a ${KS_ANCHOR} -F all"
elif /sbin/pfctl -a "$LOCK_ANCHOR" -sr 2>/dev/null | /usr/bin/grep -q . \
    || /sbin/pfctl -a "$LEGACY_LOCK_ANCHOR" -sr 2>/dev/null | /usr/bin/grep -q .; then
    warn "the network-lock anchor still holds rules; run: sudo pfctl -a ${LOCK_ANCHOR} -F all"
else
    info "Both anchors are empty."
fi

# ---------------------------------------------------------------------------
# 5. System SOCKS proxy
# ---------------------------------------------------------------------------

step "Restoring the system SOCKS proxy"
restored=0
while IFS= read -r service; do
    case "$service" in
        "" | An\ asterisk*) continue ;;
        \**) service="${service#\*}" ;;
    esac
    proxy="$(/usr/sbin/networksetup -getsocksfirewallproxy "$service" 2>/dev/null)"
    # Only touch a service whose SOCKS proxy is OnionGate's. A proxy the user
    # configured for something else is none of our business.
    case "$proxy" in
        *"Server: 127.0.0.1"*) ;;
        *) continue ;;
    esac
    case "$proxy" in
        *"Port: 9050"*) ;;
        *) continue ;;
    esac
    if /usr/sbin/networksetup -setsocksfirewallproxystate "$service" off >/dev/null 2>&1; then
        restored=$((restored + 1))
    else
        warn "could not turn the SOCKS proxy off for a network service"
    fi
done <<EOF
$(/usr/sbin/networksetup -listallnetworkservices 2>/dev/null)
EOF
if [ "$restored" -gt 0 ]; then
    info "Turned the OnionGate SOCKS proxy off on ${restored} network service(s)."
else
    info "No network service was pointing at OnionGate."
fi

# ---------------------------------------------------------------------------
# 6. Shell hooks
# ---------------------------------------------------------------------------

# Removes only the marked block and the source lines OnionGate wrote, in place,
# so the file keeps its owner and mode.
strip_hook_block() {
    path="$1"
    [ -f "$path" ] || return 0
    /usr/bin/grep -q -e "$HOOK_MARKER_BEGIN" -e "$LEGACY_HOOK_MARKER_BEGIN" \
        -e "${ETC_DIR}/shell.sh" -e "${LEGACY_ETC_DIR}/shell.sh" \
        -e "oniongate/shell-hook.sh" -e "tor-socks-gui/shell-hook.sh" \
        "$path" 2>/dev/null || return 0

    tmp="$(/usr/bin/mktemp)" || {
        warn "could not stage a rewrite of a shell startup file"
        return 1
    }
    /usr/bin/awk \
        -v begin="$HOOK_MARKER_BEGIN" -v end="$HOOK_MARKER_END" \
        -v lbegin="$LEGACY_HOOK_MARKER_BEGIN" -v lend="$LEGACY_HOOK_MARKER_END" '
        index($0, begin) || index($0, lbegin) { skip = 1; next }
        index($0, end) || index($0, lend)     { skip = 0; next }
        skip { next }
        /oniongate\/shell-hook.sh/ { next }
        /tor-socks-gui\/shell-hook.sh/ { next }
        /\/etc\/oniongate\/shell.sh/ { next }
        /\/etc\/tor-socks-gui\/shell.sh/ { next }
        { print }
    ' "$path" > "$tmp" || {
        /bin/rm -f "$tmp"
        warn "could not rewrite a shell startup file"
        return 1
    }
    # Redirect into the original so owner, group, and mode survive.
    if /bin/cat "$tmp" > "$path"; then
        info "Cleaned ${path}."
    else
        warn "could not write ${path}"
    fi
    /bin/rm -f "$tmp"
}

step "Removing the shell hooks"
for rc in /etc/zshrc /etc/bashrc /etc/profile.d/oniongate.sh /etc/profile.d/tor-socks-gui.sh; do
    strip_hook_block "$rc"
done
for rc in "${TARGET_HOME}/.zshrc" "${TARGET_HOME}/.bashrc" "${TARGET_HOME}/.bash_profile"; do
    strip_hook_block "$rc"
done
for dir in "$ETC_DIR" "$LEGACY_ETC_DIR"; do
    if [ -d "$dir" ]; then
        /bin/rm -rf "$dir" || warn "could not remove ${dir}"
        info "Removed ${dir}."
    fi
done
/bin/rm -f /etc/profile.d/oniongate.sh /etc/profile.d/tor-socks-gui.sh 2>/dev/null || true

# ---------------------------------------------------------------------------
# 7. Application bundle and receipt
# ---------------------------------------------------------------------------

step "Removing the application"
if [ -d "$APP" ]; then
    /bin/rm -rf "$APP" || warn "could not remove ${APP}"
    info "Removed ${APP}."
else
    info "Not present in /Applications."
fi

step "Forgetting the installer receipt"
if /usr/sbin/pkgutil --pkg-info "$PKG_IDENTIFIER" >/dev/null 2>&1; then
    /usr/sbin/pkgutil --forget "$PKG_IDENTIFIER" >/dev/null 2>&1 ||
        warn "could not forget the installer receipt"
    info "Forgotten."
else
    info "No receipt (this was not a .pkg install)."
fi

# ---------------------------------------------------------------------------
# 8. User data — kept unless explicitly purged
# ---------------------------------------------------------------------------

DATA_DIR="${TARGET_HOME}/Library/Application Support/${DATA_DIR_NAME}"
LEGACY_DATA_DIR="${TARGET_HOME}/Library/Application Support/${LEGACY_DATA_DIR_NAME}"
DOT_DIR="${TARGET_HOME}/.${DATA_DIR_NAME}"
LEGACY_DOT_DIR="${TARGET_HOME}/.${LEGACY_DATA_DIR_NAME}"

step "Application data"
if [ "$PURGE_DATA" -eq 1 ]; then
    for dir in "$DATA_DIR" "$LEGACY_DATA_DIR" "$DOT_DIR" "$LEGACY_DOT_DIR"; do
        if [ -d "$dir" ]; then
            /bin/rm -rf "$dir" || warn "could not remove a data directory"
            info "Deleted ${dir}."
        fi
    done
else
    kept=0
    for dir in "$DATA_DIR" "$LEGACY_DATA_DIR" "$DOT_DIR" "$LEGACY_DOT_DIR"; do
        [ -d "$dir" ] && kept=1
    done
    if [ "$kept" -eq 1 ]; then
        info "Kept ${DATA_DIR}"
        info "Settings, logs, and permanent Onion Host keys are still there."
        info "Re-run with --purge-data to delete them."
    else
        info "Nothing stored."
    fi
fi

# ---------------------------------------------------------------------------

if [ "$failures" -eq 0 ]; then
    printf '\nOnionGate has been removed.\n'
    exit 0
fi

printf '\nOnionGate has been removed, with %s warning(s) above.\n' "$failures"
exit 1
