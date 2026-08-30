# Daemons

OnionGate has one privileged operating-system daemon: `oniongate-helper`.
Managed Tor, sing-box, and pluggable transports are **session processes**. They
start when you Connect and stop when you Disconnect or when `make dev` exits.
They are not installed as boot services.

This page is the developer and operator reference for the helper. The main
project README only points here.

## What the helper does

`oniongate-helper` is a root-owned service. The app talks to it over a local
socket (Unix) or named pipe (Windows). The client sends only a typed request —
never a shell command, path, or pf/nft text.

The helper will:

- answer a liveness check;
- enable or disable the kill switch and the transition network lock;
- harvest the macOS deny journal;
- stop a single allowed pid (root VPN daemons);
- quit an `.app` bundle: unload its launch jobs (`bootout`, not `disable`), then
  stop every process whose binary lives in that bundle;
- start and stop the sing-box TUN (macOS): the client sends only routing intent,
  and the helper regenerates the sing-box config itself, writes it root-owned,
  and execs the pinned root-owned sing-box — never a binary, config, or log path
  the client named;
- randomize the primary Wi-Fi MAC address (macOS): it draws the address from the
  system CSPRNG and forces a locally-administered, unicast value, so there is no
  path that assigns a real vendor OUI;
- power the primary Wi-Fi radio on or off (macOS), used by the Wi-Fi-off-at-boot
  auto re-enable.

The helper will not run arbitrary commands, weaken Tor, or stop OnionGate,
system, or editor/terminal processes. On Unix it accepts connections only from
the console user recorded at install (`--allow-uid`). On macOS a **signed**
helper also requires the peer's code signature (`com.adamsiwiec.oniongate` /
matching Team ID). Unsigned `make dev` builds stay UID-only. Install also
accepts the ad-hoc `OnionGate` identifier used by unsigned release apps, and
the `CFBundleIdentifier` in the enclosing `.app`.

Without the helper, those same actions fall back to an administrator prompt
each time.

## Helper-backed TUN needs both halves

A prompt-free TUN requires **two** things that only the `.pkg` installer
provides together: a provisioned helper **and** the pinned, root-owned copy of
sing-box the postinstall script places at a fixed path. The helper checks that
binary (and its directory) on every start and refuses it if it is a symlink,
not root-owned, or group/world-writable.

This has two practical consequences:

- A helper you installed **in-app before running the `.pkg`** has no pinned
  sing-box, so it has **no TUN capability**. OnionGate detects this and still
  uses the administrator prompt for TUN — it does not pretend the helper can do
  it.
- On **stop**, if a non-pinned sing-box from an older admin-prompt build is
  still running, the helper cannot match it (it only ever kills the process
  whose resolved executable is the pinned binary). OnionGate falls back to a
  single administrator approval to kill that leftover, rather than leaving a
  stray tunnel process behind.

## Start it with `make dev`

```bash
make dev
```

That builds `oniongate-helper` and `oniongate-cli`, then runs `oniongate-cli helper start`.
The first time — and whenever the helper binary changes — macOS/Linux/Windows
asks for administrator approval, copies the binary into the system helper
location, and starts the service. Later `make dev` runs skip the prompt if the
installed copy is already running and matches the just-built binary.

`make cleanup` / `oniongate stop` restore host network defaults. They do **not**
remove the helper. It stays installed across debug sessions.

## CLI

```bash
oniongate-cli helper status   # supported / installed / running
oniongate-cli helper start    # install or refresh, then start
oniongate-cli helper stop     # unload and delete the service
```

`status` exits `0` only when the helper is reachable. The same Install / Remove
controls are on **Settings → Background helper**.

## Where it lives

| Platform | Service | Binary |
| --- | --- | --- |
| macOS | `com.adamsiwiec.oniongate.helper` (`/Library/LaunchDaemons/…plist`) | `/Library/PrivilegedHelperTools/com.adamsiwiec.oniongate.helper` |
| Linux | `oniongate-helper.service` | `/usr/local/lib/oniongate/oniongate-helper` |
| Windows | `OnionGateHelper` | `C:\Program Files\OnionGate\oniongate-helper.exe` |

IPC: `/var/run/oniongate-helper.sock` on Unix, `\\.\pipe\oniongate-helper` on
Windows.

Development builds the helper next to the debug app
(`src-tauri/target/debug/oniongate-helper`). Release CI stages it as a Tauri
sidecar so the bundled app can install the same way. `make dev` does not add
the helper to `externalBin`.

## Check that it is up

```bash
oniongate-cli helper status
```

`running=true` means the socket/pipe is present. Kill on a VPN/app and
kill-switch changes then go through the helper instead of a password prompt.

If `running=false` after a cancelled prompt, run `oniongate-cli helper start` or
use Settings → Install.
