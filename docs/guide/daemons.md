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
  stop every process whose binary lives in that bundle.

The helper will not run arbitrary commands, weaken Tor, or stop OnionGate,
system, or editor/terminal processes. On Unix it accepts connections only from
the console user recorded at install (`--allow-uid`). On macOS a **signed**
helper also requires the peer's code signature (`com.adamsiwiec.oniongate` /
matching Team ID). Unsigned `make dev` builds stay UID-only.

Without the helper, those same actions fall back to an administrator prompt
each time.

## Start it with `make dev`

```bash
make dev
```

That builds `oniongate-helper` and `oniongate`, then runs `oniongate helper start`.
The first time — and whenever the helper binary changes — macOS/Linux/Windows
asks for administrator approval, copies the binary into the system helper
location, and starts the service. Later `make dev` runs skip the prompt if the
installed copy is already running and matches the just-built binary.

`make cleanup` / `oniongate stop` restore host network defaults. They do **not**
remove the helper. It stays installed across debug sessions.

## CLI

```bash
oniongate helper status   # supported / installed / running
oniongate helper start    # install or refresh, then start
oniongate helper stop     # unload and delete the service
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
oniongate helper status
```

`running=true` means the socket/pipe is present. Kill on a VPN/app and
kill-switch changes then go through the helper instead of a password prompt.

If `running=false` after a cancelled prompt, run `oniongate helper start` or
use Settings → Install.
