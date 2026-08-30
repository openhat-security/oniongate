# Command line

`oniongate-cli` is the headless companion for servers, scripts, and automation. It
links the same Rust core used by the desktop app. `start` calls the same
bring-up path as Connect: managed Tor, then OS SOCKS or TUN, then the requested
kill switch. The journal is **Protected** only after those live components
verify. Known SOCKS-ignoring apps still keep proxy mode **Degraded** unless
the NIC lock is on.

Exit codes: `0` success, `1` runtime failure, `2` usage error.

```bash
oniongate-cli --help
oniongate-cli host --help
```

The compiled binary is `oniongate-cli`. It cannot be named `oniongate` next to
the GUI `OnionGate` — macOS treats those as the same file. Subcommands are
unchanged.

## Connection

```bash
oniongate-cli status     # connection, bootstrap, and recovery state
oniongate-cli start      # same protected-session bring-up as the desktop app
oniongate-cli stop       # best-effort cleanup from journal + live process discovery
oniongate-cli emergency-restore  # restore host defaults; do not leave a leftover lock
oniongate-cli newnym                 # request a new Tor identity
oniongate-cli newnym --kill-clearnet # terminate clearnet processes, then NEWNYM
oniongate-cli bridges    # list configured bridge lines
oniongate-cli settings   # print settings as JSON
oniongate-cli helper status   # privileged helper installed / running
oniongate-cli helper start    # install or refresh the helper
oniongate-cli helper stop     # remove the helper
```

`helper start` is what `make dev` runs after building the daemon. See
[Daemons](/guide/daemons).

`status` with no subcommand is the default, so bare `oniongate-cli` prints status.
Read the individual `socks_up`, `control_up`, `dns_up`, connection-mode, and
recovery fields; the phase alone is insufficient.

`stop` starts in a new process with no GUI-owned child handles. It uses the
recovery journal plus live process/port/firewall/proxy discovery, so inspect its
output and run `status` afterward. A cleanup error means state may remain.
`make cleanup` is the same restore path used when `make dev` exits.

`newnym --kill-clearnet` samples live sockets, terminates processes that currently
have public Internet flows not through OnionGate (skipping OnionGate, Tor,
editor/terminal, and core OS processes), then sends `NEWNYM`. It does not
restart OnionGate. Only PIDs from that census are killed; the flag never takes
a pid list.

If `status` reports `recovery_needed=true`, run `oniongate-cli emergency-restore`
or `oniongate-cli stop`, then confirm every affected platform component with
`status` before continuing.

::: warning `bridges` and `settings` can print sensitive local data
Bridge lines, selected application paths, and routing preferences may appear on
stdout. Do not paste their output into public issues or shared CI logs.
:::

Output is `key=value` lines, which keeps it greppable:

```bash
oniongate-cli status | grep '^socks_up='
```

Status fields:

| Field | Meaning |
| --- | --- |
| `tor_installed` | A bundled or system Tor binary was found |
| `socks_up`, `control_up`, `dns_up` | Live loopback probes for managed Tor |
| `smart_connect` | Saved Smart Connect preference |
| `bridges_enabled`, `bridge_count` | Saved bridge activation and line count |
| `connection_mode`, `kill_switch`, `exit_country` | Saved routing preferences, not proof they are live |
| `session_phase` | Recovery-journal phase; read alongside live fields |
| `recovery_needed` | A previous owner exited while OnionGate state remains live |
| `permanent_sites` | Sites in the local permanent registry |
| `temporary_sites` | Sites known to this process only |
| `egress_watch_active` | Connection daemon (or a one-shot sample) is classifying sockets |
| `egress_bypass` | Count of established public TCP flows not through OnionGate |
| `bootstrap` / `bootstrap_error` | Control-port bootstrap result when available |

## Hosting

The hosting commands are the reason to use this CLI: they let you publish and
manage onion sites on a machine with no GUI.

### List sites

```bash
oniongate-cli host ls
```

Tab-separated: id, name, address, port mapping, and authorization state.
Permanent sites are available across CLI invocations.

The core can also render temporary entries for a long-lived owning process, as
the desktop app does. Standalone CLI invocations do not share that in-memory
registry, so a temporary site created by an earlier CLI process will not appear
in a later `host ls`.

### Create a permanent site

Keeps its address across restarts. Client authorization is on unless you pass
`--public`.

```bash
oniongate-cli host add blog --local-port 3000
oniongate-cli host add blog --local-port 3000 --onion-port 80
oniongate-cli host add status-page --local-port 8080 --public
```

The site id is derived from the name (`My Blog` becomes `my-blog`) and is what
every other command takes.

A private site starts closed with an unusable authorization lock. Issue a named
credential before a client can connect:

```bash
oniongate-cli host auth add blog alice
```

### Create a temporary site

The key is discarded at creation, so the address can never be recreated. The
site disappears when Tor stops.

```bash
oniongate-cli host temp --local-port 3000
oniongate-cli host temp --local-port 3000 --onion-port 8080
oniongate-cli host temp --local-port 3000 --public
```

Unlike permanent creation, temporary creation requires a live TCP listener on
`127.0.0.1:<local-port>` and rejects a missing or wildcard-bound server.

For a private temporary site the credential is printed once, ready to paste into
a client's `.auth_private` file.

The service remains loaded in Tor until Tor stops, but the standalone CLI does
not persist its metadata or credential. Save the printed address/credential
securely. `oniongate-cli stop` stops Tor and irreversibly destroys the service.

### Delete a site

```bash
oniongate-cli host rm blog
```

This destroys the key. The address cannot be recovered.

### Audit a site

```bash
oniongate-cli host audit blog
```

Reports listener scope, whether the descriptor is published, latency, HTTP
status, and observed security headers.

Successful output uses `listener=`, `loopback_only=`, `published=`, optional
`latency_ms=`, `http_status=`, `security_headers=`, and repeated `warning=`
lines.

Full audit by CLI is currently for permanent site IDs. Temporary sites created
by a previous CLI invocation are not in the new process's in-memory registry;
test their public hostname with the desktop Verify onion test or another Tor
client instead.

## Client authorization

```bash
oniongate-cli host auth ls blog              # list credential names
oniongate-cli host auth add blog alice       # issue a credential for "alice"
oniongate-cli host auth rm blog alice        # revoke just alice
oniongate-cli host auth on blog              # require authorization
oniongate-cli host auth off blog             # make the site public
```

`auth add` prints the credential on **stdout** and the explanatory note on
stderr, so you can capture just the secret:

```bash
oniongate-cli host auth add blog alice > alice.auth_private
```

Wait until `host ls` shows the hostname first. If Tor has not written the
hostname yet, `auth add` can print only the `descriptor:x25519:…` credential,
not the complete hostname-prefixed `.auth_private` line.

::: danger Credentials are shown once
The private half is never stored. If it is lost, revoke the credential and issue
a new one. Redirecting it to a file as above writes a secret to disk — put it
somewhere encrypted, and delete it once the recipient has it.
:::

`auth off` parks the existing client files rather than deleting them, so
`auth on` restores access for everyone who already holds a credential.
Credentials issued while auth is off are parked too; `auth add` does not make a
public site private implicitly.

`auth rm` refuses to remove the final active credential, because doing so would
silently make the site public. Add a replacement first, or run `auth off`
explicitly.

There is no user-facing rename command yet. Choose the local label carefully;
changing it would not be expected to change the key or onion address.

## Desktop-only operations

The current CLI has no commands for selected-app routing, leak-report export,
bridge scanning, or workstation Checkup/Harden/Startup Items. `start` applies
the saved TUN, kill-switch, and system-proxy settings. Helper install and
removal are `oniongate-cli helper start` / `stop`.

## Scripting example

Publish a site and wait for it to be reachable:

```bash
#!/usr/bin/env bash
set -euo pipefail

oniongate-cli start
oniongate-cli host add blog --local-port 3000 --public

until oniongate-cli host audit blog | grep -q '^published=true'; do
  sleep 5
done

oniongate-cli host ls
```
