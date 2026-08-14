# Settings and logs

The **Settings** tab configures OnionGate itself. Operating-system posture and
hardening live under **System**.

## Connection presets

Applying a preset changes several settings together:

| Preset | Main changes |
| --- | --- |
| Everyday | Proxy mode, Tor DNS, Smart Connect, no kill switch, no selected-app policy |
| Censored Network | Tor DNS, Smart Connect, bundled Snowflake as the bridge source |
| Public Wi-Fi | TUN, Tor DNS, Smart Connect, UDP/QUIC kill switch |
| Maximum Isolation | Public Wi-Fi settings plus selected-app routing and Session Guard |
| Developer | Proxy mode, Tor DNS, Smart Connect, no kill switch |

A preset does not connect automatically. Review the resulting Routing and
Bridges controls, then connect. Changing any covered value later makes the
configuration **Custom**.

::: warning Maximum Isolation needs selected applications
The preset enables the selected-app policy, but it cannot choose applications
for you. Add them under **Apps → Split tunnel** before relying on Session Guard.
:::

## DNS and system proxy defaults

**Resolve through Tor** enables Tor's local DNSPort. TUN sends DNS to it
directly; proxy applications still need SOCKS hostname resolution such as
`socks5h`.

**Auto-enable system proxy** turns on the operating-system SOCKS setting after
Tor starts successfully. It does not force applications that ignore that
setting.

**Auto-disable system proxy** controls the normal automatic behavior, but a full
Disconnect or Emergency Restore always attempts to restore the proxy snapshot
recorded in the recovery journal.

## Appearance and polling

- **Theme:** follow the operating system, light, or dark.
- **Log level:** Tor's `err`, `warn`, `notice`, `info`, or `debug` verbosity.
  Higher verbosity can expose more operational detail; use it temporarily.
- **Status poll:** how often the UI refreshes live status. This is local polling,
  not telemetry.
- **Language:** English is currently the only selectable complete translation.
  Other listed languages remain disabled until their UI coverage is complete.

## Snowflake volunteer

The Snowflake volunteer control runs a proxy that helps other censored users
reach Tor. It is separate from using Snowflake as a client transport for your
own connection.

Starting it makes your machine part of Snowflake's volunteer infrastructure and
uses network bandwidth. It does not relay arbitrary exit traffic and does not
make your own OnionGate session more anonymous. Stop it before quitting if you
do not want it running for the rest of the session; Disconnect also stops the
managed volunteer process.

This control requires a separate `snowflake-proxy` executable on `PATH`. The
bundled `snowflake-client` used to reach Tor is not the volunteer proxy. If the
UI reports the proxy unavailable, OnionGate does not download or install it
automatically.

## Privileged helper

On supported systems, OnionGate can install `oniongate-helper` as a root-owned
background service. `make dev` starts it. See [Daemons](/guide/daemons) for the
typed protocol, CLI, and install paths.

There is deliberately no arbitrary-command request. TUN, proxy, helper
installation/removal, and hardening actions may still use the platform's normal
administrator prompt.

If the helper is unavailable, kill-switch operations fall back to interactive
elevation rather than reporting false success.

## Administrator access

**Grant access** primes the platform's normal elevation mechanism so a sequence
of privileged actions is less likely to prompt repeatedly. Approval is
temporary and platform-controlled.

Administrator access may be needed for:

- creating and stopping TUN;
- managing the firewall kill switch;
- installing or removing the helper;
- system proxy changes on platforms that require elevation;
- selected OS-hardening controls.

Cancelling a prompt prevents a **Protected** result. TUN may remain active while
the journal is marked **Degraded** so
captured traffic is not dropped onto a direct route; retry the failed control or
Disconnect to clean up. OnionGate does not silently label the weaker state
protected.

## Signed updates

**Check for updates** downloads the release manifest from GitHub, verifies its
Tauri updater signature against the public key embedded in the app, installs the
update, and relaunches.

Until the project publishes its first signed release, build from source. A
missing or invalid updater signature must be treated as a failed update, not
bypassed.

See [Local installers and updates](/guide/updates) for local DMG/EXE/package
builds, release preparation, and stable-versus-staging update behavior.

## Logs

The **Logs** view combines:

- up to 500 recent lines from managed Tor's local `tor.log`; and
- up to 400 in-memory OnionGate event lines for the current process.

**Clear** truncates `tor.log` and clears the in-memory list, then records a
single “Log cleared” event.

Logs are never uploaded automatically. Before sharing them, remove bridge lines,
onion addresses, local paths, application identifiers, and any destination
information. See [Local data and network activity](/reference/data-and-network).

## Local ports

The footer reports the managed local listeners:

- SOCKS `127.0.0.1:9050`;
- control `127.0.0.1:9051`;
- DNS `127.0.0.1:9053` when enabled.

The isolated per-app SOCKS listener uses `127.0.0.1:9060`.

## Related guides

- [Connect and route traffic](/guide/connection)
- [Recovery and troubleshooting](/guide/troubleshooting)
- [Privacy](/reference/privacy)
