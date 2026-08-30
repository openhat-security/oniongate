# Recovery and troubleshooting

Start with the error shown in OnionGate and the **Settings → Logs** view. Do not
post raw logs publicly; redact bridge lines, onion addresses, local paths, and
application identifiers.

Most command results appear briefly in the bottom-right status toast. Errors
remain longer than success messages but still dismiss automatically; copy or
record the redacted text before it disappears, then use Logs for supporting
context.

## Emergency Restore

Every protected session has a mode-600 recovery journal recording whether
OnionGate changed the proxy, expected TUN or firewall state, and started Tor or
pluggable transports.

On launch, OnionGate compares that journal with live processes, ports, proxy,
TUN, and firewall state. It offers **Emergency Restore** only when:

1. the journal belongs to a previous process;
2. the previous session did not finish cleanly; and
3. OnionGate-managed network state is still live.

Restore releases Session Guard processes, stops TUN, removes OnionGate's
kill-switch rule, restores the previous proxy snapshot, stops transports and
temporary onion sites, and stops managed Tor.

Emergency Restore is currently a desktop command. The CLI exposes
`recovery_needed` in `status` and a best-effort `stop`. `make cleanup` runs
that same restore after a killed `make dev` session.

If cleanup reports leftovers, do not assume the machine is back to normal.
Approve the administrator prompt and retry. Check the live firewall, proxy, and
TUN state before resuming sensitive work.

### The window closed but Tor is still running

Closing the main window hides OnionGate in the menu bar/system tray by design.
It does not disconnect. Reopen it from the tray, then use Disconnect, or choose
**Quit OnionGate** from the tray menu to run cleanup and exit.

## Tor will not connect

### Runtime missing

Release builds are intended to bundle Tor and the transport sidecars. Source
builds need:

```bash
make deps
```

The download script accepts only archives pinned in
`scripts/dependencies.sha256`. A mismatch is a supply-chain failure; do not
bypass it.

### Ports 9050 or 9051 are busy

OnionGate needs SOCKS `9050` and control `9051` on loopback. A system Tor that
offers SOCKS without OnionGate's control setup conflicts with managed Tor.
Stop the other Tor manager, then reconnect.

macOS/Linux diagnostic:

```bash
lsof -nP -iTCP:9050 -iTCP:9051
```

### Bootstrap times out

The network may block direct Tor. Use [Bridges](/guide/bridges), or leave Smart
Connect on so it can try saved BridgeDB lines and bundled Snowflake.

Repeatedly changing transports is not a substitute for reading the Tor log. A
missing transport binary appears as **missing** under Active transports.

## TUN will not start

- Connect Tor first; TUN refuses to start without live SOCKS.
- Approve the administrator prompt (only needed without a helper-backed TUN).
- Confirm bundled sing-box exists (`make deps` for a source checkout).
- Check the sing-box log (see below for where it lives).
- Disconnect another VPN that controls the default route.

OnionGate deliberately does not launch an unprivileged sing-box process as a
fallback. If it cannot observe the process/interface after startup, TUN remains
inactive. A helper-backed TUN never quietly reroutes to the administrator prompt
either: once the helper is provisioned, a refusal from it is fatal.

### Where the sing-box log is, and why Logs can look empty

Where sing-box writes depends on who started it:

- **Admin-prompt start (no helper).** sing-box runs from OnionGate's local data
  directory and writes `sing-box.log` there. The in-app **Logs** view can tail
  it.
- **Helper-backed start (the `.pkg` default).** The privileged helper starts
  sing-box as root and writes its log to a **root-only file (mode 0600)** under a
  root-owned directory. That is deliberate — the log can name routed
  applications and paths — but it means the in-app log tail is **empty** in
  helper mode, and it is not a malfunction.

So when a helper-backed TUN fails to come up, do not go looking in **Logs**.
The failure detail is returned **inside the helper's own error message** in the
status toast (for example, "sing-box exited immediately …"). Copy that text
before it dismisses; it is the authoritative signal, not the empty log tail.

## Kill switch problems

The kill switch blocks UDP/QUIC, not all direct TCP. Its platform backend needs:

- macOS: `pfctl`;
- Linux: `nft`, plus `pkexec` or passwordless `sudo` when the helper is absent;
- Windows: Windows Defender Firewall and an approved UAC prompt.

If disabling fails, Emergency Restore retries removal and verifies the live
rule where possible. Do not delete the recovery marker by hand while a rule may
still be active.

## Proxy is still enabled after exit

Reopen OnionGate and run Emergency Restore. The original proxy snapshot is in
the recovery journal.

Platform controls:

- macOS: `networksetup -getsocksfirewallproxy "<service>"`;
- GNOME Linux: `gsettings get org.gnome.system.proxy mode`;
- Windows: Internet Options / WinINet proxy settings.

Avoid manually overwriting the journal first; doing so removes the information
needed to restore the previous proxy.

## An application still connects directly

Proxy mode cannot force compliance. Check:

1. the app supports SOCKS;
2. it uses remote hostname resolution (`socks5h`);
3. Secure DNS / DoH is disabled or routed safely;
4. an app-specific helper is active, or the app is selected in TUN routing;
5. TUN is live, not merely selected in settings.

Run the application's own egress test. The general leak verifier cannot inspect
every connection from every process.

## Session Guard did not suspend an app

Session Guard requires:

- TUN running;
- split routing enabled;
- **Only selected via Tor**;
- a selected identity whose executable path or process name matches the live
  process;
- macOS or Linux.

Helper processes and children may use different executable paths. Remove and
re-add an app after it moves or updates, then verify the route status.

## Onion Host problems

See the symptom table in [Host an onion site](/guide/hosting). The most common
causes are a server not listening on `127.0.0.1`, a wildcard-bound listener, a
descriptor still publishing, or a missing client credential.

Never fix a permanent site by deleting the whole OnionGate data directory: that
also destroys its Tor-owned service key and address.

## Resetting local state

- macOS: `~/Library/Application Support/oniongate/`
- Linux: `~/.local/share/oniongate/`
- Windows: `%LOCALAPPDATA%\oniongate\`

It contains settings, logs, the database, recovery journal, generated Tor/TUN
configuration, and permanent onion keys.

::: danger Do not delete this directory as generic troubleshooting
Deleting it can permanently destroy onion-site identities and the proxy
snapshot required for crash recovery. Disconnect cleanly, export or back up only
the non-secret data you deliberately need, and remove individual state with the
app's controls.
:::

## Reporting a bug

Use the GitHub bug template and include:

- OnionGate version and operating system;
- whether the build came from a release or source;
- selected routing mode and whether Tor/TUN/firewall were live;
- exact steps and the redacted error text.

Security vulnerabilities belong in a private
[GitHub Security Advisory](https://github.com/openhat-security/oniongate/security/advisories/new),
never a public issue.
