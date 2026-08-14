# Route applications

The **Apps** page covers software that ignores the operating-system proxy and
TUN policies for routing selected applications through distinct Tor circuits.

## Choose the right approach

There are three separate mechanisms:

1. **System proxy** — easiest, but only applications that honor SOCKS are
   protected.
2. **Bypass helpers** — modify a known application's own proxy configuration or
   install a separate launcher that forces SOCKS.
3. **TUN app routing** — matches stable application identities in sing-box and
   gives routed applications distinct Tor SOCKS credentials.

None of these turns a normal browser into Tor Browser. Cookies, account logins,
fingerprinting, extensions, and local profile state remain visible.

## Shell proxy

Shell proxy writes standard proxy environment variables for command-line tools.

- **Off** removes OnionGate's shell hook and environment file.
- **Manual** writes `/etc/tor-socks-gui/env`; explicitly run
  `source /etc/tor-socks-gui/env` in a shell that should use it.
- **Auto** also installs a hook in supported shell startup files so new shells
  source OnionGate's environment automatically.

These files require administrator access. Existing terminal sessions do not
change retroactively. Many tools honor `ALL_PROXY`, `HTTP_PROXY`, and
`HTTPS_PROXY`, but some ignore them, and software that does local DNS before
connecting can still leak names.

The **Test** button compares a direct request with a Tor SOCKS request. The
addresses are displayed in the current UI state but are not written to a leak
report.

## Bypass helpers

OnionGate detects a small set of known applications on macOS and Linux. A
switch applies or removes an app-specific change:

- **Tor Browser via OnionGate** — installs a launcher that sets
  `TOR_SKIP_LAUNCH` and points Tor Browser at OnionGate’s SOCKS/control on
  `9150`/`9151`. Open the launcher, not the stock Tor
  Browser icon, and Connect OnionGate first. This preserves Tor Browser’s
  fingerprinting defenses while using OnionGate’s Tor; it is not a second Tor
  hop.
- **Chrome / Chromium** — installs a separate “Chrome Tor” launcher with an
  explicit SOCKS argument. It does not rewrite the normal Chrome app.
- **Firefox** — writes SOCKS and remote-DNS preferences into the selected
  profile's `user.js`.
- **Cursor and VS Code** — add explicit SOCKS settings to each editor's
  `settings.json`.
- **Claude Code** — adds proxy environment values to
  `~/.claude/settings.json`; SOCKS support remains dependent on the CLI and may
  require an HTTP-to-SOCKS bridge.
- **Discord and Slack** — install separate launcher applications or desktop
  entries with explicit proxy arguments.

::: warning These controls edit other applications
Review the row's information panel before applying it. Fully quit and reopen the
target application afterward. Removing a helper removes OnionGate's known
settings or launcher, but it cannot reconstruct unrelated manual edits that
were made to the same keys.
:::

Electron and browser behavior changes between releases. Always verify the
application's actual egress after an update.

## Isolated app routing

Isolated app routing requires active **TUN** mode. Use **Add app** to select a
macOS `.app`, a Linux `.desktop` file, or an executable.

OnionGate stores enough identity data to recognize the application:

- bundle identifier and signing-team identifier where macOS reports them;
- executable path;
- process name as a fallback;
- a circuit epoch used when rotating the app's circuit.

No full process command line is stored.

While the Split tunnel view is open, a routed row may show
`Isolated · exit <address>` from a live isolated-SOCKS check. That address is
ephemeral UI state and is not written to settings or reports.

### Only selected via Tor

Selected applications route through Tor. Each gets a distinct SOCKS username
and circuit-isolation context. Everything else uses the direct route.

This policy supports **Session Guard**. Because non-selected traffic is
deliberately direct, do not mistake it for whole-device protection.

### All except selected

Selected applications use the direct route; all other captured TCP uses Tor.
The Tor-routed remainder shares the default Tor isolation context rather than
getting one circuit per application.

Session Guard is disabled for this policy because the selected applications are
intentional bypasses.

## Session Guard

Session Guard is an additional fail-closed layer for **Only selected via Tor**.
Once a protected session is active, OnionGate checks Tor SOCKS and the TUN
process each second. If either disappears, it sends a stop signal to matching
selected processes. It resumes only process IDs that OnionGate itself suspended.

Process suspension is available on macOS and Linux. Windows supports the
selected-app TUN policy but does not add this process-suspension layer.

::: warning Process matching has limits
OnionGate prefers the chosen executable path and falls back to process name.
Helpers, child processes, renamed binaries, and applications that move after
selection may not match. Verify the route status shown for each running app.
:::

Turning off Session Guard, changing to **All except selected**, or ending the
session releases OnionGate-suspended processes.

## Rotate one application's circuit

**Rotate** increments that app's circuit epoch and rebuilds the active TUN
policy. New connections for that app receive a new Tor SOCKS authentication
context. Existing connections and application identity do not change.

## Removing an application

**Remove** deletes the identity from OnionGate's routing policy; it does not
uninstall or modify the selected application. If TUN is active, OnionGate
restarts it so the new policy is live.

## Related guides

- [Connect and route traffic](/guide/connection)
- [Verify the live boundary](/guide/verify)
- [Platform support](/reference/platform-support)
