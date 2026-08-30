# Connect and route traffic

The **Connect** tab has three views: the live connection dashboard,
**Routing**, and **Bridges**. This page explains what each routing control
changes and, equally important, what it does not protect.

The preset chip beside those views summarizes the active settings. Select it (or
its information action) to jump to **Settings → Preferences**.

## Managed Tor

OnionGate starts its own Tor process with loopback-only listeners:

- SOCKS at `127.0.0.1:9050`;
- isolated-auth SOCKS at `127.0.0.1:9060`;
- Tor Browser SOCKS at `127.0.0.1:9150` (`IsolateSOCKSAuth`);
- control ports at `127.0.0.1:9051` and `127.0.0.1:9151`;
- DNSPort at `127.0.0.1:9053` when remote DNS is enabled.

While those Tor Browser ports are bound, stock Tor Browser cannot start its own
Tor on the same ports. Use **Apps → Tor Browser via OnionGate** so the browser
skips its bundled Tor and treats OnionGate as the external Tor manager.

If another Tor instance occupies SOCKS port 9050 without the required control
port, OnionGate attempts to stop that instance and start the managed one. Do not
run two Tor managers on these ports at the same time.

The connection badge is based on live components, not just a saved preference:
the recovery journal must be in `protected` phase, Tor SOCKS/control and any
requested DNSPort must be reachable, and the selected proxy or TUN boundary must
be live. If the kill switch is requested, its rule must also be visible to live
inspection. Otherwise the badge says **Degraded** or **unverified** rather than
protected.

## Dashboard address and session counters

**Current IP** shows the Tor-visible address when available, otherwise the
default-path address, plus an approximate location. A background task refreshes
those values on its own (sooner after connect or New Identity, about every 30
seconds otherwise). The values remain in UI memory and are not saved to
verification reports. See [Local data and network activity](/reference/data-and-network) for
the providers and TUN behavior.

The dashboard also shows current download/upload rates, total session bytes,
observed circuit count, identity-change count, and uptime. These are local
session counters, not destination history. The small rate graph is a compact
status visualization rather than a retained traffic trace.

## Smart Connect

Smart Connect is designed for changing networks. It first tries direct Tor,
then your saved bridge lines, then the bundled Snowflake transport. It records
the gateway-derived network key, attempted strategies, and selection reason
locally. It does not upload that network key.

Turning Smart Connect off starts Tor with the currently saved bridge and routing
configuration without trying alternatives.

::: warning Snowflake is a fallback, not a faster Tor mode
Use bridges when direct Tor is blocked or conspicuous on your network. A bridge
operator or transport infrastructure can observe that your device connected to
it, and constraining Tor's entry path may reduce anonymity.
:::

## Proxy mode

Proxy mode optionally configures the operating system to advertise OnionGate's
SOCKS listener.

It is a compatibility mode, not forced containment:

- an application can ignore the system proxy;
- plain `socks5` may resolve DNS locally; use `socks5h` or the application's
  equivalent “proxy DNS” setting;
- UDP and QUIC do not travel through Tor;
- software with its own networking stack may connect directly.

Use the **Apps** page for known bypass-prone software, or use TUN when you need a
stronger system routing boundary.

The operating-system SOCKS setting is not a Connect-page toggle. Choose **Proxy**
or **TUN** under Routing. System proxy mode always enables and verifies OS SOCKS
on the live default-route service after Tor is up; **Settings → Preferences**
only controls whether other modes also apply SOCKS on Connect. The Current IP
card shows the live path (Direct, SOCKS, system proxy, or TUN) as status only.

On disconnect, OnionGate restores the proxy state it captured before enabling
its own proxy. If no captured snapshot is available, it disables only its SOCKS
configuration. If apply or primary verify fails, that restore runs immediately
instead of leaving leftover SOCKS until Disconnect. On macOS, a user-level
`networksetup` failure is retried through the privileged helper; if the helper
is not running, Connect fails closed.

## TUN mode

TUN mode starts bundled sing-box with an automatically generated configuration.
It captures system traffic, sends TCP through Tor SOCKS, and blocks all UDP,
including QUIC. DNS is sent to Tor's local DNSPort when **Resolve through Tor**
is on.

The generated policy deliberately sends private-address traffic directly so
local devices and services remain reachable. This includes destinations that
sing-box identifies as private LAN addresses.

::: warning TUN is not a VPN
Traffic still exits through Tor, Tor still carries TCP only, and OnionGate does
not provide Tor Browser's browser-state or fingerprinting defenses. TUN changes
how applications reach Tor; it does not change Tor's anonymity model.
:::

Starting and stopping TUN requires administrator access. OnionGate does not
silently fall back to an unelevated process if TUN creation fails. The UI stays
in or returns to Proxy mode and reports the failure.

## Resolve through Tor

When enabled:

- TUN sends DNS queries to Tor's local DNSPort;
- proxy applications still need SOCKS hostname resolution (`socks5h`) because
  OnionGate cannot force an application that performs its own DNS lookup.

When disabled, OnionGate uses system DNS in TUN mode and cannot claim DNS
containment for proxy applications. `.onion` names require Tor-side hostname
resolution.

## Network lock (connect / reconnect / disconnect)

Before Tor bootstraps, while Tor restarts, and while a session tears down,
OnionGate arms a **network lock** so clearnet cannot be used during the gap —
the same idea as a VPN that blocks traffic while reconnecting. That lock is
not installed at power-on. If you want no clearnet between restarts, turn on
**Block the network at boot** under System → Harden (recommended with Start
OnionGate at login and Connect on launch).

The lock always blocks clearnet **UDP/QUIC** and **IPv6** (loopback stays open
for Tor's local SOCKS/control/DNS ports). On Windows it also blocks clearnet
**TCP**, with an allow rule for the Tor binary so guards remain reachable.
macOS and Linux cannot match Tor by executable path in `pf`/`nftables`, so TCP
during the bootstrap window is contained by quitting or suspending apps and,
once TUN is up, by `strict_route`.

Connect asks whether to close foreground applications first. If you keep apps
open, you must confirm that nothing linked to your identity is running. The
network stays locked if bring-up fails; use Disconnect or Emergency Restore to
clear it.

## Kill switch

The kill switch is the **steady-state** firewall after a session is Protected.
On Everyday it blocks clearnet UDP/QUIC and IPv6. On macOS, **NIC default-deny**
(Maximum Isolation) instead drops **every** outbound IP packet except loopback,
DHCP, and OnionGate Tor’s allowlisted endpoints. That is the control that stops
Apple Push and other daemons from using the WAN IP.

TCP fail-closed without that lock still comes from TUN `strict_route` and
Session Guard. In proxy mode without the NIC lock, Connect stays **Degraded**
while known SOCKS-ignoring apps are running uncontained. TUN or the NIC lock
can still report Protected.

See [Residual leaks](/reference/residual-leaks) for what the lock does not
cover.

## Connection filter (macOS)

On a signed macOS build, Harden can load a Network Extension that intercepts
new outbound flows, allows only traffic that is already Tor or OnionGate, and
drops everything else. The in-app alert then says the connection was
**stopped**, not that it already leaked.

This is a supplement, not a replacement for `pf` or TUN. Apple can hide some
of its own processes from the filter, and a crashed or flooded extension can
fail open. Home and Verify show when the filter is up and when a live
clearnet flow never reached it. That case is **Degraded**, not Protected.

Unsigned and ad-hoc debug builds do not load the extension. They stay on the
packet lock and the after-the-fact socket watch. Turning **Connection filter**
off in Settings means Connect will not require the extension even if it is
installed.

There is no “Allow this app on clearnet.” That would be a destination hole.

When the setting is saved, Connect re-applies the firewall rule in either Proxy
or TUN mode. A requested rule that fails prevents a Protected badge.

OnionGate writes a local recovery marker and verifies the live firewall rule
where the platform permits it. Disconnect and Emergency Restore remove only
OnionGate's rules (kill switch and network lock).

If a requested kill-switch enable action fails during TUN startup, OnionGate
leaves the journal degraded and reports an error. If the action succeeds but
later live inspection is unavailable, the badge remains **unverified**. TUN may
remain active to avoid dropping captured traffic onto a direct route; retry the
kill switch or disconnect.

## Exit country and relay pins

An exit-country selection writes Tor's `ExitNodes` preference. It is a
preference among available exits, not a guarantee that an exit will always be
available.

Relay search queries the Tor Project's Onionoo service by nickname, country, or
fingerprint. Pinning an entry or exit constrains circuit selection. A smaller
relay set is easier to fingerprint and correlate, so leave these controls
automatic unless you have a specific operational reason.

**Clear pins** removes entry, middle, and fingerprint-based exit pins. It does
not clear the separate exit-country preference.

## New identity

**New identity** sends Tor's `NEWNYM` signal and increments the local identity
counter. Existing long-lived connections may keep their old circuit, and remote
accounts, cookies, browser state, and application identifiers do not change.
It is not a “become anonymous again” button.

## VPN warning

OnionGate reports when another VPN appears active because competing route and
DNS changes can invalidate its assumptions. It does not automatically disable
the VPN. Disconnect it or verify the combined route carefully before relying on
OnionGate. Automatic VPN detection is implemented on macOS and Linux, not
Windows; see [Platform support](/reference/platform-support).

## Related guides

- [Use bridges](/guide/bridges)
- [Route applications](/guide/apps)
- [Verify the live boundary](/guide/verify)
- [Threat model](/reference/threat-model)
- [Residual leaks](/reference/residual-leaks)
