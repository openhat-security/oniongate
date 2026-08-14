# Quick start

This walkthrough gets OnionGate connected with conservative defaults and shows
how to confirm what is actually protected.

## 1. Complete first-run setup

The setup wizard asks you to choose a preset and, optionally, approve
administrator access.

- **Everyday** uses Tor's local SOCKS proxy and resolves names through Tor.
- **Censored Network** enables Smart Connect and the bundled Snowflake fallback.
- **Public Wi-Fi** selects TUN mode and the UDP/QUIC kill switch.
- **Maximum Isolation** adds selected-app routing and Session Guard.
- **Developer** keeps proxy mode without the kill switch for local onion-site
  work.

Presets are starting points, not permanent modes. Changing an individual option
later makes the active configuration **Custom**.

Administrator access is needed only for operating-system changes such as TUN,
the kill switch, and some hardening controls. You can skip it and approve each
action when needed.

**Skip setup** or Escape dismisses the wizard without applying a preset. All
choices remain available under Connect, System, and Settings.

On macOS, Full Disk Access is optional and used only when you explicitly scan
Background/Login Items under **System → Startup Items**. OnionGate does not run
that scan automatically.

## 2. Connect Tor

Open **Connect → Connect** and press the onion button.

With **Smart Connect** enabled, OnionGate tries:

1. direct Tor for up to 25 seconds;
2. your saved BridgeDB lines, if any, for up to 55 seconds;
3. the bundled Snowflake transport for up to 75 seconds.

It never downloads bridge lines from third-party collectors. The selected
strategy and reason are stored locally so the UI can explain what happened.

Wait for bootstrap to reach 100%. A running Tor process by itself is not enough:
OnionGate also checks its local SOCKS and control ports before reporting the
session as connected.

## 3. Choose the protection boundary

The current routing mode appears on both **Connect** and **Connect → Routing**.

- **Proxy** exposes Tor at `127.0.0.1:9050`. Only software that honors SOCKS and
  sends hostnames through it is protected. Turning on the operating-system proxy
  does not force every application to comply.
- **TUN** uses bundled sing-box to capture system traffic, route TCP through
  Tor, and block UDP. It needs administrator access and is the stronger
  system-wide boundary.

If you only want particular applications routed, continue with
[Route applications](/guide/apps). For censorship-resistant connections, see
[Use bridges](/guide/bridges).

## 4. Verify the live state

Open **Verify** and run the leak verifier after connecting.

The verifier compares direct and Tor egress, checks Tor's DNSPort, inspects the
active TUN/firewall state, checks IPv6 route exposure, and reconciles app policy
and crash-recovery state. It is a useful live diagnostic, but not a packet
capture or proof that every application behaves safely. Read
[what each result proves](/guide/verify) before treating a report as a security
guarantee.

## 5. Disconnect cleanly

Press the onion button again. Disconnect performs a full teardown in order:

1. release any processes suspended by Session Guard;
2. stop TUN;
3. remove the OnionGate kill-switch rules;
4. restore the previous operating-system proxy;
5. stop the volunteer Snowflake proxy, if running;
6. destroy temporary onion sites;
7. stop Tor and its pluggable transports.

Permanent onion sites keep their keys and return the next time managed Tor
starts. They are offline while Tor is stopped.

Closing the main window only hides OnionGate in the menu bar/system tray; Tor,
TUN, guarded apps, and hosted sites keep their current state. Reopen it with
**Open OnionGate** in the tray menu. **Hide Window** has the same
non-disconnecting behavior. Use **Quit OnionGate** from the tray menu to exit
the process; Quit runs the same cleanup sequence before termination.

`make dev` / `make start` start the [privileged helper](/guide/daemons), then
restore host network defaults when the process exits or is interrupted
(Ctrl+C): pf/nft kill-switch and NIC lock, TUN, system proxy, managed Tor, and
transports. The helper stays installed. OnionGate's own settings file (bridges,
locale, presets) is not wiped. Run `make cleanup` or `oniongate stop` if a
killed session left the network locked.

The native tray menu is available on macOS, Linux, and Windows. It shows the
same live protection label as the app and provides:

- **Connect Tor** or **Disconnect & restore**;
- **New Identity** when Tor control is reachable;
- **Emergency Restore** only when an interrupted session needs recovery;
- shortcuts to Verify Protection, Onion Host, and Logs;
- Open, Hide, and Quit.

macOS uses a monochrome template icon that follows the menu-bar appearance.
Linux and Windows use the compact color onion icon. On macOS, left-click opens
the menu. On Windows, left-click opens the window and right-click opens the
menu. Linux tray interaction depends on the desktop implementation; use its
context menu and **Open OnionGate**.

If OnionGate or the machine exits before cleanup finishes, the next launch shows
**Emergency Restore** when live network state does not match the recovery
journal. See [Recovery and troubleshooting](/guide/troubleshooting).

## Next steps

- [Connect and route traffic](/guide/connection)
- [Route applications](/guide/apps)
- [Host an onion site](/guide/hosting)
- [Local data and network activity](/reference/data-and-network)
