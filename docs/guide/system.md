# Check and harden this machine

The **System** tab covers the computer OnionGate runs on, in three views:
*Checkup* reads its current state, *Harden* changes it, and *Startup Items*
watches what runs on its own. Anything that configures OnionGate itself lives
under **Settings** instead.

These host-audit utilities currently target macOS. Linux and Windows retain the
full Connect, Apps, Host, Verify, and Settings workflows while OS preference
management stays with their native system tools. See the
[platform matrix](/reference/platform-support).

## Checkup

A read-only pass over the machine: System Integrity Protection, FileVault,
Gatekeeper, XProtect freshness, the application firewall, Remote Login, file
sharing, externally bound TCP listeners, and whether a Tor route is live.

Each result is marked `pass`, `warn`, or `info`, and hovering the badge shows
the exact command the answer came from — `csrutil status`, `fdesetup status`,
and so on. Checkup never changes anything. FileVault, Application Firewall, and
Remote Login warnings expose **Fix in Harden**, which jumps to their matching
control; other rows provide text remediation only.

::: warning Checkup is not malware detection
It reports configuration, not compromise. Unknown items are never labeled
malicious, and a clean Checkup is not evidence that a machine is uncompromised.
:::

## Harden

Privacy and security changes are grouped into Privacy, Security, Tools, and
Lockdown Mode. Each wraps a documented macOS setting — `defaults`,
`socketfilterfw`, `systemsetup`, `mdutil`, and similar — and exposes a matching
off/remove action where applicable.

“Off” restores the conventional macOS value OnionGate knows, not an arbitrary
custom value that existed before the first change. Review managed-device policy
and record unusual settings before changing them.

Every row reads its state from the system rather than from a saved preference,
so the switches stay honest if something changes outside OnionGate. Options that
need administrator rights prompt at the moment you apply them.

Read the (i) on a row before flipping it. Several are deliberately high-impact:

- **Location Services** breaks Maps, Find My, and weather.
- **Bonjour multicast** can break printer and AirPlay discovery.
- **Lockdown Mode** is Apple's extreme setting for people facing targeted
  spyware. It blocks most message attachments, limits web features, disables
  configuration profiles, and usually needs a restart. It is not a casual
  privacy toggle.

### Current controls

Privacy controls cover Remote Apple Events, Siri preferences and an optional
Siri process watchdog, Spotlight indexing, internet spell correction, analytics
and diagnostics, personalized ads/ad ID, screenshot timestamps, Homebrew
analytics, Location Services, the iCloud default for new documents, AirDrop,
and Dock recent apps.

Security controls cover Captive Portal assistant, the macOS application
firewall and stealth/auto-allow settings, Guest login and Guest SMB, Remote
Login, AirPlay Receiver, Bonjour multicast advertisements, Remote Management,
printer sharing, immediate password after the screen saver, the legacy
cleartext servers (TFTP, Telnet, FTP), and remote printing / CUPS
administration.

**Connection filter (Network Extension)** is a LuLu-style hold-and-drop for
outbound flows that are not already Tor. It is a supplement. `pf` stays the
packet lock. Apple can hide some of its own processes from the filter, and
the framework can fail open; Home and Verify report that as Degraded. A
signed build and your approval in System Settings are required. There is no
allow-to-clearnet rule.

**Block the network at boot** is the control that closes the clearnet window
between restarts. OnionGate does not lock the NIC at power-on by default. Until
you Connect, every interface — Wi-Fi, Ethernet, USB LAN — can leak. This item
installs a root LaunchDaemon that default-denies outbound IP (loopback and DHCP
stay open) at the next boot. Connect replaces that lock with the usual
transition policy; Emergency Restore and Uninstall flush it. Pair it with
**Start OnionGate at login** and **Connect on launch** (Settings) so the Mac is
not left offline. The setup wizard and the Home screen recommend this bundle if
you want no leaks between startups.

Two Wi-Fi controls are high-impact and go through the privileged helper or a
root LaunchDaemon:

- **Randomize Wi-Fi MAC address** draws a new locally-administered, unicast
  address from the system CSPRNG through the helper and cycles the radio so the
  card associates under it. There is no path that hands out a real vendor OUI,
  and the address itself is never logged or shown. It **breaks captive portals
  and 802.1X / enterprise (WPA-Enterprise, eduroam, corporate) authentication**
  until you re-authenticate — on some networks an administrator has to clear the
  old address first. The current connection drops, and the address resets at the
  next reboot. It needs the privileged helper.
- **Turn Wi-Fi off at boot** installs a root LaunchDaemon that disables the
  Wi-Fi service before login, powers the radio down, and sets `pmset` wake
  guards so waking from sleep does not quietly bring it back. It does **not**
  block Ethernet or USB LAN — use **Block the network at boot** for that. Its
  optional companion, **turn the radio back on once the session is Protected**
  (a Settings toggle), flips Wi-Fi on again the moment OnionGate reports a
  verified Protected session, so you are not left offline by hand. Removing the
  item restores the recorded `pmset` values and re-enables the Wi-Fi service.

FileVault, Intel firmware password, and private Wi-Fi address are guide-only
controls that open the appropriate operating-system workflow rather than
forcing a sensitive setting. Tools also include **Start OnionGate at login** (a
per-user LaunchAgent, never a root daemon), a one-shot DNS-cache flush, and
optional MacPorts detection/download.

The **Kill Siri** watchdog watches an expanded set of Siri/Assistant helper
processes and kills them by the correct per-user id. It, MacPorts, launch at
login, and the Wi-Fi items are not part of OnionGate's routing boundary. The
watchdog is an OnionGate-installed LaunchAgent; it is not a third-party security
integration or malware detector.

## Startup Items

An inventory of what the machine runs without being asked — LaunchAgents,
LaunchDaemons, and other persistence points — with code-signature status and
team identifier where macOS reports them.

Save a trusted baseline once when you believe the machine is in a good state.
Later refreshes then show what was added or removed since, which is the useful
signal; the raw list on its own rarely is.

When a baseline exists and the automatic inventory detects added/removed
entries, the **System** item in the main sidebar shows the change count. The
badge is an inventory delta, not a malware verdict; open Startup Items and
review the paths and signatures.

Background/Login Items is a separate scan you trigger by hand. It needs Full
Disk Access, so it is kept out of the automatic baseline rather than prompting
you on every refresh.

## What OnionGate does not do here

Hardening sits **outside** OnionGate's core protection boundary. The guarantees
in the [threat model](/reference/threat-model) cover Tor routing, per-app
isolation, and leak prevention — not the state of your operating system.

OnionGate is not an antivirus or an endpoint detection product, and it does not
bundle, install, or recommend third-party security tools. Nothing in this tab
substitutes for keeping macOS updated.
