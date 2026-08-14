# Residual leaks

OnionGate’s macOS NIC lock default-denies outbound IP packets on every
non-loopback interface except OnionGate Tor’s allowlisted endpoints. This page
lists what that lock **does not** stop. It is not a promise of two-machine
isolation or a per-process application firewall.

Read the [threat model](/reference/threat-model) with this list.

## Kernel and platform

- **Compromised kernel, root, or firmware.** `pf` runs in that kernel.
- **NECP / Skywalk flows that never hit `pf`.** If Apple’s stack never presents
  a packet to the filter, OnionGate cannot drop it and the deny journal will not
  show it.
- **Same-host allowlist hole.** Any local process may open TCP to a listed Tor
  endpoint IP without speaking the Tor protocol. Stopping that needs a second
  machine or a process-aware filter Apple can exempt.
- **Helper authentication on unsigned debug builds is UID, not code signature.**
  Same-user malware can ask that helper to disable the lock. A signed macOS
  helper also requires the peer's Team ID / `com.adamsiwiec.oniongate`
  signature. Windows named-pipe client identity is still pre-stable.
- **Inbound traffic** is not this feature.

## Intended exceptions

- **DHCP UDP 67/68** so Wi-Fi can renew. ARP/NDP at layer 2.
- **`allow_lan`** passes RFC1918 and link-local. That is off-machine traffic.
- **User destination exceptions** are machine-wide holes. The session is
  **Degraded**. Type `LEAK` to create one.
- **Loopback** stays open so Tor SOCKS, control, and DNSPort work.

## Modes and platforms

- **Linux and Windows:** this NIC lock is macOS-only until the items in
  `TO-DO.md` land. Those platforms still use UDP/IPv6 kill-switch rules.
- **Snowflake, meek, hostname-fronted WebTunnel:** the lock is refused. There is
  no honest small IP allowlist.
- **Proxy mode without the lock:** apps can ignore SOCKS.
- **Split-tunnel `only` when the lock is off:** unmatched apps go direct by
  design.
- **`remote_dns` off:** the system resolver sees names.

## Operations

- **Competing VPN / Internet Sharing** if someone bypasses the connect refuse.
- **Short-lived sockets** the census can miss. Denies that hit `pf` still go to
  the local deny journal.
- **Time/NTP blocked** (clock drift; not a packet leak to a destination you
  chose).
- **Captive portal** is blocked; the network may be unusable until you unlock.
- **Verification is not packet-level proof.**

## What the lock does cover

When it is on, live, and has no exceptions: public IPv4/IPv6 TCP, UDP, ICMP,
ESP, and other IP leaving a real interface is dropped unless the destination is
a current Tor allowlisted endpoint (or DHCP as above). New processes are not
asked first. The packet is dropped, then logged, then a dialog is shown.
