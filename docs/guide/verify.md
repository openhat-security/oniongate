# Verify the live boundary

Connecting to Tor and *being protected* are different things. The Verify page
checks the second one against the live state of your machine rather than against
what OnionGate intended to configure.

## Live connection census

A background task samples TCP and UDP sockets (listening, inbound, and
outbound) about every two seconds, including system processes the OS will
expose. Each row shows the process name, whether it is a system binary, a
link to its on-disk location (app bundle or executable), pid, protocol,
direction, local address, the public source IP that path uses (Tor exit or
WAN, from the last IP check), and full remote addresses. Classification:

- **Through Tor** — OnionGate SOCKS/control/DNS or the TUN prefix;
- **Tor process** — OnionGate's Tor, sing-box, or a pluggable transport;
- **LAN** / **Local** — private, link-local, or loopback;
- **Not through Tor** — public Internet that is not using OnionGate.

The Connections tab is the live view. Addresses stay in process memory and are
not written to logs, SQLite, or exported leak reports (those reports store a
bypass *count* only).

This is a socket census, not packet capture. Short-lived flows can be missed.
Repeated sockets for the same process and destination are grouped into one row
with a count (×N). Stale TCP states such as TIME_WAIT are omitted. Process
names come from the executable path when the OS exposes it; click the
path to reveal it in Finder (or the platform file manager). Binaries under
system locations (`/System`, `/usr/libexec`, Windows System32, and similar)
are labeled **System** and are not killed.

## Kill leftover processes and get a new identity

After OnionGate connects, if any process still has public Internet sockets that
are not using OnionGate, the app asks whether to terminate those processes and
then request a **new identity** (Tor `NEWNYM`). That is not a restart of
OnionGate: circuits rotate after leftover clearnet sessions are dropped.

The same action is on **Verify → Connections**. On **Not through Tor**, each
process also has a **Kill** button. For a binary inside an `.app` bundle
(ExpressVPN and similar), that stops the whole app: the GUI is asked to quit,
matching launchd jobs are unloaded (`bootout` only — they are not disabled, so
the app can run again after you open it or after reboot), then leftover
processes in that bundle are stopped. A single pid that is not in an app
bundle is stopped on its own. The dialog shows the system's stdout/stderr
from the stop attempt. Root daemons are retried through the privileged helper,
or an administrator prompt if the helper is not installed. OnionGate, its
Tor/transport processes, your editor/terminal, and core OS processes are never
killed. Destinations from this census are not logged; the result names only
processes and pids in the UI.

The CLI equivalent is `oniongate newnym --kill-clearnet`.

## What each check proves

### Tor egress

Makes an HTTPS request to the IP-check service through `socks5h` on managed Tor.
A pass proves that a request succeeded through that SOCKS path at that moment.

### Direct/Tor separation (Proxy) or Default/Tor egress (TUN)

In Proxy mode, fetches one address without an application proxy and one through
Tor, then compares them in memory. Matching addresses fail. If either path is
unavailable, the result is a warning because separation could not be
established.

That direct baseline exists only in Proxy mode. In TUN mode, the operating
system captures the no-proxy request too; bypassing TUN just to discover the
clearnet address would weaken the boundary. The verifier therefore reports the
comparison as **unverifiable** instead of failing when addresses match or
claiming that different Tor circuits prove separation.

Neither address is saved to the report or database. The IP-check providers still
receive the requested network traffic; see
[Local data and network activity](/reference/data-and-network).

### Resolve through Tor

When the setting is enabled, sends a small UDP DNS query to Tor's local DNSPort
and requires a response. This proves the local DNSPort is live; it does not
observe every application's DNS requests.

When the setting is disabled, the verifier warns because it cannot establish
DNS containment for proxy applications. In proxy mode, each application must
use SOCKS hostname resolution (`socks5h`) itself.

### UDP/QUIC containment

Passes when TUN is live, or when OnionGate can inspect a live platform firewall
rule that blocks UDP. A recovery marker without a verifiable live rule produces
a warning.

This is a live configuration/rule inspection, not an end-to-end packet probe.
The kill switch does not block arbitrary direct TCP.

### IPv6 route

Checks whether the operating system has an IPv6 default route. A route is
accepted only while TUN is live; no route also passes. A default route without
TUN produces a warning.

This does not send an IPv6 test packet or prove how every application binds its
sockets.

### Selected-app policy

Checks that, when selected-app routing is enabled, at least one stable
application identity exists and TUN is live. It does not inspect every packet
or prove a currently running process matched its stored identity. Use the route
status on **Apps** for that operational check.

### Session Guard

Passes only when Session Guard, selected-app routing, **Only selected via Tor**,
and at least one selected identity are configured. This verifies the policy
preconditions, not a forced route-loss event.

### Crash recovery state

Compares the recovery journal with live Tor, proxy, TUN, and firewall state. It
fails when an interrupted session still has OnionGate-managed state requiring
Emergency Restore.

### Live clearnet watch

Uses the latest daemon sample. A pass means no established public TCP was
observed outside OnionGate, Tor/transport, or LAN. In Proxy mode, leftover
clearnet flows are a warning (apps may ignore SOCKS). In TUN mode with a
default-via-Tor policy they fail. The saved report stores the count only.

## Pass, warning, and failure

- **Pass** — the specific condition above was observed.
- **Warning** — the condition could not be established or an optional
  fail-closed control is not configured.
- **Failure** — a required live condition was absent or contradicted.

The report's overall `passed` value means there were no **failures**. A report
can pass while containing warnings. Read every row.

## Reading the report

A report is a snapshot, not a guarantee. It says what was true at that moment,
on this machine, for the applications it could observe. The live watch lists
processes that currently have clearnet TCP; it cannot tell you whether an
application you never registered leaked a moment earlier, and it cannot detect
correlation by an adversary watching both ends of your connection.

Exported reports are redacted: public IPs, bridge lines, local file paths, and
full process command lines are excluded by design. See
[Privacy](/reference/privacy) for the complete list of what is and is not stored.

OnionGate retains the newest 20 reports locally in `session.db`. Export writes
the latest report to the path you select, with
`oniongate-verification.json` as the suggested filename.

## Test a v3 onion service

The separate onion test validates a 56-character v3 hostname, then sends a
SOCKS5 domain-name request through Tor to port 80. A successful result proves
the hostname was handed to Tor rather than local DNS and that Tor accepted the
connection.

It does not use a private site's client credential. Use Onion Host's audit for a
temporary private site, or test a permanent private site from a Tor client that
holds an issued credential.

## When a check fails

Fix the failure before treating the session as protected. On macOS/Linux, a
matching selected application suspends rather than falling back when Session
Guard's documented preconditions are active. That guarantee does not extend to
unselected apps, unmatched child processes, Proxy mode, or Windows. A failing
check means some part of the assumed boundary is not doing what you expected.

If state looks stale after a crash or an interrupted disconnect, run **Emergency
Restore** on the Connect page. Protected-session network state is journaled, so
recovery replays the journal and puts proxy, TUN, and firewall state back.

See [Recovery and troubleshooting](/guide/troubleshooting) for platform checks
when cleanup cannot verify that state was removed.
