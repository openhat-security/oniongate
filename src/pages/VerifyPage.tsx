import { useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { ClearnetAlert } from "@/components/ClearnetAlert";
import { KillProcessDialog } from "@/components/KillProcessDialog";
import { ProcessIdentity } from "@/components/ProcessIdentity";
import type { TorApp } from "@/hooks/useTorApp";
import type { EgressFlow, IpReport, ProcessKillResult } from "@/lib/types";
import { cn } from "@/lib/utils";

type VerifyView = "connections" | "leaks";
type FlowFilter = "all" | "through_tor" | "clearnet" | "listen";

type VerificationCheck = {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail";
  detail: string;
  remediation: string | null;
};

type LeakReport = {
  created_at_unix: number;
  passed: boolean;
  checks: VerificationCheck[];
};

type OnionResult = {
  reachable: boolean;
  latency_ms: number | null;
  detail: string;
};

function classLabel(cls: string) {
  switch (cls) {
    case "through_tor":
      return "Through Tor";
    case "tor_transport":
      return "Tor process";
    case "lan":
      return "LAN";
    case "local":
      return "Local";
    case "clearnet":
      return "Not through Tor";
    default:
      return cls;
  }
}

function classTone(cls: string) {
  switch (cls) {
    case "through_tor":
      return "bg-accent/15 text-accent-strong";
    case "tor_transport":
      return "bg-accent/10 text-accent";
    case "clearnet":
      return "bg-danger/15 text-danger-strong";
    case "lan":
      return "bg-warn/15 text-warn-strong";
    default:
      return "bg-panel-2 text-muted";
  }
}

function matchesFilter(flow: EgressFlow, filter: FlowFilter) {
  if (filter === "all") return true;
  if (filter === "listen") return flow.direction === "listen";
  if (filter === "through_tor") {
    return flow.class === "through_tor" || flow.class === "tor_transport";
  }
  return flow.class === "clearnet";
}

/** Public source IP the remote would see for this path. From the last IP check, not this socket. */
function publicSource(
  flow: EgressFlow,
  ips: IpReport | null,
): { ip: string; label: string } | null {
  if (!ips || flow.direction === "listen") return null;
  if (flow.class === "lan" || flow.class === "local") return null;
  if (flow.class === "through_tor") {
    return ips.tor_ip ? { ip: ips.tor_ip, label: "Tor exit" } : null;
  }
  const wan = ips.direct_ip;
  const exit = ips.tor_ip;
  // In TUN mode the "direct" check is often captured too, so it is not a WAN IP.
  if (!wan || (exit && wan === exit)) return null;
  if (flow.class === "clearnet" || flow.class === "tor_transport") {
    return { ip: wan, label: "WAN" };
  }
  return null;
}

export function VerifyPage({ app }: { app: TorApp }) {
  const {
    busy,
    run,
    egressWatch,
    torOn,
    ips,
    verifyFlowFilter: filter,
    setVerifyFlowFilter: setFilter,
    killClearnetAndNewIdentity,
    denyLog,
    refreshEgressWatch,
  } = app;
  const [view, setView] = useState<VerifyView>("connections");
  const [query, setQuery] = useState("");
  const [report, setReport] = useState<LeakReport | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [onionHost, setOnionHost] = useState("");
  const [onionResult, setOnionResult] = useState<OnionResult | null>(null);
  const [confirmKill, setConfirmKill] = useState(false);
  const [killTarget, setKillTarget] = useState<{
    process: string;
    pid: number;
  } | null>(null);
  const [killPending, setKillPending] = useState(false);
  const [killResult, setKillResult] = useState<ProcessKillResult | null>(null);

  const clearnetProcesses = egressWatch?.clearnet_processes ?? [];
  const killableCount = clearnetProcesses.filter((item) => item.killable).length;
  const clearnetByPid = useMemo(() => {
    const map = new Map<number, (typeof clearnetProcesses)[number]>();
    for (const item of clearnetProcesses) {
      map.set(item.pid, item);
    }
    return map;
  }, [clearnetProcesses]);
  const showKill = filter === "clearnet";
  const tableCols = showKill ? 9 : 8;

  const flows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (egressWatch?.flows ?? []).filter((flow) => {
      if (!matchesFilter(flow, filter)) return false;
      if (!q) return true;
      const seen = publicSource(flow, ips);
      return (
        flow.process.toLowerCase().includes(q) ||
        (flow.path ?? "").toLowerCase().includes(q) ||
        (flow.location ?? "").toLowerCase().includes(q) ||
        flow.local.toLowerCase().includes(q) ||
        flow.remote.toLowerCase().includes(q) ||
        (seen?.ip.toLowerCase().includes(q) ?? false) ||
        String(flow.pid).includes(q) ||
        flow.proto.toLowerCase().includes(q)
      );
    });
  }, [egressWatch?.flows, filter, query, ips]);

  const killProcess = (process: string, pid: number) => {
    setKillTarget({ process, pid });
    setKillResult(null);
    setKillPending(true);
    void (async () => {
      try {
        const result = await invoke<ProcessKillResult>("kill_clearnet_process", {
          pid,
        });
        setKillResult(result);
        await refreshEgressWatch();
      } catch (error) {
        const message = typeof error === "string" ? error : String(error);
        setKillResult({
          process,
          pid,
          ok: false,
          detail: message,
          log: `${message}\n`,
        });
      } finally {
        setKillPending(false);
      }
    })();
  };

  return (
    <section className="flex flex-col gap-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Verify</h2>
        <p className="mt-1 text-sm text-muted">
          Live sockets on this device, classified as through Tor or not. This
          list is memory-only and never uploaded. The leak verifier is a
          separate on-demand check.
        </p>
      </header>

      <Segmented
        value={view}
        options={[
          { value: "connections", label: "Connections" },
          { value: "leaks", label: "Leak verifier" },
        ]}
        onChange={setView}
      />

      {view === "connections" ? (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-muted">
              {egressWatch?.detail ?? "Waiting for the first sample…"}
            </p>
            <span
              className={cn(
                "rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                (egressWatch?.bypass ?? 0) > 0
                  ? "bg-danger/15 text-danger-strong"
                  : "bg-accent/15 text-accent-strong",
              )}
            >
              {egressWatch?.bypass ?? 0} not through Tor
            </span>
          </div>
          {app.status?.connection_filter?.supported ? (
            <p
              className={cn(
                "text-xs",
                app.status.connection_filter.unseen_bypass > 0 ||
                  (app.status.connection_filter.required &&
                    !app.status.connection_filter.running)
                  ? "text-warn-strong"
                  : "text-muted",
              )}
            >
              {app.status.connection_filter.running
                ? app.status.connection_filter.unseen_bypass > 0
                  ? `Connection filter is up, but ${app.status.connection_filter.unseen_bypass} live clearnet flow(s) never reached it (Apple exclusion or fail-open). pf is still the packet lock.`
                  : "Connection filter is up. Clearnet flows are dropped here; pf remains the packet lock. Apple can still hide some of its own processes."
                : app.status.connection_filter.detail}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2 text-[11px] text-muted">
            <span>Through Tor {egressWatch?.through_oniongate ?? 0}</span>
            <span>Tor process {egressWatch?.tor_transport ?? 0}</span>
            <span>LAN {egressWatch?.lan ?? 0}</span>
            <span>Local {egressWatch?.local ?? 0}</span>
            <span>Listening {egressWatch?.listen ?? 0}</span>
            <span>Total {egressWatch?.total ?? 0}</span>
          </div>
          {(denyLog?.events.length ?? 0) > 0 ? (
            <div className="rounded-xl border border-danger/30 bg-danger/5 p-3">
              <div className="text-sm font-semibold">Blocked by NIC lock</div>
              <p className="mt-1 text-xs text-muted">
                Every deny is logged locally. Allowing a destination is a
                machine-wide hole.
              </p>
              <ul className="mt-2 max-h-40 space-y-1 overflow-y-auto text-xs">
                {denyLog!.events.slice(0, 50).map((event) => (
                  <li
                    key={`${event.process}-${event.dest}-${event.port}-${event.proto}`}
                    className="flex justify-between gap-2 font-mono"
                  >
                    <span className="truncate">
                      {event.process} → {event.dest}:{event.port} {event.proto}
                    </span>
                    <span className="shrink-0 text-muted">×{event.count}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          <div className="flex flex-wrap items-center gap-2">
            <Segmented
              value={filter}
              options={[
                { value: "all", label: "All" },
                { value: "through_tor", label: "Through Tor" },
                { value: "clearnet", label: "Not through Tor" },
                { value: "listen", label: "Listening" },
              ]}
              onChange={setFilter}
            />
            <Input
              value={query}
              placeholder="Filter process, address, pid…"
              className="max-w-xs"
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          {clearnetProcesses.length > 0 ? (
            <div
              className={cn(
                "flex flex-wrap items-center justify-between gap-3 rounded-xl border px-3.5 py-3",
                filter === "clearnet"
                  ? "border-danger/40 bg-danger/10"
                  : "border-line bg-panel",
              )}
            >
              <div className="min-w-0">
                <div className="text-sm font-semibold">
                  {clearnetProcesses.length} process
                  {clearnetProcesses.length === 1 ? "" : "es"} not through Tor
                </div>
                <p className="text-xs text-muted">
                  {killableCount > 0
                    ? "Kill leftover clearnet apps, then request a new Tor identity. Protected system and OnionGate processes stay running."
                    : "These are protected system or OnionGate processes and will not be killed."}
                </p>
              </div>
              <Button
                variant="danger"
                size="sm"
                disabled={busy || !torOn || killableCount === 0}
                onClick={() => setConfirmKill(true)}
              >
                Kill processes and get a new identity
              </Button>
            </div>
          ) : null}
          <div className="overflow-x-auto rounded-xl border border-line">
            <table className="w-full min-w-[820px] text-left text-xs">
              <thead className="bg-panel-2 text-[10px] uppercase tracking-wide text-muted">
                <tr>
                  <th className="px-3 py-2 font-semibold">Process</th>
                  <th className="px-3 py-2 font-semibold">Pid</th>
                  <th className="px-3 py-2 font-semibold">Proto</th>
                  <th className="px-3 py-2 font-semibold">Dir</th>
                  <th className="px-3 py-2 font-semibold">Local</th>
                  <th className="px-3 py-2 font-semibold">Public</th>
                  <th className="px-3 py-2 font-semibold">Remote</th>
                  <th className="px-3 py-2 font-semibold">Route</th>
                  {showKill ? (
                    <th className="px-3 py-2 text-right font-semibold">Kill</th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {flows.length === 0 ? (
                  <tr>
                    <td
                      colSpan={tableCols}
                      className="px-3 py-8 text-center text-muted"
                    >
                      {egressWatch?.watching
                        ? "No sockets match this filter."
                        : "Sampling sockets…"}
                    </td>
                  </tr>
                ) : (
                  flows.map((flow, index) => {
                    const seen = publicSource(flow, ips);
                    const census = clearnetByPid.get(flow.pid);
                    const firstOfPid =
                      showKill &&
                      flows.findIndex((item) => item.pid === flow.pid) ===
                        index;
                    const canKill = census?.killable === true;
                    return (
                    <tr
                      key={`${flow.pid}-${flow.proto}-${flow.local}-${flow.remote}-${index}`}
                      className="border-t border-line bg-panel"
                    >
                      <td className="max-w-[14rem] px-3 py-1.5">
                        <ProcessIdentity
                          name={flow.process}
                          pid={flow.pid}
                          location={flow.location}
                          system={flow.system}
                          onReveal={(pid) =>
                            void run(async () =>
                              invoke<string>("reveal_egress_path", { pid }),
                            )
                          }
                        />
                      </td>
                      <td className="px-3 py-1.5 text-muted">
                        {flow.pid}
                        {(flow.count ?? 1) > 1 ? (
                          <span className="ml-1 text-[10px] text-muted">
                            ×{flow.count}
                          </span>
                        ) : null}
                      </td>
                      <td className="px-3 py-1.5 uppercase text-muted">
                        {flow.proto}
                      </td>
                      <td className="px-3 py-1.5 text-muted">
                        {flow.direction}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-[11px]">
                        {flow.local}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-[11px]">
                        {seen ? (
                          <span title={`${seen.label} ${seen.ip}`}>
                            <span className="text-[10px] font-sans font-semibold uppercase text-muted">
                              {seen.label}{" "}
                            </span>
                            {seen.ip}
                          </span>
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-[11px]">
                        {flow.remote}
                      </td>
                      <td className="px-3 py-1.5">
                        <span
                          className={cn(
                            "rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                            classTone(flow.class),
                          )}
                        >
                          {classLabel(flow.class)}
                        </span>
                      </td>
                      {showKill ? (
                        <td className="px-3 py-1.5 text-right">
                          {firstOfPid ? (
                            <Button
                              variant="danger"
                              size="sm"
                              disabled={
                                busy ||
                                killPending ||
                                !canKill ||
                                (killTarget?.pid === flow.pid && killPending)
                              }
                              title={
                                canKill
                                  ? `Stop ${flow.process} (pid ${flow.pid})`
                                  : "Protected system or OnionGate process"
                              }
                              onClick={() =>
                                killProcess(flow.process, flow.pid)
                              }
                            >
                              Kill
                            </Button>
                          ) : null}
                        </td>
                      ) : null}
                    </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          <p className="text-[11px] text-muted">
            Includes inbound, outbound, and listening sockets. Repeated sockets
            for the same process and destination are grouped (×N). Click a path
            to reveal it on disk. System processes are labeled and are not
            killed. Public is the address the remote service sees for that path
            (Tor exit or WAN), from the last IP check — not this socket.
            Destinations stay in this window only — they are not logged or
            saved.
            {egressWatch?.truncated
              ? " The table is capped at 2000 rows."
              : ""}
          </p>
          {killTarget ? (
            <KillProcessDialog
              process={killResult?.process || killTarget.process}
              pid={killTarget.pid}
              pending={killPending}
              ok={killPending ? null : (killResult?.ok ?? false)}
              log={killResult?.log ?? ""}
              onClose={() => {
                if (killPending) return;
                setKillTarget(null);
                setKillResult(null);
              }}
            />
          ) : null}
          {confirmKill ? (
            <ClearnetAlert
              processes={clearnetProcesses}
              busy={busy}
              showReview={false}
              onKill={() => {
                setConfirmKill(false);
                killClearnetAndNewIdentity();
              }}
              onDismiss={() => setConfirmKill(false)}
            />
          ) : null}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={busy}
              onClick={async () => {
                setVerifying(true);
                try {
                  await run(async () => {
                    const next = await invoke<LeakReport>("run_leak_verifier");
                    setReport(next);
                    return next.passed
                      ? "Verification passed"
                      : "Verification found one or more failures";
                  });
                } finally {
                  setVerifying(false);
                }
              }}
            >
              {verifying ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Running checks…
                </>
              ) : (
                "Run leak verifier"
              )}
            </Button>
            <Button
              variant="secondary"
              disabled={busy || !report}
              onClick={() =>
                void run(async () => {
                  const path = await save({
                    defaultPath: "oniongate-verification.json",
                    filters: [{ name: "JSON", extensions: ["json"] }],
                  });
                  if (!path) return "Export cancelled";
                  return invoke<string>("export_latest_leak_report", { path });
                })
              }
            >
              Export redacted report
            </Button>
          </div>

          {!report ? (
            <div className="rounded-xl border border-dashed border-line bg-panel/60 px-4 py-6 text-center">
              <div className="text-sm font-semibold">
                No verification run yet
              </div>
              <p className="mx-auto mt-1 max-w-md text-xs text-muted">
                This checks Tor egress, DNS, IPv6, UDP/QUIC, app policy, and
                recovery. Exported reports omit addresses; the Connections tab
                is the live view.
              </p>
            </div>
          ) : (
            <div className="space-y-1.5">
              {report.checks.map((item) => (
                <div
                  key={item.id}
                  className="flex items-start justify-between gap-4 rounded-xl border border-line bg-panel px-3.5 py-2.5"
                >
                  <div className="min-w-0">
                    <div className="text-sm font-semibold">{item.label}</div>
                    <div className="text-xs text-muted">{item.detail}</div>
                    {item.status !== "pass" && item.remediation ? (
                      <div
                        className={cn(
                          "mt-1.5 rounded-md border px-2 py-1.5 text-[11px] leading-relaxed",
                          item.status === "fail"
                            ? "border-danger/30 bg-danger/10 text-ink"
                            : "border-warn/30 bg-warn/10 text-ink",
                        )}
                      >
                        <span
                          className={cn(
                            "font-semibold",
                            item.status === "fail"
                              ? "text-danger-strong"
                              : "text-warn-strong",
                          )}
                        >
                          How to fix ·{" "}
                        </span>
                        {item.remediation}
                      </div>
                    ) : null}
                  </div>
                  <span
                    className={cn(
                      "shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                      item.status === "pass" && "bg-accent/15 text-accent-strong",
                      item.status === "warn" && "bg-warn/15 text-warn-strong",
                      item.status === "fail" && "bg-danger/15 text-danger-strong",
                    )}
                  >
                    {item.status}
                  </span>
                </div>
              ))}
            </div>
          )}

          <div className="rounded-xl border border-line bg-panel p-4">
            <div className="text-sm font-semibold">Test a v3 onion service</div>
            <p className="mt-0.5 text-xs text-muted">
              Uses a SOCKS5 domain request, proving the hostname was sent to Tor
              instead of local DNS.
            </p>
            <div className="mt-3 flex gap-2">
              <Input
                value={onionHost}
                disabled={busy}
                placeholder="56-character-address.onion"
                onChange={(event) => setOnionHost(event.target.value)}
              />
              <Button
                variant="secondary"
                disabled={busy || !onionHost.trim()}
                onClick={() =>
                  void run(async () => {
                    const result = await invoke<OnionResult>(
                      "test_onion_connectivity",
                      { host: onionHost, port: 80 },
                    );
                    setOnionResult(result);
                    return result.detail;
                  })
                }
              >
                Test
              </Button>
            </div>
            {onionResult ? (
              <p
                className={cn(
                  "mt-2 text-xs",
                  onionResult.reachable ? "text-accent" : "text-danger",
                )}
              >
                {onionResult.detail}
                {onionResult.latency_ms != null
                  ? ` · ${onionResult.latency_ms} ms`
                  : ""}
              </p>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}
