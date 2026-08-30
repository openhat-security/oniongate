import { Button } from "@/components/ui/button";
import { ProcessIdentity } from "@/components/ProcessIdentity";
import type { ClearnetProcess } from "@/lib/types";

export function ClearnetAlert({
  processes,
  busy,
  showReview,
  tunRoute,
  onKill,
  onKillAndReopen,
  onReview,
  onDismiss,
}: {
  processes: ClearnetProcess[];
  busy: boolean;
  showReview: boolean;
  /** Reopening only routes an app through Tor under TUN, so the action hides otherwise. */
  tunRoute?: boolean;
  onKill: () => void;
  onKillAndReopen?: () => void;
  onReview?: () => void;
  onDismiss: () => void;
}) {
  const held = processes.some((item) => item.held);
  const killable = processes.filter((item) => item.killable);
  const protectedCount = processes.length - killable.length;
  const canReopen = !!tunRoute && !!onKillAndReopen;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="clearnet-alert-title"
    >
      <div className="flex max-h-[min(32rem,90vh)] w-full max-w-md flex-col rounded-2xl border border-line bg-panel p-5 shadow-xl">
        <h2
          id="clearnet-alert-title"
          className="text-base font-semibold tracking-tight"
        >
          {held ? "Connections stopped" : "Processes not through Tor"}
        </h2>
        <p className="mt-2 text-sm text-muted">
          {held
            ? "The connection filter held and dropped these outbound flows. They were not allowed onto clearnet. Killing the process stops it from retrying."
            : "These processes currently have public Internet sockets that are not using OnionGate. Killing them, then requesting a new identity, drops leftover sessions before circuits rotate. OnionGate, Tor, and core system processes are left running."}
        </p>
        <ul className="mt-3 max-h-48 overflow-y-auto rounded-xl border border-line bg-panel-2 px-3 py-2 text-sm">
          {processes.map((item) => (
            <li
              key={`${item.process}-${item.pid}`}
              className="flex items-start justify-between gap-3 py-1"
            >
              <ProcessIdentity
                name={item.process}
                pid={item.pid}
                location={item.location}
                system={item.system}
                compact
              />
              <span className="shrink-0 pt-0.5 text-xs text-muted">
                pid {item.pid}
                {item.killable ? "" : item.system ? " · system" : " · protected"}
              </span>
            </li>
          ))}
        </ul>
        {protectedCount > 0 ? (
          <p className="mt-2 text-[11px] text-muted">
            {protectedCount} protected process
            {protectedCount === 1 ? "" : "es"} will be left running.
          </p>
        ) : null}
        <div className="mt-4 flex flex-col gap-2">
          <Button
            variant="danger"
            disabled={busy || killable.length === 0}
            onClick={onKill}
          >
            {killable.length === 0
              ? "Nothing safe to kill"
              : "Kill these processes and get a new identity"}
          </Button>
          {canReopen ? (
            <>
              <Button
                variant="secondary"
                disabled={busy || killable.length === 0}
                onClick={onKillAndReopen}
              >
                Kill them and reopen through Tor
              </Button>
              <p className="-mt-1 text-[11px] text-muted">
                OnionGate relaunches them only once the session is verified
                Protected over TUN, so they come back inside the tunnel.
              </p>
            </>
          ) : null}
          {showReview && onReview ? (
            <Button variant="secondary" disabled={busy} onClick={onReview}>
              Review on Verify
            </Button>
          ) : null}
          <Button variant="secondary" disabled={busy} onClick={onDismiss}>
            Keep them running
          </Button>
        </div>
      </div>
    </div>
  );
}
