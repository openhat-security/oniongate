import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { shortLocation } from "@/components/ProcessIdentity";
import { startWindowDrag } from "@/lib/drag";
import type {
  ClearnetProcess,
  EgressWatch,
  ProcessKillResult,
} from "@/lib/types";

/**
 * The always-on-top popup rendered at `index.html#clearnet-alert`, outside the
 * main application shell. It exists instead of a macOS notification because
 * notification text is routed through Apple's infrastructure; everything here
 * stays in-app and memory-only.
 */
export function ClearnetAlertWindow() {
  const [processes, setProcesses] = useState<ClearnetProcess[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const delivered = useRef(false);

  const close = useCallback(() => {
    void getCurrentWebviewWindow()
      .close()
      .catch(() => {
        /* window may already be gone */
      });
  }, []);

  useEffect(() => {
    let disposed = false;
    let stopListening: (() => void) | undefined;

    void listen<ClearnetProcess[]>("clearnet-alert-processes", ({ payload }) => {
      delivered.current = true;
      // The core collapses a burst of detections into one payload rather than
      // one window per process, so replace the list wholesale.
      setProcesses(payload ?? []);
    }).then((unlisten) => {
      if (disposed) unlisten();
      else stopListening = unlisten;
    });

    // This webview can finish loading after the core emitted its payload. Seed
    // from the live watch so the popup can never come up empty.
    void invoke<EgressWatch>("get_egress_watch")
      .then((watch) => {
        if (disposed || delivered.current) return;
        setProcesses(watch.clearnet_processes ?? []);
      })
      .catch(() => {
        /* the popup still works once the event arrives */
      });

    return () => {
      disposed = true;
      stopListening?.();
    };
  }, []);

  const held = processes.some((item) => item.held);
  const killable = processes.filter((item) => item.killable);

  const kill = async (targets: ClearnetProcess[]) => {
    setBusy(true);
    setError(null);
    const killed = new Set<number>();
    const failures: string[] = [];
    for (const target of targets) {
      try {
        const result = await invoke<ProcessKillResult>("kill_clearnet_process", {
          pid: target.pid,
        });
        if (result.ok) killed.add(target.pid);
        else failures.push(`${result.process}: ${result.detail}`);
      } catch (e) {
        const detail = typeof e === "string" ? e : String(e);
        failures.push(`${target.process}: ${detail}`);
      }
    }
    const remaining = processes.filter((item) => !killed.has(item.pid));
    setProcesses(remaining);
    setError(failures.length ? failures.join(" · ") : null);
    setBusy(false);
    if (!failures.length && remaining.length === 0) close();
  };

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden border border-danger/40">
      <div
        data-tauri-drag-region
        onMouseDown={startWindowDrag}
        className="flex items-start gap-2.5 px-3.5 pb-2 pt-3.5"
      >
        <ShieldAlert
          className="mt-0.5 h-5 w-5 shrink-0 text-danger"
          strokeWidth={2}
        />
        <div className="min-w-0">
          <h1 className="text-sm font-semibold tracking-tight text-ink">
            {held
              ? processes.length > 1
                ? `${processes.length} connections were stopped`
                : "This connection was stopped"
              : processes.length > 1
                ? `${processes.length} processes are not going through Tor`
                : "A process is not going through Tor"}
          </h1>
          <p className="mt-0.5 text-[11px] leading-snug text-muted">
            {held
              ? "The connection filter held and dropped this outbound flow. It was not allowed onto clearnet. Kill the process if it should not retry."
              : "These already have public Internet sockets outside OnionGate. Killing one drops its leftover session now."}
          </p>
        </div>
      </div>

      <ul className="mx-3.5 min-h-0 flex-1 space-y-1 overflow-y-auto rounded-xl border border-line bg-panel px-2.5 py-2">
        {processes.length === 0 ? (
          <li className="py-2 text-center text-xs text-muted">
            Waiting for details…
          </li>
        ) : null}
        {processes.map((item) => (
          <li
            key={`${item.process}-${item.pid}`}
            className="flex items-center justify-between gap-2 rounded-lg px-1.5 py-1"
          >
            <div className="min-w-0">
              <div className="flex min-w-0 items-baseline gap-1.5">
                <span className="truncate text-[13px] font-semibold text-ink">
                  {item.process || "unknown"}
                </span>
                <span className="shrink-0 font-mono text-[10px] text-muted">
                  pid {item.pid}
                </span>
              </div>
              <div
                className="truncate text-[10px] text-muted"
                title={item.location || item.path}
              >
                {shortLocation(item.location || item.path) ||
                  (item.system ? "system process" : "unknown location")}
              </div>
            </div>
            {item.killable ? (
              processes.length > 1 ? (
                <Button
                  size="sm"
                  variant="danger"
                  disabled={busy}
                  onClick={() => void kill([item])}
                >
                  Kill
                </Button>
              ) : null
            ) : (
              <span className="shrink-0 rounded-md bg-panel-2 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-muted">
                {item.system ? "System" : "Protected"}
              </span>
            )}
          </li>
        ))}
      </ul>

      {error ? (
        <p className="px-3.5 pt-2 text-[11px] leading-snug text-danger">
          {error}
        </p>
      ) : null}

      <div className="flex items-center gap-2 px-3.5 pb-3.5 pt-2.5">
        <Button
          className="flex-1"
          size="sm"
          variant="danger"
          disabled={busy || killable.length === 0}
          onClick={() => void kill(killable)}
        >
          {killable.length > 1 ? `Kill all ${killable.length} now` : "Kill it now"}
        </Button>
        <Button
          className="flex-1"
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={close}
        >
          Ignore
        </Button>
      </div>
    </div>
  );
}
