import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function KillProcessDialog({
  process,
  pid,
  pending,
  ok,
  log,
  onClose,
}: {
  process: string;
  pid: number;
  pending: boolean;
  ok: boolean | null;
  log: string;
  onClose: () => void;
}) {
  const title = pending
    ? "Stopping process"
    : ok
      ? "Process stopped"
      : "Stop failed";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="kill-process-title"
    >
      <div className="flex max-h-[min(36rem,90vh)] w-full max-w-lg flex-col rounded-2xl border border-line bg-panel p-5 shadow-xl">
        <h2
          id="kill-process-title"
          className="flex items-center gap-2 text-base font-semibold tracking-tight"
        >
          {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          {title}
        </h2>
        <p className="mt-2 text-sm text-muted">
          {process || "unknown"} · pid {pid}. If this is an app such as a VPN,
          OnionGate also quits the GUI and unloads launch jobs so it does not
          immediately restart. System stdout and stderr from the stop attempt
          stay in this window.
        </p>
        <pre
          className={cn(
            "mt-3 max-h-64 overflow-auto rounded-xl border bg-panel-2 px-3 py-2 font-mono text-[11px] leading-relaxed whitespace-pre-wrap",
            ok === false ? "border-danger/40 text-danger-strong" : "border-line text-ink",
          )}
        >
          {log.trim() ? log : pending ? "Waiting for the system…" : "(no output)"}
        </pre>
        <div className="mt-4">
          <Button variant="secondary" disabled={pending} onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}
