import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { DenyEvent } from "@/lib/types";

export function StrictLockConsent({
  onConfirm,
  onCancel,
}: {
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="nic-lock-consent-title"
    >
      <div className="flex w-full max-w-md flex-col rounded-2xl border border-line bg-panel p-5 shadow-xl">
        <h2
          id="nic-lock-consent-title"
          className="text-base font-semibold tracking-tight"
        >
          Enable NIC default-deny
        </h2>
        <p className="mt-2 text-sm text-muted">
          Public traffic that is not Tor talking to an allowlisted endpoint is
          dropped on every interface. Apple Push, iMessage, and iCloud will
          break. LAN is denied unless you turn it back on. This is not
          two-machine isolation. Read residual leaks in the docs before
          continuing.
        </p>
        <div className="mt-4 flex flex-col gap-2">
          <Button variant="danger" onClick={onConfirm}>
            I understand — enable the lock
          </Button>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    </div>
  );
}

export function DenyAlert({
  event,
  busy,
  onKeepBlocked,
  onAllow,
  onReview,
}: {
  event: DenyEvent;
  busy: boolean;
  onKeepBlocked: () => void;
  onAllow: () => void;
  onReview: () => void;
}) {
  const [typed, setTyped] = useState("");
  const canAllow = typed.trim().toUpperCase() === "LEAK";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="deny-alert-title"
    >
      <div className="flex w-full max-w-md flex-col rounded-2xl border border-line bg-panel p-5 shadow-xl">
        <h2
          id="deny-alert-title"
          className="text-base font-semibold tracking-tight"
        >
          Blocked outbound connection
        </h2>
        <p className="mt-2 text-sm text-muted">
          The packet was already dropped. Allowing this destination opens a
          hole for every process on this Mac, not just this one.
        </p>
        <div className="mt-3 rounded-xl border border-line bg-panel-2 px-3 py-2 text-sm">
          <div className="font-medium">
            {event.process || "unknown"}{" "}
            <span className="text-xs text-muted">pid {event.pid}</span>
          </div>
          {event.path ? (
            <div className="mt-0.5 truncate text-xs text-muted">{event.path}</div>
          ) : null}
          <div className="mt-1 font-mono text-xs">
            {event.proto} {event.dest}:{event.port} · {event.count} hit
            {event.count === 1 ? "" : "s"}
          </div>
        </div>
        <label className="mt-3 text-xs text-muted">
          Type LEAK to allow this destination (security flaw)
          <Input
            className="mt-1"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
          />
        </label>
        <div className="mt-4 flex flex-col gap-2">
          <Button variant="danger" disabled={busy} onClick={onKeepBlocked}>
            Keep blocked
          </Button>
          <Button
            variant="secondary"
            disabled={busy || !canAllow}
            onClick={onAllow}
          >
            Allow this destination
          </Button>
          <Button variant="secondary" disabled={busy} onClick={onReview}>
            Review on Verify
          </Button>
        </div>
      </div>
    </div>
  );
}
