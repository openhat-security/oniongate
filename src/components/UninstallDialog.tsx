import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { CopyButton } from "@/components/ui/copy-button";
import { cn } from "@/lib/utils";

/**
 * Uninstalling is destructive and needs administrator rights, so it is never a
 * one-click control: the user acknowledges what goes away first.
 *
 * `open_uninstaller` only succeeds on .pkg installs, which are the only builds
 * that carry the uninstaller. On a DMG or source build it fails with the script
 * to run instead — that message is the useful part, so it is shown verbatim.
 */
export function UninstallDialog({ onClose }: { onClose: () => void }) {
  const [ack, setAck] = useState(false);
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(
    null,
  );

  const openUninstaller = () => {
    setPending(true);
    setResult(null);
    void invoke<string>("open_uninstaller")
      .then((text) => setResult({ ok: true, text }))
      .catch((e) =>
        setResult({ ok: false, text: typeof e === "string" ? e : String(e) }),
      )
      .finally(() => setPending(false));
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="uninstall-title"
    >
      <div className="flex max-h-[min(34rem,90vh)] w-full max-w-md flex-col overflow-y-auto rounded-2xl border border-line bg-panel p-5 shadow-xl">
        <h2
          id="uninstall-title"
          className="text-base font-semibold tracking-tight"
        >
          Uninstall OnionGate
        </h2>
        <p className="mt-2 text-sm text-muted">
          The uninstaller quits OnionGate, then removes it from this Mac. It asks
          for your administrator password because it has to undo system changes.
        </p>
        <ul className="mt-3 space-y-1.5 rounded-xl border border-line bg-panel-2 px-3.5 py-2.5 text-xs text-muted">
          <li>
            Removes the app, the privileged helper and its launch daemon, and the
            pinned sing-box.
          </li>
          <li>
            Reverts what OnionGate changed on the host: the pf anchors, the boot
            network lock and Wi‑Fi-off-at-boot daemons, the system SOCKS proxy
            setting, and the shell hooks.
          </li>
          <li>
            Any active Tor route ends immediately. Apps you were routing lose
            their tunnel.
          </li>
          <li className="text-ink">
            Your data directory is kept, including settings, logs, and the keys
            for permanent Onion Host sites. Deleting it is a separate, explicit
            step in the uninstaller.
          </li>
        </ul>

        {result ? (
          <div
            className={cn(
              "mt-3 rounded-xl border px-3.5 py-2.5",
              result.ok
                ? "border-accent/45 bg-panel-2"
                : "border-warn/50 bg-warn/10",
            )}
          >
            <div
              className={cn(
                "text-[11px] font-semibold uppercase tracking-wide",
                result.ok ? "text-accent" : "text-warn-strong",
              )}
            >
              {result.ok ? "Uninstaller opened" : "No uninstaller in this build"}
            </div>
            <p className="mt-1 whitespace-pre-wrap break-words font-mono text-[11px] leading-snug text-ink">
              {result.text}
            </p>
            {!result.ok ? (
              <div className="mt-1.5 flex justify-end">
                <CopyButton value={result.text} label="Copy" />
              </div>
            ) : null}
          </div>
        ) : null}

        {!result?.ok ? (
          <label className="mt-3 flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              className="mt-1"
              checked={ack}
              onChange={(event) => setAck(event.target.checked)}
            />
            <span>
              I want to remove OnionGate and undo the system changes it made.
            </span>
          </label>
        ) : null}

        <div className="mt-4 flex flex-col gap-2">
          {!result?.ok ? (
            <Button
              variant="danger"
              disabled={!ack || pending}
              onClick={openUninstaller}
            >
              {pending ? "Opening the uninstaller…" : "Open the uninstaller"}
            </Button>
          ) : null}
          <Button variant="secondary" disabled={pending} onClick={onClose}>
            {result?.ok ? "Done" : "Cancel"}
          </Button>
        </div>
      </div>
    </div>
  );
}
