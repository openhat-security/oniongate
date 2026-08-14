import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import type { TorApp } from "@/hooks/useTorApp";
import type { AppSettings } from "@/lib/types";
import { PRESETS, presetPatch, type PresetId } from "@/lib/presets";
import { StrictLockConsent } from "@/components/DenyAlert";
import { cn } from "@/lib/utils";
import { startWindowDrag } from "@/lib/drag";

const STEPS = ["Welcome", "Choose a preset", "Permissions", "Finish"];

export function SetupWizard({ app }: { app: TorApp }) {
  const isMac = app.detect?.os === "macos";
  const [step, setStep] = useState(0);
  const [preset, setPreset] = useState<PresetId>("everyday");
  const [lockConsent, setLockConsent] = useState(false);
  const [adminState, setAdminState] = useState<"idle" | "granted" | "failed">(
    "idle",
  );
  const dialogRef = useRef<HTMLDivElement>(null);

  const chosen = PRESETS.find((item) => item.id === preset);

  const finish = () => {
    if (preset === "maximum") {
      setLockConsent(true);
      return;
    }
    void app.run(async () => {
      if (app.settings) {
        await invoke<AppSettings>("update_settings", {
          next: { ...app.settings, ...presetPatch(preset) },
        });
      }
      await invoke<AppSettings>("set_setup_complete", { done: true });
      await app.refreshSettings();
      return `Setup complete — applied the ${chosen?.label ?? preset} preset`;
    });
  };

  const finishMaximum = () =>
    void app.run(async () => {
      if (app.settings) {
        await invoke<AppSettings>("update_settings", {
          next: { ...app.settings, ...presetPatch("maximum") },
        });
      }
      await invoke<AppSettings>("set_setup_complete", { done: true });
      await app.refreshSettings();
      return "Setup complete — applied Maximum Isolation";
    });

  const skip = () =>
    void app.run(async () => {
      await invoke<AppSettings>("set_setup_complete", { done: true });
      await app.refreshSettings();
      return "Setup skipped — you can change everything later in Connect, System, and Settings";
    });

  const grantAdmin = () =>
    void app.run(async () => {
      try {
        const message = await invoke<string>("prime_admin_auth");
        setAdminState("granted");
        return message;
      } catch (error) {
        setAdminState("failed");
        throw error;
      }
    });

  // Modal focus management: focus the dialog on open/step change, trap Tab
  // within it, and let Escape skip setup.
  useEffect(() => {
    const node = dialogRef.current;
    if (!node) return;
    const getFocusable = () =>
      Array.from(
        node.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((el) => !el.hasAttribute("disabled"));
    getFocusable()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        skip();
        return;
      }
      if (event.key !== "Tab") return;
      const items = getFocusable();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    node.addEventListener("keydown", onKeyDown);
    return () => node.removeEventListener("keydown", onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-canvas/80 backdrop-blur-sm">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="setup-wizard-title"
        className="mx-4 flex w-full max-w-lg flex-col overflow-hidden rounded-2xl border border-line bg-panel shadow-xl"
      >
        <div
          data-tauri-drag-region
          onMouseDown={startWindowDrag}
          className="flex items-center gap-2.5 border-b border-line px-5 py-4"
        >
          <img
            src="/logo.png"
            alt="OnionGate"
            className="h-7 w-7 shrink-0"
            draggable={false}
          />
          <div className="min-w-0">
            <div id="setup-wizard-title" className="text-sm font-semibold tracking-tight">
              OnionGate setup
            </div>
            <div className="text-[11px] text-muted">
              Step {step + 1} of {STEPS.length} · {STEPS[step]}
            </div>
          </div>
        </div>

        <div className="flex gap-1 px-5 pt-3" aria-hidden>
          {STEPS.map((label, index) => (
            <span
              key={label}
              className={cn(
                "h-1 flex-1 rounded-full",
                index <= step ? "bg-onion" : "bg-line",
              )}
            />
          ))}
        </div>

        <div className="min-h-[15rem] px-5 py-4">
          {step === 0 ? (
            <div className="space-y-3">
              <h2 className="text-lg font-semibold tracking-tight">
                Route apps through Tor, safely
              </h2>
              <p className="text-sm text-muted">
                OnionGate manages Tor, gives selected apps isolated circuits, lets you
                host localhost as a temporary or permanent onion site, and inspects the
                live routing and leak-prevention boundary.
              </p>
              <p className="rounded-lg border border-line bg-canvas px-3 py-2 text-xs text-muted">
                This build is <span className="font-semibold text-ink">alpha</span> — not
                a sole control for high-risk work. It is not a VPN, Tor Browser, or
                antivirus. Read the threat model and residual leaks before relying on
                it. This wizard sets defaults you can change anytime.
              </p>
            </div>
          ) : null}

          {step === 1 ? (
            <div className="space-y-2">
              <p className="text-sm text-muted">
                Pick how you want to connect. You can switch presets later under
                Settings.
              </p>
              <div className="space-y-1.5">
                {PRESETS.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setPreset(item.id)}
                    className={cn(
                      "w-full rounded-lg border px-3 py-2 text-left transition-colors",
                      preset === item.id
                        ? "border-onion bg-onion/10"
                        : "border-line bg-canvas hover:border-onion/50",
                    )}
                  >
                    <div className="flex items-center gap-2 text-[13px] font-semibold">
                      <span
                        className={cn(
                          "h-2.5 w-2.5 shrink-0 rounded-full border",
                          preset === item.id
                            ? "border-onion bg-onion"
                            : "border-line",
                        )}
                      />
                      {item.label}
                    </div>
                    <p className="mt-0.5 pl-[18px] text-[11px] leading-tight text-muted">
                      {item.description}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          ) : null}

          {step === 2 ? (
            <div className="space-y-3">
              <p className="text-sm text-muted">
                Turning on the system proxy, TUN, or firewall changes system settings and
                needs administrator access. Approving once now means OnionGate won't prompt
                again for a while.
              </p>
              <div className="flex items-center gap-2">
                <Button variant="secondary" disabled={app.busy} onClick={grantAdmin}>
                  Grant administrator access
                </Button>
                {adminState === "granted" ? (
                  <span className="text-xs font-semibold text-accent">Granted</span>
                ) : adminState === "failed" ? (
                  <span className="text-xs font-semibold text-warn">
                    Not granted — you can approve later
                  </span>
                ) : null}
              </div>
              {isMac ? (
                <div className="rounded-lg border border-line bg-canvas px-3 py-2">
                  <div className="text-xs font-semibold">
                    Optional: Full Disk Access
                  </div>
                  <p className="mt-0.5 text-[11px] text-muted">
                    Only needed to scan Background/Login Items in System → Startup Items.
                    Grant it once; OnionGate never scans it automatically.
                  </p>
                  <Button
                    className="mt-2"
                    size="sm"
                    variant="ghost"
                    disabled={app.busy}
                    onClick={() =>
                      void app.run(async () =>
                        invoke<string>("open_full_disk_access_settings"),
                      )
                    }
                  >
                    Open Full Disk Access settings
                  </Button>
                </div>
              ) : null}
              <p className="text-[11px] text-muted">
                This step is optional — skip it and OnionGate will ask only when a feature
                actually needs it.
              </p>
            </div>
          ) : null}

          {step === 3 ? (
            <div className="space-y-3">
              <h2 className="text-lg font-semibold tracking-tight">You're ready</h2>
              <div className="rounded-lg border border-line bg-canvas px-3 py-2">
                <div className="text-[13px] font-semibold">{chosen?.label}</div>
                <p className="mt-0.5 text-[11px] text-muted">{chosen?.description}</p>
              </div>
              <p className="text-sm text-muted">
                After connecting, open <span className="font-medium text-ink">Verify</span>{" "}
                to inspect egress, DNS, and the live protection controls.
              </p>
            </div>
          ) : null}
        </div>

        <div className="flex items-center justify-between gap-2 border-t border-line px-5 py-3">
          <Button variant="ghost" disabled={app.busy} onClick={skip}>
            Skip setup
          </Button>
          <div className="flex gap-2">
            {step > 0 ? (
              <Button
                variant="secondary"
                disabled={app.busy}
                onClick={() => setStep((value) => Math.max(0, value - 1))}
              >
                Back
              </Button>
            ) : null}
            {step < STEPS.length - 1 ? (
              <Button
                disabled={app.busy}
                onClick={() => setStep((value) => Math.min(STEPS.length - 1, value + 1))}
              >
                Continue
              </Button>
            ) : (
              <Button disabled={app.busy} onClick={finish}>
                Finish
              </Button>
            )}
          </div>
        </div>
      </div>
      {lockConsent ? (
        <StrictLockConsent
          onCancel={() => setLockConsent(false)}
          onConfirm={() => {
            setLockConsent(false);
            finishMaximum();
          }}
        />
      ) : null}
    </div>
  );
}
