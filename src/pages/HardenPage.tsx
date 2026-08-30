import { useEffect, useMemo, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { InfoTip, type TipTone } from "@/components/ui/tooltip";
import type { TorApp } from "@/hooks/useTorApp";
import type { HardenItem, KillSiriStatus, MacPortsStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

function Group({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted">
        {title}
      </h3>
      <div className="divide-y divide-line/80 overflow-hidden rounded-lg border border-line bg-panel">
        {children}
      </div>
    </div>
  );
}

function HardenRow({
  h,
  busy,
  onApply,
  description,
  highlight,
}: {
  h: HardenItem;
  busy: boolean;
  onApply: (id: string, enable: boolean) => void;
  description?: string;
  highlight?: boolean;
}) {
  return (
    <div
      data-harden-id={h.id}
      className={cn(
        "flex items-center justify-between gap-3 px-3 py-2 transition-colors",
        highlight && "bg-accent/10 ring-1 ring-inset ring-accent/50",
      )}
    >
      <div className="min-w-0">
        <div className="inline-flex min-w-0 items-center gap-1.5 text-[13px] font-medium text-ink">
          <span className="truncate">{h.title}</span>
          <HardenInfo h={h} />
        </div>
        {description ? (
          <p className="truncate text-[11px] leading-tight text-muted">
            {description}
          </p>
        ) : null}
      </div>
      <div className="shrink-0">
        <HardenControl h={h} busy={busy} onApply={onApply} />
      </div>
    </div>
  );
}

function stateChip(h: HardenItem): { label: string; tone: TipTone } {
  if (!h.supported) return { label: "Unsupported", tone: "default" };
  switch (h.control) {
    case "install":
      return h.active
        ? { label: "Installed", tone: "ok" }
        : { label: "Not installed", tone: "default" };
    case "link":
      return h.active
        ? { label: "Installed", tone: "ok" }
        : { label: "Available", tone: "accent" };
    case "guide":
      return h.active
        ? { label: "On", tone: "ok" }
        : { label: "Guide", tone: "default" };
    case "action":
      return { label: "Ready", tone: "accent" };
    default:
      return h.active
        ? { label: "On", tone: "ok" }
        : { label: "Off", tone: "default" };
  }
}

function HardenInfo({ h }: { h: HardenItem }) {
  const isLockdown = h.group === "lockdown";
  return (
    <InfoTip
      className={isLockdown ? "text-warn hover:text-warn" : undefined}
      title={h.title}
      status={stateChip(h)}
      description={h.description}
      detail={h.detail}
      risk={h.risk || undefined}
      riskTone={isLockdown ? "danger" : "warn"}
    />
  );
}

function HardenControl({
  h,
  busy,
  onApply,
}: {
  h: HardenItem;
  busy: boolean;
  onApply: (id: string, enable: boolean) => void;
}) {
  if (h.control === "install") {
    // Install needs a supported env (e.g. MacPorts for Kill Siri).
    // Uninstall stays available if a prior install is still active.
    return (
      <div className="flex gap-2">
        <Button
          size="sm"
          disabled={busy || !h.supported || h.active}
          onClick={() => onApply(h.id, true)}
        >
          Install
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy || !h.active}
          onClick={() => onApply(h.id, false)}
        >
          Uninstall
        </Button>
      </div>
    );
  }
  if (h.control === "link" || h.control === "guide" || h.control === "action") {
    return (
      <Button
        size="sm"
        variant="secondary"
        disabled={busy || !h.supported}
        onClick={() => onApply(h.id, true)}
      >
        {h.control === "link"
          ? h.active
            ? "Open guide"
            : "Download"
          : h.control === "action"
            ? "Run"
            : "Open"}
      </Button>
    );
  }
  return (
    <Switch
      checked={h.active}
      disabled={busy || !h.supported}
      aria-label={h.title}
      onCheckedChange={(enable) => onApply(h.id, enable)}
    />
  );
}

export function HardenPage({ app }: { app: TorApp }) {
  const {
    harden,
    detect,
    busy,
    run,
    refreshHarden,
    refreshSettings,
    hardenFocusId,
    setHardenFocusId,
  } = app;

  const os = detect?.os ?? "";
  const isMac = os === "macos";
  const isLinux = os === "linux";
  const isWindows = os === "windows";

  const [killStatus, setKillStatus] = useState<KillSiriStatus | null>(null);
  const [ports, setPorts] = useState<MacPortsStatus | null>(null);
  const [showProcs, setShowProcs] = useState(false);

  const refreshExtras = async () => {
    if (!isMac) return;
    try {
      setKillStatus(await invoke<KillSiriStatus>("get_kill_siri_status"));
      setPorts(await invoke<MacPortsStatus>("get_macports_status"));
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    void refreshHarden();
  }, [refreshHarden]);

  // Checkup hands off a control id; reveal that row, then drop the highlight.
  useEffect(() => {
    if (!hardenFocusId || harden.length === 0) return;
    document
      .querySelector(`[data-harden-id="${hardenFocusId}"]`)
      ?.scrollIntoView({ block: "center", behavior: "smooth" });
    const timer = window.setTimeout(() => setHardenFocusId(null), 2500);
    return () => window.clearTimeout(timer);
  }, [hardenFocusId, harden.length, setHardenFocusId]);

  useEffect(() => {
    void refreshExtras();
    if (!isMac) return;
    const id = window.setInterval(() => void refreshExtras(), 8000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isMac]);

  const groups = useMemo(() => {
    const privacy = harden.filter((h) => h.group === "privacy");
    const security = harden.filter((h) => h.group === "security");
    const tools = harden.filter((h) => h.group === "tools");
    const lockdown = harden.filter((h) => h.group === "lockdown");
    return { privacy, security, tools, lockdown };
  }, [harden]);

  const apply = (id: string, enable: boolean) => {
    void run(async () => {
      const msg = await invoke<string>("apply_harden", { id, enable });
      await refreshHarden();
      await refreshSettings();
      await refreshExtras();
      return msg;
    });
  };

  const platformBadge = isMac
    ? "macOS"
    : isLinux
      ? "Linux"
      : isWindows
        ? "Windows"
        : "Unknown";

  return (
    <section className="flex flex-col gap-3">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-xl font-semibold tracking-tight">Harden</h2>
          <p className="text-xs text-muted">
            Reversible {platformBadge} privacy &amp; security changes · details
            in (i)
          </p>
        </div>
        <span className="inline-flex items-center gap-1 rounded-md border border-line bg-panel px-2 py-0.5 text-[11px] font-semibold text-ink">
          {isMac ? (
            <span aria-hidden className="text-[12px]">
              {"\uF8FF"}
            </span>
          ) : null}
          {platformBadge}
        </span>
      </header>

      {isLinux ? (
        <div className="rounded-lg border border-line bg-panel px-4 py-6 text-center">
          <p className="text-sm font-medium text-ink">
            No additional Linux OS controls
          </p>
          <p className="mx-auto mt-1 max-w-sm text-xs text-muted">
            Tor, TUN, the kill switch, hosting, and verification are available.
            System-wide privacy preferences remain managed by your distribution.
          </p>
        </div>
      ) : null}

      {isMac ? (
        <div className="rounded-xl border border-accent/40 bg-accent/10 px-3.5 py-3">
          <div className="text-sm font-semibold text-ink">
            Recommended between restarts
          </div>
          <p className="mt-1 text-xs text-muted">
            OnionGate does not block the network at power-on. If you want no
            clearnet between startups, turn on{" "}
            <span className="font-medium text-ink">Block the network at boot</span>
            {" "}
            (covers Wi‑Fi, Ethernet, and USB),{" "}
            <span className="font-medium text-ink">Start OnionGate at login</span>,
            and <span className="font-medium text-ink">Connect on launch</span>{" "}
            in Settings. Wi‑Fi off at boot only stops the radio from probing —
            it does not cover Ethernet.
          </p>
        </div>
      ) : null}

      {isMac && killStatus ? (
        <div className="rounded-lg border border-line bg-panel px-3 py-2 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="font-medium text-ink">Siri process monitor</div>
              <p className="truncate text-muted">{killStatus.detail}</p>
            </div>
            <Button
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await refreshExtras();
                  return "Siri monitor refreshed";
                })
              }
            >
              Refresh
            </Button>
          </div>
          {killStatus.running.length > 0 ? (
            <button
              type="button"
              className="mt-1 text-[11px] text-muted underline-offset-2 hover:underline"
              onClick={() => setShowProcs((v) => !v)}
            >
              {showProcs ? "Hide" : "Show"} running (
              {killStatus.running.length}/{killStatus.total_watched})
            </button>
          ) : null}
          {showProcs ? (
            <ul className="mt-1 list-inside list-disc text-[11px] text-muted">
              {killStatus.running.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {isMac && ports && !ports.installed ? (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line bg-panel px-3 py-2 text-xs">
          <div className="min-w-0">
            <div className="font-medium text-ink">MacPorts</div>
            <p className="truncate text-muted">{ports.detail}</p>
          </div>
          <Button
            size="sm"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                const msg = await invoke<string>("open_macports_download");
                await refreshExtras();
                return msg;
              })
            }
          >
            Download pkg
          </Button>
        </div>
      ) : null}

      {isMac ? (
        <>
          {groups.privacy.length ? (
            <Group title="Privacy">
              {groups.privacy.map((h) => (
                <HardenRow
                  key={h.id}
                  h={h}
                  busy={busy}
                  onApply={apply}
                  highlight={h.id === hardenFocusId}
                  description={
                    h.supported
                      ? undefined
                      : h.detail || "Unsupported"
                  }
                />
              ))}
            </Group>
          ) : null}

          {groups.security.length ? (
            <Group title="Security">
              {groups.security.map((h) => (
                <HardenRow
                  key={h.id}
                  h={h}
                  busy={busy}
                  onApply={apply}
                  highlight={h.id === hardenFocusId}
                  description={h.supported ? undefined : "Unsupported"}
                />
              ))}
            </Group>
          ) : null}

          {groups.tools.length ? (
            <Group title="Tools">
              {groups.tools.map((h) => (
                <HardenRow
                  key={h.id}
                  h={h}
                  busy={busy}
                  onApply={apply}
                  highlight={h.id === hardenFocusId}
                />
              ))}
            </Group>
          ) : null}

          {groups.lockdown.length ? (
            <div className="space-y-1.5 border-t border-line pt-3">
              <Group title="Lockdown Mode">
                {groups.lockdown.map((h) => (
                  <HardenRow
                    key={h.id}
                    h={h}
                    busy={busy}
                    onApply={apply}
                    description={
                      h.supported
                        ? "Invasive — read (i) first"
                        : "Unsupported on this macOS"
                    }
                  />
                ))}
              </Group>
            </div>
          ) : null}
        </>
      ) : null}

      {!isMac && !isLinux ? (
        <div className="rounded-lg border border-line bg-panel px-4 py-6 text-center">
          <p className="text-sm font-medium text-ink">
            No additional OS controls
          </p>
          <p className="mx-auto mt-1 max-w-sm text-xs text-muted">
            Tor, TUN, the kill switch, hosting, and verification are available.
            System privacy preferences remain managed by your operating system.
          </p>
        </div>
      ) : null}

    </section>
  );
}
