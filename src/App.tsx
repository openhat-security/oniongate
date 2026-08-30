import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Globe,
  Home,
  Loader2,
  PanelLeftClose,
  PanelLeftOpen,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  type LucideIcon,
} from "lucide-react";
import { useTorApp } from "@/hooks/useTorApp";
import { useAppVersion } from "@/hooks/useAppVersion";
import { ProjectLink } from "@/components/ProjectLink";
import { ConnectPage } from "@/pages/ConnectPage";
import { AppsPage } from "@/pages/AppsPage";
import { VerifyPage } from "@/pages/VerifyPage";
import { OnionHostPage } from "@/pages/OnionHostPage";
import { SystemPage } from "@/pages/SystemPage";
import { AppSettingsPage } from "@/pages/AppSettingsPage";
import { Flash } from "@/components/Flash";
import { SetupWizard } from "@/components/SetupWizard";
import { ClearnetAlert } from "@/components/ClearnetAlert";
import { DenyAlert } from "@/components/DenyAlert";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipProvider } from "@/components/ui/tooltip";
import type { KillClearnetIdentityResult, Tab } from "@/lib/types";
import {
  armReopenThroughTor,
  claimReopenThroughTor,
  disarmReopenThroughTor,
  finishReopenThroughTor,
  isProtectedThroughTun,
  isTunRoute,
  listReopenableApps,
  reopenClosedApps,
  useReopenRequest,
  type ReopenPhase,
} from "@/lib/reopen";
import { cn } from "@/lib/utils";
import { effectiveLocale } from "@/lib/i18n";
import { releaseChannel } from "@/lib/release";
import { startWindowDrag } from "@/lib/drag";
import {
  readSidebarCollapsed,
  setWindowCollapsed,
  SIDEBAR_STORAGE_KEY,
} from "@/lib/window";

const NAV: { id: Tab; label: string; icon: LucideIcon }[] = [
  { id: "home", label: "Connect", icon: Home },
  { id: "apps", label: "Apps", icon: Sparkles },
  { id: "host", label: "Host", icon: Globe },
  { id: "verify", label: "Verify", icon: ShieldCheck },
  { id: "system", label: "System", icon: Shield },
  { id: "settings", label: "Settings", icon: SlidersHorizontal },
];

export default function App() {
  const app = useTorApp();
  const version = useAppVersion();
  const channel = releaseChannel(version);
  const locale = effectiveLocale(app.settings?.locale);
  const showWizard = !!app.settings && !app.settings.setup_complete;

  const [collapsed, setCollapsed] = useState<boolean>(() =>
    readSidebarCollapsed(),
  );
  const [clearnetAlert, setClearnetAlert] = useState(false);
  const [clearnetAlertDismissed, setClearnetAlertDismissed] = useState(false);

  const reopen = useReopenRequest();
  const reopenReady = isProtectedThroughTun(app);
  const tunRoute = isTunRoute(app);

  // The single place that fires a reopen. Surfaces only arm the request; apps
  // are relaunched here, after the session reports verified Protected over TUN.
  useEffect(() => {
    if (reopen.phase !== "armed" || !reopenReady) return;
    if (!claimReopenThroughTor()) return;
    void app.run(async () => {
      try {
        return await reopenClosedApps();
      } finally {
        finishReopenThroughTor();
      }
    });
  }, [reopen.phase, reopenReady, app.run]);

  // A reopen waiting on a session that never arrived (failed connect) or that
  // went away (disconnect) would never fire, so drop it once the session is
  // settled at disconnected with nothing in flight.
  useEffect(() => {
    if (reopen.phase !== "armed") return;
    if (app.busy || app.status?.session_phase !== "disconnected") return;
    disarmReopenThroughTor();
  }, [reopen.phase, app.busy, app.status?.session_phase]);

  useEffect(() => {
    if (!app.torOn) {
      setClearnetAlert(false);
      setClearnetAlertDismissed(false);
      return;
    }
    if (app.status?.session_phase === "connecting") return;
    const processes = app.egressWatch?.clearnet_processes ?? [];
    if (clearnetAlert && processes.length === 0) {
      setClearnetAlert(false);
      return;
    }
    if (clearnetAlertDismissed || clearnetAlert) return;
    if (!app.egressWatch?.watching || processes.length === 0) return;
    setClearnetAlert(true);
  }, [app.torOn, app.status?.session_phase, app.egressWatch, clearnetAlert, clearnetAlertDismissed]);

  useEffect(() => {
    let disposed = false;
    let stopListening: (() => void) | undefined;
    void listen<string>("tray:navigate", ({ payload }) => {
      if (payload === "verify") {
        app.setTab("verify");
      } else if (payload === "host") {
        app.setTab("host");
      } else if (payload === "logs") {
        app.setSettingsView("logs");
        app.setTab("settings");
      }
    }).then((unlisten) => {
      if (disposed) unlisten();
      else stopListening = unlisten;
    });
    return () => {
      disposed = true;
      stopListening?.();
    };
  }, [app.setSettingsView, app.setTab]);

  const toggleSidebar = () =>
    setCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(SIDEBAR_STORAGE_KEY, next ? "1" : "0");
      } catch {
        /* ignore storage errors */
      }
      // Shrink/grow the whole window, not just the rail.
      void setWindowCollapsed(next);
      return next;
    });

  return (
    <TooltipProvider>
      <div
        dir={locale === "fa" ? "rtl" : "ltr"}
        className="flex h-screen min-h-0 w-full overflow-hidden bg-transparent"
      >
        {showWizard ? <SetupWizard app={app} /> : null}
        <aside
          className={cn(
            "relative z-20 flex shrink-0 flex-col rail-surface text-rail-ink border-r border-white/[0.06] shadow-[8px_0_28px_-20px_rgba(0,0,0,0.8)] transition-[width] duration-200 ease-out",
            collapsed ? "w-[88px]" : "w-56",
          )}
        >
          <div
            data-tauri-drag-region
            onMouseDown={startWindowDrag}
            className={cn(
              "flex items-center gap-2.5 pb-4 pt-14",
              collapsed ? "justify-center px-0" : "px-4",
            )}
          >
            <img
              src="/logo.png"
              alt="OnionGate"
              className={cn(
                "shrink-0 rounded-xl shadow-sm",
                collapsed ? "h-12 w-12" : "h-10 w-10",
              )}
              draggable={false}
            />
            {!collapsed ? (
              <div className="min-w-0">
                <div className="truncate text-[15px] font-semibold tracking-tight text-rail-ink">
                  OnionGate
                </div>
                {version ? (
                  <div className="truncate text-[10px] text-rail-muted">
                    {version} {channel}
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>

          <nav
            className="flex flex-1 flex-col gap-1 overflow-y-auto px-2.5 pb-3"
            aria-label="Primary"
          >
            {NAV.map(({ id, label, icon: Icon }) => {
              const active = app.tab === id;
              const badge =
                id === "system" && (app.status?.persistence_changes ?? 0) > 0
                  ? app.status?.persistence_changes
                  : null;
              const button = (
                <button
                  key={id}
                  type="button"
                  onClick={() => app.setTab(id)}
                  aria-label={label}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "relative flex items-center rounded-xl text-sm font-medium transition-colors",
                    collapsed
                      ? "h-12 w-12 justify-center self-center"
                      : "gap-3 px-3 py-2.5",
                    active
                      ? "bg-rail-active text-white shadow-[0_6px_16px_-6px_rgba(124,58,237,0.6)]"
                      : "text-rail-muted hover:bg-rail-2 hover:text-rail-ink",
                  )}
                >
                  <Icon
                    className={cn("shrink-0", collapsed ? "h-6 w-6" : "h-5 w-5")}
                    strokeWidth={1.9}
                  />
                  {!collapsed ? (
                    <span className="flex min-w-0 flex-1 items-center justify-between gap-1.5">
                      <span className="truncate">{label}</span>
                      {badge != null ? (
                        <span className="rounded bg-warn/20 px-1 text-[9px] font-semibold text-warn-strong">
                          {badge}
                        </span>
                      ) : null}
                    </span>
                  ) : badge != null ? (
                    <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-warn ring-2 ring-rail" />
                  ) : null}
                </button>
              );
              return collapsed ? (
                <Tooltip key={id} label={label} side="right">
                  {button}
                </Tooltip>
              ) : (
                button
              );
            })}
          </nav>

          <div
            className={cn(
              "mt-auto border-t border-white/[0.06]",
              collapsed ? "px-2 py-3 text-center" : "px-3.5 py-3",
            )}
          >
            {!collapsed ? (
              <p className="truncate text-[10px] text-rail-muted">
                {app.protectionLabel}
              </p>
            ) : null}
            {collapsed && version ? (
              <p className="text-[10px] leading-tight text-rail-muted">
                {version}
                <br />
                {channel}
              </p>
            ) : null}
            {!collapsed ? (
              <div className="mt-1.5 flex flex-col items-start gap-0.5 text-[10px] text-rail-muted">
                <ProjectLink
                  link="docs"
                  className="text-rail-muted hover:text-rail-ink"
                >
                  See the docs
                </ProjectLink>
                <ProjectLink
                  link="github"
                  className="text-rail-muted hover:text-rail-ink"
                >
                  OpenHat Security
                </ProjectLink>
              </div>
            ) : null}
          </div>
        </aside>

        <main className="relative min-h-0 min-w-0 flex-1 overflow-y-auto">
          <div
            data-tauri-drag-region
            onMouseDown={startWindowDrag}
            className="absolute inset-x-0 top-0 z-10 h-11"
            aria-hidden
          />
          <button
            type="button"
            onClick={toggleSidebar}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="absolute left-3 top-2.5 z-20 flex h-8 w-8 items-center justify-center rounded-lg text-muted transition-colors hover:bg-panel-2 hover:text-ink"
          >
            {collapsed ? (
              <PanelLeftOpen className="h-[18px] w-[18px]" strokeWidth={1.9} />
            ) : (
              <PanelLeftClose className="h-[18px] w-[18px]" strokeWidth={1.9} />
            )}
          </button>
          <Flash
            message={app.message}
            error={app.error}
            onDismiss={app.clearFlash}
          />
          <ReopenPending
            phase={reopen.phase}
            count={reopen.apps.length}
            onCancel={disarmReopenThroughTor}
          />
          {clearnetAlert ? (
            <ClearnetAlert
              processes={app.egressWatch?.clearnet_processes ?? []}
              busy={app.busy}
              showReview
              tunRoute={tunRoute}
              onKill={() => {
                setClearnetAlert(false);
                setClearnetAlertDismissed(true);
                app.killClearnetAndNewIdentity();
              }}
              onKillAndReopen={() => {
                setClearnetAlert(false);
                setClearnetAlertDismissed(true);
                void app.run(async () => {
                  const result = await invoke<KillClearnetIdentityResult>(
                    "kill_clearnet_and_new_identity",
                  );
                  await app.refreshIps();
                  await app.refreshEgressWatch();
                  // Arm only after the processes are gone, so the watcher cannot
                  // relaunch an app that is still holding a clearnet socket.
                  armReopenThroughTor(await listReopenableApps().catch(() => []));
                  return `${result.detail} They reopen through Tor once the session is verified Protected.`;
                });
              }}
              onReview={() => {
                setClearnetAlert(false);
                setClearnetAlertDismissed(true);
                app.setVerifyFlowFilter("clearnet");
                app.setTab("verify");
              }}
              onDismiss={() => {
                setClearnetAlert(false);
                setClearnetAlertDismissed(true);
              }}
            />
          ) : null}
          {app.denyLog?.events.find((e) => e.needs_popup) ? (
            <DenyAlert
              event={app.denyLog.events.find((e) => e.needs_popup)!}
              busy={app.busy}
              onKeepBlocked={() => {
                const event = app.denyLog?.events.find((e) => e.needs_popup);
                if (!event) return;
                void invoke("acknowledge_deny", {
                  process: event.process,
                  dest: event.dest,
                  port: event.port,
                  proto: event.proto,
                }).then(() => app.refreshDenyLog());
              }}
              onAllow={() => {
                const event = app.denyLog?.events.find((e) => e.needs_popup);
                if (!event) return;
                void app.run(async () => {
                  await invoke("acknowledge_deny", {
                    process: event.process,
                    dest: event.dest,
                    port: event.port,
                    proto: event.proto,
                  });
                  const msg = await invoke<string>("add_strict_exception", {
                    dest: event.dest,
                    persist: false,
                  });
                  await app.refreshDenyLog();
                  await app.refreshSettings();
                  return msg;
                });
              }}
              onReview={() => {
                const event = app.denyLog?.events.find((e) => e.needs_popup);
                if (event) {
                  void invoke("acknowledge_deny", {
                    process: event.process,
                    dest: event.dest,
                    port: event.port,
                    proto: event.proto,
                  }).then(() => app.refreshDenyLog());
                }
                app.setTab("verify");
              }}
            />
          ) : null}
          <div className="mx-auto min-h-full w-full max-w-4xl px-6 pb-5 pt-11 animate-[fade-in_280ms_ease-out]">
            {app.tab === "home" ? <ConnectPage app={app} /> : null}
            {app.tab === "apps" ? <AppsPage app={app} /> : null}
            {app.tab === "host" ? <OnionHostPage app={app} /> : null}
            {app.tab === "verify" ? <VerifyPage app={app} /> : null}
            {app.tab === "system" ? <SystemPage app={app} /> : null}
            {app.tab === "settings" ? <AppSettingsPage app={app} /> : null}
          </div>
        </main>
      </div>
    </TooltipProvider>
  );
}

/**
 * Shows that closed applications are queued to reopen and that OnionGate is
 * still waiting for verified protection before relaunching them.
 */
function ReopenPending({
  phase,
  count,
  onCancel,
}: {
  phase: ReopenPhase;
  count: number;
  onCancel: () => void;
}) {
  if (phase === "idle") return null;
  const apps = count === 1 ? "1 app" : `${count} apps`;

  return (
    <div
      className="absolute inset-x-0 top-11 z-30 mx-auto flex w-full max-w-md items-center gap-2.5 rounded-xl border border-onion/45 bg-panel px-3.5 py-2.5 shadow-lg"
      role="status"
      aria-live="polite"
    >
      <Loader2 className="h-4 w-4 shrink-0 animate-spin text-onion" />
      <p className="min-w-0 flex-1 text-xs leading-snug text-ink">
        {phase === "running"
          ? `Reopening ${count > 0 ? apps : "closed apps"} through Tor…`
          : `Waiting for verified Protected over TUN before reopening ${
              count > 0 ? apps : "closed apps"
            }.`}
      </p>
      {phase === "armed" ? (
        <Button size="sm" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      ) : null}
    </div>
  );
}
