import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Segmented } from "@/components/ui/segmented";
import { Switch } from "@/components/ui/switch";
import { InfoTip } from "@/components/ui/tooltip";
import type { TorApp } from "@/hooks/useTorApp";
import type {
  AppIdentity,
  AppSettings,
  NetworkTestResult,
  SplitAppPick,
} from "@/lib/types";
import { cn } from "@/lib/utils";

type AppsView = "bypass" | "split";
type AppRouteStatus = {
  id: string;
  running: boolean;
  routed: boolean;
  exit_ip: string | null;
  detail: string;
};

export function AppsPage({ app }: { app: TorApp }) {
  const {
    detect,
    shellProxy,
    settings,
    status,
    networkTest,
    setNetworkTest,
    busy,
    run,
    refreshDetect,
    refreshShellProxy,
    refreshSettings,
  } = app;

  const [view, setView] = useState<AppsView>("bypass");
  const [routeStatuses, setRouteStatuses] = useState<AppRouteStatus[]>([]);
  const [routeError, setRouteError] = useState<string | null>(null);
  const shellMode = (shellProxy?.mode as "off" | "auto" | "manual") || "off";

  useEffect(() => {
    if (view !== "split") return;
    void invoke<AppRouteStatus[]>("get_app_route_statuses")
      .then((list) => {
        setRouteStatuses(list);
        setRouteError(null);
      })
      .catch((error) => {
        setRouteStatuses([]);
        setRouteError(typeof error === "string" ? error : String(error));
      });
  }, [view, busy, status?.tun.running]);

  const saveRouting = (
    apps: AppIdentity[],
    options?: Partial<Pick<AppSettings, "split_tunnel" | "app_routing_policy" | "session_guard">>,
  ) =>
    void run(async () => {
      if (!settings) throw "Settings not loaded";
      const saved = await invoke<AppSettings>("set_app_routing", {
        enabled: options?.split_tunnel ?? settings.split_tunnel,
        policy: options?.app_routing_policy ?? settings.app_routing_policy,
        sessionGuard: options?.session_guard ?? settings.session_guard,
        apps,
      });
      await refreshSettings();
      if (status?.tun.running) {
        await invoke<string>("stop_tun");
        await invoke<string>("start_tun");
      }
      return `App routing: ${saved.route_apps.length} identit${saved.route_apps.length === 1 ? "y" : "ies"}`;
    });

  const addSplitApp = () =>
    void run(async () => {
      if (!settings) throw "Settings not loaded";
      const picked = await invoke<SplitAppPick | null>("pick_split_app");
      if (!picked) return "Cancelled";
      const identity: AppIdentity = {
        id: picked.id,
        label: picked.label,
        process_name: picked.process_name,
        executable_path: picked.executable_path,
        bundle_id: picked.bundle_id,
        signing_id: picked.signing_id,
        circuit_epoch: 0,
      };
      const next = settings.route_apps.some((app) => app.id === identity.id)
        ? settings.route_apps
        : [...settings.route_apps, identity];
      await invoke<AppSettings>("set_app_routing", {
        enabled: settings.split_tunnel,
        policy: settings.app_routing_policy,
        sessionGuard: settings.session_guard,
        apps: next,
      });
      await refreshSettings();
      return `Added ${picked.label} (${picked.bundle_id ?? picked.process_name})`;
    });

  const groups = [
    { key: "browsers", label: "Browsers" },
    { key: "apps", label: "Apps" },
  ] as const;

  return (
    <section className="flex flex-col gap-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Apps</h2>
        <p className="mt-1 text-sm text-muted">
          Detected on {detect?.os_label ?? "this device"} — route or configure
          tools that ignore the system proxy.
        </p>
      </header>

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-panel px-4 py-3">
        <div className="flex min-w-0 items-center gap-1.5">
          <div className="text-sm font-semibold">Shell proxy</div>
          <InfoTip
            content={
              shellProxy?.detail ??
              "Off / Auto / Manual. Auto and Manual write /etc/oniongate/env (admin required)."
            }
          />
          <p className="truncate text-xs text-muted">
            {shellProxy?.script_path
              ? shellProxy.script_path
              : "Terminal SOCKS env"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Segmented
            value={shellMode}
            disabled={busy}
            options={[
              { value: "off", label: "Off" },
              { value: "auto", label: "Auto" },
              { value: "manual", label: "Manual" },
            ]}
            onChange={(mode) =>
              void run(async () => {
                const msg = await invoke<string>("set_shell_proxy_mode", {
                  mode,
                });
                await refreshShellProxy();
                return msg;
              })
            }
          />
          <Button
            size="sm"
            variant="ghost"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                const result = await invoke<NetworkTestResult>("test_network");
                setNetworkTest(result);
                return result.message;
              })
            }
          >
            Test
          </Button>
        </div>
      </div>
      {networkTest ? (
        <p
          className={cn(
            "text-xs",
            networkTest.success ? "text-accent" : "text-danger",
          )}
        >
          {networkTest.success ? "Success" : "Failure"}
          {networkTest.direct_ip ? ` · direct ${networkTest.direct_ip}` : ""}
          {networkTest.tor_ip ? ` · tor ${networkTest.tor_ip}` : ""}
        </p>
      ) : null}

      <Segmented
        value={view}
        options={[
          { value: "bypass", label: "Bypass helpers" },
          { value: "split", label: "Split tunnel" },
        ]}
        onChange={setView}
      />

      {view === "bypass" ? (
        <div className="space-y-4">
          {!detect ? (
            <p className="text-sm text-muted">Scanning installed apps…</p>
          ) : detect.apps.length === 0 ? (
            <p className="text-sm text-muted">
              No known bypass-prone apps detected on this {detect.os_label}{" "}
              device.
            </p>
          ) : (
            groups.map(({ key, label }) => {
              const items = detect.apps.filter((i) => i.group === key);
              if (!items.length) return null;
              return (
                <div key={key} className="space-y-1.5">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
                    {label}
                  </h3>
                  {items.map((item) => (
                    <div
                      key={item.id}
                      className="flex items-center justify-between gap-3 rounded-xl border border-line bg-panel px-3.5 py-2.5"
                    >
                      <div className="flex min-w-0 items-center gap-2">
                        <span className="truncate text-sm font-semibold">
                          {item.title}
                        </span>
                        <InfoTip
                          content={
                            <>
                              <p>{item.description}</p>
                              {item.detail ? (
                                <p className="mt-1 text-muted">{item.detail}</p>
                              ) : null}
                              {item.note ? (
                                <p className="mt-1 text-warn">{item.note}</p>
                              ) : null}
                            </>
                          }
                        />
                        <span
                          className={cn(
                            "rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase",
                            item.configured
                              ? "bg-accent/15 text-accent"
                              : "bg-panel-2 text-muted",
                          )}
                        >
                          {item.configured ? "On" : "Off"}
                        </span>
                      </div>
                      <Switch
                        checked={item.configured}
                        disabled={busy}
                        onCheckedChange={(on) =>
                          void run(async () => {
                            const msg = on
                              ? await invoke<string>("configure_advanced_item", {
                                  id: item.id,
                                })
                              : await invoke<string>("remove_advanced_item", {
                                  id: item.id,
                                });
                            await refreshDetect();
                            return msg;
                          })
                        }
                      />
                    </div>
                  ))}
                </div>
              );
            })
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-1.5">
              <div className="text-sm font-semibold">Isolated app routing (TUN)</div>
              <InfoTip content="Apps are identified by bundle ID, executable path, and signing team. Routed apps receive distinct Tor SOCKS credentials and circuits." />
            </div>
            <Switch
              checked={settings?.split_tunnel ?? false}
              disabled={busy || !settings}
              aria-label="Isolated app routing (TUN)"
              onCheckedChange={(enabled) =>
                settings &&
                saveRouting(settings.route_apps, { split_tunnel: enabled })
              }
            />
          </div>
          {settings ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <label>
                <div className="mb-1 text-xs font-semibold text-muted">Policy</div>
                <Segmented
                  value={settings.app_routing_policy}
                  disabled={busy}
                  options={[
                    { value: "only", label: "Only selected via Tor" },
                    { value: "except", label: "All except selected" },
                  ]}
                  onChange={(policy) =>
                    saveRouting(settings.route_apps, {
                      app_routing_policy: policy,
                      session_guard:
                        policy === "only" ? settings.session_guard : false,
                    })
                  }
                />
              </label>
              <div className="flex items-center justify-between rounded-lg border border-line px-3 py-2">
                <div>
                  <div id="session-guard-label" className="text-xs font-semibold">
                    Session Guard
                  </div>
                  <div className="text-[10px] text-muted">Suspend selected apps if Tor drops</div>
                </div>
                <Switch
                  checked={settings.session_guard}
                  disabled={busy || settings.app_routing_policy !== "only"}
                  aria-labelledby="session-guard-label"
                  onCheckedChange={(session_guard) =>
                    saveRouting(settings.route_apps, { session_guard })
                  }
                />
              </div>
            </div>
          ) : null}
          {routeError ? (
            <p className="text-xs text-danger">
              Couldn't read per-app route status: {routeError}
            </p>
          ) : null}
          {settings?.route_apps.length ? (
            <div className="space-y-1.5">
              {settings.route_apps.map((identity) => {
                const route = routeStatuses.find((item) => item.id === identity.id);
                return (
                  <div
                    key={identity.id}
                    className="flex items-center justify-between gap-2 rounded-xl border border-line bg-panel px-3.5 py-2.5"
                  >
                    <div className="min-w-0">
                      <div className="truncate text-xs font-semibold">{identity.label}</div>
                      <div className="truncate font-mono text-[10px] text-muted">
                        {identity.bundle_id ?? identity.executable_path}
                      </div>
                      <div className="text-[10px] text-muted">
                        {route?.routed
                          ? `Isolated${route.exit_ip ? ` · exit ${route.exit_ip}` : ""}`
                          : route?.detail ?? "Idle"}
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy || !status?.tun.running}
                        onClick={() =>
                          void run(async () =>
                            invoke<string>("rotate_app_circuit", {
                              appId: identity.id,
                            }),
                          )
                        }
                      >
                        Rotate
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy}
                        onClick={() =>
                          saveRouting(
                            settings.route_apps.filter(
                              (appIdentity) => appIdentity.id !== identity.id,
                            ),
                          )
                        }
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-sm text-muted">
              No apps yet — use Add app to pick from the file explorer.
            </p>
          )}
          <Button size="sm" variant="secondary" disabled={busy} onClick={addSplitApp}>
            Add app
          </Button>
        </div>
      )}

    </section>
  );
}
