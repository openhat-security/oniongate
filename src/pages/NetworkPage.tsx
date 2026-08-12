import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { Select } from "@/components/ui/select";
import { SettingRow } from "@/components/ui/setting-row";
import { Switch } from "@/components/ui/switch";
import { InfoTip } from "@/components/ui/tooltip";
import { LoadState } from "@/components/ui/load-state";
import type { TorApp } from "@/hooks/useTorApp";
import type { AppSettings } from "@/lib/types";

export function NetworkPage({
  app,
  onOpenBridges,
}: {
  app: TorApp;
  onOpenBridges?: () => void;
}) {
  const {
    status,
    settings,
    exitCountries,
    busy,
    exitDraft,
    setExitDraft,
    relayQuery,
    setRelayQuery,
    relays,
    run,
    saveSettings,
    refreshSettings,
    searchRelays,
  } = app;

  if (!settings) {
    return (
      <LoadState
        label="Loading network settings…"
        error={app.bootstrapError}
        onRetry={app.retryBootstrap}
      />
    );
  }

  const mode = (settings.connection_mode === "tun" ? "tun" : "proxy") as
    | "proxy"
    | "tun";

  return (
    <section className="flex flex-col gap-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Network</h2>
        <p className="mt-1 text-sm text-muted">
          Connection mode, kill switch, exit pin, and relays. Bridges live in{" "}
          <button
            type="button"
            className="underline underline-offset-2"
            onClick={onOpenBridges}
          >
            Bridges
          </button>
          .
        </p>
      </header>

      <div className="space-y-2">
        <SettingRow
          title={
            <span className="inline-flex items-center gap-1.5">
              Connection mode
              <InfoTip
                title="Connection mode"
                status={{
                  label: mode === "tun" ? "TUN" : "Proxy",
                  tone: "accent",
                }}
                description="Proxy: apps use SOCKS (system proxy optional). TUN: routes most traffic through Tor via sing-box (admin prompt)."
                detail="Connect Tor before enabling TUN."
              />
            </span>
          }
          description={status?.tun.detail ?? "Proxy or system-wide TUN"}
          className="items-start"
        >
          <Segmented
            value={mode}
            disabled={busy}
            options={[
              { value: "proxy", label: "Proxy" },
              { value: "tun", label: "TUN" },
            ]}
            onChange={(next) =>
              void run(async () => {
                if (next === "proxy") {
                  if (status?.tun.running) {
                    await invoke<string>("stop_tun");
                  } else {
                    await invoke<AppSettings>("set_connection_mode", {
                      mode: "proxy",
                    });
                  }
                  await refreshSettings();
                  return "Proxy mode";
                }
                if (!status?.socks_up) {
                  await invoke<AppSettings>("set_connection_mode", {
                    mode: "proxy",
                  });
                  await refreshSettings();
                  throw "Connect Tor first, then enable TUN (admin prompt required).";
                }
                try {
                  const msg = await invoke<string>("start_tun");
                  await refreshSettings();
                  return msg;
                } catch (e) {
                  await refreshSettings();
                  throw e;
                }
              })
            }
          />
        </SettingRow>

        <SettingRow
          title={
            <span className="inline-flex items-center gap-1.5">
              Smart Connect
              <InfoTip
                title="Smart Connect"
                status={{
                  label: settings.smart_connect ? "On" : "Off",
                  tone: settings.smart_connect ? "ok" : "default",
                }}
                description="Tries direct Tor, configured BridgeDB lines, then bundled Snowflake."
                detail={settings.last_connect_reason || "No third-party bridge feeds are used."}
              />
            </span>
          }
          description="Auto-pick working strategy for this network"
        >
          <Switch
            checked={settings.smart_connect}
            disabled={busy}
            onCheckedChange={(v) => saveSettings({ smart_connect: v })}
          />
        </SettingRow>

        <SettingRow
          title={
            <span className="inline-flex items-center gap-1.5">
              Kill switch
              <InfoTip
                title="Kill switch"
                status={{
                  label: settings.kill_switch ? "On" : "Off",
                  tone: settings.kill_switch ? "ok" : "default",
                }}
                description="Steady-state block for clearnet UDP/QUIC and IPv6 after you are Protected. Connect/reconnect already arms a separate network lock so traffic cannot leak during bootstrap."
                risk="Does not replace careful app behavior — apps that ignore SOCKS/TUN can still leak TCP in proxy mode."
              />
            </span>
          }
          description="Steady-state UDP/QUIC + IPv6 block (admin). Transitions always lock the network."
        >
          <Switch
            checked={settings.kill_switch}
            disabled={busy}
            onCheckedChange={(enabled) =>
              void run(async () => {
                const msg = await invoke<string>("set_kill_switch", {
                  enabled,
                });
                await refreshSettings();
                return msg;
              })
            }
          />
        </SettingRow>

      </div>

      <div className="rounded-xl border border-line bg-panel p-3 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-sm font-semibold">
            Exit country
            <InfoTip
              title="Exit country"
              status={{
                label: settings.exit_country
                  ? settings.exit_country.toUpperCase()
                  : "Automatic",
                tone: settings.exit_country ? "accent" : "default",
              }}
              description="Prefer exits in this country (ExitNodes). Automatic uses any suitable exit."
              risk="A smaller exit set can be easier to correlate."
            />
          </div>
          <div className="flex items-center gap-2">
            <Select
              className="h-8 w-44"
              value={exitDraft}
              disabled={busy}
              onChange={(e) => setExitDraft(e.target.value)}
            >
              {(exitCountries.length
                ? exitCountries
                : [{ code: "", label: "Any exit" }]
              ).map((opt) => (
                <option key={opt.code || "any"} value={opt.code}>
                  {opt.label}
                </option>
              ))}
              {exitDraft &&
              !exitCountries.some((c) => c.code === exitDraft) ? (
                <option value={exitDraft}>{exitDraft.toUpperCase()}</option>
              ) : null}
            </Select>
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              onClick={() => app.applyExitCountry(exitDraft)}
            >
              Apply
            </Button>
          </div>
        </div>
      </div>

      <div className="rounded-xl border border-line bg-panel p-3 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-sm font-semibold">
            Relays
            <InfoTip
              title="Relays"
              description="Search Onionoo for relays, then pin as entry or exit."
              detail="Use Clear pins to remove all entry/middle/exit pins."
              risk="Pins constrain your path — reducing relay choice can weaken anonymity."
            />
          </div>
          {settings.entry_nodes || settings.middle_nodes || settings.exit_nodes_fp ? (
            <Button
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await invoke<AppSettings>("clear_relay_pins");
                  await refreshSettings();
                  return "Cleared relay pins";
                })
              }
            >
              Clear pins
            </Button>
          ) : null}
        </div>
        <div className="flex gap-2">
          <Select
            className="h-9 flex-1"
            value={relayQuery.startsWith("country:") ? relayQuery : ""}
            disabled={busy}
            onChange={(e) => {
              const v = e.target.value;
              if (v) setRelayQuery(v);
            }}
          >
            <option value="">Country filter…</option>
            {(exitCountries.length
              ? exitCountries.filter((c) => c.code)
              : []
            ).map((opt) => (
              <option key={opt.code} value={`country:${opt.code}`}>
                {opt.label}
              </option>
            ))}
          </Select>
          <Input
            className="flex-1"
            value={relayQuery}
            disabled={busy}
            placeholder="or nickname / fingerprint"
            onChange={(e) => setRelayQuery(e.target.value)}
          />
          <Button
            size="sm"
            variant="secondary"
            disabled={busy || !relayQuery.trim()}
            onClick={searchRelays}
          >
            Search
          </Button>
        </div>
        {relays && relays.length === 0 ? (
          <p className="text-xs text-muted">
            No relays found for that query. Try a nickname, fingerprint, or a
            country filter.
          </p>
        ) : null}
        {relays && relays.length > 0 ? (
          <div className="max-h-40 space-y-1 overflow-auto">
            {relays.map((r) => (
              <div
                key={r.fingerprint}
                className="flex items-center justify-between gap-2 rounded-md border border-line bg-canvas px-2 py-1.5 text-xs"
              >
                <div className="min-w-0">
                  <div className="truncate font-semibold">
                    {r.country ?? "??"} {r.nickname}
                  </div>
                  <div className="truncate text-[10px] text-muted">
                    {r.flags.slice(0, 3).join(" ")}
                  </div>
                </div>
                <div className="flex shrink-0 gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await invoke("pin_relay", {
                          role: "entry",
                          fingerprint: r.fingerprint,
                        });
                        await refreshSettings();
                        return `Pinned entry ${r.nickname}`;
                      })
                    }
                  >
                    Entry
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    onClick={() =>
                      void run(async () => {
                        await invoke("pin_relay", {
                          role: "exit",
                          fingerprint: r.fingerprint,
                        });
                        await refreshSettings();
                        return `Pinned exit ${r.nickname}`;
                      })
                    }
                  >
                    Exit
                  </Button>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </div>

    </section>
  );
}
