import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { SettingRow } from "@/components/ui/setting-row";
import { Switch } from "@/components/ui/switch";
import { InfoTip } from "@/components/ui/tooltip";
import { LoadState } from "@/components/ui/load-state";
import type { TorApp } from "@/hooks/useTorApp";
import type { AppSettings } from "@/lib/types";
import { PRESETS, presetPatch, detectPreset, type PresetId } from "@/lib/presets";
import { StrictLockConsent } from "@/components/DenyAlert";
import { ProjectLink } from "@/components/ProjectLink";
import { UninstallDialog } from "@/components/UninstallDialog";
import { useAppVersion } from "@/hooks/useAppVersion";
import { channelLabel, releaseChannel } from "@/lib/release";

type HelperStatus = {
  supported: boolean;
  installed: boolean;
  running: boolean;
  detail: string;
};

export function SettingsPage({ app }: { app: TorApp }) {
  const {
    status,
    settings,
    snowflake,
    busy,
    saveSettings,
    run,
    refreshSnowflake,
  } = app;
  const [preset, setPreset] = useState<PresetId>("everyday");
  const [helper, setHelper] = useState<HelperStatus | null>(null);
  const [lockConsent, setLockConsent] = useState(false);
  const [uninstall, setUninstall] = useState(false);
  const version = useAppVersion();
  const channel = releaseChannel(version);
  const channelName = channelLabel(channel);

  const refreshHelper = () =>
    invoke<HelperStatus>("privileged_helper_status")
      .then(setHelper)
      .catch(() => setHelper(null));

  useEffect(() => {
    void refreshHelper();
  }, []);

  if (!settings) {
    return (
      <LoadState
        label="Loading settings…"
        error={app.bootstrapError}
        onRetry={app.retryBootstrap}
      />
    );
  }

  const currentPreset = detectPreset(settings);
  const currentPresetLabel =
    PRESETS.find((item) => item.id === currentPreset)?.label ?? "Custom";
  const applyPreset = () => {
    if (preset === "maximum" && !settings.strict_tcp_lock) {
      setLockConsent(true);
      return;
    }
    void run(async () => {
      await invoke<AppSettings>("update_settings", {
        next: { ...settings, ...presetPatch(preset) },
      });
      await app.refreshSettings();
      return `Applied ${preset.replace("-", " ")} preset`;
    });
  };

  return (
    <section className="flex flex-col gap-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Settings</h2>
        <p className="mt-1 text-sm text-muted">
          Defaults, DNS, and optional volunteer relay. This build is{" "}
          <span className="font-semibold text-ink">{channelName}</span> — not
          a sole control for high-risk work.{" "}
          <ProjectLink link="docs" className="text-onion hover:text-onion-hot">
            See the docs
          </ProjectLink>{" "}
          for the threat model and residual leaks.
        </p>
      </header>

      <div className="rounded-xl border border-line bg-panel p-4 space-y-2">
        <div className="flex items-center gap-1.5">
          <div className="text-sm font-semibold">Connection preset</div>
          <InfoTip content="Presets set connection mode, DNS, kill switch, bridges, and Session Guard together. You can still fine-tune anything below or on the Routing and Bridges tabs." />
        </div>
        <p className="text-xs text-muted">
          Current:{" "}
          <span className="font-medium text-ink">{currentPresetLabel}</span>
        </p>
        <div className="flex flex-wrap items-end gap-2">
          <label className="min-w-48 flex-1">
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">
              Apply preset
            </div>
            <Select
              value={preset}
              disabled={busy}
              onChange={(event) => setPreset(event.target.value as PresetId)}
            >
              {PRESETS.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </Select>
          </label>
          <Button
            size="sm"
            variant="secondary"
            disabled={busy}
            onClick={applyPreset}
          >
            Apply
          </Button>
        </div>
        <p className="text-[11px] text-muted">
          {PRESETS.find((item) => item.id === preset)?.description}
        </p>
      </div>

      <div className="space-y-2">
        <SettingRow
          title={
            <span className="inline-flex items-center gap-1.5">
              Resolve through Tor
              <InfoTip content="TUN sends DNS over UDP to Tor's local DNSPort. Proxy apps must use SOCKS hostname resolution (socks5h); plain socks5 can still leak DNS. Required for .onion names." />
            </span>
          }
          description="Resolve names through Tor"
        >
          <Switch
            checked={settings.remote_dns}
            disabled={busy}
            onCheckedChange={(v) => saveSettings({ remote_dns: v })}
          />
        </SettingRow>
        <SettingRow
          title="Auto-enable system proxy"
          description="Always applied in System proxy mode. When on, also apply OS SOCKS on Connect in other modes."
        >
          <Switch
            checked={settings.auto_enable_proxy}
            disabled={busy}
            onCheckedChange={(v) => saveSettings({ auto_enable_proxy: v })}
          />
        </SettingRow>
        <SettingRow
          title="Auto-disable system proxy"
          description="Disconnect always restores OS SOCKS"
        >
          <Switch
            checked={settings.auto_disable_proxy}
            disabled={busy}
            onCheckedChange={(v) => saveSettings({ auto_disable_proxy: v })}
          />
        </SettingRow>
        <SettingRow
          title={
            <span className="inline-flex items-center gap-1.5">
              Clearnet alerts
              <InfoTip content="An always-on-top OnionGate window, not a macOS notification: notification text is routed through Apple's infrastructure, so it would leak the process name off this device." />
            </span>
          }
          description="Pop up an alert when a process connects outside Tor"
        >
          <Switch
            checked={settings.clearnet_alerts}
            disabled={busy}
            onCheckedChange={(v) => saveSettings({ clearnet_alerts: v })}
          />
        </SettingRow>
        {status?.connection_filter?.supported ? (
          <SettingRow
            title={
              <span className="inline-flex items-center gap-1.5">
                Connection filter
                <InfoTip content="macOS Network Extension that holds and drops outbound flows that are not already Tor. pf remains the packet lock. Apple can hide some of its own processes from this filter, and a crashed or flooded filter can fail open — OnionGate then marks the session Degraded instead of Protected. Only a Developer ID .pkg can load it; approve it in System Settings → General → Login Items & Extensions → Network Extensions if macOS asks. Unsigned builds never appear there. Allow does not punch clearnet." />
              </span>
            }
            description="Require the hold-and-drop filter once it is installed. Unsigned debug stays on pf."
          >
            <Switch
              checked={settings.connection_filter ?? true}
              disabled={busy}
              onCheckedChange={(v) => saveSettings({ connection_filter: v })}
            />
          </SettingRow>
        ) : null}
        <SettingRow
          title="Connect on launch"
          description="Start a Tor session when OnionGate opens. Recommended with Block the network at boot so a restart is not an offline brick."
        >
          <Switch
            checked={settings.connect_on_launch}
            disabled={busy}
            onCheckedChange={(v) => saveSettings({ connect_on_launch: v })}
          />
        </SettingRow>
        <SettingRow
          title="Re-enable Wi-Fi when Protected"
          description="Turn Wi-Fi back on once the session is Protected"
        >
          <Switch
            checked={settings.wifi_off_at_boot_auto_reenable}
            disabled={busy}
            onCheckedChange={(v) =>
              saveSettings({ wifi_off_at_boot_auto_reenable: v })
            }
          />
        </SettingRow>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <label className="rounded-xl border border-line bg-panel p-3">
          <div className="text-xs font-semibold text-muted">Theme</div>
          <Select
            className="mt-1.5"
            value={settings.theme}
            disabled={busy}
            onChange={(event) =>
              saveSettings({
                theme: event.target.value as typeof settings.theme,
              })
            }
          >
            <option value="auto">Match system</option>
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </Select>
        </label>
        <label className="rounded-xl border border-line bg-panel p-3">
          <div className="text-xs font-semibold text-muted">Log level</div>
          <Select
            className="mt-1.5"
            value={settings.log_level}
            disabled={busy}
            onChange={(e) => saveSettings({ log_level: e.target.value })}
          >
            <option value="err">err</option>
            <option value="warn">warn</option>
            <option value="notice">notice</option>
            <option value="info">info</option>
            <option value="debug">debug</option>
          </Select>
        </label>
        <label className="rounded-xl border border-line bg-panel p-3">
          <div className="text-xs font-semibold text-muted">Status poll</div>
          <Select
            className="mt-1.5"
            value={String(settings.status_poll_secs)}
            disabled={busy}
            onChange={(e) =>
              saveSettings({ status_poll_secs: Number(e.target.value) })
            }
          >
            <option value="2">2s</option>
            <option value="4">4s</option>
            <option value="8">8s</option>
            <option value="15">15s</option>
          </Select>
        </label>
        <label className="rounded-xl border border-line bg-panel p-3">
          <div className="text-xs font-semibold text-muted">Language</div>
          <Select
            className="mt-1.5"
            value={settings.locale}
            disabled={busy}
            onChange={(event) =>
              saveSettings({
                locale: event.target.value as typeof settings.locale,
              })
            }
          >
            <option value="auto">English (default)</option>
            <option value="en">English</option>
            <option value="ru" disabled>
              Русский (coming soon)
            </option>
            <option value="fa" disabled>
              فارسی (coming soon)
            </option>
            <option value="zh-CN" disabled>
              简体中文 (coming soon)
            </option>
            <option value="tr" disabled>
              Türkçe (coming soon)
            </option>
          </Select>
          <p className="mt-1 text-[10px] text-muted">
            Additional languages are in progress.
          </p>
        </label>
      </div>

      <div className="rounded-xl border border-line bg-panel p-4 space-y-2">
        <div className="flex items-center gap-1.5">
          <div className="text-sm font-semibold">Snowflake volunteer</div>
          <InfoTip content="Run a Snowflake proxy to help censored users reach Tor. Optional; separate from your own connection." />
        </div>
        <p className="text-xs text-muted">
          {snowflake?.detail ?? "Help censored users reach Tor"}
        </p>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="secondary"
            disabled={busy || !snowflake?.available || !!snowflake?.running}
            onClick={() =>
              void run(async () => {
                const msg = await invoke<string>("start_snowflake");
                await refreshSnowflake();
                return msg;
              })
            }
          >
            Start
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={busy || !snowflake?.running}
            onClick={() =>
              void run(async () => {
                const msg = await invoke<string>("stop_snowflake");
                await refreshSnowflake();
                return msg;
              })
            }
          >
            Stop
          </Button>
        </div>
      </div>

      {helper?.supported ? (
        <div className="flex items-center justify-between gap-3 rounded-xl border border-line bg-panel p-4">
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <div className="text-sm font-semibold">Background helper</div>
              {helper.running ? (
                <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-accent-strong">
                  Running
                </span>
              ) : helper.installed ? (
                <span className="rounded bg-warn/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-warn-strong">
                  Installed
                </span>
              ) : null}
            </div>
            <p className="mt-0.5 text-xs text-muted">{helper.detail}</p>
            <p className="mt-1 text-[11px] text-muted">
              Install once (one prompt). The typed helper handles kill switch,
              NIC lock, deny harvest, and stopping a VPN/app. TUN, proxy, and
              hardening may still prompt.
            </p>
          </div>
          {helper.installed ? (
            <Button
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  const message = await invoke<string>("remove_privileged_helper");
                  await refreshHelper();
                  return message;
                })
              }
            >
              Remove
            </Button>
          ) : (
            <Button
              size="sm"
              variant="secondary"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  const message = await invoke<string>("install_privileged_helper");
                  await refreshHelper();
                  return message;
                })
              }
            >
              Install
            </Button>
          )}
        </div>
      ) : null}

      <div className="flex items-center justify-between gap-3 rounded-xl border border-line bg-panel p-4">
        <div>
          <div className="text-sm font-semibold">Administrator access</div>
          <p className="text-xs text-muted">
            {helper?.running
              ? "The background helper handles the kill switch. TUN, proxy, and hardening may still need temporary administrator approval."
              : "Without the background helper, enabling the system proxy, TUN, kill switch, or hardening needs administrator approval. Grant it here (or during setup) so those actions apply without repeated prompts. macOS keeps this active for a few minutes."}
          </p>
        </div>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() =>
            void run(async () => invoke<string>("prime_admin_auth"))
          }
        >
          Grant access
        </Button>
      </div>

      <div className="flex items-center justify-between gap-3 rounded-xl border border-line bg-panel p-4">
        <div>
          <div className="text-sm font-semibold">Signed updates</div>
          <p className="text-xs text-muted">
            Checks the signed release manifest and verifies the updater signature before install.
          </p>
        </div>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const update = await check();
              if (!update) return "OnionGate is up to date";
              await update.downloadAndInstall();
              await relaunch();
              return `Installed OnionGate ${update.version}`;
            })
          }
        >
          Check for updates
        </Button>
      </div>

      <div className="rounded-xl border border-line bg-panel p-4">
        <div className="text-sm font-semibold">About</div>
        <p className="mt-1 text-xs text-muted">
          OnionGate{version ? ` ${version}` : ""} ·{" "}
          <span className="font-semibold text-ink">{channelName}</span>
          {channel !== "stable"
            ? " — pre-1.0 test channel, not a stable release"
            : ""}
        </p>
        <p className="mt-2 text-xs text-muted">Copyright (C) 2026 OpenHat Security</p>
        <p className="mt-1 text-xs text-muted">
          OnionGate comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
          applicable law. This is free software, and you are welcome to
          redistribute it under the terms of the GNU General Public License,
          version 3.
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
          <ProjectLink link="license" className="text-onion hover:text-onion-hot">
            View the GNU General Public License v3
          </ProjectLink>
          <ProjectLink link="docs" className="text-onion hover:text-onion-hot">
            See the docs
          </ProjectLink>
          <ProjectLink link="github" className="text-onion hover:text-onion-hot">
            OpenHat Security
          </ProjectLink>
        </div>
      </div>

      <div className="flex items-center justify-between gap-3 rounded-xl border border-danger/40 bg-panel p-4">
        <div className="min-w-0">
          <div className="text-sm font-semibold">Uninstall OnionGate</div>
          <p className="mt-0.5 text-xs text-muted">
            Removes the app, its privileged helper, and the host changes it made
            (pf anchors, system SOCKS proxy, shell hooks). Asks for your
            administrator password and keeps your data directory unless you tell
            it otherwise. You confirm before anything runs.
          </p>
        </div>
        <Button
          size="sm"
          variant="danger"
          className="shrink-0"
          disabled={busy}
          onClick={() => setUninstall(true)}
        >
          Uninstall…
        </Button>
      </div>

      <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
        <span>
          SOCKS {status?.socks_host}:{status?.socks_port}
        </span>
        <span>Control {status?.control_port}</span>
        <span>DNS {status?.dns_port}</span>
        {status?.tor_path ? (
          <span className="truncate">{status.tor_path}</span>
        ) : null}
      </div>

      {lockConsent ? (
        <StrictLockConsent
          onCancel={() => setLockConsent(false)}
          onConfirm={() => {
            setLockConsent(false);
            void run(async () => {
              await invoke<AppSettings>("update_settings", {
                next: { ...settings, ...presetPatch("maximum") },
              });
              await app.refreshSettings();
              return "Applied Maximum Isolation preset";
            });
          }}
        />
      ) : null}

      {uninstall ? (
        <UninstallDialog onClose={() => setUninstall(false)} />
      ) : null}
    </section>
  );
}
