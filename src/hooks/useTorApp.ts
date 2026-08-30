import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  AppSettings,
  AppStatus,
  BridgeScanResult,
  DetectReport,
  ExitCountryOption,
  FetchBridgesResult,
  HardenItem,
  IpReport,
  IssuedCredential,
  NetworkTestResult,
  NewIdentityResult,
  OnionAudit,
  OnionProject,
  PermanentSite,
  RelayInfo,
  SessionOverview,
  SettingsView,
  ShellProxyStatus,
  SnowflakeStatus,
  SystemView,
  Tab,
  TorLogs,
  EgressWatch,
  DenyLogSnapshot,
  KillClearnetIdentityResult,
} from "@/lib/types";

export function useTorApp() {
  const [tab, setTab] = useState<Tab>("home");
  const [systemView, setSystemView] = useState<SystemView>("checkup");
  const [settingsView, setSettingsView] = useState<SettingsView>("preferences");
  const [verifyFlowFilter, setVerifyFlowFilter] = useState<
    "all" | "through_tor" | "clearnet" | "listen"
  >("all");
  const [hardenFocusId, setHardenFocusId] = useState<string | null>(null);
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [ips, setIps] = useState<IpReport | null>(null);
  const [detect, setDetect] = useState<DetectReport | null>(null);
  const [shellProxy, setShellProxy] = useState<ShellProxyStatus | null>(null);
  const [networkTest, setNetworkTest] = useState<NetworkTestResult | null>(
    null,
  );
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [logs, setLogs] = useState<TorLogs | null>(null);
  const [bridgeText, setBridgeText] = useState("");
  const [catalogBridges, setCatalogBridges] = useState<string[]>([]);
  const [scanResults, setScanResults] = useState<BridgeScanResult[] | null>(
    null,
  );
  const [exitDraft, setExitDraft] = useState("");
  const [exitCountries, setExitCountries] = useState<ExitCountryOption[]>([]);
  const [relayQuery, setRelayQuery] = useState("");
  const [relays, setRelays] = useState<RelayInfo[] | null>(null);
  const [snowflake, setSnowflake] = useState<SnowflakeStatus | null>(null);
  const [harden, setHarden] = useState<HardenItem[]>([]);
  const [session, setSession] = useState<SessionOverview | null>(null);
  const [scanTransport, setScanTransport] = useState("obfs4");
  const [onionProjects, setOnionProjects] = useState<OnionProject[]>([]);
  const [permanentSites, setPermanentSites] = useState<PermanentSite[]>([]);
  const [onionAudits, setOnionAudits] = useState<Record<string, OnionAudit>>({});
  const [issuedCredential, setIssuedCredential] =
    useState<IssuedCredential | null>(null);
  const [onionError, setOnionError] = useState<string | null>(null);
  const [egressWatch, setEgressWatch] = useState<EgressWatch | null>(null);
  const [denyLog, setDenyLog] = useState<DenyLogSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [bootstrapError, setBootstrapError] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    setStatus(await invoke<AppStatus>("get_status"));
  }, []);

  const refreshIps = useCallback(async () => {
    setIps(await invoke<IpReport>("get_ips"));
  }, []);

  const refreshDetect = useCallback(async () => {
    setDetect(await invoke<DetectReport>("detect_apps"));
  }, []);

  const refreshShellProxy = useCallback(async () => {
    setShellProxy(await invoke<ShellProxyStatus>("get_shell_proxy_status"));
  }, []);

  const refreshSettings = useCallback(async () => {
    const s = await invoke<AppSettings>("get_settings");
    setSettings(s);
    setBridgeText(s.bridge_lines.join("\n"));
    setExitDraft(s.exit_country);
  }, []);

  const refreshSnowflake = useCallback(async () => {
    setSnowflake(await invoke<SnowflakeStatus>("get_snowflake_status"));
  }, []);

  const refreshHarden = useCallback(async () => {
    setHarden(await invoke<HardenItem[]>("get_harden_items"));
  }, []);

  const refreshLogs = useCallback(async () => {
    setLogs(await invoke<TorLogs>("get_tor_logs"));
  }, []);

  const refreshSession = useCallback(async () => {
    setSession(await invoke<SessionOverview>("get_session_overview"));
  }, []);

  const refreshEgressWatch = useCallback(async () => {
    setEgressWatch(await invoke<EgressWatch>("get_egress_watch"));
  }, []);

  const refreshDenyLog = useCallback(async () => {
    try {
      setDenyLog(await invoke<DenyLogSnapshot>("get_deny_log"));
    } catch {
      setDenyLog(null);
    }
  }, []);

  const refreshOnionHost = useCallback(async () => {
    try {
      const [temporary, permanent] = await Promise.all([
        invoke<OnionProject[]>("list_onion_services"),
        invoke<PermanentSite[]>("list_permanent_sites"),
      ]);
      setOnionProjects(temporary);
      setPermanentSites(permanent);
      setOnionError(null);
    } catch (e) {
      setOnionProjects([]);
      setPermanentSites([]);
      setOnionError(typeof e === "string" ? e : String(e));
    }
  }, []);

  const clearFlash = useCallback(() => {
    setMessage(null);
    setError(null);
  }, []);

  const run = useCallback(
    async (action: () => Promise<string>, opts?: { refreshIps?: boolean }) => {
      setBusy(true);
      setError(null);
      setMessage(null);
      try {
        setMessage(await action());
        await refreshStatus();
        if (opts?.refreshIps) await refreshIps();
      } catch (e) {
        setError(typeof e === "string" ? e : String(e));
        await refreshStatus();
      } finally {
        setBusy(false);
      }
    },
    [refreshIps, refreshStatus],
  );

  const bootstrap = useCallback(async () => {
    setBootstrapError(null);
    try {
      const [st, det, s, shell, countries] = await Promise.all([
        invoke<AppStatus>("get_status"),
        invoke<DetectReport>("detect_apps"),
        invoke<AppSettings>("get_settings"),
        invoke<ShellProxyStatus>("get_shell_proxy_status"),
        invoke<ExitCountryOption[]>("exit_country_options"),
      ]);
      setStatus(st);
      setDetect(det);
      setSettings(s);
      setBridgeText(s.bridge_lines.join("\n"));
      setExitDraft(s.exit_country);
      setShellProxy(shell);
      setExitCountries(countries);
      const report = await invoke<IpReport>("get_ips");
      setIps(report);
    } catch (e) {
      const msg = typeof e === "string" ? e : String(e);
      setBootstrapError(msg);
      setError(msg);
    }
  }, []);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  useEffect(() => {
    const id = window.setInterval(() => {
      void refreshStatus();
      void refreshSession();
      void refreshIps();
    }, (settings?.status_poll_secs ?? 4) * 1000);
    return () => window.clearInterval(id);
  }, [refreshStatus, refreshSession, refreshIps, settings?.status_poll_secs]);

  useEffect(() => {
    // Network/Bridges live under Connect; Checkup/Harden/Startup Items under
    // System; Preferences/Logs under Settings.
    if (tab === "home" || tab === "settings") {
      void refreshSettings();
      void refreshSnowflake();
    }
    if (tab === "home" || tab === "system") {
      void refreshHarden();
    }
    if (tab === "apps") {
      void refreshSettings();
      void refreshDetect();
      void refreshShellProxy();
    }
    if (tab === "host") {
      void refreshOnionHost();
    }
    if (tab === "verify") {
      void refreshEgressWatch();
    }
  }, [
    tab,
    refreshDetect,
    refreshSettings,
    refreshShellProxy,
    refreshSnowflake,
    refreshHarden,
    refreshOnionHost,
    refreshEgressWatch,
  ]);

  // Apply the theme setting: toggle the `.dark` class on <html>, following the
  // OS when set to "auto".
  useEffect(() => {
    const theme = settings?.theme ?? "auto";
    const apply = (dark: boolean) =>
      document.documentElement.classList.toggle("dark", dark);
    if (theme === "dark") {
      apply(true);
      return;
    }
    if (theme === "light") {
      apply(false);
      return;
    }
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    apply(media.matches);
    const onChange = (event: MediaQueryListEvent) => apply(event.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [settings?.theme]);

  const torOn = status?.socks_up ?? false;
  const proxyOn = status?.proxy.enabled ?? false;
  const tunOn = status?.tun.running ?? false;

  useEffect(() => {
    if (!torOn && tab !== "verify") return;
    void refreshEgressWatch();
    void refreshDenyLog();
    const id = window.setInterval(() => {
      void refreshEgressWatch();
      void refreshDenyLog();
    }, 2000);
    return () => window.clearInterval(id);
  }, [torOn, tab, refreshEgressWatch, refreshDenyLog]);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession, torOn]);

  const protectionLabel = useMemo(() => {
    const phase = status?.session_phase ?? "disconnected";
    if (phase === "recovering") return "Recovering";
    if (phase === "connecting") {
      return status?.network_lock?.active
        ? "Connecting · network locked"
        : "Connecting";
    }
    if (phase === "degraded") return "Degraded";
    if (!torOn) return phase === "protected" ? "Degraded" : "Disconnected";
    if (phase !== "protected") return "Tor ready";

    const controlReady = status?.control_up ?? false;
    const dnsReady = !status?.remote_dns || !!status?.dns_up;
    const firewallReady =
      !status?.kill_switch ||
      (!!status?.firewall.active && !!status?.firewall.verified_live);
    if (
      settings?.strict_tcp_lock &&
      (!status?.firewall.strict_deny_live ||
        (settings.strict_tcp_exceptions?.length ?? 0) > 0)
    ) {
      return "Degraded";
    }

    if (tunOn) {
      return controlReady && dnsReady && firewallReady
        ? "Protected · TUN"
        : "TUN active · unverified";
    }
    if (proxyOn) {
      if (!controlReady || !dnsReady || !firewallReady) {
        return "Proxy active · unverified";
      }
      return status?.bridges_enabled ? "Protected · bridges" : "Protected · proxy";
    }
    return status?.bridges_enabled ? "Tor on · proxy off" : "Tor ready";
  }, [
    torOn,
    tunOn,
    proxyOn,
    status?.session_phase,
    status?.control_up,
    status?.remote_dns,
    status?.dns_up,
    status?.kill_switch,
    status?.firewall.active,
    status?.firewall.verified_live,
    status?.firewall.strict_deny_live,
    status?.network_lock?.active,
    status?.bridges_enabled,
    settings?.strict_tcp_lock,
    settings?.strict_tcp_exceptions,
  ]);

  const connectTor = () => {
    if (busy || !status?.tor_installed || torOn) return;
    void run(async () => invoke<string>("start_tor"));
  };

  const connectOnLaunchAttempted = useRef(false);
  useEffect(() => {
    if (connectOnLaunchAttempted.current) return;
    if (!settings?.setup_complete || !settings.connect_on_launch) return;
    if (!status?.tor_installed || torOn || busy) return;
    connectOnLaunchAttempted.current = true;
    void invoke<{ needed: boolean }>("get_recovery_status")
      .then((recovery) => {
        if (recovery.needed) return;
        connectTor();
      })
      .catch(() => {
        connectTor();
      });
  }, [settings, status, torOn, busy, connectTor]);

  const disconnectTor = () => {
    if (busy || !torOn) return;
    void run(async () => invoke<string>("stop_tor"));
  };

  const toggleTor = () => {
    if (busy || !status?.tor_installed) return;
    if (torOn) disconnectTor();
    else connectTor();
  };

  const toggleProxy = () => {
    if (busy || !status?.proxy.supported || !torOn) return;
    void run(() =>
      proxyOn
        ? invoke<string>("disable_proxy")
        : invoke<string>("enable_proxy"),
    );
  };

  const saveSettings = (patch: Partial<AppSettings>) => {
    if (!settings) return;
    const next = { ...settings, ...patch };
    setSettings(next);
    void run(async () => {
      const saved = await invoke<AppSettings>("update_settings", { next });
      setSettings(saved);
      setBridgeText(saved.bridge_lines.join("\n"));
      setExitDraft(saved.exit_country);
      if (patch.remote_dns !== undefined) {
        await invoke("set_remote_dns", { enabled: saved.remote_dns });
      }
      return "Settings saved";
    });
  };

  const newIdentity = () =>
    void run(async () => {
      const result = await invoke<NewIdentityResult>("new_identity");
      setIps(result.ips);
      return result.message;
    });

  const killClearnetAndNewIdentity = () =>
    void run(async () => {
      const result = await invoke<KillClearnetIdentityResult>(
        "kill_clearnet_and_new_identity",
      );
      setIps(result.identity.ips);
      await refreshEgressWatch();
      return result.detail;
    });

  // Changing the exit country pins ExitNodes and rotates the circuit (NEWNYM),
  // so refresh the IP once the new circuit settles to reflect the new location.
  const applyExitCountry = (country: string) =>
    void run(async () => {
      const result = await invoke<NewIdentityResult>("set_exit_country", {
        country,
      });
      setIps(result.ips);
      await refreshSettings();
      return result.message;
    });

  const fetchBridges = (transport?: string) =>
    void run(async () => {
      const t = transport ?? scanTransport;
      const res = await invoke<FetchBridgesResult>("fetch_bridges_for", {
        transport: t,
      });
      setCatalogBridges(res.lines);
      setScanResults(null);
      const cache = res.from_cache ? " (cached)" : "";
      return `Catalog ${t}: ${res.lines.length} from ${res.source}${cache}`;
    });

  const saveBridges = () =>
    void run(async () => {
      const saved = await invoke<AppSettings>("set_bridge_lines", {
        text: bridgeText,
      });
      setSettings(saved);
      setBridgeText(saved.bridge_lines.join("\n"));
      return `Saved ${saved.bridge_lines.length} bridge line(s)`;
    });

  const scanBridges = (lines?: string[]) =>
    void run(async () => {
      const list =
        lines ??
        (catalogBridges.length
          ? catalogBridges
          : (settings?.bridge_lines ?? []));
      const results = await invoke<BridgeScanResult[]>("scan_bridges", {
        lines: list,
      });
      setScanResults(results);
      const ok = results.filter((r) => r.ok).length;
      return `Scanned ${ok}/${results.length} reachable`;
    });

  const applyReachableBridges = () =>
    void run(async () => {
      const okLines = scanResults?.filter((r) => r.ok).map((r) => r.raw) ?? [];
      const msg = await invoke<string>("apply_scanned_bridges", {
        lines: okLines,
        enable: true,
      });
      await refreshSettings();
      if (okLines.length) {
        await invoke("save_bridge_library", { lines: okLines });
      }
      return msg;
    });

  const searchRelays = () =>
    void run(async () => {
      const list = await invoke<RelayInfo[]>("search_relays", {
        query: relayQuery,
        limit: 15,
      });
      setRelays(list);
      return `Found ${list.length} relay(s)`;
    });

  /* Onion Host ------------------------------------------------------------- */

  const startTemporarySite = (
    localPort: number,
    virtualPort: number,
    isPrivate: boolean,
  ) =>
    void run(async () => {
      const project = await invoke<OnionProject>("start_onion_service", {
        localPort,
        virtualPort,
        private: isPrivate,
      });
      await refreshOnionHost();
      return `Created ${project.hostname}`;
    });

  const stopTemporarySite = (serviceId: string) =>
    void run(async () => {
      const message = await invoke<string>("stop_onion_service", { serviceId });
      await refreshOnionHost();
      return message;
    });

  const auditTemporarySite = (serviceId: string) =>
    void run(async () => {
      const result = await invoke<OnionAudit>("audit_onion_service", {
        serviceId,
      });
      setOnionAudits((current) => ({ ...current, [serviceId]: result }));
      return result.published
        ? "Onion site is published"
        : "Descriptor is not reachable yet";
    });

  const addPermanentSite = (
    nickname: string,
    localPort: number,
    virtualPort: number,
    enableAuth: boolean,
  ) =>
    void run(async () => {
      const site = await invoke<PermanentSite>("add_permanent_site", {
        nickname,
        localPort,
        virtualPort,
        enableAuth,
      });
      await refreshOnionHost();
      return site.hostname
        ? `Created ${site.hostname}`
        : `Created "${site.nickname}". Tor is still publishing its address.`;
    });

  const removePermanentSite = (id: string) =>
    void run(async () => {
      const message = await invoke<string>("remove_permanent_site", { id });
      await refreshOnionHost();
      return message;
    });

  const renamePermanentSite = (id: string, nickname: string) =>
    void run(async () => {
      await invoke<PermanentSite>("rename_permanent_site", { id, nickname });
      await refreshOnionHost();
      return "Renamed site";
    });

  const addPermanentSiteClient = (id: string, name: string) =>
    void run(async () => {
      const issued = await invoke<IssuedCredential>(
        "add_permanent_site_client",
        { id, name },
      );
      setIssuedCredential(issued);
      await refreshOnionHost();
      return `Issued credential "${issued.client_name}". Copy it now — it is not stored.`;
    });

  const revokePermanentSiteClient = (id: string, name: string) =>
    void run(async () => {
      const message = await invoke<string>("revoke_permanent_site_client", {
        id,
        name,
      });
      await refreshOnionHost();
      return message;
    });

  const setPermanentSiteAuth = (id: string, enabled: boolean) =>
    void run(async () => {
      await invoke<PermanentSite>("set_permanent_site_auth", { id, enabled });
      await refreshOnionHost();
      return enabled
        ? "Client authorization is on"
        : "Client authorization is off — anyone with the address can connect";
    });

  const auditPermanentSite = (id: string) =>
    void run(async () => {
      const result = await invoke<OnionAudit>("audit_permanent_site", { id });
      setOnionAudits((current) => ({ ...current, [id]: result }));
      return result.published
        ? "Onion site is published"
        : "Descriptor is not reachable yet";
    });

  const dismissIssuedCredential = useCallback(
    () => setIssuedCredential(null),
    [],
  );

  return {
    tab,
    setTab,
    systemView,
    setSystemView,
    settingsView,
    setSettingsView,
    verifyFlowFilter,
    setVerifyFlowFilter,
    hardenFocusId,
    setHardenFocusId,
    status,
    ips,
    detect,
    shellProxy,
    networkTest,
    setNetworkTest,
    settings,
    logs,
    bridgeText,
    setBridgeText,
    catalogBridges,
    scanResults,
    exitDraft,
    setExitDraft,
    exitCountries,
    relayQuery,
    setRelayQuery,
    relays,
    snowflake,
    harden,
    session,
    scanTransport,
    setScanTransport,
    busy,
    message,
    error,
    bootstrapError,
    retryBootstrap: bootstrap,
    clearFlash,
    torOn,
    proxyOn,
    tunOn,
    protectionLabel,
    run,
    refreshIps,
    refreshSettings,
    refreshSnowflake,
    refreshHarden,
    refreshLogs,
    refreshDetect,
    refreshShellProxy,
    refreshSession,
    refreshEgressWatch,
    egressWatch,
    denyLog,
    refreshDenyLog,
    onionProjects,
    permanentSites,
    onionAudits,
    onionError,
    issuedCredential,
    dismissIssuedCredential,
    refreshOnionHost,
    startTemporarySite,
    stopTemporarySite,
    auditTemporarySite,
    addPermanentSite,
    removePermanentSite,
    renamePermanentSite,
    addPermanentSiteClient,
    revokePermanentSiteClient,
    setPermanentSiteAuth,
    auditPermanentSite,
    toggleTor,
    connectTor,
    disconnectTor,
    toggleProxy,
    saveSettings,
    newIdentity,
    killClearnetAndNewIdentity,
    applyExitCountry,
    fetchBridges,
    saveBridges,
    scanBridges,
    applyReachableBridges,
    searchRelays,
  };
}

export type TorApp = ReturnType<typeof useTorApp>;
