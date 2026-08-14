import type { AppSettings } from "@/lib/types";

export type PresetId =
  | "everyday"
  | "censored"
  | "public-wifi"
  | "maximum"
  | "developer";

export const PRESETS: { id: PresetId; label: string; description: string }[] = [
  {
    id: "everyday",
    label: "Everyday",
    description:
      "System SOCKS proxy through Tor with DNS resolved over Tor. Simple and easy to turn off.",
  },
  {
    id: "censored",
    label: "Censored Network",
    description:
      "Adds the bundled Snowflake transport so you can reach Tor where it is blocked.",
  },
  {
    id: "public-wifi",
    label: "Public Wi-Fi",
    description:
      "System-wide TUN plus the UDP/QUIC kill switch. On macOS, Maximum Isolation adds the NIC default-deny; this preset does not.",
  },
  {
    id: "maximum",
    label: "Maximum Isolation",
    description:
      "TUN, kill switch, remote DNS, and Session Guard. The NIC default-deny is macOS-only; Linux and Windows still use the UDP/QUIC kill switch.",
  },
  {
    id: "developer",
    label: "Developer",
    description:
      "Proxy mode without a kill switch — convenient for local onion site development.",
  },
];

/** Identify which preset the current settings match, or null for "Custom". */
export function detectPreset(settings: AppSettings): PresetId | null {
  for (const { id } of PRESETS) {
    const patch = presetPatch(id);
    const matches = (Object.keys(patch) as (keyof AppSettings)[]).every(
      (key) => settings[key] === patch[key],
    );
    if (matches) return id;
  }
  return null;
}

/** Settings patch applied when a preset is selected. */
export function presetPatch(preset: PresetId): Partial<AppSettings> {
  switch (preset) {
    case "censored":
      return {
        smart_connect: true,
        remote_dns: true,
        bridge_source: "builtin:snowflake",
        last_connect_strategy: "builtin:snowflake",
      };
    case "public-wifi":
      return {
        connection_mode: "tun",
        kill_switch: true,
        remote_dns: true,
        smart_connect: true,
      };
    case "maximum":
      return {
        connection_mode: "tun",
        kill_switch: true,
        remote_dns: true,
        smart_connect: true,
        split_tunnel: true,
        app_routing_policy: "only",
        session_guard: true,
        strict_tcp_lock: true,
        allow_lan: false,
        strict_tcp_exceptions: [],
      };
    case "developer":
      return {
        connection_mode: "proxy",
        remote_dns: true,
        smart_connect: true,
        kill_switch: false,
      };
    case "everyday":
    default:
      return {
        connection_mode: "proxy",
        remote_dns: true,
        smart_connect: true,
        kill_switch: false,
        split_tunnel: false,
        session_guard: false,
      };
  }
}
