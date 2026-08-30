import { useSyncExternalStore } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AppStatus, ReopenableApp } from "@/lib/types";

/**
 * Reopening closed applications is a two-step handshake, never a single action.
 *
 * A UI surface (the pre-connect gate, the clearnet alert) *arms* the request
 * once the apps are actually closed. A single watcher in `App` *fires* it, and
 * only once the session reports verified Protected over TUN. Relaunching an app
 * any earlier — optimistically alongside the connect request, or in proxy mode —
 * would put it back on the network before Tor is carrying its traffic.
 *
 * The state lives outside React so it survives tab switches and so both
 * surfaces share one request; the app list is memory-only and never persisted.
 */
export type ReopenPhase = "idle" | "armed" | "running";

export type ReopenRequest = {
  phase: ReopenPhase;
  apps: ReopenableApp[];
};

const IDLE: ReopenRequest = { phase: "idle", apps: [] };

let current: ReopenRequest = IDLE;
const listeners = new Set<() => void>();

function publish(next: ReopenRequest) {
  current = next;
  for (const listener of listeners) listener();
}

const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

export function armReopenThroughTor(apps: ReopenableApp[]) {
  publish({ phase: "armed", apps });
}

export function disarmReopenThroughTor() {
  if (current.phase === "idle") return;
  publish(IDLE);
}

/**
 * Transition armed -> running. Returns false when another caller already took
 * the request, so a re-run of the watcher cannot relaunch the apps twice.
 */
export function claimReopenThroughTor(): boolean {
  if (current.phase !== "armed") return false;
  publish({ phase: "running", apps: current.apps });
  return true;
}

export function finishReopenThroughTor() {
  publish(IDLE);
}

export function useReopenRequest(): ReopenRequest {
  return useSyncExternalStore(subscribe, () => current);
}

/**
 * The only state in which relaunching an app routes it through Tor: TUN is live
 * and the session is verified Protected. `protectionLabel` is the UI's single
 * source of truth for verified protection (it folds session phase, control
 * port, DNS, and kill-switch verification together in `useTorApp`).
 */
export const PROTECTED_TUN_LABEL = "Protected · TUN";

export function isProtectedThroughTun(app: {
  status: AppStatus | null;
  tunOn: boolean;
  protectionLabel: string;
}): boolean {
  return (
    app.status?.session_phase === "protected" &&
    app.tunOn &&
    app.protectionLabel === PROTECTED_TUN_LABEL
  );
}

/** TUN is the configured route, so a relaunched app will be carried by Tor. */
export function isTunRoute(app: {
  status: AppStatus | null;
  settings: { connection_mode: string } | null;
  tunOn: boolean;
}): boolean {
  return app.tunOn || app.settings?.connection_mode === "tun";
}

export function listReopenableApps(): Promise<ReopenableApp[]> {
  return invoke<ReopenableApp[]>("list_reopenable_apps");
}

export function reopenClosedApps(): Promise<string> {
  return invoke<string>("reopen_closed_apps");
}
