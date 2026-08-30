import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { ClearnetAlertWindow } from "@/components/ClearnetAlertWindow";
import { applyPresetWindowSize, readSidebarCollapsed } from "@/lib/window";

// The core opens the always-on-top clearnet alert as a separate WebviewWindow
// pointing at `index.html#clearnet-alert`. That popup renders on its own, with
// no sidebar, no tabs, and no main-window sizing.
const isClearnetAlert =
  window.location.hash.replace(/^#/, "") === "clearnet-alert";

// Apply the OS color scheme before first paint to avoid a light flash. Once the
// saved theme setting loads, useTorApp reconciles this (auto/light/dark).
if (
  window.matchMedia &&
  window.matchMedia("(prefers-color-scheme: dark)").matches
) {
  document.documentElement.classList.add("dark");
}

// The main window is created hidden and non-resizable; pick a preset size for
// the device's screen (matching the saved sidebar state), center, and reveal it.
if (!isClearnetAlert) {
  void applyPresetWindowSize(readSidebarCollapsed());
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {isClearnetAlert ? <ClearnetAlertWindow /> : <App />}
  </React.StrictMode>,
);
