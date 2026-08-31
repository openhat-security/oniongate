export type Channel = "alpha" | "beta" | "rc" | "stable";

/**
 * Channel from the bundled version string.
 * Semver prerelease tags (`-alpha`, `-beta`, `-rc`) win; any other hyphenated
 * prerelease is treated as alpha. Plain `0.x` stays alpha by policy until the
 * stable gates pass — never call a 0.x build stable.
 */
export function releaseChannel(version: string | null): Channel {
  if (!version) return "alpha";
  if (/-alpha/i.test(version)) return "alpha";
  if (/-beta/i.test(version)) return "beta";
  if (/-rc/i.test(version)) return "rc";
  if (version.includes("-")) return "alpha";
  return version.startsWith("0.") ? "alpha" : "stable";
}

/** Title-case label for Settings, sidebar, and banners. */
export function channelLabel(channel: Channel): string {
  switch (channel) {
    case "alpha":
      return "Alpha";
    case "beta":
      return "Beta";
    case "rc":
      return "RC";
    case "stable":
      return "Stable";
  }
}

export function isStableChannel(channel: Channel): boolean {
  return channel === "stable";
}
