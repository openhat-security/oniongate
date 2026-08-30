export type Channel = "alpha" | "beta" | "rc" | "stable";

/** 0.x is alpha by policy; a semver prerelease tag wins over it. */
export function releaseChannel(version: string | null): Channel {
  if (!version) return "alpha";
  if (/-beta/i.test(version)) return "beta";
  if (/-rc/i.test(version)) return "rc";
  return version.startsWith("0.") ? "alpha" : "stable";
}
