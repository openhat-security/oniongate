import { defineConfig } from "vitepress";

const repo = "https://github.com/openhat-security/oniongate";

export default defineConfig({
  title: "OnionGate",
  titleTemplate: ":title · OnionGate",
  description:
    "Route selected apps through Tor, host temporary or permanent onion sites, and inspect the live protection boundary.",
  lang: "en-US",
  // Published under a repository subpath on GitHub Pages.
  base: "/oniongate/",
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: false,
  sitemap: {
    hostname: "https://openhat-security.github.io/oniongate/",
  },
  head: [
    ["link", { rel: "icon", href: "/oniongate/logo.png" }],
    ["meta", { name: "theme-color", content: "#7c3aed" }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:title", content: "OnionGate" }],
    [
      "meta",
      {
        property: "og:description",
        content:
          "Route selected apps through Tor, host onion sites, and inspect the live protection boundary.",
      },
    ],
    [
      "meta",
      {
        property: "og:image",
        content: "https://openhat-security.github.io/oniongate/logo.png",
      },
    ],
  ],

  themeConfig: {
    logo: "/logo.png",

    nav: [
      { text: "Guide", link: "/guide/", activeMatch: "/guide/" },
      {
        text: "Security",
        items: [
          { text: "Threat model", link: "/reference/threat-model" },
          { text: "Residual leaks", link: "/reference/residual-leaks" },
          { text: "Privacy", link: "/reference/privacy" },
          { text: "Local data and network activity", link: "/reference/data-and-network" },
          { text: "Platform support", link: "/reference/platform-support" },
          { text: "Security policy", link: `${repo}/blob/main/SECURITY.md` },
        ],
      },
      { text: "Reference", link: "/reference/architecture", activeMatch: "/reference/" },
      { text: "Install", link: "/guide/install" },
    ],

    sidebar: {
      "/guide/": [
        {
          text: "Getting started",
          items: [
            { text: "What OnionGate is", link: "/guide/" },
            { text: "Install", link: "/guide/install" },
            { text: "Local installers and updates", link: "/guide/updates" },
            { text: "Quick start", link: "/guide/quick-start" },
          ],
        },
        {
          text: "Protect traffic",
          items: [
            { text: "Connect and route traffic", link: "/guide/connection" },
            { text: "Use bridges", link: "/guide/bridges" },
            { text: "Route applications", link: "/guide/apps" },
            { text: "Verify the live boundary", link: "/guide/verify" },
          ],
        },
        {
          text: "Onion services",
          items: [
            { text: "Host an onion site", link: "/guide/hosting" },
            { text: "Command line", link: "/guide/cli" },
          ],
        },
        {
          text: "Operate",
          items: [
            { text: "Check and harden this machine", link: "/guide/system" },
            { text: "Settings and logs", link: "/guide/settings" },
            { text: "Daemons", link: "/guide/daemons" },
            { text: "Recovery and troubleshooting", link: "/guide/troubleshooting" },
            { text: "Demo script", link: "/guide/demo" },
          ],
        },
      ],
      "/reference/": [
        {
          text: "Reference",
          items: [
            { text: "Architecture", link: "/reference/architecture" },
            { text: "Platform support", link: "/reference/platform-support" },
            { text: "Local data and network activity", link: "/reference/data-and-network" },
            { text: "Threat model", link: "/reference/threat-model" },
            { text: "Residual leaks", link: "/reference/residual-leaks" },
            { text: "Privacy", link: "/reference/privacy" },
            { text: "Third-party software", link: "/reference/third-party" },
            { text: "Release process", link: "/reference/release" },
            { text: "Changelog", link: "/reference/changelog" },
            { text: "Release audit trail", link: "/reference/release-audit" },
          ],
        },
        {
          text: "Project",
          items: [
            { text: "Security policy", link: `${repo}/blob/main/SECURITY.md` },
            { text: "Contributing", link: `${repo}/blob/main/CONTRIBUTING.md` },
            { text: "Code of conduct", link: `${repo}/blob/main/CODE_OF_CONDUCT.md` },
          ],
        },
      ],
    },

    socialLinks: [{ icon: "github", link: repo }],

    editLink: {
      pattern: `${repo}/edit/main/docs/:path`,
      text: "Edit this page on GitHub",
    },

    search: { provider: "local" },

    footer: {
      message:
        "GPL-3.0. An independent project, not affiliated with or endorsed by The Tor Project.",
      copyright: "Copyright (C) 2026 OpenHat Security",
    },
  },
});
