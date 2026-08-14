#!/usr/bin/env node
// Assemble the Tauri updater manifest from artifacts already uploaded to a
// release.
//
// Each platform build publishes its own payload and detached signature. Having
// one job derive latest.json from those files afterwards keeps the platform
// builds independent, so they can run in parallel without racing each other to
// rewrite a shared manifest.

import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Tauri looks up `${os}-${arch}`. The payload for each is whichever bundle
// format that platform's updater installs.
//
// The bundler's own arch spelling differs from the Rust target triple's, and
// differs again between formats: Intel macOS ships as `_x64.app.tar.gz` while
// the Linux AppImage uses Debian's `amd64`. Accept every spelling seen for a
// target rather than assuming the triple's.
const endsWithAny = (...suffixes) => (name) =>
  suffixes.some((suffix) => name.endsWith(suffix));

const TARGETS = [
  {
    key: "darwin-aarch64",
    matches: endsWithAny("_aarch64.app.tar.gz", "_arm64.app.tar.gz"),
  },
  {
    key: "darwin-x86_64",
    matches: endsWithAny("_x64.app.tar.gz", "_x86_64.app.tar.gz"),
  },
  { key: "linux-x86_64", matches: endsWithAny(".AppImage") },
  { key: "windows-x86_64", matches: endsWithAny("-setup.exe") },
];

const [assetDir, version, baseUrl, output] = process.argv.slice(2);

if (!assetDir || !version || !baseUrl || !output) {
  console.error(
    "usage: build-updater-manifest.mjs <asset-dir> <version> <base-url> <output>",
  );
  process.exit(1);
}

const names = readdirSync(assetDir);
const platforms = {};
const problems = [];

for (const { key, matches } of TARGETS) {
  const found = names.filter((name) => matches(name) && !name.endsWith(".sig"));

  if (found.length === 0) {
    problems.push(`${key}: no updater payload was uploaded`);
    continue;
  }
  if (found.length > 1) {
    problems.push(`${key}: ambiguous payloads ${found.join(", ")}`);
    continue;
  }

  const payload = found[0];
  const signature = `${payload}.sig`;
  if (!names.includes(signature)) {
    problems.push(`${key}: ${payload} has no ${signature}`);
    continue;
  }

  platforms[key] = {
    signature: readFileSync(join(assetDir, signature), "utf8").trim(),
    url: `${baseUrl}/${encodeURIComponent(payload)}`,
  };
}

if (problems.length > 0) {
  for (const problem of problems) {
    console.error(`::error::Updater manifest incomplete — ${problem}`);
  }
  process.exit(1);
}

const manifest = {
  version,
  notes: "",
  pub_date: new Date().toISOString(),
  platforms,
};

writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Wrote ${output} covering ${Object.keys(platforms).join(", ")}`);
