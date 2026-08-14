#!/usr/bin/env node
/**
 * Fail CI / `make check` when the user-facing trail is missing or stale.
 * Compares CHANGELOG.md to generated docs pages. Optionally compares against
 * a git base (GITHUB_BASE_REF, CHANGELOG_BASE, or main) for PR behavior files.
 */
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  behaviorPath,
  parseChangelog,
  renderDocsChangelog,
  requireTrailForChanges,
  validateChangelogText,
} from "./lib/changelog.mjs";

const root = new URL("../", import.meta.url);

function git(args) {
  return execFileSync("git", args, {
    cwd: fileURLToPath(root),
    encoding: "utf8",
  }).trim();
}

function changedFiles(base) {
  try {
    const mergeBase = git(["merge-base", base, "HEAD"]);
    const text = git(["diff", "--name-only", `${mergeBase}...HEAD`]);
    return text ? text.split("\n").filter(Boolean) : [];
  } catch {
    return [];
  }
}

function fileVersion(relative, fallback) {
  try {
    const text = git(["show", `${fallback}:${relative}`]);
    const match = text.match(/"version":\s*"([^"]+)"/);
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

const changelog = await readFile(new URL("CHANGELOG.md", root), "utf8");
const docsChangelog = await readFile(
  new URL("docs/reference/changelog.md", root),
  "utf8",
).catch(() => "");
const packageJson = JSON.parse(
  await readFile(new URL("package.json", root), "utf8"),
);

const { sections, failures } = validateChangelogText(changelog);
const expectedDocs = renderDocsChangelog(changelog);
if (docsChangelog !== expectedDocs) {
  failures.push(
    "docs/reference/changelog.md is stale; run `make changelog-sync`",
  );
}

const base =
  process.env.CHANGELOG_BASE ||
  (process.env.GITHUB_BASE_REF
    ? `origin/${process.env.GITHUB_BASE_REF}`
    : "main");
const files = changedFiles(base);
if (files.length > 0) {
  const baseVersion = fileVersion("package.json", base);
  const versionBumped =
    Boolean(baseVersion) && baseVersion !== packageJson.version;
  failures.push(
    ...requireTrailForChanges({
      behaviorChanged: files.some(behaviorPath),
      versionBumped,
      newVersion: packageJson.version,
      sections,
    }),
  );
}

if (failures.length > 0) {
  console.error("Changelog trail check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

const parsed = parseChangelog(changelog);
console.log(
  `Changelog trail ok (${parsed.length} sections, docs in sync, version ${packageJson.version})`,
);
