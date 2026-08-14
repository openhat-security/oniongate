#!/usr/bin/env node
/** Copy CHANGELOG.md into the docs site and write a commit-subject audit page. */
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseChangelog, renderDocsChangelog, renderReleaseAudit } from "./lib/changelog.mjs";

const root = new URL("../", import.meta.url);

function git(args) {
  return execFileSync("git", args, {
    cwd: fileURLToPath(root),
    encoding: "utf8",
  }).trim();
}

function previousTag(version) {
  try {
    const tags = git(["tag", "-l", "v*", "--sort=-v:refname"])
      .split("\n")
      .filter(Boolean);
    const current = `v${version}`;
    return tags.find((tag) => tag !== current) ?? null;
  } catch {
    return null;
  }
}

function commitSubjects(range) {
  try {
    const log = range
      ? git(["log", "--format=%h %s", range])
      : git(["log", "--format=%h %s"]);
    return log
      ? log.split("\n").filter((line) => line && !/secret|bridge line|onion key/i.test(line))
      : [];
  } catch {
    return [];
  }
}

const changelog = await readFile(new URL("CHANGELOG.md", root), "utf8");
const packageJson = JSON.parse(
  await readFile(new URL("package.json", root), "utf8"),
);
const version = packageJson.version;
const prev = previousTag(version);
const range = prev ? `${prev}..HEAD` : null;

await writeFile(
  new URL("docs/reference/changelog.md", root),
  renderDocsChangelog(changelog),
);
await writeFile(
  new URL("docs/reference/release-audit.md", root),
  renderReleaseAudit({
    version,
    range,
    commits: commitSubjects(range),
  }),
);

const sections = parseChangelog(changelog);
console.log(
  `Wrote docs/reference/changelog.md (${sections.length} sections) and release-audit.md (${version})`,
);
