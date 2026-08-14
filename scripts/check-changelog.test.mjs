import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  behaviorPath,
  parseChangelog,
  requireTrailForChanges,
  sectionHasEntries,
  unreleasedSection,
  validateChangelogText,
} from "./lib/changelog.mjs";

const sample = `# Changelog

## [Unreleased]

### Added

- New helper start.

## [0.2.0] - 2026-07-30

### Added

- First public alpha.
`;

describe("parseChangelog", () => {
  it("reads Unreleased and dated sections", () => {
    const sections = parseChangelog(sample);
    assert.equal(sections.length, 2);
    assert.equal(sections[0].version, "Unreleased");
    assert.equal(sections[1].version, "0.2.0");
    assert.equal(sections[1].date, "2026-07-30");
    assert.equal(sectionHasEntries(unreleasedSection(sections)), true);
  });
});

describe("validateChangelogText", () => {
  it("rejects a file without Unreleased", () => {
    const { failures } = validateChangelogText("# Changelog\n\n## [1.0.0] - 2026-01-01\n\n- x\n");
    assert.ok(failures.some((item) => item.includes("Unreleased")));
  });

  it("accepts a well-formed file", () => {
    assert.deepEqual(validateChangelogText(sample).failures, []);
  });
});

describe("behaviorPath", () => {
  it("treats app and guide docs as behavior", () => {
    assert.equal(behaviorPath("src/App.tsx"), true);
    assert.equal(behaviorPath("src-tauri/src/cli.rs"), true);
    assert.equal(behaviorPath("docs/guide/cli.md"), true);
  });

  it("ignores generated changelog pages and rustfmt-only paths", () => {
    assert.equal(behaviorPath("docs/reference/changelog.md"), false);
    assert.equal(behaviorPath("docs/reference/release-audit.md"), false);
    assert.equal(behaviorPath("src-tauri/Cargo.lock"), false);
  });
});

describe("requireTrailForChanges", () => {
  const sections = parseChangelog(sample);

  it("requires Unreleased bullets when behavior changed without a version bump", () => {
    const empty = parseChangelog(`# Changelog\n\n## [Unreleased]\n\n## [0.2.0] - 2026-07-30\n\n- x\n`);
    const failures = requireTrailForChanges({
      behaviorChanged: true,
      versionBumped: false,
      newVersion: "0.2.0",
      sections: empty,
    });
    assert.ok(failures[0].includes("Unreleased"));
  });

  it("requires a dated section when the version was bumped", () => {
    const failures = requireTrailForChanges({
      behaviorChanged: true,
      versionBumped: true,
      newVersion: "0.2.1",
      sections,
    });
    assert.ok(failures[0].includes("0.2.1"));
  });

  it("passes a bump that has a populated dated section", () => {
    const bumped = parseChangelog(`# Changelog

## [Unreleased]

## [0.2.1] - 2026-08-13

### Security

- CLI start is Degraded.

## [0.2.0] - 2026-07-30

- x
`);
    assert.deepEqual(
      requireTrailForChanges({
        behaviorChanged: true,
        versionBumped: true,
        newVersion: "0.2.1",
        sections: bumped,
      }),
      [],
    );
  });
});
