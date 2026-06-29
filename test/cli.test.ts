/**
 * CLI version tests (v0.3.0 — drift guard for the fix-stale-cli-version milestone).
 *
 * `attestload --version` used to print a hardcoded `0.1.0` literal in cli.ts,
 * which drifted from the real package version the moment the package shipped
 * 0.2.0+. For a provenance tool whose value is truthful reporting, the bin
 * lying about its own version is a correctness defect. These tests assert the
 * CLI-reported version is read from package.json, so the two can never silently
 * diverge again.
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { buildProgram, packageVersion } from "../src/cli.js";

/** The version recorded in the real package.json (the source of truth). */
function pkgJsonVersion(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const pkg = JSON.parse(
    readFileSync(path.join(here, "..", "package.json"), "utf8"),
  ) as { version?: string };
  return pkg.version ?? "";
}

describe("cli version", () => {
  it("packageVersion() returns the real package.json version (not a hardcoded literal)", () => {
    const fromPkg = pkgJsonVersion();
    expect(fromPkg).toMatch(/^\d+\.\d+\.\d+/); // sanity: a real semver
    expect(packageVersion()).toBe(fromPkg);
  });

  it("packageVersion() is never the stale 0.1.0 literal once the package has bumped", () => {
    // Guards the specific regression: the CLI must not report 0.1.0 while
    // package.json says otherwise.
    if (pkgJsonVersion() !== "0.1.0") {
      expect(packageVersion()).not.toBe("0.1.0");
    }
  });

  it("commander program is wired with the package version", () => {
    const program = buildProgram();
    expect(program.version()).toBe(pkgJsonVersion());
  });
});
