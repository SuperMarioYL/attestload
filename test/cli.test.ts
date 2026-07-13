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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync, promises as fs } from "node:fs";
import * as os from "node:os";
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

/**
 * v0.7.0 — the `verify --allowlist` command fails loudly on a malformed
 * allowlist file rather than silently degrading to "no allowlist" and refusing
 * a cold-start skill with a misleading reason. Drives the real CLI action so the
 * runVerify code path (not just the loader-guard library) is exercised.
 */
describe("v0.7.0: verify --allowlist reports a malformed allowlist file", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-cli-allow-"));
  });

  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("exits non-zero with a message naming the file (not a silent no-allowlist degrade)", async () => {
    const skill = path.join(tmp, "skill");
    await fs.mkdir(skill, { recursive: true });
    const bad = path.join(tmp, "allow.json");
    await fs.writeFile(bad, "{ not valid json");

    const errors: string[] = [];
    const spy = vi
      .spyOn(console, "error")
      .mockImplementation((...a: unknown[]) => {
        errors.push(a.map(String).join(" "));
      });
    const prevExit = process.exitCode;
    process.exitCode = undefined;
    try {
      await buildProgram().parseAsync([
        "node",
        "attestload",
        "verify",
        skill,
        "--allowlist",
        "--allowlist-file",
        bad,
      ]);
      expect(process.exitCode).toBe(1);
      const joined = errors.join("\n");
      expect(joined).toMatch(/failed to load allowlist/i);
      expect(joined).toContain("allow.json");
    } finally {
      spy.mockRestore();
      process.exitCode = prevExit;
    }
  });
});
