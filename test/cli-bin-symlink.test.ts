/**
 * v0.9.0 regression — `fix-cli-bin-symlink-silent-noop`.
 *
 * When `attestload` is installed via npm, the bin is a symlink
 * (`/usr/local/bin/attestload` → `.../dist/cli.js`). The old `invokedDirectly`
 * check compared `import.meta.url` (which Node resolves to the REAL dist/cli.js,
 * following symlinks) against `file://${path.resolve(process.argv[1])}` (the
 * invoked symlink path, which `path.resolve` does NOT symlink-resolve). The two
 * sides never matched, so `main()` never ran, commander never parsed argv, and
 * `attestload verify <unattested>` silently exited 0 — bypassing the gate.
 *
 * These tests run the BUILT bin (`dist/cli.js`) through a symlink and assert the
 * bin actually executes: `--version` prints the version, and `verify` on an
 * unattested dir exits 1 (the gate fires). They build dist in `beforeAll` so the
 * regression is reproducible from a clean checkout. test/cli.test.ts calls
 * `buildProgram().parseAsync` directly, which bypasses the `invokedDirectly`
 * guard — so without this file the bin-entry logic can silently break again.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");
const distCli = path.join(repoRoot, "dist", "cli.js");
const tscBin = path.join(repoRoot, "node_modules", "typescript", "bin", "tsc");

/** The version recorded in package.json — what `--version` must print. */
function pkgJsonVersion(): string {
  const pkg = JSON.parse(
    readFileSync(path.join(repoRoot, "package.json"), "utf8"),
  ) as { version?: string };
  return pkg.version ?? "";
}

describe("v0.9.0: bin runs through an npm-installed symlink (invokedDirectly)", () => {
  let tmp: string;
  let symlinkPath: string;

  beforeAll(() => {
    // Build dist so the bin actually exists (faithful to `npm run build`).
    execFileSync(process.execPath, [tscBin], {
      cwd: repoRoot,
      stdio: "ignore",
    });
    expect(existsSync(distCli)).toBe(true);

    tmp = mkdtempSync(path.join(os.tmpdir(), "attestload-binsymlink-"));
    symlinkPath = path.join(tmp, "attestload");
    // Reproduce the npm-install layout: a bin-name symlink → dist/cli.js.
    symlinkSync(distCli, symlinkPath);
  });

  afterAll(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  it("`--version` prints the version when invoked via a symlink (not a silent noop)", () => {
    const out = execFileSync(process.execPath, [symlinkPath, "--version"], {
      encoding: "utf8",
    });
    expect(out.trim()).toBe(pkgJsonVersion());
  });

  it("`verify <unattested>` exits 1 via a symlink (gate fires, not silent exit 0)", () => {
    const unsignedDir = path.join(tmp, "unsigned");
    mkdirSync(unsignedDir, { recursive: true });
    writeFileSync(path.join(unsignedDir, "SKILL.md"), "# unsigned skill\n");

    let code: number | null = null;
    let stderr = "";
    try {
      execFileSync(process.execPath, [symlinkPath, "verify", unsignedDir], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      code = (e as { status?: number }).status ?? null;
      stderr = (e as { stderr?: string }).stderr ?? "";
    }
    // Without the fix, main() never runs, commander never parses, exit code is
    // 0 with no BLOCKED output. With the fix, the gate fires → exit 1.
    expect(code).toBe(1);
    expect(stderr).toMatch(/BLOCKED|refusing to load/i);
  });
});
