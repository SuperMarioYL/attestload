/**
 * v0.9.0 regression — `fix-sigstore-verify-tuf-dep-undeclared`.
 *
 * `verifySigstore` (src/verify.ts) dynamically imports `@sigstore/tuf` to call
 * `getTrustedRoot()` (the Fulcio/Rekor root `@sigstore/verify` chains a cert
 * against). If the import fails it returns `{ ok: false, identity: "" }` — the
 * short-circuit at verify.ts:178. But `@sigstore/tuf` was NOT declared in
 * package.json and absent from node_modules, so in any real install the import
 * always rejected and EVERY sigstore-signed attestation was rejected as
 * `signature-invalid`. The headline signing mode was unverifiable out of the
 * box.
 *
 * The fix declares `@sigstore/tuf` in package.json + installs it. The regression
 * asserts (a) the dep is declared and (b) the dynamic import the verify path
 * performs actually resolves to a module exposing a callable `getTrustedRoot` —
 * the exact condition that flips the short-circuit. We do NOT call
 * `getTrustedRoot()` here (it hits the TUF network repo) nor feed verifySigstore
 * a real bundle (same network path); the loadable-module assertion is the
 * faithful, non-flaky mirror of "no longer short-circuits to ok:false due to a
 * missing tuf module".
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");

describe("v0.9.0: @sigstore/tuf is declared + importable so verifySigstore proceeds past the tuf load", () => {
  it("package.json declares @sigstore/tuf as a runtime dependency", () => {
    const pkg = JSON.parse(
      readFileSync(path.join(repoRoot, "package.json"), "utf8"),
    ) as { dependencies?: Record<string, string> };
    expect(pkg.dependencies).toBeDefined();
    expect(pkg.dependencies!["@sigstore/tuf"]).toMatch(/^[\^~]?\d/);
  });

  it("the dynamic import('@sigstore/tuf') the verify path performs resolves (not ERR_MODULE_NOT_FOUND)", async () => {
    // This is the exact import verify.ts does at verify.ts:175. Without the
    // fix it rejected with ERR_MODULE_NOT_FOUND; with the fix it resolves.
    const mod = (await import("@sigstore/tuf")) as {
      getTrustedRoot?: unknown;
    };
    expect(mod).toBeDefined();
    expect(typeof mod.getTrustedRoot).toBe("function");
  });
});
