/**
 * v0.10.0 regression — `fix-sigstore-verify-bundle-dep-undeclared` (twin of the
 * v0.9.0 `fix-sigstore-verify-tuf-dep-undeclared`).
 *
 * `verifySigstore` (src/verify.ts) dynamically imports `@sigstore/bundle` to call
 * `bundleFromJSON()` (verify.ts:167) — the parser that turns the protobuf-JSON
 * sigstore bundle in the manifest into the `SignedEntity` `@sigstore/verify`
 * checks against the trusted root. If that import rejects, the outer try/catch
 * swallows it to `{ ok: false, identity: "" }` — the short-circuit at
 * verify.ts:196 — so EVERY sigstore-signed attestation is rejected as
 * `signature-invalid`. But `@sigstore/bundle` was NOT declared in package.json
 * `dependencies`; it reached node_modules only transitively (via
 * `@sigstore/sign` and `@sigstore/verify`). Under default hoisting the import
 * resolves today, but under a strict-isolation install (e.g. pnpm
 * `hoist-pattern: []`, where each package may only resolve its OWN declared
 * deps) it rejects with ERR_MODULE_NOT_FOUND and the flagship keyless-verify
 * path silently short-circuits to ok:false. This is the exact twin of the v0.9.0
 * tuf-dep fix, for the other dynamic import the verify path performs.
 *
 * The fix declares `@sigstore/bundle` in package.json `dependencies` (mirroring
 * how v0.9 added `@sigstore/tuf`). The regression asserts (a) the dep is
 * declared and (b) the dynamic import the verify path performs actually resolves
 * to a module exposing a callable `bundleFromJSON` — the exact condition that
 * keeps verifySigstore from short-circuiting via the outer catch. We do NOT feed
 * verifySigstore a real bundle (that would also pull the tuf network root); the
 * loadable-module assertion is the faithful, non-flaky mirror of "no longer
 * short-circuits to ok:false due to a missing bundle module".
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");

describe("v0.10.0: @sigstore/bundle is declared + importable so verifySigstore proceeds past the bundleFromJSON load", () => {
  it("package.json declares @sigstore/bundle as a runtime dependency", () => {
    const pkg = JSON.parse(
      readFileSync(path.join(repoRoot, "package.json"), "utf8"),
    ) as { dependencies?: Record<string, string> };
    expect(pkg.dependencies).toBeDefined();
    expect(pkg.dependencies!["@sigstore/bundle"]).toMatch(/^[\^~]?\d/);
  });

  it("the dynamic import('@sigstore/bundle') the verify path performs resolves (not ERR_MODULE_NOT_FOUND)", async () => {
    // This is the exact import verify.ts does at verify.ts:167. Without the
    // fix it rejected with ERR_MODULE_NOT_FOUND under a strict-isolation
    // install; with the fix it resolves to the declared dep.
    const mod = (await import("@sigstore/bundle")) as {
      bundleFromJSON?: unknown;
    };
    expect(mod).toBeDefined();
    expect(typeof mod.bundleFromJSON).toBe("function");
  });
});
