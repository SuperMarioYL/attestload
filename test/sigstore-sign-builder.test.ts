/**
 * v0.11.0 regression — `fix-sigstore-sign-bundlebuilder-undefined` (restore
 * keyless Sigstore signing, severity: high).
 *
 * Root cause (verified by the grill bug-hunter against the real installed
 * package): `trySignSigstore` (src/attest.ts) constructed the sigstore bundle
 * with `new mod.BundleBuilder({ signer, witnesses: [witness] })`, but
 * `@sigstore/sign@3.1.0` exports `BundleBuilder` ONLY as a TypeScript *type*
 * (`export type { Artifact, BundleBuilder, BundleBuilderOptions }` in
 * dist/index.d.ts — erased at runtime). The concrete runtime classes are
 * `DSSEBundleBuilder` and `MessageSignatureBundleBuilder` (dist/index.js wires
 * them as getter-backed `exports.*` values). So `mod.BundleBuilder` was
 * `undefined`, `new undefined(...)` threw a `TypeError`, and the surrounding
 * `try { ... } catch { return undefined; }` swallowed it → `trySignSigstore`
 * ALWAYS returned `undefined` → the headline keyless Sigstore signing feature
 * silently NEVER worked (every run degraded to ed25519). This is the worst
 * class of bug a try/catch-swallowing fallback can hide: the happy path was
 * structurally unreachable, and verify-side + ed25519-side stayed green so it
 * looked fine.
 *
 * The fix swaps the constructor to
 * `new mod.MessageSignatureBundleBuilder({ signer, witnesses: [witness] })`
 * (the concrete class for signing a raw message body — the canonical manifest
 * JSON — whose constructor takes `{ signer, witnesses }` and whose
 * `create({ data: Buffer })` matches the Artifact shape, so NO other
 * signing-path change is needed) and renames the local type cast accordingly.
 *
 * The regression STUBS the dynamic `import("@sigstore/sign")` to return a fake
 * `MessageSignatureBundleBuilder` whose `create()` resolves a fake bundle
 * (with `toJSON()` + `verificationMaterial.tlogEntries[0].logIndex`), invokes
 * `trySignSigstore` with a fake OIDC token, and ASSERTS
 * `MessageSignatureBundleBuilder` is constructed and `create` is called — so
 * the constructor can never silently regress to a non-existent (type-only)
 * export again. No real network/OIDC is exercised; the stub makes the signing
 * path deterministic. A complementary static assertion reads the installed
 * package's dist files to confirm `MessageSignatureBundleBuilder` is a runtime
 * value while `BundleBuilder` is type-only — the exact shape that made the old
 * code throw.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { trySignSigstore } from "../src/attest.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, "..");
const sigsignPkg = JSON.parse(
  readFileSync(path.join(repoRoot, "node_modules/@sigstore/sign/package.json"), "utf8"),
) as { version?: string; main?: string; types?: string };

/** Build a JWT-shaped string whose payload decodes to the given claims. */
function jwtWith(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.sig`;
}

// vi.hoisted runs before the vi.mock factory is registered, so the holders are
// initialized before the stubbed module is ever imported. The factory closes
// over these mutable stores; beforeEach truncates them between tests.
const stores = vi.hoisted(() => ({
  builderCtorCalls: [] as Array<{ signer: unknown; witnesses: unknown[] }>,
  createCalls: [] as Array<{ data: Buffer }>,
  toJSONCalls: 0,
}));

// Stub the dynamic `import("@sigstore/sign")` trySignSigstore performs. The
// fake MessageSignatureBundleBuilder records every construction + create() so
// the assertion can prove the signing path reached the concrete builder rather
// than throwing inside `new undefined(...)` and short-circuiting via the catch.
vi.mock("@sigstore/sign", () => {
  const ctor = function (this: unknown, options: {
    signer: unknown;
    witnesses: unknown[];
  }) {
    stores.builderCtorCalls.push({
      signer: options.signer,
      witnesses: options.witnesses,
    });
    return {
      create: (artifact: { data: Buffer }) => {
        stores.createCalls.push({ data: artifact.data });
        return Promise.resolve({
          toJSON: () => {
            stores.toJSONCalls += 1;
            return {
              verificationMaterial: { tlogEntries: [{ logIndex: 12345 }] },
            };
          },
          verificationMaterial: { tlogEntries: [{ logIndex: 12345 }] },
        });
      },
    };
  };
  return {
    DEFAULT_FULCIO_URL: "https://fulcio.sigstore.dev",
    DEFAULT_REKOR_URL: "https://rekor.sigstore.dev",
    FulcioSigner: function () {
      return {};
    },
    RekorWitness: function () {
      return {};
    },
    MessageSignatureBundleBuilder: ctor,
  };
});

describe("v0.11.0: trySignSigstore reaches the concrete MessageSignatureBundleBuilder (not the type-only BundleBuilder)", () => {
  beforeEach(() => {
    stores.builderCtorCalls.length = 0;
    stores.createCalls.length = 0;
    stores.toJSONCalls = 0;
  });

  it("constructs MessageSignatureBundleBuilder and calls create() to produce a full Signature", async () => {
    const token = jwtWith({ email: "alice@example.com" });
    const sig = await trySignSigstore("canonical-body", token);

    // The headline regression guard. Before the fix, `mod.BundleBuilder` was
    // undefined → `new undefined(...)` threw → the catch swallowed it →
    // trySignSigstore returned `undefined` and keyless signing silently
    // degraded to ed25519. With the fix, the concrete builder runs and
    // create() is invoked, so a real Signature comes back.
    expect(sig).toBeDefined();
    expect(stores.builderCtorCalls).toHaveLength(1);
    expect(stores.createCalls).toHaveLength(1);

    // The signed bytes are exactly the canonical body the caller passed in.
    expect(stores.createCalls[0]!.data.toString("utf8")).toBe("canonical-body");

    // The builder was constructed with the FulcioSigner + RekorWitness the
    // signing path wires up.
    expect(stores.builderCtorCalls[0]!.witnesses).toHaveLength(1);
    expect(stores.builderCtorCalls[0]!.signer).toBeDefined();

    // The returned Signature carries the Rekor log index from the fake bundle
    // and the email identity decoded from the fake JWT.
    expect(sig!.rekor_log_index).toBe(12345);
    expect(sig!.cert_identity).toBe("alice@example.com");
    expect(sig!.cert_issuer).toBe("sigstore");
    expect((sig!.bundle as { signing_mode: string }).signing_mode).toBe("sigstore");

    // The bundle is serialized via toJSON() for storage.
    expect(stores.toJSONCalls).toBe(1);
  });

  it("the installed @sigstore/sign exposes MessageSignatureBundleBuilder as a runtime value, not the type-only BundleBuilder", () => {
    // Static, non-flaky mirror of the root cause: the runtime dist wires
    // MessageSignatureBundleBuilder as a getter-backed export, while
    // BundleBuilder appears only under `export type { ... }` (erased).
    const distDir = path.join(repoRoot, "node_modules/@sigstore/sign", sigsignPkg.main ?? "dist/index.js", "..");
    const indexJs = readFileSync(path.join(distDir, "index.js"), "utf8");
    const indexDts = readFileSync(path.join(distDir, "index.d.ts"), "utf8");

    // Runtime: MessageSignatureBundleBuilder is a real exported value.
    expect(indexJs).toMatch(/exports\.MessageSignatureBundleBuilder\b/);
    // Runtime: BundleBuilder is NOT a real exported value (no getter, no
    // assignment) — it exists only as a type.
    expect(indexJs).not.toMatch(/exports\.BundleBuilder\b/);
    // Types: BundleBuilder is type-only; MessageSignatureBundleBuilder is a
    // value export. (These two lines are the exact source of the bug: the old
    // code reached for a name that was erased at runtime.)
    expect(indexDts).toMatch(/export type \{[^}]*\bBundleBuilder\b/);
    expect(indexDts).toMatch(/export \{[^}]*\bMessageSignatureBundleBuilder\b/);
  });
});
