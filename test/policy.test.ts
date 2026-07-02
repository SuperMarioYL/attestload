/**
 * Regression tests for the v0.2.0 cold-start / allowlist policy fix (fix 4).
 *
 * Two holes are pinned here:
 *   1. The dead `no-manifest` arm of the cold-start path is gone — a dir with no
 *      attestation at all can never reach the allowlist branch.
 *   2. A name-only allowlist entry no longer passes an UNSIGNED bundle that
 *      merely self-declares a popular name (the impersonation surface). A
 *      cold-start entry must PIN the artifact_digest; only then does it pass.
 *
 * These operate on `evaluatePolicy` directly with synthesized VerifyResults, so
 * no signing/network is involved.
 */

import { describe, expect, it } from "vitest";

import { evaluatePolicy } from "../src/policy.js";
import {
  PolicySchema,
  type Allowlist,
  type AttestationManifest,
  type VerifyResult,
} from "../src/types.js";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

/** A minimal well-formed manifest body claiming `name` + `artifact_digest`. */
function fakeManifest(name: string, digest: string): AttestationManifest {
  return {
    schema: "attestload/v1",
    subject: {
      name,
      version: "1.0.0",
      kind: "skill",
      artifact_digest: digest,
      sbom_source: "file-manifest",
    },
    sbom: { spdx_lite: true, source: "file-manifest", packages: [] },
    files: [{ path: "SKILL.md", sha256: DIGEST_A, size: 10, mode: 0o644, type: "file" }],
    provenance: {
      builder_id: "local:tester",
      source_repo: "",
      source_commit: "",
      build_type: "local",
    },
  };
}

/** An UNSIGNED-but-present result (verify() returns `no-signature` + manifest). */
function unsignedResult(name: string, digest: string): VerifyResult {
  return {
    ok: false,
    blocked_reason: "no-signature",
    message: "attestation carries no signature — unsigned code refused to load",
    manifest: fakeManifest(name, digest),
  };
}

/** A no-attestation-at-all result (verify() returns `no-manifest`, no manifest). */
function noManifestResult(): VerifyResult {
  return {
    ok: false,
    blocked_reason: "no-manifest",
    message: "no attestation found — refusing to load unattested code",
  };
}

const COLD_START = PolicySchema.parse({ use_allowlist: true });

describe("fix 4: cold-start no-manifest arm is dead and removed", () => {
  it("a no-manifest result never reaches the allowlist (no manifest to trust)", () => {
    const allowlist: Allowlist = {
      schema: "attestload-allowlist/v1",
      entries: [{ name: "github-mcp", artifact_digest: DIGEST_A, source_repo: "" }],
    };
    const decision = evaluatePolicy(noManifestResult(), COLD_START, allowlist);
    expect(decision.allowed).toBe(false);
  });
});

describe("fix 4: name-only allowlist entry cannot pass an unsigned self-claimed name", () => {
  it("an unsigned bundle claiming a popular name with a name-only entry is REFUSED", () => {
    // The classic impersonation: attacker ships an unsigned attestation that
    // self-declares name "github-mcp"; a name-only allowlist entry must NOT
    // bless it.
    const allowlist: Allowlist = {
      schema: "attestload-allowlist/v1",
      entries: [{ name: "github-mcp", source_repo: "github.com/github/github-mcp-server" }],
    };
    const decision = evaluatePolicy(
      unsignedResult("github-mcp", DIGEST_B),
      COLD_START,
      allowlist,
    );
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/name-only|pinned/i);
  });

  it("a digest-PINNED entry passes only when the self-declared digest matches", () => {
    const allowlist: Allowlist = {
      schema: "attestload-allowlist/v1",
      entries: [{ name: "github-mcp", artifact_digest: DIGEST_A, source_repo: "" }],
    };

    // matching digest → cold-start pass
    const ok = evaluatePolicy(unsignedResult("github-mcp", DIGEST_A), COLD_START, allowlist);
    expect(ok.allowed).toBe(true);
    expect(ok.reason).toMatch(/allowlisted/i);

    // mismatched digest → refused
    const bad = evaluatePolicy(unsignedResult("github-mcp", DIGEST_B), COLD_START, allowlist);
    expect(bad.allowed).toBe(false);
    expect(bad.reason).toMatch(/different digest/i);
  });

  it("a subject not present in the allowlist is still refused", () => {
    const allowlist: Allowlist = {
      schema: "attestload-allowlist/v1",
      entries: [{ name: "github-mcp", artifact_digest: DIGEST_A, source_repo: "" }],
    };
    const decision = evaluatePolicy(
      unsignedResult("totally-unknown-skill", DIGEST_A),
      COLD_START,
      allowlist,
    );
    expect(decision.allowed).toBe(false);
  });
});

/**
 * Regression tests for the v0.4.0 relaxed-path provenance fix.
 *
 * The signature-optional relaxed branch (require_signature=false + a no-signature
 * verdict) used to allow an unsigned-but-digest-verified artifact WITHOUT applying
 * require_provenance — asymmetric with the cryptographically-verified path, which
 * always enforces it. A coherent {require_signature:false, require_provenance:true}
 * posture ("accept digest-pinned unsigned code but still demand a builder identity")
 * must refuse a builder-less artifact on BOTH paths.
 */
describe("v0.4.0 fix: relaxed path enforces require_provenance symmetrically", () => {
  /** An unsigned-but-present result whose manifest has an EMPTY builder_id. */
  function unsignedResultNoBuilder(): VerifyResult {
    const manifest = fakeManifest("some-skill", DIGEST_A);
    return {
      ok: false,
      blocked_reason: "no-signature",
      message: "attestation carries no signature — unsigned code refused to load",
      manifest: { ...manifest, provenance: { ...manifest.provenance, builder_id: "" } },
    };
  }

  const RELAXED_PROV_REQUIRED = PolicySchema.parse({
    require_signature: false,
    require_provenance: true,
  });

  it("refuses an unsigned, builder-less artifact when provenance is required", () => {
    const decision = evaluatePolicy(unsignedResultNoBuilder(), RELAXED_PROV_REQUIRED);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/provenance|builder_id/i);
  });

  it("still allows an unsigned artifact that DOES carry a builder_id", () => {
    // fakeManifest sets builder_id "local:tester", so provenance is satisfied.
    const decision = evaluatePolicy(
      unsignedResult("some-skill", DIGEST_A),
      RELAXED_PROV_REQUIRED,
    );
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toMatch(/signature not required/i);
  });

  it("allows a builder-less unsigned artifact when provenance is NOT required", () => {
    const relaxedNoProv = PolicySchema.parse({
      require_signature: false,
      require_provenance: false,
    });
    const decision = evaluatePolicy(unsignedResultNoBuilder(), relaxedNoProv);
    expect(decision.allowed).toBe(true);
  });
});
