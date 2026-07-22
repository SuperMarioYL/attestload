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

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { attest } from "../src/attest.js";
import { checkLoad } from "../src/loader-guard.js";
import { evaluatePolicy, loadPolicy } from "../src/policy.js";
import {
  DEFAULT_POLICY,
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

/**
 * Regression tests for the v0.5.0 policy-discovery fixes.
 *
 * fix 1 — a policy file planted INSIDE the verified artifact dir is no longer
 * honored (a downloaded skill can no longer self-authorize with its own relaxed
 * policy), but an explicit --policy file OUTSIDE the artifact still applies.
 *
 * fix 2 — a malformed or missing explicit --policy file fails loudly (throws,
 * naming the file) instead of silently degrading to DEFAULT_POLICY; a missing
 * default policy still cleanly falls back to DEFAULT_POLICY, while a malformed
 * default policy in the search dir surfaces rather than being swallowed.
 */
describe("v0.5.0 fix 2: malformed/missing explicit policy fails loudly; missing default falls back", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-policy-fix2-"));
  });

  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("a malformed explicit --policy file (invalid JSON) throws and names the file", async () => {
    const file = path.join(tmp, "bad.json");
    await fs.writeFile(file, "{ not valid json");
    await expect(loadPolicy({ file })).rejects.toThrow(/bad\.json/);
  });

  it("a schema-violating explicit --policy file throws and names the file", async () => {
    const file = path.join(tmp, "bad-schema.json");
    // require_signature must be a boolean; a string violates the policy schema.
    await fs.writeFile(file, JSON.stringify({ require_signature: "no" }));
    await expect(loadPolicy({ file })).rejects.toThrow(/bad-schema\.json/);
  });

  it("a missing explicit --policy file throws (ENOENT surfaces, not swallowed)", async () => {
    const file = path.join(tmp, "nope.json");
    await expect(loadPolicy({ file })).rejects.toThrow(/nope\.json/);
  });

  it("a missing default policy in the search dir falls back to DEFAULT_POLICY", async () => {
    // Empty tmp dir holds no attestload.policy.* → strict default.
    const policy = await loadPolicy({ searchDir: tmp });
    expect(policy).toEqual(DEFAULT_POLICY);
  });

  it("a malformed default policy in the search dir throws (not swallowed as absent)", async () => {
    const file = path.join(tmp, "attestload.policy.json");
    await fs.writeFile(file, "{ broken");
    await expect(loadPolicy({ searchDir: tmp })).rejects.toThrow(
      /attestload\.policy\.json/,
    );
  });
});

describe("v0.5.0 fix 1: a policy file inside the verified artifact dir is NOT honored", () => {
  let workspace: string;
  let skillDir: string;
  let keyDir: string;

  beforeEach(async () => {
    workspace = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-policy-fix1-"));
    skillDir = path.join(workspace, "skill");
    keyDir = path.join(workspace, "keys");
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(
      path.join(skillDir, "SKILL.md"),
      "---\nname: fixture-skill\nversion: 1.0.0\n---\n# Fixture\nhello.\n",
    );
    // A self-authorizing policy planted INSIDE the artifact dir. Under the old
    // trust-boundary bug this was discovered and used to bless the unsigned
    // manifest below; it must now be ignored.
    await fs.writeFile(
      path.join(skillDir, "attestload.policy.json"),
      JSON.stringify({ require_signature: false, require_provenance: false }),
    );
    // Attest WITH the policy file present so the file manifest's digest covers
    // it (adding it later would shift the digest → digest-mismatch, not the
    // no-signature scenario this fix targets).
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    // Strip the signature → an unsigned-but-present, digest-valid manifest.
    // verify() now returns `no-signature` with the parsed manifest attached.
    const attestationPath = path.join(skillDir, ".attestload", "attestation.json");
    const manifest = JSON.parse(
      await fs.readFile(attestationPath, "utf8"),
    ) as { signature?: unknown } & Record<string, unknown>;
    delete manifest.signature;
    await fs.writeFile(
      attestationPath,
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
  });

  afterEach(async () => {
    await fs.rm(workspace, { recursive: true, force: true });
  });

  it("the in-dir relaxed policy does not self-authorize an unsigned skill (BLOCKED)", async () => {
    const decision = await checkLoad(skillDir);
    expect(decision.allowed).toBe(false);
    // Pin the scenario: blocked for being UNSIGNED (the in-dir relaxed policy
    // was ignored and the strict default applied), not for a tamper.
    expect(decision.verify.blocked_reason).toBe("no-signature");
  });

  it("an explicit --policy file OUTSIDE the artifact still applies (relaxed → PASS)", async () => {
    const outside = path.join(workspace, "consumer.policy.json");
    await fs.writeFile(
      outside,
      JSON.stringify({ require_signature: false, require_provenance: false }),
    );
    const decision = await checkLoad(skillDir, { policyFile: outside });
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toMatch(/signature not required/i);
  });
});

/**
 * Regression tests for the v0.7.0 allowlist-load fix.
 *
 * resolveContext (loader-guard) used to blanket `.catch(() => undefined)` the
 * allowlist load — the same silent-swallow footgun v0.5.0 closed for the policy
 * file, and inconsistent with the policy load in the very same function (which
 * already fails loudly). A malformed allowlist file therefore degraded to "no
 * allowlist", so a consumer's digest-pinned known-good skill was refused with a
 * misleading `no-signature` reason and no hint the allowlist file was the cause.
 * A missing file must still resolve cleanly (empty index); only a malformed one
 * fails loudly with the file named.
 */
describe("v0.7.0 fix: a malformed allowlist file fails loudly (not silently swallowed)", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-allow-fix-"));
  });

  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  const USE_ALLOWLIST = PolicySchema.parse({ use_allowlist: true });

  it("a malformed allowlist file throws (naming the file) instead of degrading to no allowlist", async () => {
    const skill = path.join(tmp, "skill");
    await fs.mkdir(skill, { recursive: true }); // no attestation → verify() = no-manifest
    const bad = path.join(tmp, "allow.json");
    await fs.writeFile(bad, "{ not valid json");

    await expect(
      checkLoad(skill, { policy: USE_ALLOWLIST, allowlistFile: bad }),
    ).rejects.toThrow(/allow\.json/);
  });

  it("a missing allowlist file still resolves cleanly (empty index, no throw)", async () => {
    const skill = path.join(tmp, "skill");
    await fs.mkdir(skill, { recursive: true });
    const missing = path.join(tmp, "does-not-exist.json");

    // Must NOT throw: a missing file is a normal empty index, not an error.
    const decision = await checkLoad(skill, {
      policy: USE_ALLOWLIST,
      allowlistFile: missing,
    });
    expect(decision.allowed).toBe(false); // refused (no-manifest), but did not crash
  });
});

// ---------------------------------------------------------------------------
// v0.8.0 fix — sigstore allowed_identities bypass via the unsigned
// cert_identity field. The sigstore twin of the v0.6.0 ed25519 bypass.
// ---------------------------------------------------------------------------
describe("v0.8.0 fix: sigstore allowed_identities binds to the verified cert SAN, not the forgeable cert_identity", () => {
  // For sigstore, boundSignerIdentity used to return the self-declared
  // signature.cert_identity — but that field lives INSIDE the signature block,
  // which verify.ts STRIPS before computing the signed canonical body
  // (canonicalize(manifest minus signature)). So cert_identity is NOT covered
  // by the Sigstore signature: any holder of a valid keyless attestation could
  // rewrite it to a value in a consumer's allowed_identities, verifySigstore
  // would still return true (the bundle validly signs the unchanged body), and
  // the forged identity would match -> the gate ALLOWED attacker code as a
  // trusted signer.
  //
  // The fix derives the sigstore identity from the VERIFIED bundle's cert SAN
  // (surfaced onto the VerifyResult as verified_signer_identity by verify.ts,
  // pulled from @sigstore/verify's Signer.identity.subjectAlternativeName -- the
  // OIDC email/URI Fulcio issued the cert for, chained against Fulcio's root).
  // allowed_identities now binds to THAT, never the forgeable field.
  //
  // These tests synthesize a verified sigstore VerifyResult offline: a real
  // keyless sigstore attestation needs network + an OIDC token, but the gate's
  // BINDING (policy.ts boundSignerIdentity) is the logic under test and is
  // deterministic given the VerifyResult. The synthesized identity is the value
  // verify.ts would surface for a real verified bundle.

  const REAL_SAN = "attacker@example.com"; // the cert SAN @sigstore/verify chained
  const FORGED = "trusted@example.com"; // what the attacker rewrote cert_identity to

  /** A VERIFIED sigstore result whose self-declared cert_identity was FORGED. */
  function verifiedSigstoreResult(
    verifiedSan: string,
    forgedCertIdentity: string,
  ): VerifyResult {
    return {
      ok: true,
      message: "PASS -- attestation verified, code is safe to load",
      // The cryptographically-bound identity verify.ts surfaced from the
      // verified bundle's cert SAN (the attacker's REAL OIDC email).
      verified_signer_identity: verifiedSan,
      manifest: {
        ...fakeManifest("some-mcp-server", DIGEST_A),
        signature: {
          rekor_log_index: 42,
          // The forgeable, UNSIGNED field -- the attacker rewrote it to a value
          // the consumer's allowlist trusts, hoping the gate matches on it.
          cert_identity: forgedCertIdentity,
          cert_issuer: "sigstore",
          bundle: { signing_mode: "sigstore", sigstore: {} },
        },
      },
    };
  }

  it("a forged cert_identity in the consumer's allowlist does NOT authorize (binds to the verified SAN)", () => {
    // The consumer trust-lists the value the attacker rewrote cert_identity to.
    // The OLD code matched cert_identity -> ALLOWED (the bypass). The fix binds
    // allowed_identities to the cryptographically-verified cert SAN, which is
    // the attacker's REAL email and is NOT allowlisted -> REFUSED.
    const result = verifiedSigstoreResult(REAL_SAN, FORGED);
    const policy = PolicySchema.parse({ allowed_identities: [FORGED] });
    const decision = evaluatePolicy(result, policy);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toContain(REAL_SAN);
    expect(decision.reason).toMatch(/not in allowed_identities/);
  });

  it("an honest sigstore attestation still authorizes when the real SAN is allowlisted (non-breaking)", () => {
    // Honest case: cert_identity was set from the same email as the cert SAN,
    // so they agree. An allowlist pinning that identity still passes under the
    // fix -- only FORGED cert_identity values (!= the verified SAN) are refused.
    const result = verifiedSigstoreResult(REAL_SAN, REAL_SAN);
    const policy = PolicySchema.parse({ allowed_identities: [REAL_SAN] });
    const decision = evaluatePolicy(result, policy);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toMatch(/identity allowed/);
  });

  it("an empty/absent verified SAN fails closed (no forgeable fallback to cert_identity)", () => {
    // If @sigstore/verify surfaced no SAN (defensively), the bound identity is
    // "" -- matching nothing -- so the gate refuses EVEN IF the forged
    // cert_identity is allowlisted. The unsigned field is never a fallback.
    const result = verifiedSigstoreResult("", FORGED);
    const policy = PolicySchema.parse({ allowed_identities: [FORGED] });
    const decision = evaluatePolicy(result, policy);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/not in allowed_identities/);
  });
});

// ---------------------------------------------------------------------------
// v0.8.0 fix -- a schema-malformed allowlist (valid JSON, wrong shape) now
// names the file, not only JSON-syntax errors.
// ---------------------------------------------------------------------------
describe("v0.8.0 fix: a schema-malformed allowlist (valid JSON, wrong shape) names the file", () => {
  let tmp: string;

  beforeEach(async () => {
    tmp = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-allow-schema-"));
  });

  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  const USE_ALLOWLIST = PolicySchema.parse({ use_allowlist: true });

  it("a schema-malformed allowlist rejects and names the file (not only JSON-syntax errors)", async () => {
    // The v0.7.0 fix pinned only the JSON-syntax case (a SyntaxError wrapped
    // with the path). A ZodError from AllowlistSchema.parse -- valid JSON but a
    // wrong-shape entry, e.g. an artifact_digest that isn't a sha256 -- used to
    // fall through to the bare `throw err` with no filename, so the CLI labeled
    // it by option name (--allowlist-file) rather than the actual path. Now
    // every non-ENOENT error names the file, mirroring parsePolicyFile.
    const skill = path.join(tmp, "skill");
    await fs.mkdir(skill, { recursive: true }); // no attestation -> verify() = no-manifest
    const bad = path.join(tmp, "bad-schema.json");
    await fs.writeFile(
      bad,
      JSON.stringify({
        schema: "attestload-allowlist/v1",
        entries: [{ name: "x", artifact_digest: "not-a-sha256" }],
      }),
    );

    await expect(
      checkLoad(skill, { policy: USE_ALLOWLIST, allowlistFile: bad }),
    ).rejects.toThrow(/bad-schema\.json/);
  });
});
