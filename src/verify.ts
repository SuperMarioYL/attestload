/**
 * `attestload verify <dir>` — the m2 gate-load core (the "refusal").
 *
 * Verification re-derives, from the directory on disk, everything the signed
 * attestation claims, and refuses to load if any link in the chain breaks:
 *
 *   1. parse  — `<dir>/.attestload/attestation.json` must exist and be a
 *               well-formed {@link AttestationManifest} (else `no-manifest` /
 *               `malformed-manifest`).
 *   2. files  — re-walk the dir into a content-addressed file manifest and
 *               re-roll it up; the digest must equal the signed
 *               `subject.artifact_digest` (else `digest-mismatch` → TAMPERED).
 *   3. sbom   — for a file-manifest SBOM, every package digest must still match
 *               the recomputed leaves (else `sbom-mismatch`).
 *   4. sig    — a signature block must be present (else `no-signature` →
 *               UNSIGNED) and must verify over the canonical manifest body:
 *                 - `ed25519`  → detached signature check with the embedded
 *                                SPKI public key (fully local, no network);
 *                 - `sigstore` → Sigstore bundle verified against the trusted
 *                                root via `@sigstore/verify` (dynamic import so
 *                                the dep stays optional; any failure is
 *                                `signature-invalid` → SIG_INVALID, never a
 *                                crash).
 *
 * The first failing check short-circuits with a structured {@link VerifyResult}.
 * A clean run returns `ok: true` plus a one-line provenance summary. Policy
 * (allowed identities, allowlist, what's *required*) is layered on top by
 * policy.ts — this module reports facts, policy decides if they're acceptable.
 *
 * The coarse verdict — `VERIFIED | TAMPERED | UNSIGNED | SIG_INVALID` — is
 * surfaced via {@link verdictOf} for callers (CLI, loader-guard) that want a
 * single word.
 */

import { promises as fs } from "node:fs";
import { verify as edVerify, createPublicKey } from "node:crypto";
import * as path from "node:path";

import {
  AttestationManifestSchema,
  type AttestationManifest,
  type BlockReason,
  type VerifyResult,
} from "./types.js";
import { buildFileManifest, rollupDigest, sha256Hex } from "./manifest.js";
import {
  ATTESTATION_DIR,
  ATTESTATION_FILE,
  canonicalize,
  type SignatureBundle,
} from "./attest.js";

/** Single-word verdict, the human-facing summary of a {@link VerifyResult}. */
export type Verdict = "VERIFIED" | "TAMPERED" | "UNSIGNED" | "SIG_INVALID";

/** Strip an optional `sha256:` prefix to compare bare hex digests. */
function bareDigest(d: string): string {
  return d.startsWith("sha256:") ? d.slice("sha256:".length) : d;
}

/** Map a machine {@link BlockReason} to the coarse {@link Verdict}. */
export function verdictOf(result: VerifyResult): Verdict {
  if (result.ok) return "VERIFIED";
  switch (result.blocked_reason) {
    case "digest-mismatch":
    case "sbom-mismatch":
      return "TAMPERED";
    case "no-manifest":
    case "no-signature":
    case "provenance-missing":
      return "UNSIGNED";
    case "signature-invalid":
    case "rekor-not-found":
    case "identity-not-allowed":
    case "malformed-manifest":
    case "empty-artifact":
      return "SIG_INVALID";
    default:
      return "SIG_INVALID";
  }
}

/** Build the failing result for a given reason + message. */
function blocked(
  blocked_reason: BlockReason,
  message: string,
  manifest?: AttestationManifest,
): VerifyResult {
  return manifest
    ? { ok: false, blocked_reason, message, manifest }
    : { ok: false, blocked_reason, message };
}

/** One-line "who built it, from which commit, how it was signed" summary. */
function provenanceSummary(manifest: AttestationManifest): string {
  const p = manifest.provenance;
  const sig = manifest.signature;
  const bundle = sig?.bundle as SignatureBundle | undefined;
  const mode = bundle?.signing_mode ?? "unknown";
  const commit = p.source_commit ? p.source_commit.slice(0, 12) : "no-commit";
  const repo = p.source_repo || "local";
  const log =
    mode === "sigstore" && sig
      ? ` · rekor#${sig.rekor_log_index}`
      : "";
  return `built by ${p.builder_id} from ${repo}@${commit} · signed ${mode}${log}`;
}

/**
 * Verify the ed25519 detached signature over the canonical manifest body using
 * the SPKI public key embedded in the bundle. Pure local crypto, no network.
 */
function verifyEd25519(
  body: string,
  bundle: Extract<SignatureBundle, { signing_mode: "ed25519" }>,
): boolean {
  try {
    const pub = createPublicKey(bundle.public_key_pem);
    return edVerify(
      null,
      Buffer.from(body, "utf8"),
      pub,
      Buffer.from(bundle.signature, "base64"),
    );
  } catch {
    return false;
  }
}

/**
 * Verify a Sigstore bundle against the public trusted root.
 *
 * `@sigstore/verify` is imported dynamically and treated as untyped: the dep is
 * optional at type-check time, and any failure (missing dep, offline, bad
 * inclusion proof, body mismatch) resolves to `{ ok: false, identity: "" }`
 * rather than throwing — the caller turns that into a `signature-invalid`
 * verdict. The signed body is supplied as the artifact the bundle must attest
 * to.
 *
 * On success the returned `identity` is the cryptographically-VERIFIED signer
 * identity: the certificate Subject Alternative Name (the OIDC email/URI Fulcio
 * issued the leaf cert for) that `@sigstore/verify` already chained against
 * Fulcio's root, exposed on the returned `Signer` object. This is the value an
 * attacker CANNOT forge without controlling Fulcio — unlike the manifest's
 * self-declared `signature.cert_identity`, which lives INSIDE the unsigned
 * signature block and is therefore NOT covered by the Sigstore signature (see
 * `boundSignerIdentity` in policy.ts). The caller surfaces it onto the
 * VerifyResult so `allowed_identities` binds to it. Non-breaking for honest
 * attestations: the bundle's cert SAN equals the email `cert_identity` was
 * derived from at signing time (attest.ts `extractIdentity` reads the JWT
 * `email` claim, and Fulcio puts that same email in the cert's rfc822Name SAN).
 */
export async function verifySigstore(
  body: string,
  bundle: Extract<SignatureBundle, { signing_mode: "sigstore" }>,
): Promise<{ ok: boolean; identity: string }> {
  try {
    const mod = (await import("@sigstore/verify")) as unknown as {
      toSignedEntity: (b: unknown, artifact?: Buffer) => unknown;
      toTrustMaterial: (root: unknown) => unknown;
      Verifier: new (tm: unknown) => {
        verify: (e: unknown) => {
          identity?: { subjectAlternativeName?: string };
        };
      };
    };
    const bundleMod = (await import("@sigstore/bundle")) as unknown as {
      bundleFromJSON: (j: unknown) => unknown;
    };

    // `@sigstore/tuf` supplies the public trusted root but is an indirect dep;
    // resolve it through an opaque specifier so a missing/absent package
    // degrades to a refusal (signature-invalid) instead of a type/resolve error.
    const tufSpecifier = "@sigstore/tuf";
    const tufMod = (await import(/* @vite-ignore */ tufSpecifier).catch(
      () => undefined,
    )) as { getTrustedRoot: () => Promise<unknown> } | undefined;
    if (!tufMod) return { ok: false, identity: "" };

    const trustedRoot = await tufMod.getTrustedRoot();
    const trustMaterial = mod.toTrustMaterial(trustedRoot);
    const verifier = new mod.Verifier(trustMaterial);

    const parsed = bundleMod.bundleFromJSON(bundle.sigstore);
    const entity = mod.toSignedEntity(parsed, Buffer.from(body, "utf8"));
    // verifier.verify throws on any failure (bad cert chain against Fulcio's
    // root, bad Rekor inclusion proof, body mismatch). On success it returns
    // the Signer carrying the cryptographically-bound certificate identity —
    // the SAN the leaf cert was issued for and whose chain @sigstore/verify
    // just validated against the trusted root. An attacker who rewrites the
    // manifest's self-declared `cert_identity` cannot change THIS value without
    // a certificate Fulcio actually issued to them.
    const signer = verifier.verify(entity);
    const identity = signer.identity?.subjectAlternativeName ?? "";
    return { ok: true, identity };
  } catch {
    return { ok: false, identity: "" };
  }
}

/** Where the attestation bundle is expected, given an artifact root. */
export function attestationPath(root: string): string {
  return path.join(root, ATTESTATION_DIR, ATTESTATION_FILE);
}

/**
 * Verify the attestation bundle that travels with `dir`. Returns a structured
 * verdict; the caller (policy/loader-guard/CLI) decides whether to load.
 *
 * This function reports cryptographic *facts* only — it does not consult policy.
 * It treats a missing or unparseable bundle as a refusal, never an exception.
 */
export async function verify(dir: string): Promise<VerifyResult> {
  const root = path.resolve(dir);

  // 1. parse the bundle
  const bundlePath = attestationPath(root);
  let raw: string;
  try {
    raw = await fs.readFile(bundlePath, "utf8");
  } catch {
    return blocked(
      "no-manifest",
      `no attestation found at ${path.relative(root, bundlePath) || ATTESTATION_FILE} — refusing to load unattested code`,
    );
  }

  let manifest: AttestationManifest;
  try {
    manifest = AttestationManifestSchema.parse(JSON.parse(raw));
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return blocked(
      "malformed-manifest",
      `attestation is present but malformed: ${detail}`,
    );
  }

  // 2. recompute the file manifest + roll-up digest, compare to the signed value.
  //
  // buildFileManifest walks the on-disk directory and validates each leaf with
  // FileEntrySchema, which rejects a path carrying a control character (a byte a
  // POSIX filename may legally hold). If a file with such a name is added AFTER
  // signing, the walk throws — which would turn a directory that should verdict
  // TAMPERED into an uncaught exception (the CLI exits 2 "error:", not a clean
  // BLOCKED exit 1). That breaks this module's contract of always returning a
  // structured VerifyResult and never throwing. Treat any recompute failure as a
  // refusal: the directory on disk cannot be re-manifested to match what was
  // signed, which is exactly a post-sign modification → digest-mismatch/TAMPERED.
  let recomputedFiles;
  let recomputedDigest: string;
  try {
    recomputedFiles = await buildFileManifest(root, {
      exclude: [`${ATTESTATION_DIR}/${ATTESTATION_FILE}`],
    });
    recomputedDigest = rollupDigest(recomputedFiles);
  } catch {
    return blocked(
      "digest-mismatch",
      "the directory could not be re-manifested to check against the signed attestation — it contains an unattestable file (e.g. a name with a control character) added or changed after signing",
      manifest,
    );
  }

  // An attestation that covers zero files is meaningless: rollupDigest([])
  // collapses to a fixed empty-string sha256, so an "empty but signed" payload
  // (only a re-signed bundle plus ignored dirs) would otherwise pass. Treat an
  // empty signed manifest OR an empty on-disk file set as a hard refusal.
  if (manifest.files.length === 0 || recomputedFiles.length === 0) {
    return blocked(
      "empty-artifact",
      "attestation covers zero files — refusing an empty (or emptied) artifact",
      manifest,
    );
  }

  if (recomputedDigest !== bareDigest(manifest.subject.artifact_digest)) {
    return blocked(
      "digest-mismatch",
      "directory digest does not match the signed attestation — files were added, removed, or modified after signing",
      manifest,
    );
  }

  // 3. SBOM consistency for the file-manifest source (every package digest must
  //    still match a recomputed leaf). Lockfile-derived SBOMs name upstream
  //    deps, not local files, so they are covered by the digest check above.
  if (manifest.sbom.source === "file-manifest") {
    const leafByPath = new Map(
      recomputedFiles.map((f) => [f.path, bareDigest(f.sha256)]),
    );
    // Forward direction: every CLAIMED package must still match a recomputed leaf.
    for (const pkg of manifest.sbom.packages) {
      const leaf = leafByPath.get(pkg.name);
      if (leaf === undefined || leaf !== bareDigest(pkg.digest)) {
        return blocked(
          "sbom-mismatch",
          `SBOM entry for "${pkg.name}" does not match the directory contents`,
          manifest,
        );
      }
    }
    // Reverse direction: a file-manifest SBOM is defined as one package PER file —
    // a TOTAL map of the artifact (see sbom.ts sbomFromFileManifest). If any
    // attested leaf is NOT named by a package, the bill-of-materials is
    // incomplete, so refuse. The roll-up digest above already pins the file set,
    // but this restores the file-manifest SBOM's own completeness invariant
    // rather than leaving it implicit.
    const namedPackages = new Set(manifest.sbom.packages.map((p) => p.name));
    for (const f of recomputedFiles) {
      if (!namedPackages.has(f.path)) {
        return blocked(
          "sbom-mismatch",
          `file "${f.path}" is attested but not named by any SBOM package — the bill-of-materials is incomplete`,
          manifest,
        );
      }
    }
  }

  // 4. signature presence + cryptographic validity
  if (!manifest.signature) {
    return blocked(
      "no-signature",
      "attestation carries no signature — unsigned code refused to load",
      manifest,
    );
  }

  const bundle = manifest.signature.bundle as SignatureBundle | undefined;
  if (!bundle || typeof bundle !== "object" || !("signing_mode" in bundle)) {
    return blocked(
      "signature-invalid",
      "signature bundle is missing or has no signing_mode",
      manifest,
    );
  }

  // re-derive the exact canonical body that was signed: the manifest minus its
  // signature block, serialized deterministically.
  const { signature: _omit, ...body } = manifest;
  void _omit;
  const canonical = canonicalize(body);

  let sigOk: boolean;
  // For a sigstore verification, the cryptographically-bound signer identity
  // (the cert SAN @sigstore/verify chained against Fulcio's root) is surfaced
  // here so policy.ts can bind `allowed_identities` to it instead of the
  // forgeable, unsigned `signature.cert_identity`. ed25519 has no such value —
  // its identity IS the verified key fingerprint, computed in policy.ts.
  let verifiedSignerIdentity: string | undefined = undefined;
  if (bundle.signing_mode === "ed25519") {
    sigOk = verifyEd25519(canonical, bundle);
  } else if (bundle.signing_mode === "sigstore") {
    const sigstoreResult = await verifySigstore(canonical, bundle);
    sigOk = sigstoreResult.ok;
    verifiedSignerIdentity = sigstoreResult.identity;
  } else {
    return blocked(
      "signature-invalid",
      `unknown signing mode "${(bundle as { signing_mode: string }).signing_mode}"`,
      manifest,
    );
  }

  if (!sigOk) {
    return blocked(
      "signature-invalid",
      "signature does not verify over the manifest body — the attestation is forged or corrupted",
      manifest,
    );
  }

  // all checks passed
  const verified: VerifyResult = {
    ok: true,
    message: "PASS — attestation verified, code is safe to load",
    provenance_summary: provenanceSummary(manifest),
    manifest,
  };
  // Only a sigstore verification surfaces a verified cert SAN. The field's
  // presence itself signals "this identity came from a verified sigstore
  // bundle"; an empty/absent SAN leaves it unset so policy.ts's
  // `?? ""` fails the allowlist check closed.
  if (verifiedSignerIdentity) {
    verified.verified_signer_identity = verifiedSignerIdentity;
  }
  return verified;
}

/** Convenience: stable handle so the canonical content digest can be logged. */
export function manifestContentDigest(manifest: AttestationManifest): string {
  const { signature: _omit, ...body } = manifest;
  void _omit;
  return sha256Hex(canonicalize(body));
}
