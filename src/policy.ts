/**
 * Policy — turn a cryptographic {@link VerifyResult} into a load decision.
 *
 * verify.ts answers "is this attestation cryptographically sound?". policy.ts
 * answers the orthogonal question "given my org's rules, am I willing to load
 * this?". Splitting the two keeps verify pure (facts) and lets the same verified
 * bundle pass under a lax policy and fail under a strict one.
 *
 * A {@link Policy} (schema in types.ts, validated with zod) expresses:
 *   - `require_signature`   — refuse anything not cryptographically signed.
 *   - `require_provenance`  — refuse anything without a builder identity.
 *   - `allowed_identities`  — if non-empty, the signing identity must match one
 *                             (exact or `*` glob).
 *   - `use_allowlist`       — a subject named in the local allowlist may pass
 *                             even without a per-dir signature (cold-start).
 *
 * Policy is loaded from a JSON/YAML file (`attestload.policy.json` or
 * `.yaml/.yml`) or taken inline; an absent file yields {@link DEFAULT_POLICY}
 * (the strictest sensible posture: signature + provenance required).
 */

import { promises as fs } from "node:fs";
import { createHash, createPublicKey } from "node:crypto";
import * as path from "node:path";

import { parse as parseYaml } from "yaml";

import {
  DEFAULT_POLICY,
  PolicySchema,
  type Allowlist,
  type Policy,
  type VerifyResult,
} from "./types.js";

/** Default policy filenames searched, in priority order. */
export const POLICY_FILENAMES = [
  "attestload.policy.json",
  "attestload.policy.yaml",
  "attestload.policy.yml",
] as const;

/** Outcome of a policy evaluation: whether to load, and why not if refused. */
export interface PolicyDecision {
  /** True when the artifact is allowed to load. */
  readonly allowed: boolean;
  /** Human-readable reason (always set; on allow it's a short rationale). */
  readonly reason: string;
  /** The verify result the decision was made from. */
  readonly verify: VerifyResult;
}

/** Parse + validate raw policy text (JSON or YAML) into a {@link Policy}. */
export function parsePolicy(raw: string, filename = ""): Policy {
  const isYaml = /\.ya?ml$/i.test(filename);
  const data: unknown = isYaml ? parseYaml(raw) : JSON.parse(raw);
  return PolicySchema.parse(data ?? {});
}

/**
 * Parse + validate raw policy text and attach the offending filename to any
 * failure. A bare {@link parsePolicy} error (a JSON `SyntaxError`, a Zod schema
 * violation) does not name the file it came from, so a typo'd policy file would
 * surface as an opaque parse message with no indication of which file caused
 * it. Wrapping the throw here keeps the filename in the message so the CLI / a
 * caller's loud-fail path can point at the right file.
 */
function parsePolicyFile(raw: string, filename: string): Policy {
  try {
    return parsePolicy(raw, filename);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`failed to load policy file "${filename}": ${msg}`);
  }
}

/**
 * Load a policy. If `file` is given it must exist and parse; otherwise the cwd
 * (or `searchDir`) is probed for a default policy file. When nothing is found,
 * {@link DEFAULT_POLICY} is returned (strict).
 *
 * Error handling is deliberate: the default-search loop catches ONLY `ENOENT`
 * (a candidate filename simply not present → try the next one). Any other
 * failure — a present-but-malformed file (JSON/YAML syntax error, Zod schema
 * violation) or a non-ENOENT I/O error — propagates with the offending
 * filename, so a typo'd policy file fails loudly instead of being silently
 * treated as "absent" and degrading to the strict default.
 */
export async function loadPolicy(options: {
  readonly file?: string;
  readonly searchDir?: string;
} = {}): Promise<Policy> {
  if (options.file) {
    const raw = await fs.readFile(options.file, "utf8");
    return parsePolicyFile(raw, options.file);
  }
  const dir = options.searchDir ?? process.cwd();
  for (const name of POLICY_FILENAMES) {
    const candidate = path.join(dir, name);
    let raw: string;
    try {
      raw = await fs.readFile(candidate, "utf8");
    } catch (err) {
      // File not present → try the next candidate. Anything else (EACCES, a
      // malformed file body, ...) propagates with the path already named.
      if (
        err instanceof Error &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        continue;
      }
      throw err;
    }
    return parsePolicyFile(raw, candidate);
  }
  return DEFAULT_POLICY;
}

/**
 * The cryptographically-BOUND signer identity that `allowed_identities` is
 * matched against.
 *
 * For ed25519 the detached signature verifies against a public key EMBEDDED in
 * the bundle, and `cert_identity` sits in the UNSIGNED signature block — so an
 * attacker holding any ed25519 key could sign an artifact with their own key and
 * set `cert_identity` to an allowed value to impersonate a trusted signer and
 * pass `allowed_identities`. The only value bound to the verified key is the key
 * itself, so the identity is its SPKI-DER sha256 fingerprint (`ed25519:<hex>`),
 * which an org pins in `allowed_identities`. An unparseable key yields `""` so
 * the allowlist check fails CLOSED. (This is a breaking hardening: an ed25519
 * `allowed_identities` config that listed a human `cert_identity` string must be
 * migrated to the key fingerprint; a previously-allowed artifact now refuses
 * rather than being impersonable.)
 *
 * For sigstore the identity is derived from the VERIFIED Sigstore bundle's
 * certificate SAN (the OIDC email/URI Fulcio issued the leaf cert for, which
 * `@sigstore/verify` already chained against Fulcio's root), surfaced onto the
 * VerifyResult by verify.ts as `verified_signer_identity`. The manifest's
 * self-declared `signature.cert_identity` is NOT used: it lives INSIDE the
 * signature block, which is STRIPPED from the signed canonical body
 * (verify.ts canonicalizes the manifest minus its signature), so
 * `cert_identity` is not covered by the Sigstore signature and any holder of
 * a valid keyless attestation could rewrite it to a value in a consumer's
 * `allowed_identities` — `verifySigstore` still returns true (the bundle
 * validly signs the unchanged body) and the forged identity would match. This
 * closes the sigstore twin of the v0.6.0 ed25519 `cert_identity` bypass: every
 * signing mode's identity is now cryptographically bound, never self-declared.
 * An empty/absent `verified_signer_identity` yields `""` so the allowlist
 * check fails CLOSED. Non-breaking for honest attestations: the bundle's cert
 * SAN equals the email `cert_identity` was derived from at signing time.
 */
function boundSignerIdentity(result: VerifyResult): string {
  const m = result.manifest;
  const bundle = m?.signature?.bundle as
    | { signing_mode?: string; public_key_pem?: string }
    | undefined;
  if (
    bundle &&
    typeof bundle === "object" &&
    bundle.signing_mode === "ed25519" &&
    typeof bundle.public_key_pem === "string"
  ) {
    try {
      const der = createPublicKey(bundle.public_key_pem).export({
        type: "spki",
        format: "der",
      });
      return "ed25519:" + createHash("sha256").update(der).digest("hex");
    } catch {
      return "";
    }
  }
  // sigstore: the cryptographically-verified cert SAN surfaced by verify.ts.
  // Never the self-declared signature.cert_identity (unsigned + forgeable).
  return result.verified_signer_identity ?? "";
}

/** Match an identity against a pattern supporting a trailing/embedded `*`. */
function identityMatches(pattern: string, identity: string): boolean {
  if (pattern === identity) return true;
  if (!pattern.includes("*")) return false;
  const escaped = pattern
    .split("*")
    .map((seg) => seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`).test(identity);
}

/**
 * Evaluate a {@link VerifyResult} against a {@link Policy}, optionally with the
 * local allowlist in hand (for the cold-start `use_allowlist` path).
 *
 * Decision order:
 *   1. If verify already passed cryptographically, apply identity allowlisting
 *      and provenance requirements, then allow.
 *   2. If verify failed only because the bundle is unsigned/absent AND
 *      `use_allowlist` is on AND the subject is in the allowlist (digest pinned
 *      and matching, when present) → allow as a known-good cold-start entry.
 *   3. Otherwise refuse with verify's reason.
 */
export function evaluatePolicy(
  result: VerifyResult,
  policy: Policy,
  allowlist?: Allowlist,
): PolicyDecision {
  // ---- 1. cryptographically verified path -------------------------------
  if (result.ok && result.manifest) {
    const m = result.manifest;

    if (policy.require_provenance && !m.provenance.builder_id) {
      return {
        allowed: false,
        reason: "policy requires provenance but the attestation has no builder_id",
        verify: result,
      };
    }

    if (policy.allowed_identities.length > 0) {
      // Match against the cryptographically-bound signer identity (the verified
      // key fingerprint for ed25519, or the verified sigstore cert SAN), NOT the
      // self-declared cert_identity, which an attacker's own key (or a forged
      // sigstore bundle field) could set to impersonate an allowed signer.
      const identity = boundSignerIdentity(result);
      const ok = policy.allowed_identities.some((p) =>
        identityMatches(p, identity),
      );
      if (!ok) {
        return {
          allowed: false,
          reason: `signing identity "${identity}" is not in allowed_identities`,
          verify: result,
        };
      }
    }

    return {
      allowed: true,
      reason: `verified${
        policy.allowed_identities.length > 0 ? " (identity allowed)" : ""
      }`,
      verify: result,
    };
  }

  // ---- 2. allowlist cold-start path -------------------------------------
  // Only an attestation that is *present and intact* but merely unsigned is
  // eligible — i.e. `no-signature`. The old code also accepted `no-manifest`,
  // but verify() returns `no-manifest` WITHOUT a parsed manifest, so that arm
  // was dead (the `result.manifest` guard below could never be satisfied). Worse
  // it advertised "you can cold-start with no attestation at all", which is
  // exactly the impersonation surface we must close.
  const unsignedButPresent = result.blocked_reason === "no-signature";

  if (policy.use_allowlist && allowlist && unsignedButPresent && result.manifest) {
    const subject = result.manifest.subject;
    const entry = allowlist.entries.find((e) => e.name === subject.name);
    if (entry) {
      // A cold-start entry MUST pin a known-good artifact_digest. A name-only
      // entry would trust whatever digest an UNSIGNED bundle self-declares, so
      // an attacker could ship an unsigned attestation claiming name
      // "github-mcp" and pass. Reject name-only entries outright.
      if (!entry.artifact_digest) {
        return {
          allowed: false,
          reason: `allowlist entry for "${subject.name}" is name-only (no pinned digest); cold-start requires a pinned artifact_digest`,
          verify: result,
        };
      }
      const pinnedOk =
        bareDigest(entry.artifact_digest) ===
        bareDigest(subject.artifact_digest);
      if (pinnedOk) {
        return {
          allowed: true,
          reason: `allowlisted known-good skill "${subject.name}" (cold-start, digest pinned)`,
          verify: result,
        };
      }
      return {
        allowed: false,
        reason: `allowlist entry for "${subject.name}" pins a different digest`,
        verify: result,
      };
    }
  }

  // ---- 3. refuse --------------------------------------------------------
  // Honor a relaxed policy: if signature is not required and the only failure
  // is a missing signature, allow — but keep provenance enforcement SYMMETRIC
  // with the cryptographically-verified path (step 1). A no-signature verdict
  // still carries the parsed manifest (verify() attaches it before the signature
  // check), so `require_provenance` must be applied here too; otherwise a policy
  // of {require_signature: false, require_provenance: true} would load an
  // unsigned, builder-less artifact — the weaker path silently skipping the very
  // check the policy asked for.
  if (!policy.require_signature && result.blocked_reason === "no-signature") {
    if (
      policy.require_provenance &&
      !result.manifest?.provenance.builder_id
    ) {
      return {
        allowed: false,
        reason: "policy requires provenance but the attestation has no builder_id",
        verify: result,
      };
    }
    return {
      allowed: true,
      reason: "signature not required by policy; manifest digest verified",
      verify: result,
    };
  }

  return {
    allowed: false,
    reason: result.message,
    verify: result,
  };
}

/** Strip an optional `sha256:` prefix for digest comparison. */
function bareDigest(d: string): string {
  return d.startsWith("sha256:") ? d.slice("sha256:".length) : d;
}
