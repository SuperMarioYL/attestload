/**
 * Shared data model for AttestLoad.
 *
 * Everything here mirrors the attestation manifest primitive: a signed bundle
 * that travels alongside a Skill / MCP server directory and lets a coding agent
 * decide, before load, whether the code is trustworthy.
 *
 * The on-disk artifact is `attestload.manifest.json`. Its shape is defined by
 * {@link AttestationManifestSchema}; the other schemas are its sub-objects.
 *
 * Zod is the single source of truth: each TypeScript type is inferred from its
 * schema so the runtime parser and the compile-time type can never drift.
 */

import { z } from "zod";

/** Current manifest schema version. Bumped on any breaking shape change. */
export const MANIFEST_SCHEMA_VERSION = "attestload/v1" as const;

/** Canonical filename of the signed attestation, expected at the dir root. */
export const MANIFEST_FILENAME = "attestload.manifest.json" as const;

/** A lowercase hex sha256 digest (64 hex chars), optionally `sha256:`-prefixed. */
export const Sha256Schema = z
  .string()
  .regex(
    /^(sha256:)?[0-9a-f]{64}$/,
    "expected a sha256 hex digest (64 hex chars, optional 'sha256:' prefix)",
  );
export type Sha256 = z.infer<typeof Sha256Schema>;

/**
 * How the SBOM was derived for a given subject.
 * - `file-manifest`: content-addressed digest of every file in the dir
 *   (the default for flat Skill dirs).
 * - `lockfile`: parsed from a dependency lockfile present in the dir
 *   (e.g. an npm / pip MCP server).
 */
export const SbomSourceSchema = z.enum(["file-manifest", "lockfile"]);
export type SbomSource = z.infer<typeof SbomSourceSchema>;

/** The class of artifact being attested. */
export const ArtifactKindSchema = z.enum(["skill", "mcp-server"]);
export type ArtifactKind = z.infer<typeof ArtifactKindSchema>;

// ---------------------------------------------------------------------------
// Subject — what is being attested
// ---------------------------------------------------------------------------

export const SubjectSchema = z.object({
  /** Human-facing artifact name (e.g. the skill or MCP server name). */
  name: z.string().min(1),
  /** Artifact version string (free-form; semver recommended). */
  version: z.string().min(1),
  /** The kind of artifact (drives default SBOM derivation strategy). */
  kind: ArtifactKindSchema,
  /**
   * Digest of the whole directory: a deterministic Merkle-style roll-up of the
   * per-file entries in {@link AttestationManifest.files}. Recomputed at verify
   * time; a mismatch means tampering.
   */
  artifact_digest: Sha256Schema,
  /** How {@link Sbom.packages} was produced for this subject. */
  sbom_source: SbomSourceSchema,
});
export type Subject = z.infer<typeof SubjectSchema>;

// ---------------------------------------------------------------------------
// SBOM — SPDX-lite bill of materials
// ---------------------------------------------------------------------------

/**
 * One SBOM package entry. For a Skill (file-manifest source) this is one entry
 * per file; for an MCP server (lockfile source) it is one entry per resolved
 * dependency.
 */
export const SbomPackageSchema = z.object({
  name: z.string().min(1),
  version: z.string().default(""),
  /** SPDX license identifier, or empty when unknown. */
  license: z.string().default(""),
  /** Content digest of the package (file content, or resolved tarball). */
  digest: Sha256Schema,
});
export type SbomPackage = z.infer<typeof SbomPackageSchema>;

/** SPDX-lite SBOM: the list of packages that compose the subject. */
export const SbomSchema = z.object({
  /** Marks the reduced SPDX dialect we emit. */
  spdx_lite: z.literal(true).default(true),
  source: SbomSourceSchema,
  packages: z.array(SbomPackageSchema),
});
export type Sbom = z.infer<typeof SbomSchema>;

// ---------------------------------------------------------------------------
// File manifest — content-addressed Merkle leaves
// ---------------------------------------------------------------------------

/** One file in the content-addressed directory manifest. */
export const FileEntrySchema = z.object({
  /** POSIX-style path relative to the artifact root. */
  path: z.string().min(1),
  /** sha256 of the file's bytes. */
  sha256: Sha256Schema,
  /** File size in bytes. */
  size: z.number().int().nonnegative(),
});
export type FileEntry = z.infer<typeof FileEntrySchema>;

// ---------------------------------------------------------------------------
// Provenance — SLSA-lite build origin
// ---------------------------------------------------------------------------

export const ProvenanceSchema = z.object({
  /** Identity of who/what built the artifact (e.g. OIDC subject). */
  builder_id: z.string().min(1),
  /** Source repository URL the artifact was built from. */
  source_repo: z.string().default(""),
  /** Git commit SHA the artifact was built from. */
  source_commit: z.string().default(""),
  /** Build type discriminator (e.g. "git", "local", "ci"). */
  build_type: z.string().default("git"),
  /** ISO-8601 timestamp the attestation was produced. */
  built_at: z.string().datetime().optional(),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

// ---------------------------------------------------------------------------
// Signature — Sigstore keyless binding
// ---------------------------------------------------------------------------

export const SignatureSchema = z.object({
  /** Rekor transparency-log index the signing event was recorded at. */
  rekor_log_index: z.number().int().nonnegative(),
  /** Certificate identity (OIDC subject) the signature was issued to. */
  cert_identity: z.string().min(1),
  /** OIDC issuer that vouched for the identity. */
  cert_issuer: z.string().default(""),
  /**
   * The Sigstore bundle (serialized protobuf JSON) carrying the cert chain,
   * signature, and inclusion proof. Opaque to us; passed to @sigstore/verify.
   */
  bundle: z.unknown(),
});
export type Signature = z.infer<typeof SignatureSchema>;

// ---------------------------------------------------------------------------
// Attestation manifest — the top-level signed artifact
// ---------------------------------------------------------------------------

export const AttestationManifestSchema = z.object({
  /** Schema discriminator; see {@link MANIFEST_SCHEMA_VERSION}. */
  schema: z.literal(MANIFEST_SCHEMA_VERSION).default(MANIFEST_SCHEMA_VERSION),
  subject: SubjectSchema,
  sbom: SbomSchema,
  /** Content-addressed manifest of every file in the artifact directory. */
  files: z.array(FileEntrySchema),
  provenance: ProvenanceSchema,
  /**
   * Signature block. Absent on a freshly `init`-ed skeleton, present after
   * `attest`. Verification treats a missing signature as unattested.
   */
  signature: SignatureSchema.optional(),
});
export type AttestationManifest = z.infer<typeof AttestationManifestSchema>;

// ---------------------------------------------------------------------------
// Policy — verification rules
// ---------------------------------------------------------------------------

export const PolicySchema = z.object({
  /** Require a valid provenance block (builder_id present). */
  require_provenance: z.boolean().default(true),
  /** Require a valid Sigstore signature verified against Rekor. */
  require_signature: z.boolean().default(true),
  /**
   * If non-empty, the signing cert identity must match one of these (exact or
   * glob). Empty array means any identity is accepted.
   */
  allowed_identities: z.array(z.string()).default([]),
  /**
   * If true, a subject whose name is present in the local allowlist passes even
   * without a per-dir signature (cold-start path for known-good skills).
   */
  use_allowlist: z.boolean().default(false),
});
export type Policy = z.infer<typeof PolicySchema>;

/** Default policy: strictest sensible posture (signature + provenance required). */
export const DEFAULT_POLICY: Policy = PolicySchema.parse({});

// ---------------------------------------------------------------------------
// Allowlist — local index of pre-verified popular skills (cold-start)
// ---------------------------------------------------------------------------

/** One entry in the verified-skill allowlist. */
export const AllowlistEntrySchema = z.object({
  name: z.string().min(1),
  /** Known-good artifact digest, if pinned. */
  artifact_digest: Sha256Schema.optional(),
  /** Source repo this entry refers to, for traceability. */
  source_repo: z.string().default(""),
  /** When the entry was added (ISO-8601). */
  added_at: z.string().datetime().optional(),
});
export type AllowlistEntry = z.infer<typeof AllowlistEntrySchema>;

export const AllowlistSchema = z.object({
  schema: z.literal("attestload-allowlist/v1").default("attestload-allowlist/v1"),
  entries: z.array(AllowlistEntrySchema).default([]),
});
export type Allowlist = z.infer<typeof AllowlistSchema>;

// ---------------------------------------------------------------------------
// Verification result — the verb `verify(dir, policy) -> result`
// ---------------------------------------------------------------------------

/** Machine-readable reason a verification was blocked. */
export const BlockReasonSchema = z.enum([
  "no-manifest",
  "malformed-manifest",
  "no-signature",
  "digest-mismatch",
  "sbom-mismatch",
  "signature-invalid",
  "rekor-not-found",
  "identity-not-allowed",
  "provenance-missing",
]);
export type BlockReason = z.infer<typeof BlockReasonSchema>;

/**
 * Outcome of `verify`. `ok: true` means the agent may load the code; otherwise
 * `blocked_reason` carries the machine code and `message` the human string the
 * CLI prints in red.
 */
export interface VerifyResult {
  ok: boolean;
  blocked_reason?: BlockReason;
  message: string;
  /** One-line provenance summary shown on PASS (who built it, from which commit). */
  provenance_summary?: string;
  /** The parsed manifest, when one was present and well-formed. */
  manifest?: AttestationManifest;
}
