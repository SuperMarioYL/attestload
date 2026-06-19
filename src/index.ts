/**
 * Public API barrel for AttestLoad.
 *
 * `import { guardLoad, verify, attest } from "attestload"` resolves here. The
 * CLI (cli.ts) is a separate bin entry; this module is the programmatic surface
 * an agent or pre-commit hook embeds.
 */

export * from "./types.js";
export {
  attest,
  captureProvenance,
  canonicalize,
  loadOrCreateLocalKey,
  trySignSigstore,
  ATTESTATION_DIR,
  ATTESTATION_FILE,
  type AttestOptions,
  type AttestResult,
  type SigningMode,
  type SignatureBundle,
} from "./attest.js";
export {
  verify,
  verdictOf,
  verifySigstore,
  attestationPath,
  manifestContentDigest,
  type Verdict,
} from "./verify.js";
export {
  loadPolicy,
  parsePolicy,
  evaluatePolicy,
  POLICY_FILENAMES,
  type PolicyDecision,
} from "./policy.js";
export {
  loadAllowlist,
  saveAllowlist,
  addEntry,
  removeEntry,
  findEntry,
  seedAllowlist,
  defaultAllowlistPath,
  SEED_ALLOWLIST,
  type AddEntryInput,
} from "./index-allowlist.js";
export {
  guardLoad,
  checkLoad,
  LoadRefused,
  type GuardOptions,
} from "./loader-guard.js";
export {
  buildFileManifest,
  rollupDigest,
  serializeFileManifest,
  sha256Hex,
  type BuildManifestOptions,
} from "./manifest.js";
export {
  deriveSbom,
  detectSbomStrategy,
  sbomFromFileManifest,
  sbomFromLockfile,
  type SbomStrategy,
} from "./sbom.js";
