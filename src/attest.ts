/**
 * `attestload attest <dir>` — the m1 core verb.
 *
 * Given a Skill / MCP-server directory it:
 *   1. walks the dir into a content-addressed file manifest (manifest.ts),
 *   2. rolls those leaves up into a single `artifact_digest`,
 *   3. derives an SPDX-lite SBOM (sbom.ts) — file-manifest for flat Skills,
 *      lockfile for MCP servers,
 *   4. captures git provenance (SLSA-lite),
 *   5. signs the canonical manifest body and attaches a signature block,
 *   6. writes the bundle to `<dir>/.attestload/attestation.json`.
 *
 * ## Signing modes (graceful degradation)
 *
 * The product's headline is keyless Sigstore signing — one browser OIDC click,
 * recorded in the public Rekor transparency log. But that path needs network
 * access AND an OIDC identity token, neither of which exists offline or in a CI
 * job without an `id-token` permission. Rather than fail there, `attest`
 * **degrades**:
 *
 *   - `sigstore`  — keyless Sigstore via `@sigstore/sign`, Rekor inclusion proof
 *                   in the bundle. Used when an OIDC token is reachable.
 *   - `ed25519`   — a local detached ed25519 signature over the same canonical
 *                   body, key generated/loaded under `~/.attestload/keys`. No
 *                   transparency log; clearly marked as a local trust root.
 *
 * The chosen mode is recorded on the signature bundle (`signing_mode`) so verify
 * and any human reading the manifest can see exactly what backed the signature.
 * A locally-signed attestation is honest about being local; it never masquerades
 * as a Rekor-backed one.
 */

import { promises as fs } from "node:fs";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import { execFile } from "node:child_process";
import * as os from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";

import {
  AttestationManifestSchema,
  MANIFEST_SCHEMA_VERSION,
  type ArtifactKind,
  type AttestationManifest,
  type Provenance,
  type Signature,
} from "./types.js";
import { buildFileManifest, rollupDigest } from "./manifest.js";
import { deriveSbom } from "./sbom.js";

const execFileAsync = promisify(execFile);

/** Where the written attestation lives, relative to the artifact root. */
export const ATTESTATION_DIR = ".attestload";
export const ATTESTATION_FILE = "attestation.json";

/** Signing modes, most-trusted first. */
export type SigningMode = "sigstore" | "ed25519";

/**
 * The bundle we store under {@link Signature.bundle}. It is `z.unknown()` in the
 * schema, so we own its shape. The discriminator `signing_mode` is what verify
 * branches on.
 */
export type SignatureBundle =
  | {
      signing_mode: "sigstore";
      /** Serialized Sigstore bundle (protobuf-JSON) from @sigstore/sign. */
      sigstore: unknown;
    }
  | {
      signing_mode: "ed25519";
      /** base64 detached signature over the canonical manifest body. */
      signature: string;
      /** PEM-encoded SPKI public key the signature verifies against. */
      public_key_pem: string;
      /** Algorithm tag, fixed for this mode. */
      algorithm: "ed25519";
    };

export interface AttestOptions {
  /** Artifact class; drives SBOM strategy. Defaults to `"skill"`. */
  readonly kind?: ArtifactKind;
  /** Subject name override. Defaults to the directory's basename. */
  readonly name?: string;
  /** Subject version override. Defaults to git describe / "0.0.0". */
  readonly version?: string;
  /**
   * Force a signing mode. When unset, attest prefers `sigstore` and falls back
   * to `ed25519` if Sigstore is unavailable.
   */
  readonly signingMode?: SigningMode;
  /** OIDC identity token for keyless Sigstore (else read from env/ambient). */
  readonly identityToken?: string;
  /** Directory to store the local ed25519 keypair. Defaults to ~/.attestload. */
  readonly keyDir?: string;
}

export interface AttestResult {
  readonly manifest: AttestationManifest;
  /** Absolute path the attestation bundle was written to. */
  readonly path: string;
  readonly signingMode: SigningMode;
}

/**
 * Canonical, stable serialization of the manifest *body* (everything except the
 * signature). This is the exact byte string that gets signed and, at verify
 * time, re-serialized and checked — so it must be deterministic. We sort object
 * keys recursively and use no insignificant whitespace.
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = sortKeys(obj[key]);
    }
    return out;
  }
  return value;
}

/** Run a git command in `dir`, returning trimmed stdout or `undefined`. */
async function git(dir: string, args: readonly string[]): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync("git", ["-C", dir, ...args]);
    return stdout.trim();
  } catch {
    return undefined;
  }
}

/** Capture SLSA-lite provenance from the directory's git state (best-effort). */
export async function captureProvenance(
  dir: string,
  builderId: string,
): Promise<Provenance> {
  const [commit, repo] = await Promise.all([
    git(dir, ["rev-parse", "HEAD"]),
    git(dir, ["config", "--get", "remote.origin.url"]),
  ]);
  return {
    builder_id: builderId,
    source_repo: repo ?? "",
    source_commit: commit ?? "",
    build_type: commit ? "git" : "local",
    built_at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Local ed25519 fallback signer
// ---------------------------------------------------------------------------

interface LocalKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly publicKeyPem: string;
}

/**
 * Load (or, on first use, generate) the local ed25519 keypair under
 * `<keyDir>/ed25519.{key,pub}`. The private key never leaves the machine; only
 * the SPKI public key is embedded in the attestation so a verifier can check
 * the detached signature.
 */
export async function loadOrCreateLocalKey(keyDir: string): Promise<LocalKeyPair> {
  const privPath = path.join(keyDir, "ed25519.key");
  const pubPath = path.join(keyDir, "ed25519.pub");
  try {
    const privPem = await fs.readFile(privPath, "utf8");
    const pubPem = await fs.readFile(pubPath, "utf8");
    return {
      privateKey: createPrivateKey(privPem),
      publicKey: createPublicKey(pubPem),
      publicKeyPem: pubPem,
    };
  } catch {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    await fs.mkdir(keyDir, { recursive: true });
    await fs.writeFile(privPath, privPem, { mode: 0o600 });
    await fs.writeFile(pubPath, pubPem);
    return { privateKey, publicKey, publicKeyPem: pubPem };
  }
}

/** Produce a detached ed25519 signature block over `body`. */
async function signEd25519(body: string, keyDir: string): Promise<Signature> {
  const { privateKey, publicKeyPem } = await loadOrCreateLocalKey(keyDir);
  const sig = edSign(null, Buffer.from(body, "utf8"), privateKey);
  const bundle: SignatureBundle = {
    signing_mode: "ed25519",
    signature: sig.toString("base64"),
    public_key_pem: publicKeyPem,
    algorithm: "ed25519",
  };
  return {
    // No transparency log in local mode; 0 is a sentinel and the bundle's
    // signing_mode makes the absence of a real Rekor entry explicit.
    rekor_log_index: 0,
    cert_identity: `local:${os.userInfo().username}@${os.hostname()}`,
    cert_issuer: "attestload-local-ed25519",
    bundle,
  };
}

// ---------------------------------------------------------------------------
// Sigstore keyless signer (with graceful unavailability)
// ---------------------------------------------------------------------------

/**
 * Attempt a keyless Sigstore signature over `body`. Returns `undefined` (rather
 * than throwing) whenever Sigstore is unavailable for ANY reason — package not
 * installed, no OIDC token, no network — so the caller can transparently fall
 * back to ed25519. The happy path returns a full {@link Signature} carrying the
 * Rekor log index and the serialized Sigstore bundle.
 *
 * The `@sigstore/sign` import is dynamic on purpose: the dep is optional at
 * type-check time and its absence must degrade, not crash.
 */
export async function trySignSigstore(
  body: string,
  identityToken: string | undefined,
): Promise<Signature | undefined> {
  const token = identityToken ?? process.env["SIGSTORE_ID_TOKEN"] ?? process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
  if (!token) return undefined; // no OIDC identity → cannot do keyless

  try {
    // Dynamic + untyped: the package may be absent during type-check/offline.
    const mod = (await import("@sigstore/sign")) as unknown as {
      DEFAULT_REKOR_URL?: string;
      DEFAULT_FULCIO_URL?: string;
      FulcioSigner: new (o: unknown) => unknown;
      RekorWitness: new (o: unknown) => unknown;
      CIContextProvider?: new () => unknown;
      BundleBuilder: new (o: unknown) => {
        create(o: { data: Buffer }): Promise<{
          toJSON?: () => unknown;
          verificationMaterial?: {
            tlogEntries?: Array<{ logIndex?: string | number }>;
          };
        }>;
      };
    };

    const fulcioURL = mod.DEFAULT_FULCIO_URL ?? "https://fulcio.sigstore.dev";
    const rekorURL = mod.DEFAULT_REKOR_URL ?? "https://rekor.sigstore.dev";

    const identityProvider = { getToken: async () => token };
    const signer = new mod.FulcioSigner({ fulcioBaseURL: fulcioURL, identityProvider });
    const witness = new mod.RekorWitness({ rekorBaseURL: rekorURL });
    const builder = new mod.BundleBuilder({ signer, witnesses: [witness] });

    const bundle = await builder.create({ data: Buffer.from(body, "utf8") });
    const serialized = bundle.toJSON ? bundle.toJSON() : bundle;

    const rawIndex = bundle.verificationMaterial?.tlogEntries?.[0]?.logIndex;
    const rekorIndex = typeof rawIndex === "string" ? Number.parseInt(rawIndex, 10) : rawIndex ?? 0;

    const sigBundle: SignatureBundle = { signing_mode: "sigstore", sigstore: serialized };
    return {
      rekor_log_index: Number.isFinite(rekorIndex) ? Math.max(0, rekorIndex as number) : 0,
      cert_identity: extractIdentity(token),
      cert_issuer: "sigstore",
      bundle: sigBundle,
    };
  } catch {
    // Any failure (offline, network, Fulcio rejection, missing dep) → degrade.
    return undefined;
  }
}

/** Best-effort identity from a JWT's `sub`/`email` claim, for display only. */
function extractIdentity(token: string): string {
  try {
    const part = token.split(".")[1];
    if (!part) return "unknown";
    const json = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as {
      email?: string;
      sub?: string;
    };
    return json.email ?? json.sub ?? "unknown";
  } catch {
    return "unknown";
  }
}

// ---------------------------------------------------------------------------
// attest()
// ---------------------------------------------------------------------------

/**
 * Produce and persist a signed attestation for `dir`.
 *
 * Signing-mode selection:
 *   - explicit `signingMode: "ed25519"` → always local;
 *   - explicit `signingMode: "sigstore"` → Sigstore, error if unavailable;
 *   - unset (default) → try Sigstore, fall back to ed25519.
 */
export async function attest(
  dir: string,
  options: AttestOptions = {},
): Promise<AttestResult> {
  const root = path.resolve(dir);
  const kind: ArtifactKind = options.kind ?? "skill";

  // 1. content-addressed file manifest (excluding the bundle we're about to write)
  const files = await buildFileManifest(root, {
    exclude: [`${ATTESTATION_DIR}/${ATTESTATION_FILE}`],
  });

  // Refuse to attest a directory that covers zero files: an empty manifest
  // rolls up to the fixed empty-string digest, so an "empty but signed" bundle
  // would otherwise verify clean while attesting no content at all.
  if (files.length === 0) {
    throw new Error(
      `refusing to attest ${root}: no files to attest (the directory is empty or every entry was ignored/excluded)`,
    );
  }

  // 2. directory roll-up digest
  const artifactDigest = rollupDigest(files);

  // 3. SBOM (file-manifest for skills, lockfile for MCP servers)
  const { sbom, strategy } = await deriveSbom(root, kind, files);

  // 4. provenance
  const builderId =
    options.identityToken !== undefined
      ? extractIdentity(options.identityToken)
      : `local:${os.userInfo().username}`;
  const provenance = await captureProvenance(root, builderId);

  // assemble the unsigned body
  const body = AttestationManifestSchema.parse({
    schema: MANIFEST_SCHEMA_VERSION,
    subject: {
      name: options.name ?? path.basename(root),
      version: options.version ?? (provenance.source_commit.slice(0, 12) || "0.0.0"),
      kind,
      artifact_digest: artifactDigest,
      sbom_source: strategy.source,
    },
    sbom,
    files,
    provenance,
  });

  // 5. sign the canonical body
  const canonical = canonicalize(body);
  const keyDir = options.keyDir ?? path.join(os.homedir(), ".attestload", "keys");

  let signature: Signature;
  let signingMode: SigningMode;

  if (options.signingMode === "ed25519") {
    signature = await signEd25519(canonical, keyDir);
    signingMode = "ed25519";
  } else if (options.signingMode === "sigstore") {
    const s = await trySignSigstore(canonical, options.identityToken);
    if (!s) {
      throw new Error(
        "sigstore signing requested but unavailable (no OIDC token or @sigstore/sign not reachable); " +
          "re-run without --sigstore to use the local ed25519 fallback",
      );
    }
    signature = s;
    signingMode = "sigstore";
  } else {
    const s = await trySignSigstore(canonical, options.identityToken);
    if (s) {
      signature = s;
      signingMode = "sigstore";
    } else {
      signature = await signEd25519(canonical, keyDir);
      signingMode = "ed25519";
    }
  }

  const manifest: AttestationManifest = { ...body, signature };

  // 6. write the bundle next to the artifact
  const outDir = path.join(root, ATTESTATION_DIR);
  await fs.mkdir(outDir, { recursive: true });
  const outPath = path.join(outDir, ATTESTATION_FILE);
  await fs.writeFile(outPath, `${JSON.stringify(manifest, null, 2)}\n`);

  return { manifest, path: outPath, signingMode };
}
