/**
 * Content-addressed file manifest.
 *
 * This is the building block AttestLoad's SBOM derivation stands on for flat
 * Skill directories: walk every file under a directory, record its POSIX path,
 * sha256 of its bytes, and size. The resulting list is a Merkle-style leaf set
 * — each leaf is content-addressed, and a deterministic roll-up of those leaves
 * yields a single `artifact_digest` for the whole directory.
 *
 * At verify time the consumer re-walks the directory and recomputes both the
 * per-file leaves and the roll-up; any drift (a changed byte, an added or
 * removed file) changes a leaf and therefore the roll-up, which is how
 * tampering is detected.
 *
 * Nothing here touches the network or signing — it is pure filesystem + hashing
 * so it can be unit-tested with `node --test` against a fixture directory.
 */

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

import { FileEntrySchema, type FileEntry } from "./types.js";

/** Directory names never walked into — they are environment, not artifact. */
const IGNORED_DIRS = new Set<string>([
  "node_modules",
  ".git",
  ".attestload",
]);

/**
 * The attestation file itself must never be part of the manifest it describes,
 * otherwise the digest would depend on its own (not-yet-written) contents.
 */
const IGNORED_FILES = new Set<string>(["attestload.manifest.json"]);

/** Options controlling how a directory is walked into a file manifest. */
export interface BuildManifestOptions {
  /**
   * Extra relative paths (POSIX, relative to the root) to skip. Used to exclude
   * the freshly written attestation bundle or lockfiles already represented
   * elsewhere. Compared against the normalized relative path.
   */
  readonly exclude?: readonly string[];
}

/** Compute the lowercase-hex sha256 of a buffer. */
export function sha256Hex(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Recursively collect every file under `root`, skipping ignored dirs/files.
 * Returns absolute paths; ordering is not guaranteed here (callers sort).
 */
async function collectFiles(root: string, dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      out.push(...(await collectFiles(root, abs)));
    } else if (entry.isFile()) {
      if (IGNORED_FILES.has(entry.name)) continue;
      out.push(abs);
    }
    // symlinks / sockets / fifos are intentionally skipped: an attestation
    // describes regular file content only.
  }
  return out;
}

/** Normalize an absolute path to a POSIX-style path relative to `root`. */
function toRelPosix(root: string, abs: string): string {
  return path.relative(root, abs).split(path.sep).join("/");
}

/**
 * Build the content-addressed manifest of `root`.
 *
 * Every regular file (minus ignored dirs/files and any caller-supplied
 * exclusions) becomes one {@link FileEntry}. Entries are returned sorted by
 * path so the manifest — and therefore {@link rollupDigest} — is deterministic
 * regardless of filesystem enumeration order.
 */
export async function buildFileManifest(
  root: string,
  options: BuildManifestOptions = {},
): Promise<FileEntry[]> {
  const exclude = new Set<string>(options.exclude ?? []);
  const absFiles = await collectFiles(root, root);

  const entries: FileEntry[] = [];
  for (const abs of absFiles) {
    const rel = toRelPosix(root, abs);
    if (exclude.has(rel)) continue;
    const bytes = await fs.readFile(abs);
    entries.push(
      FileEntrySchema.parse({
        path: rel,
        sha256: sha256Hex(bytes),
        size: bytes.byteLength,
      }),
    );
  }

  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return entries;
}

/**
 * Deterministic Merkle-style roll-up of a sorted file manifest into a single
 * directory digest.
 *
 * We hash a canonical line-oriented serialization (`<sha256>  <size>  <path>\n`
 * per entry, already path-sorted) rather than a binary Merkle tree: it is
 * simpler, equally tamper-evident for our purpose (any leaf change perturbs the
 * input), and trivially reproducible by a third party. The entries MUST already
 * be sorted (as {@link buildFileManifest} returns them); we sort defensively.
 */
export function rollupDigest(files: readonly FileEntry[]): string {
  const sorted = [...files].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  const hash = createHash("sha256");
  for (const f of sorted) {
    const digest = f.sha256.startsWith("sha256:")
      ? f.sha256.slice("sha256:".length)
      : f.sha256;
    hash.update(`${digest}  ${f.size}  ${f.path}\n`);
  }
  return hash.digest("hex");
}

/** Serialize a file manifest to canonical, stable JSON (sorted by path). */
export function serializeFileManifest(files: readonly FileEntry[]): string {
  const sorted = [...files].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  return JSON.stringify(sorted, null, 2);
}
