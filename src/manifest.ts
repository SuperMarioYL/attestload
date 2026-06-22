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
 * Files that are never part of any manifest. Intentionally empty: the legacy
 * `attestload.manifest.json` blanket-exclusion was a digest-coverage hole — it
 * dropped any file with that basename at *any* depth, so an attacker could plant
 * one anywhere and still verify clean. The real on-disk bundle
 * (`.attestload/attestation.json`) is already excluded by the `.attestload`
 * IGNORED_DIR plus the explicit `exclude` option callers pass, so nothing needs
 * a basename-based blanket skip.
 */
const IGNORED_FILES = new Set<string>([]);

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

/** A raw filesystem entry collected during the walk, before hashing. */
interface CollectedEntry {
  readonly abs: string;
  readonly kind: "file" | "symlink";
}

/**
 * Recursively collect every regular file and symlink under `root`, skipping
 * ignored dirs/files. Returns absolute paths tagged with their kind; ordering is
 * not guaranteed here (callers sort).
 *
 * Symlinks are recorded as their own leaf rather than followed: following them
 * would either resolve outside the artifact (a `run.sh -> ../../evil` escape) or
 * double-count their target, neither of which the attestation should hide. The
 * link itself — path plus the digest of its unresolved target — is attested.
 */
async function collectFiles(root: string, dir: string): Promise<CollectedEntry[]> {
  const out: CollectedEntry[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      out.push({ abs, kind: "symlink" });
    } else if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      out.push(...(await collectFiles(root, abs)));
    } else if (entry.isFile()) {
      if (IGNORED_FILES.has(entry.name)) continue;
      out.push({ abs, kind: "file" });
    }
    // sockets / fifos are still skipped: an attestation describes regular file
    // content and symlinks only.
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
  const collected = await collectFiles(root, root);

  const entries: FileEntry[] = [];
  for (const { abs, kind } of collected) {
    const rel = toRelPosix(root, abs);
    if (exclude.has(rel)) continue;

    if (kind === "symlink") {
      // Record the link itself: the digest is over the *unresolved* target
      // string, so re-targeting a symlink (run.sh -> ../../evil) perturbs the
      // leaf and the roll-up. We never read through the link.
      const target = await fs.readlink(abs);
      const lstat = await fs.lstat(abs);
      entries.push(
        FileEntrySchema.parse({
          path: rel,
          sha256: sha256Hex(target),
          size: Buffer.byteLength(target),
          mode: lstat.mode & 0o7777,
          type: "symlink",
          link_target: target,
        }),
      );
      continue;
    }

    const [bytes, stat] = await Promise.all([fs.readFile(abs), fs.stat(abs)]);
    entries.push(
      FileEntrySchema.parse({
        path: rel,
        sha256: sha256Hex(bytes),
        size: bytes.byteLength,
        mode: stat.mode & 0o7777,
        type: "file",
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
 * The encoding hashes a *canonical JSON array* of the sorted leaves rather than
 * a two-space-delimited line format. The old `<sha256>  <size>  <path>\n`
 * serialization was ambiguous: a POSIX path may legally contain spaces and
 * newlines, so a crafted name could move the field/record boundary and make two
 * distinct file sets hash to the same byte stream (a forged collision). JSON
 * string-escaping makes every field self-delimiting, and FileEntrySchema also
 * now rejects control characters in `path`, so there is no in-band separator to
 * smuggle. Each leaf contributes its digest, size, mode, type, link target, and
 * path, so a re-targeted symlink or a post-sign `chmod +x` also changes the
 * roll-up. Entries MUST already be path-sorted (as {@link buildFileManifest}
 * returns them); we sort defensively.
 */
export function rollupDigest(files: readonly FileEntry[]): string {
  const sorted = [...files].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  const leaves = sorted.map((f) => ({
    path: f.path,
    sha256: f.sha256.startsWith("sha256:")
      ? f.sha256.slice("sha256:".length)
      : f.sha256,
    size: f.size,
    mode: f.mode ?? 0,
    type: f.type ?? "file",
    ...(f.link_target !== undefined ? { link_target: f.link_target } : {}),
  }));
  const canonical = JSON.stringify(leaves);
  return createHash("sha256").update(canonical).digest("hex");
}

/** Serialize a file manifest to canonical, stable JSON (sorted by path). */
export function serializeFileManifest(files: readonly FileEntry[]): string {
  const sorted = [...files].sort((a, b) =>
    a.path < b.path ? -1 : a.path > b.path ? 1 : 0,
  );
  return JSON.stringify(sorted, null, 2);
}
