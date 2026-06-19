/**
 * SBOM derivation — SPDX-lite.
 *
 * AttestLoad derives a software bill-of-materials from whatever ground truth a
 * directory actually offers, per the schema-verified design:
 *
 *  - **Flat Skill dirs** (the common case — a real Claude skill is `SKILL.md`
 *    plus loose files, no lockfile) get a SBOM derived from the content-
 *    addressed file manifest: one package per file, keyed on the file's own
 *    sha256. There is no dependency graph to resolve, so the bill-of-materials
 *    *is* the file set. This is what makes "no lockfile" a first-class case
 *    rather than a failure.
 *
 *  - **MCP servers / lockfile-bearing dirs** additionally parse their declared
 *    dependencies from a lockfile (`package-lock.json`, `pnpm-lock.yaml`, or
 *    `requirements.txt`) so the SBOM names real upstream packages, not just the
 *    server's own files.
 *
 * Either way the output is the same SPDX-lite {@link Sbom} shape, so verify and
 * policy code never branch on artifact kind — only `sbom.source` records how it
 * was produced.
 *
 * Pure functions over an already-built file manifest + the directory contents;
 * no network, no signing. Unit-testable in isolation.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";

import { parse as parseYaml } from "yaml";

import { sha256Hex } from "./manifest.js";
import {
  SbomSchema,
  type ArtifactKind,
  type FileEntry,
  type Sbom,
  type SbomPackage,
  type SbomSource,
} from "./types.js";

/** Lockfiles we know how to read, in detection priority order. */
const LOCKFILES = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "requirements.txt",
] as const;
type LockfileName = (typeof LOCKFILES)[number];

/** Result of probing a directory for the right SBOM strategy. */
export interface SbomStrategy {
  readonly source: SbomSource;
  /** The detected lockfile (relative path), when `source === "lockfile"`. */
  readonly lockfile?: LockfileName;
}

/**
 * Decide how to derive the SBOM for a directory.
 *
 * An MCP server class only forces a lockfile read if a known lockfile actually
 * exists; a Skill always uses the file manifest. If the caller passes
 * `kind: "mcp-server"` but the dir has no lockfile, we fall back to the
 * file-manifest source (an MCP server can still be flat).
 */
export async function detectSbomStrategy(
  dir: string,
  kind: ArtifactKind,
): Promise<SbomStrategy> {
  if (kind === "skill") return { source: "file-manifest" };

  for (const name of LOCKFILES) {
    try {
      const stat = await fs.stat(path.join(dir, name));
      if (stat.isFile()) return { source: "lockfile", lockfile: name };
    } catch {
      // not present; try the next candidate
    }
  }
  return { source: "file-manifest" };
}

/**
 * SBOM for a flat Skill: one package per file in the content-addressed
 * manifest. The package name is the file path, the digest is the file's
 * sha256, version/license are left empty (a loose file has neither).
 */
export function sbomFromFileManifest(files: readonly FileEntry[]): Sbom {
  const packages: SbomPackage[] = files.map((f) => ({
    name: f.path,
    version: "",
    license: "",
    digest: f.sha256,
  }));
  return SbomSchema.parse({
    spdx_lite: true,
    source: "file-manifest",
    packages,
  });
}

/** Parse `package-lock.json` (npm v2/v3 `packages` map, or v1 `dependencies`). */
function parsePackageLock(raw: string): SbomPackage[] {
  const json = JSON.parse(raw) as {
    packages?: Record<string, { version?: string; license?: string; integrity?: string }>;
    dependencies?: Record<string, { version?: string; integrity?: string }>;
  };
  const out: SbomPackage[] = [];

  if (json.packages) {
    for (const [key, meta] of Object.entries(json.packages)) {
      if (key === "") continue; // the root project itself
      const name = key.startsWith("node_modules/")
        ? key.slice("node_modules/".length)
        : key;
      out.push({
        name,
        version: meta.version ?? "",
        license: meta.license ?? "",
        digest: integrityToDigest(meta.integrity),
      });
    }
  } else if (json.dependencies) {
    for (const [name, meta] of Object.entries(json.dependencies)) {
      out.push({
        name,
        version: meta.version ?? "",
        license: "",
        digest: integrityToDigest(meta.integrity),
      });
    }
  }
  return out;
}

/** Parse a `pnpm-lock.yaml` packages section into SBOM entries. */
function parsePnpmLock(raw: string): SbomPackage[] {
  const doc = parseYaml(raw) as {
    packages?: Record<string, { resolution?: { integrity?: string } }>;
  };
  const out: SbomPackage[] = [];
  if (!doc.packages) return out;

  for (const [key, meta] of Object.entries(doc.packages)) {
    // keys look like "/lodash@4.17.21" or "lodash@4.17.21"
    const trimmed = key.startsWith("/") ? key.slice(1) : key;
    const at = trimmed.lastIndexOf("@");
    const name = at > 0 ? trimmed.slice(0, at) : trimmed;
    const version = at > 0 ? trimmed.slice(at + 1) : "";
    out.push({
      name,
      version,
      license: "",
      digest: integrityToDigest(meta.resolution?.integrity),
    });
  }
  return out;
}

/** Parse a pip `requirements.txt` (best-effort: `name==version` lines). */
function parseRequirements(raw: string): SbomPackage[] {
  const out: SbomPackage[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    const m = /^([A-Za-z0-9._-]+)\s*([=<>!~]=?)?\s*([^;#\s]+)?/.exec(trimmed);
    if (!m || !m[1]) continue;
    out.push({
      name: m[1],
      version: m[3] ?? "",
      license: "",
      // requirements.txt carries no content digest; address the declaration.
      digest: sha256Hex(`${m[1]}@${m[3] ?? ""}`),
    });
  }
  return out;
}

/**
 * Convert an npm/SRI `integrity` string ("sha512-...base64...") into the
 * lowercase-hex sha256 our schema accepts. SRI uses base64 (and often sha512),
 * which our {@link Sha256Schema} cannot store directly, so we re-hash the SRI
 * string itself to a stable sha256 surrogate digest. The point is a stable,
 * tamper-evident handle per resolved package, not re-deriving the tarball hash.
 */
function integrityToDigest(integrity: string | undefined): string {
  return sha256Hex(integrity && integrity.length > 0 ? integrity : "");
}

/**
 * Derive a lockfile-based SBOM. The lockfile's own declared deps become the
 * SBOM packages; the artifact's files are still covered by the file manifest in
 * the manifest's `files[]`, but the *named* dependencies come from here.
 */
export async function sbomFromLockfile(
  dir: string,
  lockfile: LockfileName,
): Promise<Sbom> {
  const raw = await fs.readFile(path.join(dir, lockfile), "utf8");
  let packages: SbomPackage[];
  switch (lockfile) {
    case "package-lock.json":
      packages = parsePackageLock(raw);
      break;
    case "pnpm-lock.yaml":
      packages = parsePnpmLock(raw);
      break;
    case "requirements.txt":
      packages = parseRequirements(raw);
      break;
  }
  packages.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return SbomSchema.parse({
    spdx_lite: true,
    source: "lockfile",
    packages,
  });
}

/**
 * Top-level SBOM derivation: probe the directory, then derive from the file
 * manifest (Skill) or the lockfile (MCP server). The `files` manifest is always
 * supplied by the caller (it is needed for the directory digest regardless), so
 * the file-manifest path is free.
 */
export async function deriveSbom(
  dir: string,
  kind: ArtifactKind,
  files: readonly FileEntry[],
): Promise<{ sbom: Sbom; strategy: SbomStrategy }> {
  const strategy = await detectSbomStrategy(dir, kind);
  if (strategy.source === "lockfile" && strategy.lockfile) {
    const sbom = await sbomFromLockfile(dir, strategy.lockfile);
    return { sbom, strategy };
  }
  return { sbom: sbomFromFileManifest(files), strategy };
}
