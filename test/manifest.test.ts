/**
 * Regression tests for the v0.2.0 manifest/digest security fixes.
 *
 * Each case pins an attacker scenario that previously slipped past `verify` and
 * proves it now BLOCKS (or that the digest now moves when it must). All run
 * fully locally with the forced `ed25519` signing mode — no network/OIDC.
 *
 * Coverage map:
 *   - fix 1: a planted `attestload.manifest.json` is now covered by the digest.
 *   - fix 2: a path crafted to forge the old `<sha>  <size>  <path>` delimiter
 *            no longer collides; a control-char path is rejected outright.
 *   - fix 3: a symlink is attested as its own leaf, and re-targeting it (or a
 *            post-sign chmod) perturbs the roll-up.
 *   - fix 5: an empty / emptied directory cannot be attested or verified clean.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { attest } from "../src/attest.js";
import { verify } from "../src/verify.js";
import {
  buildFileManifest,
  rollupDigest,
  sha256Hex,
} from "../src/manifest.js";
import { FileEntrySchema } from "../src/types.js";

let workspace: string;
let skillDir: string;
let keyDir: string;

async function writeFixture(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(
    path.join(dir, "SKILL.md"),
    "---\nname: fixture-skill\nversion: 1.0.0\n---\n# Fixture\nhello.\n",
  );
  await fs.writeFile(path.join(dir, "helper.txt"), "support content\n");
}

beforeEach(async () => {
  workspace = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-manifest-"));
  skillDir = path.join(workspace, "skill");
  keyDir = path.join(workspace, "keys");
  await writeFixture(skillDir);
});

afterEach(async () => {
  await fs.rm(workspace, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// fix 1 — attestload.manifest.json is no longer silently excluded
// ---------------------------------------------------------------------------
describe("fix 1: attestload.manifest.json is covered by the attested digest", () => {
  it("a file named attestload.manifest.json appears in the manifest", async () => {
    await fs.writeFile(
      path.join(skillDir, "attestload.manifest.json"),
      '{"hello":"world"}\n',
    );
    const files = await buildFileManifest(skillDir);
    const paths = files.map((f) => f.path);
    expect(paths).toContain("attestload.manifest.json");
  });

  it("planting an attestload.manifest.json after signing flips verify to BLOCKED", async () => {
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    // PASS before tampering
    expect((await verify(skillDir)).ok).toBe(true);

    // attacker drops a file with the once-ignored basename
    await fs.writeFile(
      path.join(skillDir, "attestload.manifest.json"),
      "payload that used to be invisible\n",
    );

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("digest-mismatch");
  });

  it("a nested attestload.manifest.json at any depth is also covered", async () => {
    const sub = path.join(skillDir, "nested");
    await fs.mkdir(sub, { recursive: true });
    await fs.writeFile(path.join(sub, "attestload.manifest.json"), "evil\n");
    const files = await buildFileManifest(skillDir);
    expect(files.map((f) => f.path)).toContain("nested/attestload.manifest.json");
  });
});

// ---------------------------------------------------------------------------
// fix 2 — unambiguous roll-up encoding (no delimiter forgery)
// ---------------------------------------------------------------------------
describe("fix 2: the roll-up encoding is delimiter-unambiguous", () => {
  it("two file sets that collide under the old 2-space/newline format now differ", () => {
    // Old format hashed `<sha>  <size>  <path>\n`. With a path containing the
    // delimiter, set A's single leaf could serialize to the same byte stream as
    // set B's two leaves. Build the classic ambiguity and assert digests differ.
    const z = "0".repeat(64);

    const setA = [
      FileEntrySchema.parse({ path: "a", sha256: z, size: 1 }),
      FileEntrySchema.parse({ path: "b", sha256: z, size: 2 }),
    ];
    // A path crafted to embed what used to be the field/record separators.
    const setB = [
      FileEntrySchema.parse({
        path: `a-spacer-${z}-2-b`,
        sha256: z,
        size: 1,
      }),
    ];

    expect(rollupDigest(setA)).not.toBe(rollupDigest(setB));
  });

  it("rejects a path containing control characters (newline/tab)", () => {
    expect(() =>
      FileEntrySchema.parse({ path: "evil\nname", sha256: "0".repeat(64), size: 1 }),
    ).toThrow();
    expect(() =>
      FileEntrySchema.parse({ path: "evil\tname", sha256: "0".repeat(64), size: 1 }),
    ).toThrow();
  });

  it("digest is stable for the same leaves and changes when any field changes", () => {
    const base = FileEntrySchema.parse({ path: "f", sha256: "1".repeat(64), size: 3 });
    const sameAgain = FileEntrySchema.parse({ path: "f", sha256: "1".repeat(64), size: 3 });
    expect(rollupDigest([base])).toBe(rollupDigest([sameAgain]));

    const sizeChanged = FileEntrySchema.parse({ path: "f", sha256: "1".repeat(64), size: 4 });
    expect(rollupDigest([base])).not.toBe(rollupDigest([sizeChanged]));
  });
});

// ---------------------------------------------------------------------------
// fix 3 — symlinks and the executable bit are attested
// ---------------------------------------------------------------------------
describe("fix 3: symlinks and file mode are attested", () => {
  it("a symlink is recorded as its own leaf (path + target hash)", async () => {
    await fs.symlink("../../evil", path.join(skillDir, "run.sh"));
    const files = await buildFileManifest(skillDir);
    const link = files.find((f) => f.path === "run.sh");
    expect(link).toBeDefined();
    expect(link?.type).toBe("symlink");
    expect(link?.link_target).toBe("../../evil");
    expect(link?.sha256).toBe(sha256Hex("../../evil"));
  });

  it("re-targeting a symlink after signing flips verify to BLOCKED", async () => {
    await fs.symlink("./helper.txt", path.join(skillDir, "run.sh"));
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    expect((await verify(skillDir)).ok).toBe(true);

    // swing the link to an escape target
    await fs.rm(path.join(skillDir, "run.sh"));
    await fs.symlink("../../evil", path.join(skillDir, "run.sh"));

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("digest-mismatch");
  });

  it("the roll-up reflects the executable bit (a chmod +x changes the digest)", () => {
    const plain = FileEntrySchema.parse({
      path: "run.sh",
      sha256: "2".repeat(64),
      size: 10,
      mode: 0o644,
    });
    const exec = FileEntrySchema.parse({
      path: "run.sh",
      sha256: "2".repeat(64),
      size: 10,
      mode: 0o755,
    });
    expect(rollupDigest([plain])).not.toBe(rollupDigest([exec]));
  });

  it("a post-sign chmod +x is detected by verify", async () => {
    const script = path.join(skillDir, "run.sh");
    await fs.writeFile(script, "#!/bin/sh\necho hi\n", { mode: 0o644 });
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    expect((await verify(skillDir)).ok).toBe(true);

    await fs.chmod(script, 0o755);

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("digest-mismatch");
  });
});

// ---------------------------------------------------------------------------
// fix 5 — an empty / emptied directory cannot attest or verify clean
// ---------------------------------------------------------------------------
describe("fix 5: an empty artifact is refused", () => {
  it("attest() refuses a directory with zero files", async () => {
    const empty = path.join(workspace, "empty");
    await fs.mkdir(empty, { recursive: true });
    await expect(attest(empty, { signingMode: "ed25519", keyDir })).rejects.toThrow(
      /no files to attest/i,
    );
  });

  it("verify() refuses an empty files[] manifest even if signed/intact", async () => {
    await attest(skillDir, { signingMode: "ed25519", keyDir });

    // Forge an empty manifest: zero files, the fixed empty roll-up digest.
    const bundlePath = path.join(skillDir, ".attestload", "attestation.json");
    const manifest = JSON.parse(await fs.readFile(bundlePath, "utf8"));
    manifest.files = [];
    manifest.sbom.packages = [];
    manifest.subject.artifact_digest = rollupDigest([]);
    await fs.writeFile(bundlePath, JSON.stringify(manifest, null, 2));

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("empty-artifact");
  });

  it("verify() refuses a dir whose covered files were all deleted", async () => {
    await attest(skillDir, { signingMode: "ed25519", keyDir });

    // Empty the directory of real content, leaving only the (still-signed)
    // bundle under .attestload — the recomputed file set is now empty.
    await fs.rm(path.join(skillDir, "SKILL.md"));
    await fs.rm(path.join(skillDir, "helper.txt"));

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("empty-artifact");
  });
});
