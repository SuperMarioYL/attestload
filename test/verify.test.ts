/**
 * End-to-end attest → verify tests (the m2 gate-load milestone).
 *
 * These run fully locally: every `attest` call forces the `ed25519` signing mode
 * so no network, OIDC token, or Sigstore service is required — the same
 * canonical-body signature path the Sigstore mode shares, minus the transparency
 * log. Each test gets its own throwaway temp dir (skill fixture + an isolated
 * key dir) so they are order-independent and leave nothing behind.
 *
 * Coverage:
 *   - happy path     → VERIFIED, decision allowed, provenance summary present
 *   - tampered file  → TAMPERED (digest-mismatch), refused
 *   - unsigned dir   → refusal (no-manifest), and `--allowlist` cold-start pass
 *   - policy         → identity allowlisting + relaxed (signature-not-required)
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { attest } from "../src/attest.js";
import { verify, verdictOf } from "../src/verify.js";
import { evaluatePolicy } from "../src/policy.js";
import { PolicySchema, type Allowlist } from "../src/types.js";

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
  workspace = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-test-"));
  skillDir = path.join(workspace, "skill");
  keyDir = path.join(workspace, "keys");
  await writeFixture(skillDir);
});

afterEach(async () => {
  await fs.rm(workspace, { recursive: true, force: true });
});

describe("attest → verify", () => {
  it("VERIFIED: a freshly attested skill passes the gate", async () => {
    const a = await attest(skillDir, { signingMode: "ed25519", keyDir });
    expect(a.signingMode).toBe("ed25519");
    expect(a.manifest.signature).toBeDefined();
    expect(a.manifest.files.length).toBeGreaterThanOrEqual(2);

    const result = await verify(skillDir);
    expect(result.ok).toBe(true);
    expect(verdictOf(result)).toBe("VERIFIED");
    expect(result.provenance_summary).toContain("signed ed25519");

    const decision = evaluatePolicy(result, PolicySchema.parse({}));
    expect(decision.allowed).toBe(true);
  });

  it("TAMPERED: editing a file after signing flips the verdict to BLOCKED", async () => {
    await attest(skillDir, { signingMode: "ed25519", keyDir });

    // mutate one byte of a covered file
    await fs.appendFile(path.join(skillDir, "helper.txt"), "tampered!\n");

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("digest-mismatch");
    expect(verdictOf(result)).toBe("TAMPERED");

    const decision = evaluatePolicy(result, PolicySchema.parse({}));
    expect(decision.allowed).toBe(false);
  });

  it("TAMPERED: a forged signature (wrong key) does not verify", async () => {
    await attest(skillDir, { signingMode: "ed25519", keyDir });

    // Rewrite the embedded signature with garbage; digest still matches but the
    // ed25519 check must fail → signature-invalid.
    const bundlePath = path.join(skillDir, ".attestload", "attestation.json");
    const manifest = JSON.parse(await fs.readFile(bundlePath, "utf8"));
    manifest.signature.bundle.signature = Buffer.from("not a real signature").toString("base64");
    await fs.writeFile(bundlePath, JSON.stringify(manifest, null, 2));

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("signature-invalid");
    expect(verdictOf(result)).toBe("SIG_INVALID");
  });

  it("UNSIGNED: a dir with no attestation is refused", async () => {
    const result = await verify(skillDir); // never attested
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("no-manifest");
    expect(verdictOf(result)).toBe("UNSIGNED");

    const decision = evaluatePolicy(result, PolicySchema.parse({}));
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/refusing to load/i);
  });

  it("policy: identity allowlisting refuses a non-matching signer", async () => {
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    const result = await verify(skillDir);
    expect(result.ok).toBe(true);

    const strict = PolicySchema.parse({ allowed_identities: ["someone-else@example.com"] });
    const decision = evaluatePolicy(result, strict);
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/not in allowed_identities/);

    // a glob that matches the local identity ("local:user@host") passes
    const loose = PolicySchema.parse({ allowed_identities: ["local:*"] });
    expect(evaluatePolicy(result, loose).allowed).toBe(true);
  });

  it("policy: relaxed policy (signature not required) loads an unsigned-but-intact dir", async () => {
    // sign, then strip just the signature so digest still verifies
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    const bundlePath = path.join(skillDir, ".attestload", "attestation.json");
    const manifest = JSON.parse(await fs.readFile(bundlePath, "utf8"));
    delete manifest.signature;
    await fs.writeFile(bundlePath, JSON.stringify(manifest, null, 2));

    const result = await verify(skillDir);
    expect(result.blocked_reason).toBe("no-signature");

    const relaxed = PolicySchema.parse({ require_signature: false });
    const decision = evaluatePolicy(result, relaxed);
    expect(decision.allowed).toBe(true);
  });

  it("v0.4.0: a file-manifest SBOM missing a package for an attested file is BLOCKED (sbom-mismatch)", async () => {
    // A file-manifest SBOM is defined as one package PER file — a total map of
    // the artifact. Drop one package from sbom.packages while leaving files[] and
    // the on-disk files intact: the roll-up digest still matches (so we get PAST
    // the digest-mismatch check), but the bill-of-materials no longer covers every
    // attested file, so verify() must refuse with sbom-mismatch.
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    const bundlePath = path.join(skillDir, ".attestload", "attestation.json");
    const manifest = JSON.parse(await fs.readFile(bundlePath, "utf8"));

    expect(manifest.subject.sbom_source).toBe("file-manifest");
    expect(manifest.sbom.packages.length).toBeGreaterThanOrEqual(2);
    // remove exactly one package (leave files[] and the digest untouched)
    const droppedName: string = manifest.sbom.packages[0].name;
    manifest.sbom.packages = manifest.sbom.packages.slice(1);
    await fs.writeFile(bundlePath, JSON.stringify(manifest, null, 2));

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);
    expect(result.blocked_reason).toBe("sbom-mismatch");
    expect(result.message).toContain(droppedName);
  });

  it("m3 allowlist: cold-start lets a digest-pinned known-good name pass without a signature", async () => {
    // attest then strip the signature: an unsigned-but-named skill
    await attest(skillDir, { signingMode: "ed25519", keyDir });
    const bundlePath = path.join(skillDir, ".attestload", "attestation.json");
    const manifest = JSON.parse(await fs.readFile(bundlePath, "utf8"));
    const subjectName: string = manifest.subject.name;
    const subjectDigest: string = manifest.subject.artifact_digest;
    delete manifest.signature;
    await fs.writeFile(bundlePath, JSON.stringify(manifest, null, 2));

    const result = await verify(skillDir);
    expect(result.ok).toBe(false);

    // A cold-start entry must PIN the artifact_digest: trusting a name-only
    // entry against an unsigned bundle would be an impersonation surface.
    const allowlist: Allowlist = {
      schema: "attestload-allowlist/v1",
      entries: [
        {
          name: subjectName,
          artifact_digest: subjectDigest,
          source_repo: "",
          added_at: new Date().toISOString(),
        },
      ],
    };
    const policy = PolicySchema.parse({ use_allowlist: true });
    const decision = evaluatePolicy(result, policy, allowlist);
    expect(decision.allowed).toBe(true);
    expect(decision.reason).toMatch(/allowlisted/i);
  });
});
