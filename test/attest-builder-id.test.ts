/**
 * v0.9.0 regression — `fix-sigstore-env-token-builder-id-mismatch`.
 *
 * `attest()` derived `builderId` from `options.identityToken` (the
 * `--identity-token` flag) ONLY, but `trySignSigstore` resolves the OIDC token
 * as `identityToken ?? SIGSTORE_ID_TOKEN ?? ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
 * When the token arrived via `SIGSTORE_ID_TOKEN` (the standard Sigstore CI
 * path, with no flag), `builderId` became `local:<username>` while the
 * sigstore cert identity was the email — `provenance.builder_id` disagreed
 * with the verified signer identity, which is exactly the kind of untruthful
 * provenance a provenance tool must not emit.
 *
 * The fix centralizes token resolution in `resolveIdentityToken` (flag ?? env)
 * and derives `builderId` from THAT. The regression drives `attest()` with an
 * env-supplied token and `signingMode: "ed25519"` (so no network/OIDC is
 * exercised — the provenance-derivation path is independent of the signing
 * branch) and asserts `builder_id` is the email from the env token, not
 * `local:<username>`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { attest, resolveIdentityToken } from "../src/attest.js";

/** Build a JWT-shaped string whose payload decodes to the given claims. */
function jwtWith(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.sig`;
}

describe("v0.9.0: resolveIdentityToken mirrors trySignSigstore's token resolution", () => {
  const envKeys = ["SIGSTORE_ID_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"] as const;
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of envKeys) saved[k] = process.env[k];
    for (const k of envKeys) delete process.env[k];
  });

  afterEach(() => {
    for (const k of envKeys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k] as string;
    }
  });

  it("prefers the explicit --identity-token flag over both env vars", () => {
    process.env["SIGSTORE_ID_TOKEN"] = "sigstore-env-token";
    process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "actions-env-token";
    expect(resolveIdentityToken("flag-token")).toBe("flag-token");
  });

  it("falls back to SIGSTORE_ID_TOKEN when no flag is set", () => {
    process.env["SIGSTORE_ID_TOKEN"] = "sigstore-env-token";
    process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "actions-env-token";
    expect(resolveIdentityToken(undefined)).toBe("sigstore-env-token");
  });

  it("falls back to ACTIONS_ID_TOKEN_REQUEST_TOKEN when no flag and no SIGSTORE_ID_TOKEN", () => {
    process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "actions-env-token";
    expect(resolveIdentityToken(undefined)).toBe("actions-env-token");
  });

  it("returns undefined when no token is reachable at all (local fallback path)", () => {
    expect(resolveIdentityToken(undefined)).toBeUndefined();
  });
});

describe("v0.9.0: attest() derives provenance.builder_id from the env-supplied OIDC token", () => {
  let workspace: string;
  let skillDir: string;
  let keyDir: string;
  const prevSigstore = process.env["SIGSTORE_ID_TOKEN"];

  beforeEach(async () => {
    workspace = await fs.mkdtemp(path.join(os.tmpdir(), "attestload-builderid-"));
    skillDir = path.join(workspace, "skill");
    keyDir = path.join(workspace, "keys");
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(path.join(skillDir, "SKILL.md"), "# fixture\n");
    // Standard CI path: the OIDC token arrives via env, NOT via --identity-token.
    process.env["SIGSTORE_ID_TOKEN"] = jwtWith({ email: "alice@example.com" });
  });

  afterEach(async () => {
    if (prevSigstore === undefined) delete process.env["SIGSTORE_ID_TOKEN"];
    else process.env["SIGSTORE_ID_TOKEN"] = prevSigstore;
    await fs.rm(workspace, { recursive: true, force: true });
  });

  it("builder_id is the email from the env token (not local:<username>)", async () => {
    // Force ed25519 so no network/OIDC is touched; the provenance-derivation
    // path runs before the signing-mode branch, so builder_id is still derived
    // from the resolved env token.
    const result = await attest(skillDir, { signingMode: "ed25519", keyDir });
    expect(result.manifest.provenance.builder_id).toBe("alice@example.com");
    // Regression guard: the old code gated on options.identityToken only, so
    // with no flag it emitted `local:<username>`.
    expect(result.manifest.provenance.builder_id).not.toMatch(/^local:/);
  });
});
