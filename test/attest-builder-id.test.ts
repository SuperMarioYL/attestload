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

  it("does NOT fall back to ACTIONS_ID_TOKEN_REQUEST_TOKEN — it is a request token, not a JWT identity (v0.10 fix)", () => {
    // v0.10.0 regression for fix-sigstore-actions-request-token-builder-id-unknown:
    // ACTIONS_ID_TOKEN_REQUEST_TOKEN is a bearer REQUEST token for the OIDC
    // fetch URL, NOT a JWT identity token, so it must no longer be returned
    // here. The old code returned it, which fed "unknown" into builder_id.
    process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "actions-env-token";
    expect(resolveIdentityToken(undefined)).toBeUndefined();
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

/**
 * v0.10.0 regression — `fix-sigstore-actions-request-token-builder-id-unknown`
 * (a v0.9 regression of v0.8 honesty).
 *
 * `resolveIdentityToken` (src/attest.ts) fell back to
 * `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, but that GitHub Actions env var is a bearer
 * REQUEST token used to hit `ACTIONS_ID_TOKEN_REQUEST_URL` to FETCH the OIDC
 * JWT — it is NOT itself a JWT. In a standard CI job (`id-token: write`, no
 * `SIGSTORE_ID_TOKEN`), the old code returned it, so
 * `builderId = extractIdentity(requestToken) = "unknown"` (a request token is
 * not a dotted JWT, so `token.split(".")[1]` is undefined → "unknown"),
 * while `trySignSigstore` failed and silently degraded to ed25519.
 * `provenance.builder_id` therefore read `"unknown"` for an attestation
 * actually built by a local ed25519 key — untruthful provenance, and a
 * regression from v0.8 (which emitted the honest `local:<username>` before the
 * v0.9 fix wired `resolveIdentityToken` into builder_id).
 *
 * The fix drops `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from `resolveIdentityToken`'s
 * fallback chain. With no real JWT (`SIGSTORE_ID_TOKEN` or `--identity-token`)
 * reachable, builder_id honestly falls back to `local:<username>` and sigstore
 * cleanly degrades to ed25519, restoring v0.8 honesty WITHOUT touching the
 * `SIGSTORE_ID_TOKEN` alignment the v0.9 fix added (that path still yields the
 * email). The regression drives `attest()` with ONLY the request token set and
 * asserts `builder_id` is the honest `local:<username>`, not `"unknown"`.
 */
describe("v0.10.0: attest() emits an honest local builder_id when only the GH Actions request token is set (not 'unknown')", () => {
  let workspace: string;
  let skillDir: string;
  let keyDir: string;
  const prevSigstore = process.env["SIGSTORE_ID_TOKEN"];
  const prevActions = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];

  beforeEach(async () => {
    workspace = await fs.mkdtemp(
      path.join(os.tmpdir(), "attestload-builderid-v10-"),
    );
    skillDir = path.join(workspace, "skill");
    keyDir = path.join(workspace, "keys");
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(path.join(skillDir, "SKILL.md"), "# fixture\n");
    // Standard CI job shape: `id-token: write`, no SIGSTORE_ID_TOKEN. The only
    // token-shaped env var present is the GH Actions REQUEST token (a non-JWT).
    delete process.env["SIGSTORE_ID_TOKEN"];
    process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "gh-actions-request-token";
  });

  afterEach(async () => {
    if (prevSigstore === undefined) delete process.env["SIGSTORE_ID_TOKEN"];
    else process.env["SIGSTORE_ID_TOKEN"] = prevSigstore;
    if (prevActions === undefined)
      delete process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
    else process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = prevActions;
    await fs.rm(workspace, { recursive: true, force: true });
  });

  it("builder_id is the honest local:<username>, not the request token's 'unknown'", async () => {
    // Force ed25519 so no network/OIDC is touched; the provenance-derivation
    // path runs before the signing-mode branch, so builder_id is still derived
    // from the resolved token (here: none — the request token is no longer a
    // fallback), landing the honest local identity.
    const result = await attest(skillDir, { signingMode: "ed25519", keyDir });
    expect(result.manifest.provenance.builder_id).toBe(
      `local:${os.userInfo().username}`,
    );
    // Regression guard: the v0.9 wiring returned the request token, which
    // extractIdentity read as "unknown".
    expect(result.manifest.provenance.builder_id).not.toBe("unknown");
  });
});
