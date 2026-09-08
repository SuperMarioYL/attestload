[简体中文](./README.md) · [Website](https://attestload.lei6393.com) · [GitHub](https://github.com/SuperMarioYL/attestload)

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/hero-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/hero-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/hero-dark.svg">
  <img src="./assets/presentation/hero-light.svg" width="960" alt="Hero diagram">
</picture>

# AttestLoad

**Check what you are about to load**

AttestLoad signs a directory manifest and verifies the files before your loader proceeds. Use its CLI in CI or call guardLoad from an application that owns the loading step.

## Why use it

A directory can change between review and installation. A signed manifest records the reviewed file set, while verification detects changed content and policy decides which signer identities your workflow accepts.

- **Content checks** — Rebuild file digests, executable modes and symlink metadata before verification.
- **Explicit signing mode** — Local Ed25519 and network-backed Sigstore signatures are separately identified.
- **A loader decision** — guardLoad throws LoadRefused when verification or policy refuses the artifact.

## Architecture

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/architecture-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/architecture-dark.svg">
  <img src="./assets/presentation/architecture-light.svg" width="960" alt="Architecture diagram">
</picture>

manifest.ts walks files into a content-addressed list. sbom.ts derives file-level or supported lockfile metadata; attest.ts adds provenance and signs canonical JSON. verify.ts recomputes the content and verifies the signature. policy.ts applies provenance and bound-signer rules; loader-guard.ts exposes the result to the caller.

| Component | Responsibility |
| --- | --- |
| `Directory manifest` | files, modes and symlinks |
| `SBOM + provenance` | file or lockfile metadata |
| `Signature` | Ed25519 or Sigstore |
| `Verify + policy` | digest and signer checks |
| `Loader guard` | allow or LoadRefused |

## Install and quickstart

Node.js 22+. The recorded example keeps its temporary signing key outside the signed directory.

```bash
git clone https://github.com/SuperMarioYL/attestload.git
cd attestload
npm ci
npm run build
```

This complete example creates a temporary skill and key, signs with local Ed25519, verifies it, then modifies the file. It does not contact Fulcio or Rekor.

```bash
node examples/presentation-demo.mjs
```

## Recorded demo

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/process-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/process-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/process-dark.svg">
  <img src="./assets/presentation/process-light.svg" width="960" alt="Process diagram">
</picture>

Local signing changes UNSIGNED to VERIFIED; editing the file produces TAMPERED.

```text
unsigned: UNSIGNED
signing mode: ed25519
signed: VERIFIED
modified: TAMPERED
Scope: local Ed25519 integrity checks; no Sigstore network or trusted-publisher assertion.
```

The complete command and output are recorded in [docs/demo-results.json](./docs/demo-results.json). Inputs and reproduction code are included in the repository.

## Usage

attest writes .attestload/attestation.json beside the files. verify returns 0 when policy accepts and 1 when blocked. The unsigned example intentionally blocks. For an application, import guardLoad from attestload and await it before the application executes or imports the directory’s code; checkLoad returns a decision without throwing.

```bash
node dist/cli.js attest ./examples/signed-skill --kind skill
node dist/cli.js verify ./examples/signed-skill --json
node dist/cli.js verify ./examples/unsigned-skill --json
```

## Configuration

Policy supports require_provenance, require_signature, allowed_identities and use_allowlist. Pin Ed25519 identities as ed25519:<SPKI-DER SHA-256>; Sigstore identities come from the verified certificate SAN. With no allowed_identities restriction, a valid self-signed local key does not establish a trusted publisher. Cold-start allowlisting requires a present intact unsigned manifest and a matching pinned artifact digest; a name-only entry is insufficient. --sigstore requires a usable OIDC token and network access; default signing may fall back to local Ed25519.

```yaml
require_provenance: true
require_signature: true
allowed_identities: []
use_allowlist: false
```

## Integrations and responsibilities

<picture>
  <source media="(max-width: 600px) and (prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-mobile-dark.svg">
  <source media="(max-width: 600px)" srcset="./assets/presentation/integrations-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="./assets/presentation/integrations-dark.svg">
  <img src="./assets/presentation/integrations-light.svg" width="960" alt="Integrations diagram">
</picture>

A verifier only gates loading when the application or CI workflow calls it and honors its result. It does not automatically intercept every agent. SPDX-lite and SLSA-lite describe the repository’s reduced metadata formats; they are not claims of full standards certification.

| Route | Implemented role |
| --- | --- |
| Skill directories | file-manifest SBOM |
| MCP directories | supported lockfile SBOM |
| CLI / CI | JSON and exit codes |
| Loader API | guardLoad / checkLoad |
| Sigstore | optional keyless signing |

## Limits and next steps

- Signature validity and content integrity do not establish that code is harmless. Review what the skill can execute.
- The demo validates local signing only; Sigstore transparency-log and identity flows were not exercised.
- A guarded check does not prevent later file changes unless the caller controls the check-to-execution boundary.

The repository provides local attest/verify, signer policy, allowlist management and a loader API. Further runtime adapters and team policy distribution remain future work; no hosted subscription service is demonstrated by this repository. See CHANGELOG.md for implementation changes.

## License and contributions

See [LICENSE](./LICENSE). When reporting an issue, include a minimal input, the command, and the observed output.
