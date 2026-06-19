<div align="right"><sub><b>English</b>&nbsp;&nbsp;⇄&nbsp;&nbsp;<a href="./README.md">简体中文</a></sub></div>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg">
  <img src="./assets/hero-light.svg" width="880" alt="AttestLoad — the attest-before-load gate for coding agents">
</picture>

<p><sub>AttestLoad gives every Skill and MCP server a verifiable SBOM + build-provenance signature, so a coding agent refuses any unsigned code before it loads — trust stops being star count and becomes a cryptographic fact.</sub></p>

<p align="center">
  <a href="./LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-1D1D1F"></a>
  <a href="https://github.com/SuperMarioYL/attestload/releases"><img alt="Release" src="https://img.shields.io/badge/release-v0.1.0-E0541B"></a>
  <a href="https://github.com/SuperMarioYL/attestload/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/SuperMarioYL/attestload/ci.yml?branch=main&label=ci"></a>
  <img alt="Node" src="https://img.shields.io/badge/node-%E2%89%A522-339933?logo=node.js&logoColor=white">
  <img alt="MCP-ready" src="https://img.shields.io/badge/MCP-ready-C81E1E">
  <img alt="Sigstore" src="https://img.shields.io/badge/Sigstore-keyless-D97706">
</p>

**You install a Skill by star count and have no idea what it will run on load — AttestLoad turns that trust gap into a cryptographic check: unsigned or tampered code is refused before it ever loads.**

The recent "10k trojaned GitHub repos" supply-chain story made the gap obvious: autonomous **Coding Agents** auto-install Skills and **MCP** servers by star count, and nobody has actually read the code. AttestLoad wires the mature SBOM / SLSA / Sigstore supply-chain primitives into the one place they have never lived — the **agent's skill-loading path** — as a new verb: **attest-before-load**.

---

## Table of contents

- [Architecture](#architecture)
- [Install](#install)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Demo](#demo)
- [Why this exists](#why-this-exists)
- [vs cosign / Trivy](#vs-cosign--trivy)
- [Configuration](#configuration)
- [Roadmap](#roadmap)
- [Pricing](#pricing)
- [License](#license)

---

<h2 id="architecture"><img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Architecture</h2>

A single Node CLI — no services, no database, no Kubernetes; network calls only to public Sigstore (Fulcio / Rekor) when signing or verifying. On the producer side `attest` emits a signed manifest; on the consumer side `verify` checks it before load, while `policy` and `loader-guard` decide PASS or BLOCKED.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
  <img src="./assets/atlas-light.svg" width="880" alt="Architecture: attest → SBOM/manifest → sign → verify → policy/loader-guard → allowlist">
</picture>

The new primitive is the **attestation manifest** — a signed bundle that travels with a Skill / MCP directory:

| Field | Meaning |
|---|---|
| `subject` | name / version / directory sha256 digest / SBOM source (`file-manifest` or `lockfile`) |
| `sbom` | SPDX-lite package list (per-file entries for a Skill; lockfile-derived for an MCP server) |
| `files` | content-addressed per-file manifest (path · sha256 · size) |
| `provenance` | SLSA-lite provenance (builder · source_repo · source_commit) |
| `signature` | Sigstore bundle + Rekor log index (or a local ed25519 fallback signature) |

<h2 id="install"><img src="https://api.iconify.design/tabler:rocket.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Install</h2>

Requires Node ≥ 22.

```bash
npm install -g attestload     # or run without installing: npx attestload <command>
```

<h2 id="quickstart"><img src="https://api.iconify.design/tabler:bolt.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Quickstart</h2>

From cold clone to the first "refusal moment" in three commands:

```bash
git clone https://github.com/SuperMarioYL/attestload && cd attestload && npm install && npm run build
node dist/cli.js attest ./examples/signed-skill      # issue an attestation (local ed25519 by default)
node dist/cli.js verify ./examples/unsigned-skill    # BLOCKED, exit code 1 — that's the hook
```

<details>
<summary>sample output</summary>

```text
$ attestload attest ./examples/signed-skill
✓ attested
  subject : signed-skill@1.0.0 (skill)
  digest  : 1a72a17cf6a691f8249d73b5762ee0d513cf6e2e8e2a73c055e73e382948779e
  sbom    : file-manifest, 2 package(s)
  signing : ed25519
  written : ./examples/signed-skill/.attestload/attestation.json

$ attestload verify ./examples/signed-skill
PASS — verified
  built by local:you from local@no-commit · signed ed25519

$ attestload verify ./examples/unsigned-skill
BLOCKED: no attestation found at .attestload/attestation.json — refusing to load unattested code
  verdict: UNSIGNED (no-manifest)
  unattested code refused to load
# exit code: 1
```

</details>

<h2 id="usage"><img src="https://api.iconify.design/tabler:terminal-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Usage</h2>

Four subcommands cover the full loop. Every command accepts `--json` for machine-readable output; `verify`'s exit code plugs straight into CI and git hooks.

**Attest (producer)** — derive an SBOM for a Skill or MCP-server directory, capture git provenance, and sign it:

```bash
attestload attest ./my-skill --kind skill           # flat Skill; SBOM from the file manifest
attestload attest ./my-mcp-server --kind mcp-server # lockfile-derived SBOM when one is present
attestload attest ./my-skill --sigstore             # force keyless Sigstore (one browser OIDC click)
```

**Verify (consumer)** — the load-time gate; tampered / unsigned is refused:

```bash
attestload verify ./downloaded-skill                # PASS → exit 0, BLOCKED → exit 1
attestload verify ./downloaded-skill --policy attestload.policy.yaml
attestload verify ./downloaded-skill --allowlist    # also pass if present in the verified allowlist
```

**Index (cold-start)** — a verified-skill allowlist that gives consumers value before authors sign:

```bash
attestload index seed                               # seed popular Skills / MCP servers
attestload index add my-skill --digest sha256:...   # pin an expected digest
attestload index list
```

**Guard** — drop a git pre-commit hook that verifies before every commit:

```bash
attestload guard install
```

More runnable examples live in [`examples/`](./examples).

<h2 id="demo"><img src="https://api.iconify.design/tabler:photo.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Demo</h2>

`verify` refuses an unsigned Skill, then passes the same Skill once signed — that refusal moment is the shareable hook.

![demo](assets/demo.gif)

<h2 id="why-this-exists"><img src="https://api.iconify.design/tabler:shield-lock.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Why this exists</h2>

Today you pick a Skill / MCP server mostly by star count, and an autonomous agent self-installs it with no human review — the ideal entry point for a supply-chain attack. AttestLoad swaps that trust from social proof to a cryptographic fact: digest + signature + provenance, checked once before load. A digest-and-signature check is the only thing that scales to fleets of agents.

<h2 id="vs-cosign--trivy"><img src="https://api.iconify.design/tabler:scale.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> vs cosign / Trivy</h2>

Honest positioning: the general-purpose tools are more mature. AttestLoad's difference is wiring these primitives into the **agent's skill-loading path**.

| Capability | AttestLoad | cosign | Trivy |
|---|:---:|:---:|:---:|
| Refuse-to-load on a Skill / MCP directory at load time | ✓ | — | — |
| Content-addressed SBOM that ships with the artifact | ✓ | partial | ✓ |
| Keyless Sigstore + Rekor signing | ✓ | ✓ | — |
| General container-image / OCI artifact signing | — | ✓ | partial |
| Maturity / ecosystem breadth | early | mature | mature |

To sign container images, use cosign; to scan CVEs, use Trivy. To make a **Coding Agent refuse unattested code before it loads a Skill** — that verb only exists in AttestLoad.

<h2 id="configuration"><img src="https://api.iconify.design/tabler:adjustments.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Configuration</h2>

`verify` reads an optional `attestload.policy.json` / `.yaml` from nearby; the default is strict.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `require_provenance` | bool | `true` | refuse if provenance is missing |
| `require_signature` | bool | `true` | refuse if a valid signature is missing |
| `allowed_identities` | string[] | `[]` | accepted signer identities (OIDC; empty means no restriction) |
| `use_allowlist` | bool | `false` | also pass if present in the verified allowlist (cold-start) |

<h2 id="roadmap"><img src="https://api.iconify.design/tabler:map-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Roadmap</h2>

- [x] **m1** — `attest` signs a Skill / MCP directory into a verifiable SBOM + provenance manifest
- [x] **m2** — `verify` refuses unsigned / tampered artifacts and passes signed ones (the refusal demo)
- [x] **m3** — `index` maintains a verified-skill allowlist to solve cold-start
- [ ] Hosted team tier: continuously-updated verified-skill allowlist + org-wide policy enforcement (see [Pricing](#pricing))
- [ ] Reference integrations landed in popular directories like awesome-mcp-servers
- [ ] Loader-guard adapters for more agent runtimes

<h2 id="pricing"><img src="https://api.iconify.design/tabler:building-store.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Pricing</h2>

The open-source CLI (this repo) is openly available and covers the full local attest / verify / allowlist loop. When a team needs to move verification from "every laptop fends for itself" to "enforced org-wide," the hosted tier takes over:

| Tier | Price | What you get |
|---|---|---|
| **OSS CLI** | open | local attest / verify / local allowlist · git pre-commit guard |
| **Hosted team tier** | **$199 / month** (10 seats) | continuously-updated verified-skill allowlist + org-wide policy enforcement (a CI / pre-commit service that gates which Skills the fleet may auto-install) + an audit trail of every attestation decision |
| **Seat expansion** | **$15 / seat / month** | beyond 10 seats |
| **Enterprise** | **~$2k / year** | SSO + audit + design-partner support |

Smallest "here's my credit card" path: the free CLI proves the refuse-then-pass value locally → the team wants it enforced org-wide → a hosted dashboard hands you one allowlist URL + a Stripe checkout link; paste the URL into your pre-commit / CI config and the fleet is gated in under 10 minutes. The first three design-partner teams are onboarded by hand.

<h2 id="license"><img src="https://api.iconify.design/tabler:license.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> License & contributing</h2>

MIT — see [LICENSE](./LICENSE). Issues and PRs are welcome — especially a reference integration that adds an `attestload.manifest.json` to a popular Skill / MCP-server repo. File one [here](https://github.com/SuperMarioYL/attestload/issues).

After pushing, set the repo topics: `gh repo edit --add-topic mcp --add-topic coding-agent --add-topic skill --add-topic sbom`

## Share this

```text
AttestLoad — the attest-before-load gate for coding agents. Sign your Skill / MCP server into a verifiable SBOM, and the agent refuses unsigned code before it loads. Trust stops being star count. https://github.com/SuperMarioYL/attestload
```

---

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
