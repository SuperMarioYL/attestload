# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-19

First public release. The CLI implements the full attest-before-load loop end to
end: sign a Skill / MCP server, verify it, and refuse to load anything that is
unsigned or tampered.

### Added

- **m1 — `attestload attest`**: signs a Skill / MCP-server directory into a
  verifiable `attestload.manifest.json`. The SBOM is derived from a
  content-addressed file manifest (sha256 + size + path of every file) for flat
  Skills, and from the lockfile for lockfile-bearing classes like MCP servers.
  Git provenance (builder, source repo, commit) is captured (SLSA-lite) and the
  manifest is signed keyless via Sigstore, with a local ed25519 signer as the
  offline fallback.
- **m2 — `attestload verify`**: the gate. Recomputes the directory digest,
  re-derives the SBOM, and checks the signature; returns **PASS** (exit 0) with a
  one-line provenance summary for a clean artifact, and **BLOCKED** (exit 1) for
  an unsigned directory or any post-signing tamper (digest mismatch). Covered by
  `test/verify.test.ts`.
- **m3 — `attestload index`**: maintains a local verified-skill allowlist
  (`add` / `remove` / `seed` / `list`) seeded with popular Skills and MCP
  servers to solve cold-start; `verify --allowlist` gates against the known-good
  set offline.
- **`attestload guard install`**: drops a git pre-commit hook that runs `verify`
  before each commit, so unattested code never lands.
- Programmatic API (`import { verify, attest, guardLoad } from "attestload"`) for
  embedding the gate in a coding agent's skill-loading path.

[Unreleased]: https://github.com/SuperMarioYL/attestload/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SuperMarioYL/attestload/releases/tag/v0.1.0
