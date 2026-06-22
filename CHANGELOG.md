# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-23

A security-hardening release. No new feature surface — five load-bearing holes in
the trust model are closed, each with regression coverage that pins the attacker
case to BLOCK. If you generated attestations with 0.1.0, re-run `attestload attest`
after upgrading: the digest now covers more (symlinks, file mode, and files the
old build silently skipped), so old manifests will no longer match.

### Security

- **Stop excluding `attestload.manifest.json` from the attested digest.** The
  manifest walk dropped every file with that basename at any depth, so an
  attacker could plant or modify one anywhere and still verify clean. Removed the
  basename blanket-skip; the real on-disk bundle (`.attestload/attestation.json`)
  is already excluded by the `.attestload` ignored-dir plus the explicit exclude
  option, so nothing legitimate is lost.
- **Domain-separate the Merkle roll-up so paths can't forge collisions.** The
  roll-up hashed `<sha256>  <size>  <path>\n` with two-space field and newline
  record separators; because a POSIX path may contain spaces and newlines, a
  crafted name could shift the field/record boundary and make two distinct file
  sets hash to the same bytes. The roll-up now hashes a canonical JSON array of
  the sorted leaves (every field self-delimiting), and `FileEntry.path` rejects
  control characters outright.
- **Attest symlinks and the executable bit.** The walk recorded only regular
  files and silently skipped symlinks, and entries carried no mode — so a
  malicious `run.sh -> ../../evil` symlink or a post-sign `chmod +x` still passed.
  Symlinks are now their own leaf type (path + digest of the unresolved target),
  and each entry carries its POSIX mode; both feed the roll-up.
- **Remove the dead `no-manifest` cold-start arm and pin allowlist cold-start on
  a real digest.** `evaluatePolicy` treated `no-manifest` as an eligible
  cold-start state, but `verify` never returns a manifest in that case, so the
  arm was dead. The live `no-signature` path trusted a self-declared name in an
  unsigned bundle against a name-only allowlist entry — an unsigned attestation
  claiming `github-mcp` passed. Cold-start now requires the allowlist entry to
  pin a known-good `artifact_digest`; name-only entries are refused.
- **Refuse an empty or emptied artifact.** `rollupDigest([])` collapses to the
  fixed empty-string sha256, and nothing rejected a zero-file manifest — so a dir
  holding only a re-signed bundle plus ignored dirs verified clean while covering
  no content. `attest` now errors on an empty file manifest, and `verify` blocks
  an empty `files[]` / empty roll-up with a new `empty-artifact` reason.

### Tests

- Added `test/manifest.test.ts` and `test/policy.test.ts` regression suites that
  reproduce each attacker scenario above and assert it now BLOCKS (planted
  manifest.json, delimiter-collision path, re-targeted symlink, post-sign chmod,
  empty/emptied dir, unsigned name-only impersonation), plus the positive case
  that a digest-pinned cold-start entry still passes.

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

[Unreleased]: https://github.com/SuperMarioYL/attestload/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/SuperMarioYL/attestload/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/attestload/releases/tag/v0.1.0
