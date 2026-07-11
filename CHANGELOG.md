# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-07-11

A trust-boundary correctness release closing an identity-allowlist bypass. No
attestation format change.

### Fixed
- **`allowed_identities` can no longer be bypassed via the self-declared
  `cert_identity` on ed25519 attestations.** The ed25519 detached signature
  verifies against a public key *embedded in the bundle*, while `cert_identity`
  sits in the (unsigned) signature block — so any holder of any ed25519 key could
  sign an artifact with their own key and set `cert_identity` to a value listed in
  a consumer's `allowed_identities` to impersonate a trusted signer and pass the
  gate. `evaluatePolicy` now matches `allowed_identities` against the
  cryptographically **bound** signer identity — for ed25519 the verified key's
  SPKI-DER sha256 fingerprint, `ed25519:<hex>` — rather than the self-declared
  string. An unparseable key yields no identity, so the check fails closed.
  (Sigstore identities remain matched on `cert_identity`, which the bundle
  verification cryptographically gates against the OIDC certificate.)

  **Breaking (security hardening, fails closed):** an ed25519 `allowed_identities`
  entry that listed a human `cert_identity` string (e.g. `local:*`) no longer
  matches; pin the key fingerprint instead. When such a config now refuses, the
  block message names the bound identity to pin (`signing identity "ed25519:<hex>"
  is not in allowed_identities`). No artifact that should be refused becomes
  allowed — a previously-allowed (impersonable) config now refuses until it is
  re-pinned. `allowed_identities` is empty by default, so consumers that do not
  enforce an identity allowlist are unaffected.

## [0.5.0] - 2026-07-05

A trust-boundary correctness release. The headline fix closes a
self-authorization hole in the policy-discovery path; two further fixes make a
malformed policy file fail loudly instead of silently degrading, and stop the
README release badge from drifting. No attestation format change — existing
attestations remain valid.

### Fixed

- **Policy files are no longer discovered inside the verified artifact directory.**
  `verify` and `guardLoad` used to probe the *verified* dir for
  `attestload.policy.{json,yaml,yml}`, so a downloaded skill could ship its own
  relaxed policy (`{require_signature: false, require_provenance: false}`) and
  self-authorize: its unsigned manifest made `verify()` return `no-signature`,
  and `evaluatePolicy`'s relaxed branch returned `allowed: true` — exit 0, PASS.
  The artifact defined its own admission rules, inverting the trust boundary the
  whole product is built on. The policy search now defaults to the consumer's
  cwd and NEVER probes the artifact dir; an explicit `--policy <file outside the
  artifact>` still applies. Pinned by new cases in `test/policy.test.ts`.

- **A malformed policy file now fails loudly instead of silently degrading to the
  strict default.** `loadPolicy`'s search loop caught every error from
  `fs.readFile` + `parsePolicy` — not just `ENOENT` — so a typo'd
  `attestload.policy.json` was treated as "not present", and both call sites
  blanket-caught the whole `loadPolicy` call down to `DEFAULT_POLICY`. That
  meant an explicit `--policy ./my-policy.json` with a single syntax typo
  silently refused everything, with no signal that the policy file was the
  cause. The search loop now catches ONLY `ENOENT` (try the next candidate) and
  re-throws parse/schema errors with the offending filename; the call sites no
  longer blanket-catch an explicit `--policy` load, so a malformed or missing
  explicit policy fails the command with a non-zero exit and a message naming
  the file. A malformed default policy in cwd surfaces the same way. Pinned by
  new cases in `test/policy.test.ts`.

- **The README release badge now tracks the real GitHub release tag.** Both
  `README.md` and `README.en.md` carried a hardcoded `release-v0.1.0` shields.io
  static literal, which had drifted across four version bumps while
  `package.json` shipped 0.2.0–0.5.0 — the same truthful-reporting defect the
  0.3.0 CLI version fix addressed. Replaced with a dynamic `github/v/release`
  badge (brand color preserved), and a CI drift guard now fails the build if
  either README regresses to a static `release-vX.Y.Z` badge.

## [0.4.0] - 2026-07-02

A trust-model correctness release. Two fixes close asymmetric-enforcement gaps in the
load-decision path; both are in the same family as the 0.2.0 five-hole hardening. No
attestation format change — existing attestations remain valid.

### Fixed

- **The signature-optional policy path now enforces `require_provenance` symmetrically.**
  `evaluatePolicy`'s relaxed branch — reached when `require_signature: false` and the
  bundle is unsigned-but-digest-verified — returned `allowed` without applying the
  `require_provenance` / `builder_id` guard that the cryptographically-verified path
  always enforces. So a coherent `{require_signature: false, require_provenance: true}`
  policy ("accept digest-pinned unsigned code but still demand a builder identity")
  would load an unsigned, builder-less artifact — the weaker path silently skipping the
  very check the policy asked for. Provenance is now enforced identically on both paths.
  Pinned by new cases in `test/policy.test.ts`.

- **`verify` now enforces file-manifest SBOM completeness in both directions.** For a
  `file-manifest`-source SBOM (defined as one package per file — a total map of the
  artifact), `verify` checked that every *claimed* package matched a recomputed leaf but
  not the reverse: that every attested file is *named by* a package. A manifest whose
  `sbom.packages` covered only a subset of its `files[]` passed the SBOM stage. `verify`
  now also refuses (`sbom-mismatch`) when any attested file is not named by an SBOM
  package, restoring the file-manifest SBOM's completeness invariant. (The roll-up digest
  already pinned the file set, so this closes a correctness gap rather than a live
  tamper bypass.) Pinned by a new case in `test/verify.test.ts`.

## [0.3.0] - 2026-06-30

A correctness-and-coverage release. One fix makes the CLI report its real version,
and one feature completes lockfile-class SBOM coverage with `yarn.lock`. No trust-model
surface changes — existing attestations remain valid.

### Fixed

- **`attestload --version` now reports the real package version.** The CLI hardcoded
  `0.1.0` in `cli.ts`, so `--version` kept printing `0.1.0` even after the package
  shipped `0.2.0`. For a provenance tool whose value is truthful reporting, the bin
  must not lie about its own version. The version is now read from `package.json` at
  startup, and `test/cli.test.ts` asserts the CLI-reported version equals the package
  version so the two can never silently drift again.

### Added

- **`yarn.lock` SBOM derivation.** SBOM lockfile coverage previously handled
  `package-lock.json`, `pnpm-lock.yaml`, and `requirements.txt` but not `yarn.lock`,
  so a yarn-based MCP server silently fell back to a file-manifest SBOM and never named
  its upstream dependencies. `attestload attest` now parses `yarn.lock` — both the
  classic (Yarn v1) block format and the berry (Yarn v2+) YAML format — into a
  `source: "lockfile"` SBOM that names the declared packages. This stays inside the
  already-supported lockfile class: it is a single declared-lockfile parser, not a
  transitive build-graph resolver. Covered by `test/sbom.test.ts`.

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

[Unreleased]: https://github.com/SuperMarioYL/attestload/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/SuperMarioYL/attestload/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/SuperMarioYL/attestload/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SuperMarioYL/attestload/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/SuperMarioYL/attestload/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SuperMarioYL/attestload/releases/tag/v0.1.0
