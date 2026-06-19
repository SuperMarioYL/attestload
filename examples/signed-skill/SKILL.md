---
name: signed-skill
description: A tiny example Skill used by AttestLoad's demo as the PASS case — attest it, then verify it to see a green PASS plus a one-line provenance summary.
version: 1.0.0
---

# Signed Skill (AttestLoad demo)

This is a minimal, harmless example Skill. It exists so the AttestLoad demo has a
real directory to attest and then verify.

## Demo

```bash
# 1) sign this directory into a verifiable attestation (local ed25519 by default)
attestload attest ./examples/signed-skill

# 2) verify it — PASS, with a provenance line
attestload verify ./examples/signed-skill
```

Tamper with any file in this directory after attesting, re-run `verify`, and the
gate flips to **BLOCKED** (digest mismatch) — that refusal is the whole pitch.
