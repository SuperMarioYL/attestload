---
name: unsigned-skill
description: A tiny example Skill that ships with NO attestation — AttestLoad's refusal demo. Running `attestload verify` against this directory exits non-zero with a red BLOCKED.
version: 0.0.0
---

# Unsigned Skill (AttestLoad refusal demo)

This directory deliberately carries **no** `.attestload/attestation.json`. It
stands in for the everyday case: a Skill or MCP server pulled from a random
GitHub repo, trusted on star count alone, with no verifiable bill-of-materials.

## Demo

```bash
# No attestation present → the gate refuses to load it.
attestload verify ./examples/unsigned-skill
# BLOCKED: no attestation found — refusing to load unattested code   (exit 1)
```

This is the "trust stops being star count and becomes a cryptographic fact"
moment: unattested code does not load.
