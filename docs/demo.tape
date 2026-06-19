# vhs script for AttestLoad — renders the refuse-then-pass demo to assets/demo.gif.
# Run locally with `vhs docs/demo.tape`; CI renders it via .github/workflows/demo.yml.
# https://github.com/charmbracelet/vhs

Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 45ms

# Use the local build of the CLI so the demo runs without a global install.
Hide
Type "npm install --silent && npm run build --silent && alias attestload='node dist/cli.js'" Enter
Sleep 2s
Type "clear" Enter
Show

Type "# 1) Attest the example Skill — derive its SBOM, capture provenance, sign it." Sleep 600ms Enter
Type "attestload attest ./examples/signed-skill" Sleep 600ms Enter
Sleep 2.5s

Type "# 2) Verify the signed Skill — PASS, with a one-line provenance summary." Sleep 600ms Enter
Type "attestload verify ./examples/signed-skill" Sleep 600ms Enter
Sleep 2.5s

Type "# 3) Verify an UNSIGNED Skill — the gate refuses. exit code 1." Sleep 600ms Enter
Type "attestload verify ./examples/unsigned-skill; echo \"exit=$?\"" Sleep 600ms Enter
Sleep 3s

Type "# That refusal is the whole pitch: trust becomes a cryptographic fact." Sleep 800ms Enter
Sleep 2.5s
