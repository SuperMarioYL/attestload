#!/usr/bin/env node
/**
 * `attestload` CLI — commander-based entry point (the `dist/cli.js` bin).
 *
 * Subcommands:
 *   attest <dir>   — m1: sign a Skill / MCP dir into a verifiable attestation.
 *   verify <dir>   — m2: the gate. PASS (exit 0) or BLOCKED (exit 1) with a
 *                    structured verdict — the refusal demo.
 *   index <...>    — m3: manage the local verified-skill allowlist (cold-start).
 *   guard install  — drop a git pre-commit hook that verifies before commit.
 *
 * Every command accepts `--json` for machine-readable output. Exit codes are
 * load-bearing: `verify` exits non-zero on refusal so it can gate CI / hooks.
 */

import { promises as fs, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { Command } from "commander";

import { attest, type SigningMode } from "./attest.js";
import { verify, verdictOf } from "./verify.js";
import { loadPolicy, evaluatePolicy } from "./policy.js";
import {
  loadAllowlist,
  saveAllowlist,
  addEntry,
  removeEntry,
  seedAllowlist,
} from "./index-allowlist.js";
import { type ArtifactKind, type Policy } from "./types.js";

// ---------------------------------------------------------------------------
// Package version (read at startup from package.json — never hardcoded).
// ---------------------------------------------------------------------------
/**
 * Resolve the real package version from `package.json` so `attestload --version`
 * always matches the shipped release. The literal that used to live in
 * `.version("0.1.0")` drifted (the package shipped 0.2.0+ while the CLI still
 * reported 0.1.0), which is a correctness defect for a provenance tool whose
 * value is truthful reporting. We read it relative to this module's URL so it
 * works both from `dist/cli.js` (→ ../package.json) and from `tsx src/cli.ts`
 * (→ ../package.json). Any read/parse failure degrades to "0.0.0" rather than
 * crashing the CLI.
 */
export function packageVersion(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // dist/cli.js and src/cli.ts both sit one level under the package root.
    const pkgPath = path.join(here, "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    return typeof pkg.version === "string" && pkg.version ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

// ---------------------------------------------------------------------------
// Tiny ANSI helpers (no dep). Disabled when not a TTY or NO_COLOR is set.
// ---------------------------------------------------------------------------
const useColor = process.stdout.isTTY && !process.env["NO_COLOR"];
const c = (code: string, s: string): string =>
  useColor ? `[${code}m${s}[0m` : s;
const green = (s: string) => c("32;1", s);
const red = (s: string) => c("31;1", s);
const dim = (s: string) => c("2", s);

function out(json: boolean, payload: unknown, human: () => void): void {
  if (json) {
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  } else {
    human();
  }
}

// ---------------------------------------------------------------------------
// attest
// ---------------------------------------------------------------------------
async function runAttest(
  dir: string,
  opts: {
    json?: boolean;
    kind?: string;
    name?: string;
    version?: string;
    sigstore?: boolean;
    ed25519?: boolean;
    identityToken?: string;
  },
): Promise<number> {
  const json = Boolean(opts.json);
  let signingMode: SigningMode | undefined;
  if (opts.sigstore) signingMode = "sigstore";
  if (opts.ed25519) signingMode = "ed25519";

  const result = await attest(dir, {
    kind: (opts.kind as ArtifactKind | undefined) ?? "skill",
    ...(opts.name ? { name: opts.name } : {}),
    ...(opts.version ? { version: opts.version } : {}),
    ...(signingMode ? { signingMode } : {}),
    ...(opts.identityToken ? { identityToken: opts.identityToken } : {}),
  });

  out(
    json,
    {
      ok: true,
      path: result.path,
      signing_mode: result.signingMode,
      subject: result.manifest.subject,
      provenance: result.manifest.provenance,
    },
    () => {
      const s = result.manifest.subject;
      console.log(green("✓ attested"));
      console.log(`  subject : ${s.name}@${s.version} (${s.kind})`);
      console.log(`  digest  : ${dim(s.artifact_digest)}`);
      console.log(`  sbom    : ${s.sbom_source}, ${result.manifest.sbom.packages.length} package(s)`);
      console.log(`  signing : ${result.signingMode}`);
      console.log(`  written : ${result.path}`);
    },
  );
  return 0;
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------
async function runVerify(
  dir: string,
  opts: { json?: boolean; policy?: string; allowlist?: boolean; allowlistFile?: string },
): Promise<number> {
  const json = Boolean(opts.json);

  const result = await verify(dir);

  // Layer policy on top of the raw cryptographic verdict. The policy file is
  // NEVER discovered inside the verified artifact dir (`dir`): that would let a
  // downloaded skill ship its own relaxed `attestload.policy.json` and
  // self-authorize (unsigned manifest → no-signature → relaxed policy →
  // allowed:true → exit 0, PASS), inverting the trust boundary the whole
  // product is built on. Default search is the consumer's cwd; an explicit
  // `--policy <file outside the artifact>` still applies. A malformed or
  // missing explicit policy — or a malformed default policy in cwd — fails
  // loudly with a non-zero exit and a message naming the file, rather than
  // silently degrading to the strict default (which would refuse everything
  // with no signal that the policy file is the cause).
  let policy: Policy;
  try {
    policy = await loadPolicy(opts.policy ? { file: opts.policy } : {});
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const where = opts.policy ? "explicit --policy" : "default policy search in cwd";
    out(
      json,
      { allowed: false, message: `policy load failed (${where}): ${msg}` },
      () => {
        console.error(red(`BLOCKED: failed to load policy (${where}): ${msg}`));
      },
    );
    return 1;
  }
  const effectivePolicy = opts.allowlist
    ? { ...policy, use_allowlist: true }
    : policy;

  const allowlist =
    effectivePolicy.use_allowlist
      ? await loadAllowlist(opts.allowlistFile).catch(() => undefined)
      : undefined;

  const decision = evaluatePolicy(result, effectivePolicy, allowlist);
  const verdict = verdictOf(result);

  out(
    json,
    {
      allowed: decision.allowed,
      verdict,
      blocked_reason: result.blocked_reason ?? null,
      message: decision.reason,
      provenance_summary: result.provenance_summary ?? null,
      subject: result.manifest?.subject ?? null,
    },
    () => {
      if (decision.allowed) {
        console.log(green("PASS") + ` — ${decision.reason}`);
        if (result.provenance_summary) {
          console.log(dim(`  ${result.provenance_summary}`));
        }
      } else {
        console.error(red(`BLOCKED: ${decision.reason}`));
        console.error(dim(`  verdict: ${verdict}` + (result.blocked_reason ? ` (${result.blocked_reason})` : "")));
        console.error(dim("  unattested code refused to load"));
      }
    },
  );

  return decision.allowed ? 0 : 1;
}

// ---------------------------------------------------------------------------
// index (allowlist)
// ---------------------------------------------------------------------------
async function runIndexAdd(
  name: string,
  opts: { json?: boolean; digest?: string; repo?: string; file?: string },
): Promise<number> {
  const json = Boolean(opts.json);
  const allowlist = await loadAllowlist(opts.file);
  const next = addEntry(allowlist, {
    name,
    ...(opts.digest ? { artifact_digest: opts.digest } : {}),
    ...(opts.repo ? { source_repo: opts.repo } : {}),
  });
  const saved = await saveAllowlist(next, opts.file);
  out(json, { ok: true, added: name, file: saved, count: next.entries.length }, () => {
    console.log(green(`✓ indexed "${name}"`) + dim(` → ${saved} (${next.entries.length} entries)`));
  });
  return 0;
}

async function runIndexRemove(
  name: string,
  opts: { json?: boolean; file?: string },
): Promise<number> {
  const json = Boolean(opts.json);
  const allowlist = await loadAllowlist(opts.file);
  const { allowlist: next, removed } = removeEntry(allowlist, name);
  const saved = await saveAllowlist(next, opts.file);
  out(json, { ok: removed, removed: removed ? name : null, file: saved }, () => {
    if (removed) console.log(green(`✓ removed "${name}"`));
    else console.error(red(`"${name}" not in the allowlist`));
  });
  return removed ? 0 : 1;
}

async function runIndexSeed(opts: { json?: boolean; file?: string }): Promise<number> {
  const json = Boolean(opts.json);
  const allowlist = await loadAllowlist(opts.file);
  const { allowlist: next, added } = seedAllowlist(allowlist);
  const saved = await saveAllowlist(next, opts.file);
  out(json, { ok: true, added, total: next.entries.length, file: saved }, () => {
    console.log(green(`✓ seeded ${added} popular skill(s)`) + dim(` → ${saved} (${next.entries.length} total)`));
  });
  return 0;
}

async function runIndexList(opts: { json?: boolean; file?: string }): Promise<number> {
  const json = Boolean(opts.json);
  const allowlist = await loadAllowlist(opts.file);
  out(json, allowlist, () => {
    if (allowlist.entries.length === 0) {
      console.log(dim("(allowlist is empty — run `attestload index seed`)"));
      return;
    }
    for (const e of allowlist.entries) {
      const pin = e.artifact_digest ? dim(`  ${e.artifact_digest.slice(0, 16)}…`) : dim("  (name-only)");
      console.log(`${e.name}${pin}${e.source_repo ? dim(`  ${e.source_repo}`) : ""}`);
    }
  });
  return 0;
}

// ---------------------------------------------------------------------------
// guard install — git pre-commit hook
// ---------------------------------------------------------------------------
async function runGuardInstall(
  opts: { json?: boolean; dir?: string },
): Promise<number> {
  const json = Boolean(opts.json);
  const repo = path.resolve(opts.dir ?? process.cwd());
  const hookDir = path.join(repo, ".git", "hooks");
  const hookPath = path.join(hookDir, "pre-commit");

  try {
    await fs.access(path.join(repo, ".git"));
  } catch {
    out(json, { ok: false, error: "not a git repository" }, () => {
      console.error(red(`BLOCKED: ${repo} is not a git repository`));
    });
    return 1;
  }

  const script = `#!/bin/sh
# attestload pre-commit guard: refuse to commit unattested/tampered skill code.
# Verifies the repo root as a skill/MCP dir before allowing the commit.
if command -v attestload >/dev/null 2>&1; then
  attestload verify . || {
    echo "attestload: commit blocked — unattested or tampered code" >&2
    exit 1
  }
else
  npx --no-install attestload verify . || {
    echo "attestload: commit blocked (run 'npm i -g attestload')" >&2
    exit 1
  }
fi
`;

  await fs.mkdir(hookDir, { recursive: true });
  await fs.writeFile(hookPath, script, { mode: 0o755 });

  out(json, { ok: true, hook: hookPath }, () => {
    console.log(green("✓ installed pre-commit guard") + dim(` → ${hookPath}`));
  });
  return 0;
}

// ---------------------------------------------------------------------------
// wire up commander
// ---------------------------------------------------------------------------
export function buildProgram(): Command {
  const program = new Command();
  program
    .name("attestload")
    .description(
      "Attest-before-load gate for coding agents: sign Skills / MCP servers into verifiable SBOM + provenance, and refuse to load unattested code.",
    )
    .version(packageVersion());

  program
    .command("attest")
    .description("sign a Skill / MCP-server directory into a verifiable attestation")
    .argument("<dir>", "the skill / MCP-server directory to attest")
    .option("--json", "emit machine-readable JSON")
    .option("--kind <kind>", "artifact kind: skill | mcp-server", "skill")
    .option("--name <name>", "subject name (defaults to the directory basename)")
    .option("--version <version>", "subject version (defaults to git describe)")
    .option("--sigstore", "force keyless Sigstore signing (fails if unavailable)")
    .option("--ed25519", "force the local ed25519 fallback signer")
    .option("--identity-token <jwt>", "OIDC identity token for keyless Sigstore")
    .action(async (dir: string, opts) => {
      process.exitCode = await runAttest(dir, opts);
    });

  program
    .command("verify")
    .description("verify a directory's attestation; exit non-zero (BLOCKED) on refusal")
    .argument("<dir>", "the directory to verify before load")
    .option("--json", "emit machine-readable JSON")
    .option("--policy <file>", "policy file (JSON/YAML); defaults to strict")
    .option("--allowlist", "honor the local verified-skill allowlist (cold-start)")
    .option("--allowlist-file <file>", "path to the allowlist index")
    .action(async (dir: string, opts) => {
      process.exitCode = await runVerify(dir, opts);
    });

  const index = program
    .command("index")
    .description("manage the local verified-skill allowlist (cold-start)");

  index
    .command("add")
    .description("add (or update) a skill in the allowlist")
    .argument("<name>", "skill / MCP-server name")
    .option("--json", "emit machine-readable JSON")
    .option("--digest <sha256>", "pin an expected artifact digest")
    .option("--repo <url>", "source repository, for traceability")
    .option("--file <path>", "allowlist file (defaults to ~/.attestload/allowlist.json)")
    .action(async (name: string, opts) => {
      process.exitCode = await runIndexAdd(name, opts);
    });

  index
    .command("remove")
    .alias("rm")
    .description("remove a skill from the allowlist")
    .argument("<name>", "skill / MCP-server name")
    .option("--json", "emit machine-readable JSON")
    .option("--file <path>", "allowlist file")
    .action(async (name: string, opts) => {
      process.exitCode = await runIndexRemove(name, opts);
    });

  index
    .command("seed")
    .description("seed the allowlist with popular skills / MCP servers")
    .option("--json", "emit machine-readable JSON")
    .option("--file <path>", "allowlist file")
    .action(async (opts) => {
      process.exitCode = await runIndexSeed(opts);
    });

  index
    .command("list")
    .alias("ls")
    .description("list allowlist entries")
    .option("--json", "emit machine-readable JSON")
    .option("--file <path>", "allowlist file")
    .action(async (opts) => {
      process.exitCode = await runIndexList(opts);
    });

  const guard = program
    .command("guard")
    .description("install the attest-before-load guard");

  guard
    .command("install")
    .description("drop a git pre-commit hook that verifies before each commit")
    .option("--json", "emit machine-readable JSON")
    .option("--dir <path>", "git repository root (defaults to cwd)")
    .action(async (opts) => {
      process.exitCode = await runGuardInstall(opts);
    });

  return program;
}

/** Parse argv and run. Kept separate so tests can import buildProgram(). */
export async function main(argv: readonly string[] = process.argv): Promise<void> {
  const program = buildProgram();
  await program.parseAsync(argv as string[]);
}

// Run when invoked as the bin (not when imported by a test).
// `import.meta.url` ends with the actually-executed file path.
const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === `file://${path.resolve(process.argv[1])}`;

if (invokedDirectly) {
  main().catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(red(`error: ${msg}`));
    process.exitCode = 2;
  });
}
