/**
 * loader-guard — the attest-before-load gate an agent calls before loading a
 * Skill / MCP-server directory.
 *
 * This is the integration surface: the single function a coding agent (or a
 * pre-commit hook, or a CI step) wraps around `loadSkill(dir)` so that
 * unattested or tampered code never reaches the runtime. It composes the two
 * lower layers — verify.ts (cryptographic facts) and policy.ts (load decision)
 * — and either returns silently (allowed) or refuses (throws {@link LoadRefused}
 * or returns a structured refusal, your choice of API).
 *
 * ## Integration snippet (copy-paste)
 *
 * ```ts
 * import { guardLoad, LoadRefused } from "attestload";
 *
 * async function loadSkill(dir: string) {
 *   try {
 *     // Throws LoadRefused unless the dir carries a valid, policy-approved
 *     // attestation. `policyFile`/`allowlistFile` are optional.
 *     const decision = await guardLoad(dir);
 *     console.log(`[attestload] ${decision.reason}`);
 *   } catch (err) {
 *     if (err instanceof LoadRefused) {
 *       console.error(`[attestload] BLOCKED: ${err.message}`);
 *       return; // do NOT import/execute anything from `dir`
 *     }
 *     throw err;
 *   }
 *   // ...safe to import/execute the skill's entrypoint here...
 * }
 * ```
 *
 * For a non-throwing call site (e.g. building your own UI), use
 * {@link checkLoad}, which returns the {@link PolicyDecision} without throwing.
 *
 * ## As a git pre-commit hook
 *
 * `attestload guard install` (see cli.ts) drops a hook that runs
 * `attestload verify` over the staged skill dir and aborts the commit on
 * refusal — the same gate, earlier in the lifecycle. v0.1 ships this wrapper +
 * hook, not a fork of any agent's loader.
 */

import { verify } from "./verify.js";
import { evaluatePolicy, loadPolicy, type PolicyDecision } from "./policy.js";
import { loadAllowlist } from "./index-allowlist.js";
import { type Allowlist, type Policy } from "./types.js";

/** Thrown by {@link guardLoad} when an artifact is refused. */
export class LoadRefused extends Error {
  /** Machine-readable refusal reason from verify, if any. */
  readonly blockedReason: string | undefined;
  /** The full decision, for callers that want structured detail. */
  readonly decision: PolicyDecision;

  constructor(decision: PolicyDecision) {
    super(decision.reason);
    this.name = "LoadRefused";
    this.blockedReason = decision.verify.blocked_reason;
    this.decision = decision;
  }
}

/** Options for the guard. All optional; sensible strict defaults apply. */
export interface GuardOptions {
  /** Inline policy. Takes precedence over `policyFile`. */
  readonly policy?: Policy;
  /** Path to a policy file (JSON/YAML). Ignored if `policy` is set. */
  readonly policyFile?: string;
  /** Inline allowlist. Takes precedence over `allowlistFile`. */
  readonly allowlist?: Allowlist;
  /** Path to the allowlist index. Defaults to the standard location. */
  readonly allowlistFile?: string;
}

/** Resolve the effective policy + allowlist from options. */
async function resolveContext(
  options: GuardOptions,
): Promise<{ policy: Policy; allowlist: Allowlist | undefined }> {
  // The policy file is NEVER discovered inside the verified artifact dir: a
  // downloaded skill must not ship its own relaxed `attestload.policy.json` and
  // self-authorize (unsigned manifest → relaxed policy → allowed), inverting
  // the trust boundary. Default search is the consumer's cwd; an explicit
  // `policyFile` outside the artifact still applies. A malformed or missing
  // explicit policy — or a malformed default policy in cwd — propagates as an
  // error rather than silently degrading to the strict default (which would
  // refuse everything with no signal that the policy file is the cause).
  const policy =
    options.policy ??
    (await loadPolicy(options.policyFile ? { file: options.policyFile } : {}));

  let allowlist: Allowlist | undefined = options.allowlist;
  if (!allowlist && policy.use_allowlist) {
    allowlist = await loadAllowlist(options.allowlistFile).catch(() => undefined);
  }
  return { policy, allowlist };
}

/**
 * Non-throwing gate. Runs verify + policy and returns the decision. Use this
 * when you want to render a refusal yourself rather than catch an exception.
 */
export async function checkLoad(
  dir: string,
  options: GuardOptions = {},
): Promise<PolicyDecision> {
  const result = await verify(dir);
  const { policy, allowlist } = await resolveContext(options);
  return evaluatePolicy(result, policy, allowlist);
}

/**
 * Throwing gate. Returns the {@link PolicyDecision} on allow, throws
 * {@link LoadRefused} on refusal. This is the call an agent's loader should
 * `await` before importing anything from `dir`.
 */
export async function guardLoad(
  dir: string,
  options: GuardOptions = {},
): Promise<PolicyDecision> {
  const decision = await checkLoad(dir, options);
  if (!decision.allowed) {
    throw new LoadRefused(decision);
  }
  return decision;
}
