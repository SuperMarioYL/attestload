/**
 * `attestload index` — the m3 verified-skill allowlist (cold-start solver).
 *
 * The supply-side chicken-and-egg problem: a consumer wants to gate on signed
 * attestations, but on day one almost no skill author has signed anything. The
 * allowlist bridges that gap — a local, JSON-backed index mapping a skill
 * name / repo → its expected attestation digest (and, optionally, signing
 * identity). A consumer can seed it with the top popular skills they already
 * trust, and `verify --allowlist` then passes those known-good entries even
 * before their authors ship a per-dir signature.
 *
 * Storage is a single JSON file (default `~/.attestload/allowlist.json`),
 * validated with the zod {@link AllowlistSchema}. The index is content-pinned:
 * an entry carries the expected `artifact_digest`, so an allowlisted name still
 * fails if the bytes on disk drift from what was indexed.
 *
 * This module is pure data management — `add`, `remove`, `list`, `seed`. The
 * decision to honor an allowlist entry lives in policy.ts (`use_allowlist`).
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  AllowlistSchema,
  AllowlistEntrySchema,
  type Allowlist,
  type AllowlistEntry,
} from "./types.js";

/** Default on-disk location of the allowlist index. */
export function defaultAllowlistPath(): string {
  return path.join(os.homedir(), ".attestload", "allowlist.json");
}

/** Load the allowlist from `file`, returning an empty one if absent. */
export async function loadAllowlist(file?: string): Promise<Allowlist> {
  const target = file ?? defaultAllowlistPath();
  try {
    const raw = await fs.readFile(target, "utf8");
    return AllowlistSchema.parse(JSON.parse(raw));
  } catch (err) {
    // A missing file is normal (empty index). A present-but-broken file is not.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return AllowlistSchema.parse({});
    }
    if (err instanceof SyntaxError) {
      throw new Error(`allowlist at ${target} is not valid JSON: ${err.message}`);
    }
    throw err;
  }
}

/** Persist the allowlist to `file` (creating parent dirs as needed). */
export async function saveAllowlist(
  allowlist: Allowlist,
  file?: string,
): Promise<string> {
  const target = file ?? defaultAllowlistPath();
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, `${JSON.stringify(allowlist, null, 2)}\n`);
  return target;
}

/** Fields needed to add/update an allowlist entry. */
export interface AddEntryInput {
  readonly name: string;
  readonly artifact_digest?: string;
  readonly source_repo?: string;
}

/**
 * Add (or replace, keyed by `name`) an entry. Pure: returns a new allowlist,
 * does not write. The entry is stamped with `added_at`.
 */
export function addEntry(allowlist: Allowlist, input: AddEntryInput): Allowlist {
  const entry: AllowlistEntry = AllowlistEntrySchema.parse({
    name: input.name,
    ...(input.artifact_digest ? { artifact_digest: input.artifact_digest } : {}),
    source_repo: input.source_repo ?? "",
    added_at: new Date().toISOString(),
  });
  const entries = allowlist.entries.filter((e) => e.name !== input.name);
  entries.push(entry);
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { ...allowlist, entries };
}

/** Remove an entry by name. Pure. Returns `{ allowlist, removed }`. */
export function removeEntry(
  allowlist: Allowlist,
  name: string,
): { allowlist: Allowlist; removed: boolean } {
  const entries = allowlist.entries.filter((e) => e.name !== name);
  return {
    allowlist: { ...allowlist, entries },
    removed: entries.length !== allowlist.entries.length,
  };
}

/** Look up an entry by name. */
export function findEntry(
  allowlist: Allowlist,
  name: string,
): AllowlistEntry | undefined {
  return allowlist.entries.find((e) => e.name === name);
}

/**
 * A small seed set of popular AI agent skills / MCP servers, so the index is
 * non-empty out of the box and the cold-start path is demonstrable. Digests are
 * intentionally absent (name-only trust) until the consumer pins one via
 * `index add <name> --digest <sha256>` or by attesting the dir themselves.
 */
export const SEED_ALLOWLIST: readonly AddEntryInput[] = [
  { name: "everything-claude-code", source_repo: "github.com/affaan-m/everything-claude-code" },
  { name: "chrome-devtools-mcp", source_repo: "github.com/ChromeDevTools/chrome-devtools-mcp" },
  { name: "awesome-mcp-servers", source_repo: "github.com/punkpeye/awesome-mcp-servers" },
  { name: "filesystem-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
  { name: "git-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
  { name: "github-mcp", source_repo: "github.com/github/github-mcp-server" },
  { name: "fetch-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
  { name: "sqlite-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
  { name: "puppeteer-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
  { name: "slack-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
  { name: "memory-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
  { name: "time-mcp", source_repo: "github.com/modelcontextprotocol/servers" },
];

/**
 * Seed the allowlist with {@link SEED_ALLOWLIST} (only names not already
 * present). Pure: returns the seeded allowlist + how many were newly added.
 */
export function seedAllowlist(
  allowlist: Allowlist,
): { allowlist: Allowlist; added: number } {
  let next = allowlist;
  let added = 0;
  for (const input of SEED_ALLOWLIST) {
    if (!findEntry(next, input.name)) {
      next = addEntry(next, input);
      added += 1;
    }
  }
  return { allowlist: next, added };
}
