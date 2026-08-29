/**
 * The program that actually runs inside the OS sandbox.
 *
 * ## The nesting, and why
 *
 * Design §19.7 requires two layers, and phase 4b measured why neither is
 * sufficient alone. A script handed straight to `node` inside the phase-4a
 * sandbox could `require('fs')` to read its granted file without the API
 * observing it, and could print a forged coverage line on the same stdout the
 * runtime writes to. The OS sandbox was working correctly the whole time — the
 * read was inside `readPaths`. What failed was the assumption that the
 * injected API is the only route to the data.
 *
 * So the arrangement is nested:
 *
 * - **This file** is host-authored and is the only thing Node executes.
 * - **The model's code is data.** It arrives as a string, is parsed by acorn
 *   and walked by the confined evaluator. Node never executes it.
 * - **The OS sandbox contains this process**, so even a defect in the
 *   interpreter is still bounded by `readPaths`, zero egress and the rlimits.
 *
 * Coverage is authored by the ledger inside `runQueryScript`, which the
 * model's code cannot name, and leaves the process in a base64 frame the
 * model's code cannot produce (see `tools/protocol.ts`).
 *
 * ## Bundling
 *
 * This is bundled by `npm run bundle-query-runner` into
 * `dist/query/runner.js`, with acorn and the interpreter inlined, so the
 * sandboxed process needs no `node_modules` resolution and the sandbox's read
 * surface stays as narrow as one file.
 */

import { readFileSync } from "node:fs";
import {
  boundRunDocument,
  encodeResultFrame,
  runQueryScript,
  type QueryToolContext,
  type QueryToolDeps,
  type RunDocument,
  type ScopeInfo,
  type ScriptBlock,
  type ScriptHit,
} from "@opendatalabs/personal-server-ts-core/query/tools";

/** Everything the host injects, as a JSON literal prepended to the bundle. */
export interface RunnerInput {
  modelCode: string;
  scopes: {
    scope: string;
    path: string;
    itemCount?: number;
    collectedAt?: string;
    version?: string;
    contentKind?: string;
    profile?: string;
  }[];
  budget: { toolCalls: number; outputBytes: number; classifyUsd?: number };
  callerId?: string;
  enforcementNotes: string[];
  maxSteps?: number;
  /**
   * Ceiling on the encoded result frame. The host sets this below the
   * sandbox's `maxOutputBytes` so the frame always survives: a frame cut by
   * the output cap is untrustworthy and costs the run all of its coverage.
   */
  frameBudgetBytes?: number;
  /**
   * Host-authority results precomputed before the run, because `search`,
   * `classify` and `introspect` need authority that must never be inside the
   * sandbox. Absent capabilities throw `CAPABILITY_UNAVAILABLE`, which is an
   * honest denial rather than a silent empty result.
   */
  searchResults?: Record<string, ScriptHit[]>;
}

declare const __VANA_INPUT__: RunnerInput;

/** Parse one scope file into records. Counting is the ledger's job, not ours. */
interface LoadedScope {
  items: unknown[];
  /** Source bytes on disk, so `bytesScanned` reflects what was actually read. */
  bytes: number;
}

function loadScope(path: string): LoadedScope {
  const text = readFileSync(path, "utf8");
  const parsed: unknown = JSON.parse(text);
  return {
    items: Array.isArray(parsed) ? parsed : [parsed],
    bytes: Buffer.byteLength(text, "utf8"),
  };
}

function buildDeps(input: RunnerInput): QueryToolDeps {
  const byScope = new Map(input.scopes.map((s) => [s.scope, s]));
  // Cache per scope: a script that reads the same scope twice should not pay
  // twice, and more importantly should not be counted twice.
  const cache = new Map<string, LoadedScope>();

  const load = (scope: string): LoadedScope => {
    const hit = cache.get(scope);
    if (hit) return hit;
    const entry = byScope.get(scope);
    if (!entry) throw new Error(`scope not granted: ${scope}`);
    const loaded = loadScope(entry.path);
    cache.set(scope, loaded);
    return loaded;
  };

  const records = (scope: string): unknown[] => load(scope).items;

  return {
    async listScopes(): Promise<ScopeInfo[]> {
      return input.scopes.map((s) => {
        const info: ScopeInfo = { scope: s.scope };
        if (s.itemCount !== undefined) info.itemCount = s.itemCount;
        if (s.collectedAt !== undefined) info.collectedAt = s.collectedAt;
        if (s.version !== undefined) info.version = s.version;
        if (s.contentKind !== undefined) info.contentKind = s.contentKind;
        if (s.profile !== undefined) info.profile = s.profile;
        return info;
      });
    },

    async streamScope(scope, onItem) {
      const { items, bytes } = load(scope);
      for (const item of items) await onItem(item);
      // Records are counted by the runtime as they pass through; bytes are the
      // one quantity only the source knows, so report them here.
      return bytes;
    },

    async readBlocks(scope, opts): Promise<ScriptBlock[]> {
      const all = records(scope);
      const limit = opts.maxBytes ?? Number.MAX_SAFE_INTEGER;
      const out: ScriptBlock[] = [];
      let bytes = 0;
      for (let i = 0; i < all.length; i += 1) {
        const json = all[i];
        const size = JSON.stringify(json).length;
        if (bytes + size > limit && out.length > 0) break;
        bytes += size;
        // One block is one record here. Without `itemCount` the runtime's
        // `recordsRead` sums to zero, which is how a live run reported
        // `recordsScanned: 0` after reading 8.5MB.
        out.push({
          id: `${scope}#${i}`,
          scope,
          sizeBytes: size,
          itemCount: 1,
          json,
        });
      }
      return out;
    },

    /**
     * Lexical search is a host-authority operation — it reads an index that
     * spans scopes and must never be inside the sandbox. The host resolves
     * the queries it can predict before the run; anything else is an honest
     * denial rather than an empty array, because an empty array reads as
     * "there is nothing there" and that is the Q8 false negative.
     */
    async search(query): Promise<ScriptHit[]> {
      const pre = __VANA_INPUT__.searchResults?.[query];
      if (pre) return pre;
      throw new Error(
        `search("${query}") was not resolved by the host for this run; ` +
          `re-issue the question so the host can prepare it, or scan the scope directly`,
      );
    },
  };
}

async function main(): Promise<void> {
  const input = __VANA_INPUT__;
  const ctx: QueryToolContext = {
    grantedScopes: input.scopes.map((s) => s.scope),
    resolveScopePath(scope: string): string {
      const entry = input.scopes.find((s) => s.scope === scope);
      if (!entry) throw new Error(`scope not granted: ${scope}`);
      return entry.path;
    },
    budget: input.budget,
    ...(input.callerId === undefined ? {} : { callerId: input.callerId }),
  };

  const outcome = await runQueryScript(input.modelCode, ctx, buildDeps(input), {
    enforcementNotes: input.enforcementNotes,
    ...(input.maxSteps === undefined ? {} : { maxSteps: input.maxSteps }),
  });

  const doc: RunDocument = {
    v: 1,
    coverage: outcome.coverage,
    notes: outcome.notes,
    toolCalls: outcome.toolCalls,
    classifyUsd: outcome.classifyUsd,
    ...(outcome.result ? { result: outcome.result } : {}),
    ...(outcome.error ? { error: outcome.error } : {}),
  };
  process.stdout.write(
    encodeResultFrame(boundRunDocument(doc, input.frameBudgetBytes)),
  );
}

void main().catch((err: unknown) => {
  // Even a runner crash must produce a frame, or the host cannot distinguish
  // "the run failed" from "output was truncated" — and those differ in whether
  // any coverage at all can be trusted.
  const doc: RunDocument = {
    v: 1,
    coverage: {
      scopesScanned: [],
      recordsScanned: 0,
      bytesScanned: 0,
      unreadable: 0,
      perScope: {},
      scopesSkipped: [],
      complete: false,
      method: "full",
      stoppedBecause: "error",
      enforcementNotes: [],
    },
    notes: [],
    toolCalls: 0,
    classifyUsd: 0,
    error: {
      code: "RUNNER_ERROR",
      message: err instanceof Error ? err.message : String(err),
    },
  };
  process.stdout.write(encodeResultFrame(doc));
  process.exitCode = 1;
});
