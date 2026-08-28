import { CoverageLedger } from "./coverage.js";
import { QueryToolError, ScriptCompleted } from "./errors.js";
import type {
  ClassifyOptions,
  QueryToolContext,
  QueryToolDeps,
  ReadOptions,
  ScopeInfo,
  ScriptBlock,
  ScriptHit,
  ScriptResult,
  SearchOptions,
} from "./types.js";

/**
 * The `vana` object as the script sees it (prompt contract §3).
 *
 * Registered per request from the consumer's grant, so a scope outside the
 * grant is not merely denied — it is never named by `vana.scopes()` and
 * `resolveScopePath` throws on it. Combined with the OS layer's `readPaths`,
 * out-of-grant data is unreachable by two independent mechanisms.
 */
export interface VanaApi {
  scopes(): Promise<ScopeInfo[]>;
  readAll(scope: string): Promise<unknown[]>;
  read(scope: string, opts?: ReadOptions): Promise<ScriptBlock[]>;
  stream(
    scope: string,
    onItem: (item: unknown, index: number) => void | Promise<void>,
  ): Promise<number>;
  search(query: string, opts?: SearchOptions): Promise<ScriptHit[]>;
  classify(
    items: unknown[],
    instruction: string,
    opts?: ClassifyOptions,
  ): Promise<unknown[]>;
  introspect(): Promise<{
    grants: unknown[];
    accessLog: unknown[];
    lineage: unknown[];
  }>;
  note(message: string): void;
  result(payload: ScriptResult): void;
}

export interface QueryRuntimeState {
  readonly coverage: CoverageLedger;
  readonly notes: string[];
  readonly result: ScriptResult | undefined;
  readonly toolCalls: number;
  readonly classifyUsd: number;
}

export interface CreatedApi {
  api: VanaApi;
  state: () => QueryRuntimeState;
}

/**
 * Build the confined API for one request.
 *
 * The returned `state()` is the *host's* view: the ledger it closes over is
 * never bound into the script's realm, so the script cannot read, write or
 * forge any of it (prompt §1).
 */
export function createVanaApi(
  ctx: QueryToolContext,
  deps: QueryToolDeps,
): CreatedApi {
  const coverage = new CoverageLedger(ctx.grantedScopes);
  const notes: string[] = [];
  let result: ScriptResult | undefined;
  let toolCalls = 0;
  let classifyUsd = 0;

  const granted = new Set(ctx.grantedScopes);

  const spend = () => {
    if (++toolCalls > ctx.budget.toolCalls) {
      coverage.stop("budget");
      throw new QueryToolError(
        "BUDGET_EXHAUSTED",
        `tool-call budget of ${ctx.budget.toolCalls} exhausted`,
      );
    }
  };

  /**
   * Grant binding. Throws rather than returning empty: a script that names an
   * ungranted scope has misunderstood its world, and silently returning `[]`
   * would let it conclude "there is nothing there" — the exact false-negative
   * the absence class (Q8) must never produce.
   */
  const requireGranted = (scope: string): string => {
    if (!granted.has(scope)) {
      throw new QueryToolError(
        "SCOPE_NOT_GRANTED",
        `scope "${scope}" is not in this grant`,
      );
    }
    return ctx.resolveScopePath(scope);
  };

  const api: VanaApi = {
    async scopes() {
      spend();
      const all = await deps.listScopes();
      // Defence in depth: even if a deps implementation over-returns, the
      // script only ever sees granted scopes.
      return all.filter((s) => granted.has(s.scope));
    },

    async readAll(scope) {
      spend();
      requireGranted(scope);
      const out: unknown[] = [];
      await deps.streamScope(scope, (item) => {
        out.push(item);
      });
      coverage.recordsRead(out.length);
      coverage.completeScope(scope);
      return out;
    },

    async read(scope, opts = {}) {
      spend();
      requireGranted(scope);
      const blocks = await deps.readBlocks(scope, opts);
      coverage.bytesRead(
        blocks.reduce((n, b) => n + (b.sizeBytes ?? b.text?.length ?? 0), 0),
      );
      coverage.recordsRead(blocks.reduce((n, b) => n + (b.itemCount ?? 0), 0));
      // A bounded read is by definition not a full pass.
      coverage.partialScope(scope);
      return blocks;
    },

    async stream(scope, onItem) {
      spend();
      requireGranted(scope);
      let n = 0;
      await deps.streamScope(scope, async (item) => {
        await onItem(item, n);
        n++;
      });
      coverage.recordsRead(n);
      coverage.completeScope(scope);
      return n;
    },

    async search(query, opts = {}) {
      spend();
      for (const s of opts.scopes ?? []) requireGranted(s);
      const hits = await deps.search(query, {
        ...opts,
        scopes: opts.scopes ?? ctx.grantedScopes,
      });
      // Search is a ranked prefilter, never a full pass. Recording it as such
      // is what forces Q9/Q15 to say "earliest found", not "earliest".
      coverage.prefiltered();
      return hits;
    },

    async classify(items, instruction, opts = {}) {
      spend();
      if (!deps.classify) {
        throw new QueryToolError(
          "CAPABILITY_UNAVAILABLE",
          "classify is not registered for this request",
        );
      }
      const ceiling = ctx.budget.classifyUsd;
      if (ceiling !== undefined && classifyUsd >= ceiling) {
        coverage.stop("budget");
        throw new QueryToolError(
          "BUDGET_EXHAUSTED",
          `classify cost ceiling of $${ceiling} reached`,
        );
      }
      const res = await deps.classify(items, instruction, opts);
      classifyUsd += res.usd;
      if (ceiling !== undefined && classifyUsd > ceiling) {
        coverage.stop("budget");
      }
      return res.values;
    },

    async introspect() {
      spend();
      if (!deps.introspect) {
        throw new QueryToolError(
          "CAPABILITY_UNAVAILABLE",
          "introspect is not registered for this request",
        );
      }
      return deps.introspect(ctx.callerId);
    },

    note(message) {
      notes.push(String(message));
    },

    result(payload) {
      if (result !== undefined) {
        throw new QueryToolError(
          "RESULT_ALREADY_SET",
          "vana.result was already called",
        );
      }
      result = payload;
      // Unwinds the interpreter: `result` terminates the script (prompt §3).
      throw new ScriptCompleted();
    },
  };

  return {
    api,
    state: () => ({
      coverage,
      notes: [...notes],
      result,
      toolCalls,
      classifyUsd,
    }),
  };
}
