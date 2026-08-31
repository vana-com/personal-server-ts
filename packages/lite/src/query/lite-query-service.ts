/**
 * The query layer's single execution path on PS-Lite.
 *
 * The browser counterpart of `packages/server/src/query/query-service.ts`, and
 * deliberately the same shape: resolve the grant, materialize it, run the
 * agent loop against a tool host over a sandbox, then fold the scopes this
 * request could not reach back into coverage.
 *
 * ## Materialization without a filesystem
 *
 * The Node route's containment rests on a per-request scratch *directory*:
 * only granted scopes are written into it, so a scope outside the grant has no
 * file to read and the containment survives a bad `readPaths` computation as
 * well as a hostile script. A browser has no such directory — PS-Lite's
 * storage is OPFS, or IndexedDB where OPFS is unavailable, and neither is
 * reachable from inside a QuickJS VM in any case.
 *
 * So the scratch directory becomes a **per-request in-memory map** from a
 * virtual path to that scope's records as JSON text
 * ({@link materializeGrantInMemory}). The property that made the directory
 * work is preserved exactly: the map is built one scope at a time through the
 * caller's own read path, it holds nothing the grant did not name, and the
 * sandbox refuses to start if the map and `readPaths` disagree in *either*
 * direction. Data that was never materialized is not "denied" — it does not
 * exist in the address space the VM can reach.
 *
 * The one property the Node route gets for free and this one must state: the
 * grant is resident in the page's heap for the duration of the request. On
 * Node it is resident on disk in a directory the OS sandbox confines; here
 * there is no OS layer to confine anything, which is the same single-layer
 * fact `quickjs-sandbox.ts` reports in its enforcement notes.
 *
 * ## What is deliberately not here
 *
 * No result cache (plan §6 leaves it gated on an eval-verified result), no
 * `vana.search` wiring (design §19.16 measured that it collapses how much of
 * the grant gets read), and no concurrency gate — a page runs one question at
 * a time by construction, where a server can be asked ten at once.
 */

import {
  EMPTY_COVERAGE,
  parseTurn,
  runQueryLoop,
  type QueryAnswer,
  type QueryBudget,
  type QueryCoverage,
  type QueryToolHost,
} from "@opendatalabs/personal-server-ts-core/query/agent";
import type {
  QueryToolContext,
  QueryToolDeps,
  ScopeInfo,
  ScriptBlock,
  ScriptHit,
} from "@opendatalabs/personal-server-ts-core/query/tools";
import type {
  InferenceChatInput,
  InferenceProvider,
} from "@opendatalabs/personal-server-ts-core/derivatives";

import { createQuickJsSandbox } from "./quickjs-sandbox.js";
import { createLiteToolHost, type LiteGrantedScope } from "./lite-tool-host.js";

/* ------------------------------------------------------------------ *
 * The grant seam
 * ------------------------------------------------------------------ */

/** One scope's contents, as the caller's ordinary read path returned them. */
export interface LiteScopePayload {
  /** The parsed data file: a `DataFileEnvelope` or a bare record array. */
  data: unknown;
  collectedAt?: string;
  version?: string;
}

/**
 * How one caller reaches its own data.
 *
 * Identical in intent to the Node `QueryScopeReader`: the implementation reads
 * through whatever path already performs the grant check and writes the
 * access-log row, so the metered set and the readable set are the same set by
 * construction.
 */
export interface LiteScopeReader {
  grantedScopes(): Promise<readonly string[]> | readonly string[];
  readScope(scope: string): Promise<LiteScopePayload>;
}

/* ------------------------------------------------------------------ *
 * Envelope unwrapping
 * ------------------------------------------------------------------ */

const RECORD_ARRAY_KEYS = [
  "items",
  "records",
  "rows",
  "entries",
  "data",
  "results",
  "messages",
  "events",
];

export interface LiteUnwrapResult {
  items: unknown[];
  key: string | null;
  note?: string;
}

/**
 * Turn one scope's data into the record array the sandbox expects.
 *
 * Behaviourally identical to the Node route's `unwrapEnvelopeData`, and
 * identical for the same reason: handed a `DataFileEnvelope` directly, a
 * runner counts the envelope as ONE record and every figure in `coverage`
 * reads `1` — a coverage lie. Because a real envelope's `data` shape is
 * source-specific the choice is a heuristic, and a heuristic that silently
 * picks the wrong key changes every denominator in the answer, so the key and
 * the reason are reported rather than applied invisibly.
 *
 * `lite-query-service.unwrap.test.ts` pins it against the Node implementation's
 * own cases so the two cannot drift into counting differently — which would
 * make a Lite-vs-Node comparison meaningless.
 */
export function unwrapEnvelopeData(data: unknown): LiteUnwrapResult {
  if (Array.isArray(data)) return { items: data, key: null };
  if (data === null || typeof data !== "object") {
    return { items: [data], key: null, note: "scope data is not an object" };
  }
  const record = data as Record<string, unknown>;
  if (
    "data" in record &&
    typeof record["version"] !== "undefined" &&
    typeof record["scope"] === "string"
  ) {
    const inner = unwrapEnvelopeData(record["data"]);
    return {
      items: inner.items,
      key: inner.key === null ? "data" : `data.${inner.key}`,
      ...(inner.note ? { note: inner.note } : {}),
    };
  }

  const arrayKeys = Object.keys(record).filter((k) => Array.isArray(record[k]));
  if (arrayKeys.length === 1) {
    const key = arrayKeys[0] as string;
    return { items: record[key] as unknown[], key };
  }
  for (const key of RECORD_ARRAY_KEYS) {
    if (arrayKeys.includes(key)) {
      return {
        items: record[key] as unknown[],
        key,
        note: `${arrayKeys.length} array-valued keys (${arrayKeys.join(", ")}); took "${key}"`,
      };
    }
  }
  return {
    items: [record],
    key: null,
    note:
      arrayKeys.length === 0
        ? "no array-valued key; the scope is treated as a single record"
        : `array-valued keys ${arrayKeys.join(", ")} matched no known record key; the scope is treated as a single record`,
  };
}

/* ------------------------------------------------------------------ *
 * Materialization
 * ------------------------------------------------------------------ */

/**
 * Scope ids safe to use as a virtual path segment.
 *
 * Deliberately a whitelist, for the same reason the Node route uses one: this
 * string becomes a `readPaths` entry, so anything that could carry a separator
 * or a `..` must never reach it. There is no filesystem here to traverse, but
 * a scope id that could collide with another scope's virtual path would let
 * one grant entry shadow another, which is the same class of bug.
 */
const SAFE_SCOPE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Root the virtual paths hang off. Never touches any real storage. */
export const VIRTUAL_GRANT_ROOT = "/vana/grant";

export interface LiteMaterializedScope {
  scope: string;
  path: string;
  itemCount: number;
  bytes: number;
  collectedAt?: string;
  version?: string;
  unwrappedFrom: string | null;
  note?: string;
}

export interface LiteSkippedScope {
  scope: string;
  reason: string;
}

export interface LiteMaterializedGrant {
  scopes: LiteMaterializedScope[];
  skipped: LiteSkippedScope[];
  /** Virtual path -> records as JSON text. The VM's entire universe. */
  files: Map<string, string>;
}

/**
 * Read each granted scope through the caller's own path into an in-memory
 * grant.
 *
 * This is both the metering point and the containment: one `readScope` call
 * per scope touched, and the resulting map is everything the sandbox can see.
 * A scope that fails to read produces no entry, so it is unreachable by the
 * script *and* absent from coverage's scanned set — the two cannot drift.
 */
export async function materializeGrantInMemory(
  reader: LiteScopeReader,
  scopes: readonly string[],
): Promise<LiteMaterializedGrant> {
  const materialized: LiteMaterializedScope[] = [];
  const skipped: LiteSkippedScope[] = [];
  const files = new Map<string, string>();

  for (const scope of scopes) {
    if (!SAFE_SCOPE.test(scope)) {
      skipped.push({ scope, reason: "unsafe scope id" });
      continue;
    }
    try {
      const payload = await reader.readScope(scope);
      const unwrapped = unwrapEnvelopeData(payload.data);
      const text = JSON.stringify(unwrapped.items);
      const path = `${VIRTUAL_GRANT_ROOT}/${scope}.json`;
      if (files.has(path)) {
        skipped.push({ scope, reason: "duplicate scope id in grant" });
        continue;
      }
      files.set(path, text);
      materialized.push({
        scope,
        path,
        itemCount: unwrapped.items.length,
        // `TextEncoder`, not `Buffer.byteLength`: the same UTF-8 byte count,
        // computed with a global a browser actually has.
        bytes: new TextEncoder().encode(text).length,
        unwrappedFrom: unwrapped.key,
        ...(payload.collectedAt ? { collectedAt: payload.collectedAt } : {}),
        ...(payload.version ? { version: payload.version } : {}),
        ...(unwrapped.note ? { note: unwrapped.note } : {}),
      });
    } catch (err) {
      skipped.push({
        scope,
        reason: err instanceof Error ? err.message : "unreadable",
      });
    }
  }
  return { scopes: materialized, skipped, files };
}

/* ------------------------------------------------------------------ *
 * Grant resolution and coverage
 * ------------------------------------------------------------------ */

/** Intersect the caller's own scopes with an optional narrowing request. */
export function resolveGrant(
  granted: readonly string[],
  requested?: readonly string[],
): { scopes: string[]; rejected: string[] } {
  const owned = new Set(granted);
  if (!requested) return { scopes: [...owned], rejected: [] };
  const scopes: string[] = [];
  const rejected: string[] = [];
  for (const scope of new Set(requested)) {
    if (owned.has(scope)) scopes.push(scope);
    else rejected.push(scope);
  }
  return { scopes, rejected };
}

/**
 * Fold the scopes this request could not reach back into coverage.
 *
 * Strictly one-directional: it only ever ADDS to `scopesSkipped`, and never
 * removes an entry or touches a counter, so it cannot launder a partial run
 * into a total one. A named-but-unread scope always reaches the answer text,
 * because `honestAnswerText` caveats on a non-empty `scopesSkipped`.
 */
export function applyGrantCoverage(
  coverage: QueryCoverage,
  skipped: readonly LiteSkippedScope[],
): QueryCoverage {
  if (skipped.length === 0) return coverage;
  const seen = new Set(coverage.scopesSkipped.map((s) => s.scope));
  const merged = [
    ...coverage.scopesSkipped,
    ...skipped.filter((s) => !seen.has(s.scope)),
  ];
  return { ...coverage, scopesSkipped: merged };
}

/* ------------------------------------------------------------------ *
 * Limits
 * ------------------------------------------------------------------ */

/**
 * Budget and limits, matched in value to `QUERY_SANDBOX_BUDGET` /
 * `QUERY_SANDBOX_LIMITS` on the Node route.
 *
 * Matched deliberately: `recordsScanned`, `scopesScanned` and `unreadable` have
 * to mean the same thing on both runtimes or the Lite-vs-Node comparison measures
 * the limits rather than the runtimes. The one value that could not be copied
 * is memory — 512 MB is a *process* ceiling on Node and here it is the VM heap
 * — and design §19.17 measured the working set at 32 MB for a 20 MB grant and
 * 192 MB for a 252 MB one. 512 MB therefore sits well above the measured need
 * while staying under the 128 MiB vault cap's implied corpus.
 */
export const LITE_QUERY_BUDGET = {
  toolCalls: 50,
  outputBytes: 1_000_000,
} as const;

export const LITE_QUERY_LIMITS = {
  cpuMs: 30_000,
  memoryMb: 512,
  wallClockMs: 60_000,
  maxOutputBytes: 1_000_000,
} as const;

/* ------------------------------------------------------------------ *
 * Events
 * ------------------------------------------------------------------ */

export type LiteQueryEvent =
  | {
      type: "start";
      question: string;
      model: string;
      grantedScopes: string[];
      scopes: Omit<LiteMaterializedScope, "path">[];
      skipped: LiteSkippedScope[];
    }
  | {
      type: "turn";
      turn: number;
      content: string;
      parsed: string;
      violation?: string;
      usage?: unknown;
    }
  | { type: "script"; run: number; script: string }
  | {
      type: "run";
      run: number;
      termination: string;
      coverage: unknown;
      notes: string[];
      violations: string[];
      truncated: boolean;
      result?: unknown;
      error?: unknown;
      durationMs?: number;
    }
  | { type: "answer"; answer: QueryAnswer };

export type LiteQueryEventSink = (
  event: LiteQueryEvent,
) => void | Promise<void>;

/* ------------------------------------------------------------------ *
 * The run
 * ------------------------------------------------------------------ */

export interface RunLiteQueryOptions {
  reader: LiteScopeReader;
  provider: InferenceProvider;
  question: string;
  scopes?: readonly string[];
  budget?: QueryBudget;
  model?: string;
  onEvent?: LiteQueryEventSink;
  /** T2 profiles by scope, exactly as the Node route resolves them. */
  profiles?: Readonly<Record<string, string>>;
  limits?: {
    cpuMs: number;
    memoryMb: number;
    wallClockMs: number;
    maxOutputBytes: number;
  };
}

/**
 * Answer one question over the caller's own data, in the browser.
 *
 * Never throws for an ordinary bad outcome — an empty grant, an unreadable
 * scope or an exhausted budget all come back as a `QueryAnswer` with honest
 * coverage, because an exception tells the caller nothing about how much of
 * their data was actually read.
 */
export async function runLiteQuery(
  options: RunLiteQueryOptions,
): Promise<QueryAnswer> {
  const {
    reader,
    provider,
    question,
    scopes: requested,
    budget,
    model,
    onEvent,
    profiles,
    limits = LITE_QUERY_LIMITS,
  } = options;

  const emit = async (event: LiteQueryEvent) => {
    if (onEvent) await onEvent(event);
  };

  const granted = await reader.grantedScopes();
  const { scopes: grantScopes, rejected } = resolveGrant(granted, requested);
  const grant = await materializeGrantInMemory(reader, grantScopes);

  const skipped: LiteSkippedScope[] = [
    ...grant.skipped,
    ...rejected.map((scope) => ({
      scope,
      reason: "not in the caller's granted scopes",
    })),
  ];

  await emit({
    type: "start",
    question,
    model: model ?? provider.defaultModel,
    grantedScopes: grant.scopes.map((s) => s.scope),
    scopes: grant.scopes.map(({ path: _path, ...rest }) => rest),
    skipped,
  });

  if (grant.scopes.length === 0) {
    const answer: QueryAnswer = {
      answer:
        "No readable scope was available for this question, so there is nothing to compute an answer from.",
      citations: [],
      // Spread rather than passed straight through: `EMPTY_COVERAGE` is
      // frozen, and this object goes on to be handed to a caller.
      coverage: applyGrantCoverage({ ...EMPTY_COVERAGE }, skipped),
      determinism: "generated",
      cost: { toolCalls: 0, inputTokens: 0, outputTokens: 0 },
    };
    await emit({ type: "answer", answer });
    return answer;
  }

  const hostScopes: LiteGrantedScope[] = grant.scopes.map((s) => ({
    scope: s.scope,
    path: s.path,
    itemCount: s.itemCount,
    ...(s.collectedAt ? { collectedAt: s.collectedAt } : {}),
    ...(s.version ? { version: s.version } : {}),
    ...(profiles?.[s.scope] ? { profile: profiles[s.scope] as string } : {}),
  }));

  /*
   * Deps are served from the materialized grant and nothing else.
   *
   * `streamScope` returns the scope's byte count because that is the one
   * quantity only the source knows, and the ledger counts records as they pass
   * — the same division of labour as the Node runner's `loadScope`. Records
   * are parsed once per scope and cached, so a script that reads a scope twice
   * neither pays twice nor is counted twice.
   */
  const parsed = new Map<string, { items: unknown[]; bytes: number }>();
  const byScope = new Map(grant.scopes.map((s) => [s.scope, s]));
  const load = (scope: string): { items: unknown[]; bytes: number } => {
    const hit = parsed.get(scope);
    if (hit) return hit;
    const entry = byScope.get(scope);
    if (!entry) throw new Error(`scope not granted: ${scope}`);
    const text = grant.files.get(entry.path);
    if (text === undefined) throw new Error(`scope not materialized: ${scope}`);
    const value: unknown = JSON.parse(text);
    const loaded = {
      items: Array.isArray(value) ? value : [value],
      bytes: entry.bytes,
    };
    parsed.set(scope, loaded);
    return loaded;
  };

  const deps: QueryToolDeps = {
    async listScopes(): Promise<ScopeInfo[]> {
      return hostScopes.map((s) => {
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
      return bytes;
    },
    async readBlocks(scope, opts): Promise<ScriptBlock[]> {
      const all = load(scope).items;
      const limit = opts.maxBytes ?? Number.MAX_SAFE_INTEGER;
      const out: ScriptBlock[] = [];
      let bytes = 0;
      for (let i = 0; i < all.length; i += 1) {
        const json = all[i];
        const size = JSON.stringify(json).length;
        if (bytes + size > limit && out.length > 0) break;
        bytes += size;
        // One block is one record. Without `itemCount` the runtime's
        // `recordsRead` sums to zero, which is how a live Node run once
        // reported `recordsScanned: 0` after reading 8.5MB.
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
     * Lexical search is host authority that spans scopes, and PS-Lite has no
     * cross-scope index. An honest denial, never an empty array: an empty
     * array reads as "there is nothing there", which is the false negative the
     * absence class exists to prevent.
     */
    async search(query): Promise<ScriptHit[]> {
      throw new Error(
        `search("${query}") is not available on PS-Lite; scan the scope directly`,
      );
    },
  };

  const context: QueryToolContext = {
    grantedScopes: grant.scopes.map((s) => s.scope),
    resolveScopePath(scope: string): string {
      const entry = byScope.get(scope);
      if (!entry) throw new Error(`scope not granted: ${scope}`);
      return entry.path;
    },
    budget: { ...LITE_QUERY_BUDGET },
  };

  const host = createLiteToolHost({
    sandbox: createQuickJsSandbox({ grant: grant.files, context, deps }),
    scopes: hostScopes,
    limits,
  });

  let turn = 0;
  let run = 0;

  const observedProvider: InferenceProvider = {
    defaultModel: provider.defaultModel,
    async chat(input: InferenceChatInput) {
      const reply = await provider.chat(input);
      turn += 1;
      const parsedTurn = parseTurn(reply.content);
      await emit({
        type: "turn",
        turn,
        content: reply.content,
        parsed: parsedTurn.kind,
        ...(parsedTurn.kind === "violation"
          ? { violation: parsedTurn.violation }
          : {}),
        usage: reply.usage ?? null,
      });
      return reply;
    },
  };

  // Explicit delegation rather than a spread, so a new method on
  // `QueryToolHost` becomes a compile error here instead of an unobserved call.
  const observedTools: QueryToolHost = {
    listScopes: () => host.listScopes(),
    coverage: () => host.coverage(),
    async execute(modelCode: string) {
      run += 1;
      const index = run;
      await emit({ type: "script", run: index, script: modelCode });
      const t0 = Date.now();
      const result = await host.execute(modelCode);
      await emit({
        type: "run",
        run: index,
        termination: result.termination,
        coverage: result.coverage,
        notes: result.notes,
        violations: result.violations,
        truncated: result.truncated,
        result: result.result ?? null,
        error: result.error ?? null,
        durationMs: Date.now() - t0,
      });
      return result;
    },
  };

  const raw = await runQueryLoop(
    {
      question,
      grantedScopes: grant.scopes.map((s) => s.scope),
      ...(budget ? { budget } : {}),
    },
    {
      provider: observedProvider,
      tools: observedTools,
      ...(model ? { model } : {}),
    },
  );

  const answer: QueryAnswer = {
    ...raw,
    coverage: applyGrantCoverage(raw.coverage, skipped),
  };
  await emit({ type: "answer", answer });
  return answer;
}
