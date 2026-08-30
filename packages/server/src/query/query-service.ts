/**
 * The query layer's single execution path (implementation plan phase 8).
 *
 * Both real entrypoints — the `ask_personal_data` MCP tool and the owner
 * authenticated `POST /v1/query/ask` HTTP route — run a question through
 * `runQuery` here. One path means the security and coverage properties are
 * established once rather than argued twice.
 *
 * ## The four properties this file exists to hold
 *
 * 1. **`readPaths` is exactly the grant.** Not "derived from" it: the sandbox
 *    is pointed at a per-request scratch directory into which *only* the
 *    granted scopes were materialized. A scope outside the grant has no file
 *    there to read, so the containment survives a bad path computation as
 *    well as a hostile script. See {@link materializeGrant}.
 *
 * 2. **Metering and access logging happen per scope touched**, because
 *    materialization is the only way data reaches the sandbox and it goes one
 *    scope at a time through the caller's ordinary read path
 *    ({@link QueryScopeReader.readScope}). The metered set and the readable
 *    set are therefore the same set by construction — you cannot read a scope
 *    this request did not pay for and log, because an unpaid scope has no
 *    file. Phase 8: "settle and log per scope touched."
 *
 * 3. **Coverage stays honest.** `runQueryLoop` assembles coverage from
 *    host counters, and a scope that never materialized is invisible to that
 *    host — which would let a partial sweep report `complete: true`. So every
 *    scope the grant named and this request could not read is folded back in
 *    as `scopesSkipped` and forces `complete: false`. See
 *    {@link applyGrantCoverage}, the one place that can weaken completeness
 *    and never strengthen it.
 *
 * 4. **Concurrency is bounded.** Ten consumers asking scan-shaped questions
 *    is ten full scans (plan §3 risk 4). See {@link createQueryConcurrency}.
 *
 * ## What it deliberately does not do
 *
 * No result cache: plan §6 leaves that gated on an eval-verified result,
 * because a cache over a wrong answer freezes the error permanently. No
 * `vana.search` wiring: design §19.16 measured that it destroys
 * `coverage.complete` (six complete rows to zero), and completeness is the
 * property that distinguishes this from a naive LLM call.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  parseTurn,
  runQueryLoop,
  type QueryAnswer,
  type QueryBudget,
  type QueryCoverage,
  type QueryToolHost,
} from "@opendatalabs/personal-server-ts-core/query/agent";
import type {
  InferenceChatInput,
  InferenceProvider,
} from "@opendatalabs/personal-server-ts-core/derivatives";

import { createNodeSandbox } from "./node-sandbox.js";
import { createSandboxToolHost } from "./sandbox-tool-host.js";

/* ------------------------------------------------------------------ *
 * The grant seam
 * ------------------------------------------------------------------ */

/** One scope's contents, as its caller's ordinary read path returned them. */
export interface QueryScopePayload {
  /**
   * The parsed data file. A real Personal Server file is a `DataFileEnvelope`
   * (`{version, scope, collectedAt, data}`); pass the whole envelope and
   * {@link unwrapEnvelopeData} finds the records. A bare array is also
   * accepted — that is the shape the eval corpus writes.
   */
  data: unknown;
  collectedAt?: string;
  version?: string;
}

/**
 * How one caller reaches its own data.
 *
 * The two implementations differ in exactly the way they should: the HTTP
 * owner route reads through `DataStoragePort` and writes its own access-log
 * row, while the MCP tool reads through `McpDataReadClient`, which performs
 * the grant check, the access-log write and (on a paying session) the x402
 * settlement inside the same call that returns the bytes. Neither invents a
 * metering concept; both call the path their caller already had.
 */
export interface QueryScopeReader {
  /**
   * Every scope this caller is entitled to, before any narrowing. The result
   * is the ceiling: {@link resolveGrant} may only intersect with it.
   */
  grantedScopes(): Promise<readonly string[]> | readonly string[];
  /**
   * Read one scope. Called at most once per scope per request, and only for
   * scopes inside the resolved grant — so the count of calls is the count of
   * billable/loggable scope touches.
   */
  readScope(scope: string): Promise<QueryScopePayload>;
}

/* ------------------------------------------------------------------ *
 * Grant resolution
 * ------------------------------------------------------------------ */

/**
 * Intersect the caller's own scopes with an optional narrowing request.
 *
 * A caller may narrow its grant and may never widen it: an unknown scope in
 * `requested` is dropped rather than honoured, and dropping it silently would
 * hide the fact that the answer covers less than the caller asked about — so
 * it comes back in `rejected` and reaches `coverage.scopesSkipped`.
 */
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

/* ------------------------------------------------------------------ *
 * Envelope unwrapping
 * ------------------------------------------------------------------ */

/**
 * Keys an envelope's `data` might hang its record array off, ordered by how
 * unambiguous they are. A lone array-valued key beats this list.
 */
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

export interface UnwrapResult {
  items: unknown[];
  /** Which key the records came from; null when the value was already a list. */
  key: string | null;
  /** Why, whenever the choice was not forced. Reported, never silent. */
  note?: string;
}

/**
 * Turn one scope's data into the record array the sandbox runner expects.
 *
 * The runner's `loadScope` counts a JSON array's elements. Handed a
 * `DataFileEnvelope` directly it counts the envelope as ONE record and every
 * figure in `coverage` reads `1` — a coverage lie, which is the failure mode
 * this whole layer is built to prevent. So the envelope is unwrapped here,
 * and because a real envelope's `data` shape is source-specific the choice is
 * a heuristic. A heuristic that silently picks the wrong key changes every
 * denominator in the answer, so the key and the reason are reported to the
 * caller rather than applied invisibly.
 */
export function unwrapEnvelopeData(data: unknown): UnwrapResult {
  if (Array.isArray(data)) return { items: data, key: null };
  if (data === null || typeof data !== "object") {
    return { items: [data], key: null, note: "scope data is not an object" };
  }
  const record = data as Record<string, unknown>;
  // A `DataFileEnvelope` wraps the payload one level down. Unwrap it first so
  // the key search runs over the payload, not over `{version, scope, ...}`.
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
 * Scope ids safe to use as a scratch filename.
 *
 * Deliberately a whitelist. The scratch path is `${dataRoot}/${scope}.json`,
 * so anything that could carry a separator or a `..` must never reach it —
 * this is the string that becomes a `readPaths` entry.
 */
const SAFE_SCOPE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export interface MaterializedScope {
  scope: string;
  path: string;
  itemCount: number;
  bytes: number;
  collectedAt?: string;
  version?: string;
  unwrappedFrom: string | null;
  note?: string;
}

export interface SkippedScope {
  scope: string;
  reason: string;
}

export interface MaterializedGrant {
  scopes: MaterializedScope[];
  skipped: SkippedScope[];
}

/**
 * Read each granted scope through the caller's own path and write it into the
 * per-request scratch root.
 *
 * This is both the metering point and the containment: one `readScope` call
 * per scope touched, and the resulting directory is the entire universe the
 * sandbox can see. A scope that fails to read produces no file, so it is
 * unreadable by the script *and* absent from coverage's scanned set — the two
 * cannot drift apart.
 */
export async function materializeGrant(
  reader: QueryScopeReader,
  scopes: readonly string[],
  dataRoot: string,
): Promise<MaterializedGrant> {
  const materialized: MaterializedScope[] = [];
  const skipped: SkippedScope[] = [];

  for (const scope of scopes) {
    if (!SAFE_SCOPE.test(scope)) {
      skipped.push({ scope, reason: "unsafe scope id" });
      continue;
    }
    try {
      const payload = await reader.readScope(scope);
      const unwrapped = unwrapEnvelopeData(payload.data);
      const text = JSON.stringify(unwrapped.items);
      const path = join(dataRoot, `${scope}.json`);
      await writeFile(path, text, "utf8");
      materialized.push({
        scope,
        path,
        itemCount: unwrapped.items.length,
        bytes: Buffer.byteLength(text, "utf8"),
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
  return { scopes: materialized, skipped };
}

/* ------------------------------------------------------------------ *
 * Coverage
 * ------------------------------------------------------------------ */

/**
 * Fold the scopes this request could not reach back into the answer's
 * coverage.
 *
 * `runQueryLoop` builds coverage from the sandbox host's counters, and the
 * host only ever knew about scopes that materialized. Without this, a request
 * granted eight scopes that could only read six would report a *complete*
 * scan of six and never mention the other two — plan §3's worst bug, a
 * confident total over a partial corpus.
 *
 * Strictly one-directional: it can add skipped scopes and it can turn
 * `complete` false. It can never turn `complete` true, so it cannot launder a
 * partial run into a total one.
 */
export function applyGrantCoverage(
  coverage: QueryCoverage,
  skipped: readonly SkippedScope[],
): QueryCoverage {
  if (skipped.length === 0) return coverage;
  const seen = new Set(coverage.scopesSkipped.map((s) => s.scope));
  const merged = [
    ...coverage.scopesSkipped,
    ...skipped.filter((s) => !seen.has(s.scope)),
  ];
  return { ...coverage, scopesSkipped: merged, complete: false };
}

/* ------------------------------------------------------------------ *
 * Concurrency
 * ------------------------------------------------------------------ */

/**
 * Default ceiling on questions running at once.
 *
 * Plan §3 risk 4: "ten consumers asking scan-shaped questions is ten full
 * scans." The binding resources are the scratch copy of the grant on disk
 * (96MB of readable scopes at the 252MB corpus, per design §19.16) and the
 * sandbox subprocess's 512MB memory ceiling. `createNodeSandbox` already
 * serialises `sandbox.run` process-wide through its own queue, so extra
 * concurrent questions do not buy parallel scanning — they buy queueing
 * behind a 60s wall clock while holding their materialized grant on disk.
 *
 * Four keeps a desktop app responsive to a couple of overlapping questions
 * plus an MCP client, without letting a fifth start a scan it will only spend
 * waiting. Override with `PS_QUERY_MAX_CONCURRENT` or the `maxConcurrent`
 * option.
 */
export const DEFAULT_MAX_CONCURRENT_QUERIES = 4;

export class QueryBusyError extends Error {
  readonly code = "QUERY_BUSY";
  constructor(readonly limit: number) {
    super(
      `Too many questions are already running (limit ${limit}). Retry shortly.`,
    );
    this.name = "QueryBusyError";
  }
}

export interface QueryConcurrency {
  /** Reserve a slot, or throw {@link QueryBusyError}. */
  acquire(): () => void;
  readonly inFlight: number;
  readonly limit: number;
}

/**
 * A counting gate that rejects rather than queues.
 *
 * Rejecting is the honest answer: because sandbox runs are serialised anyway,
 * an accepted-but-queued question would sit until its own wall clock killed
 * it and then report a budget-stopped partial answer, which reads as a bad
 * answer rather than as a busy server. A caller told `QUERY_BUSY` can retry.
 */
export function createQueryConcurrency(limit: number): QueryConcurrency {
  const max = Math.max(1, Math.floor(limit));
  let active = 0;
  return {
    get inFlight() {
      return active;
    },
    get limit() {
      return max;
    },
    acquire() {
      if (active >= max) throw new QueryBusyError(max);
      active += 1;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        active -= 1;
      };
    },
  };
}

/** Read the configured ceiling, ignoring anything that is not a positive int. */
export function resolveMaxConcurrent(
  option?: number,
  env: Record<string, string | undefined> = process.env,
): number {
  const raw = option ?? Number(env["PS_QUERY_MAX_CONCURRENT"]);
  return Number.isFinite(raw) && (raw as number) >= 1
    ? Math.floor(raw as number)
    : DEFAULT_MAX_CONCURRENT_QUERIES;
}

/* ------------------------------------------------------------------ *
 * Sandbox limits
 * ------------------------------------------------------------------ */

/**
 * The budget and limits the eval harness runs under, verbatim.
 *
 * Shared with `scripts/query-eval-harness.ts` in value so that
 * `coverage.recordsScanned`, `unreadable` and `complete` mean at this API
 * boundary exactly what they mean on a graded row. Changing one without the
 * other would make the benchmark stop predicting the product.
 */
export const QUERY_SANDBOX_BUDGET = {
  toolCalls: 50,
  outputBytes: 1_000_000,
} as const;

export const QUERY_SANDBOX_LIMITS = {
  cpuMs: 30_000,
  memoryMb: 512,
  wallClockMs: 60_000,
  maxOutputBytes: 1_000_000,
} as const;

/* ------------------------------------------------------------------ *
 * Events
 * ------------------------------------------------------------------ */

/**
 * Turn-by-turn progress, for a UI that shows reasoning as it happens.
 *
 * Emitted by wrapping the loop's two injected seams — `InferenceProvider.chat`
 * and `QueryToolHost.execute` — in pass-throughs that observe and change
 * nothing. `runQueryLoop` needs no progress callback and gets none, so
 * `packages/core` is untouched and nothing here can alter the behaviour the
 * eval grades.
 */
export type QueryEvent =
  | {
      type: "start";
      question: string;
      model: string;
      grantedScopes: string[];
      scopes: Omit<MaterializedScope, "path">[];
      skipped: SkippedScope[];
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
      /** What the script returned, when it returned anything. */
      result?: unknown;
      error?: unknown;
    }
  | { type: "answer"; answer: QueryAnswer };

export type QueryEventSink = (event: QueryEvent) => void | Promise<void>;

/* ------------------------------------------------------------------ *
 * The run
 * ------------------------------------------------------------------ */

export interface RunQueryOptions {
  reader: QueryScopeReader;
  provider: InferenceProvider;
  question: string;
  /** Narrowing only. Anything outside the caller's own scopes is rejected. */
  scopes?: readonly string[];
  budget?: QueryBudget;
  model?: string;
  onEvent?: QueryEventSink;
  concurrency?: QueryConcurrency;
  /** Test seam: override the OS sandbox factory. */
  createSandbox?: typeof createNodeSandbox;
}

/**
 * Answer one question over the caller's own data.
 *
 * Never throws for an ordinary bad outcome — an empty grant, an unreadable
 * scope or an exhausted budget all come back as a `QueryAnswer` with honest
 * coverage, because a 500 tells the caller nothing about how much of their
 * data was actually read. It throws only for {@link QueryBusyError} and for
 * genuine transport failures.
 */
export async function runQuery(options: RunQueryOptions): Promise<QueryAnswer> {
  const {
    reader,
    provider,
    question,
    scopes: requested,
    budget,
    model,
    onEvent,
    concurrency,
    createSandbox = createNodeSandbox,
  } = options;

  const release = concurrency?.acquire();
  const emit = async (event: QueryEvent) => {
    if (onEvent) await onEvent(event);
  };

  let scratch: string | undefined;
  try {
    scratch = await mkdtemp(join(tmpdir(), "ps-query-"));
    const dataRoot = join(scratch, "scopes");
    const runScratch = join(scratch, "run");
    await mkdir(dataRoot, { recursive: true });
    await mkdir(runScratch, { recursive: true });

    const granted = await reader.grantedScopes();
    const { scopes: grantScopes, rejected } = resolveGrant(granted, requested);
    const grant = await materializeGrant(reader, grantScopes, dataRoot);
    // A narrowing request naming a scope the caller does not hold is a
    // coverage fact, not an error: the answer covers less than was asked.
    const skipped: SkippedScope[] = [
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
        coverage: applyGrantCoverage(
          {
            scopesScanned: [],
            recordsScanned: 0,
            scopesSkipped: [],
            complete: false,
          },
          skipped,
        ),
        determinism: "generated",
        cost: { toolCalls: 0, inputTokens: 0, outputTokens: 0 },
      };
      await emit({ type: "answer", answer });
      return answer;
    }

    const host = createSandboxToolHost({
      sandbox: createSandbox({ dataRoot }),
      // `readPaths` is derived from exactly this list, and this list is
      // exactly what materialized — nothing else exists under `dataRoot`.
      scopes: grant.scopes.map((s) => ({
        scope: s.scope,
        path: s.path,
        itemCount: s.itemCount,
        ...(s.collectedAt ? { collectedAt: s.collectedAt } : {}),
        ...(s.version ? { version: s.version } : {}),
      })),
      dataRoot,
      scratchDir: runScratch,
      budget: { ...QUERY_SANDBOX_BUDGET },
      limits: { ...QUERY_SANDBOX_LIMITS },
    });

    let turn = 0;
    let run = 0;

    const observedProvider: InferenceProvider = {
      defaultModel: provider.defaultModel,
      async chat(input: InferenceChatInput) {
        const reply = await provider.chat(input);
        turn += 1;
        const parsed = parseTurn(reply.content);
        await emit({
          type: "turn",
          turn,
          content: reply.content,
          parsed: parsed.kind,
          ...(parsed.kind === "violation"
            ? { violation: parsed.violation }
            : {}),
          usage: reply.usage ?? null,
        });
        return reply;
      },
    };

    // Delegation is explicit rather than a spread of `host`, so a new method
    // on `QueryToolHost` becomes a compile error here instead of a silently
    // unobserved call.
    const observedTools: QueryToolHost = {
      listScopes: () => host.listScopes(),
      coverage: () => host.coverage(),
      async execute(modelCode: string) {
        run += 1;
        const index = run;
        // Emitted BEFORE execute, so a script the sandbox kills is still on
        // screen — the ordering the eval harness's recorder also uses.
        await emit({ type: "script", run: index, script: modelCode });
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
  } finally {
    release?.();
    if (scratch) {
      await rm(scratch, { recursive: true, force: true }).catch(
        () => undefined,
      );
    }
  }
}
