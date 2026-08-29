/**
 * Capability-confined script API for the query layer (plan phase 4b,
 * prompt contract §3).
 *
 * Every type here is pure: `packages/core` is imported by `packages/lite` and
 * must stay browser-safe, so nothing under `tools/` may import a Node built-in.
 * Data access is injected through {@link QueryToolDeps}.
 */

/** One granted scope, as the script sees it. */
export interface ScopeInfo {
  scope: string;
  itemCount?: number;
  collectedAt?: string;
  version?: string;
  contentKind?: string;
  /**
   * The T2 prose summary for this scope. Absent means no profile exists, and
   * per the system prompt the answer must say so and lower its confidence.
   */
  profile?: string;
}

/** A block of scope content, as returned by `vana.read`. */
export interface ScriptBlock {
  id: string;
  scope: string;
  mediaType?: string;
  sizeBytes?: number;
  itemCount?: number;
  text?: string;
  json?: unknown;
}

/** A lexical search hit. Carries `blockRef` so the script can fetch the block. */
export interface ScriptHit {
  id: string;
  scope: string;
  score: number;
  title?: string;
  preview?: string;
  blockRef?: string;
}

export interface ReadOptions {
  cursor?: string;
  maxBytes?: number;
  blockIds?: string[];
}

export interface SearchOptions {
  scopes?: string[];
  limit?: number;
}

export interface ClassifyOptions {
  /** Items per model call. The host may lower this. */
  batchSize?: number;
  /** Abort the classify once this many USD have been spent on it. */
  maxUsd?: number;
}

/**
 * Why a run stopped short. Budget exhaustion is a first-class outcome, not an
 * error (prompt §3): the run ends with a partial answer and honest coverage.
 */
export type StoppedBecause =
  | "budget"
  | "cpu"
  | "memory"
  | "wallClock"
  | "outputCap"
  | "policyDenied"
  | "error";

/** How completely the granted data was actually examined. */
export type CoverageMethod = "full" | "prefiltered";

/**
 * Host-authored coverage (prompt §1).
 *
 * Assembled from counters incremented by the runtime as reads happen. The
 * script does not author any field here and has no way to write to it — see
 * `coverage.ts` and `interpreter/realm.ts`.
 */
export interface CoverageCounters {
  scopesScanned: string[];
  recordsScanned: number;
  bytesScanned: number;
  scopesSkipped: { scope: string; reason: string }[];
  complete: boolean;
  /**
   * Records that were present but could not be read — a scanned PDF with no
   * text layer, an undecodable attachment.
   *
   * Host-authored like every other counter: the runtime recognises the
   * record's own unreadable marker as it streams past. This is what lets an
   * absence answer be honest — "no match across 318 readable documents; 22
   * could not be read" is a true negative, while a bare "no" over the same
   * data is not (design §4.3 point 1).
   */
  unreadable: number;
  /**
   * Per-scope attribution of the totals above.
   *
   * Carried rather than derived so the cross-run merge can apply the same
   * subsumption rule the single-run ledger does: a scope re-read in a later
   * turn covers the same records, and summing bare totals across runs would
   * reintroduce the double-count at the request level.
   */
  perScope: Record<
    string,
    { records: number; bytes: number; unreadable: number }
  >;
  method: CoverageMethod;
  stoppedBecause?: StoppedBecause;
  /**
   * What the sandbox actually enforced, verbatim from
   * `SandboxEnforcement.notes`. Plan §4.3: reduced capability must be visible,
   * so this is surfaced rather than swallowed.
   */
  enforcementNotes: string[];
}

/** Per-request budget ceilings, enforced by the host. */
export interface QueryBudget {
  toolCalls: number;
  outputBytes: number;
  /** Cost ceiling for `vana.classify` across the whole run. */
  classifyUsd?: number;
}

/**
 * Per-request capability context, built from the consumer's grant.
 *
 * Scopes outside the grant are not merely denied — they are absent from
 * `grantedScopes`, so `vana.scopes()` never names them and
 * `resolveScopePath` throws.
 */
export interface QueryToolContext {
  grantedScopes: string[];
  /** Throws `QueryToolError("SCOPE_NOT_GRANTED")` for anything not granted. */
  resolveScopePath(scope: string): string;
  budget: QueryBudget;
  /**
   * The consumer asking the question. `vana.introspect()` is refused when the
   * question is about this same party (prompt §3) — a builder may not use the
   * server to audit what the server told it.
   */
  callerId?: string;
  /**
   * Who the question is *about*, when it names a party. Set by the host after
   * parsing the question; `vana.introspect()` is refused when this equals
   * `callerId`.
   *
   * Deliberately host-supplied rather than derived inside the API: the script
   * must not be able to influence who the subject is, or the refusal is
   * decorative.
   */
  introspectSubject?: string;
}

/** The payload a script hands to `vana.result`, terminating the run. */
export interface ScriptResult {
  answer: string;
  citations?: { scope: string; recordId?: string; blockRef?: string }[];
  confidence?: "high" | "medium" | "low";
  value?: number;
}

/**
 * Host-supplied data access. Everything the API can reach is here, so a test
 * can substitute an in-memory implementation and a runtime can substitute a
 * filesystem or OPFS one without `tools/` ever importing a Node built-in.
 */
export interface QueryToolDeps {
  listScopes(): Promise<ScopeInfo[]>;
  /**
   * Streams a scope's records.
   *
   * May return the number of bytes it read, which the runtime folds into
   * `bytesScanned`. Records are counted by the runtime as they pass through,
   * never from anything a deps implementation claims; bytes are the one
   * quantity only the source can know, so this is the channel for them.
   * Returning nothing simply leaves `bytesScanned` unchanged.
   */
  streamScope(
    scope: string,
    onItem: (item: unknown) => void | Promise<void>,
  ): Promise<void | number>;
  readBlocks(scope: string, opts: ReadOptions): Promise<ScriptBlock[]>;
  search(query: string, opts: SearchOptions): Promise<ScriptHit[]>;
  /**
   * LLM judgement over every item. Supplied by phase 5 — `tools/` defines the
   * shape and meters the cost but never calls the relay itself.
   */
  classify?: ClassifyFn;
  introspect?: IntrospectFn;
}

export interface ClassifyResult<T = unknown> {
  values: T[];
  usd: number;
  inputTokens: number;
  outputTokens: number;
}

export type ClassifyFn = (
  items: unknown[],
  instruction: string,
  opts: ClassifyOptions,
) => Promise<ClassifyResult>;

export type IntrospectFn = (callerId?: string) => Promise<{
  grants: unknown[];
  accessLog: unknown[];
  lineage: unknown[];
}>;
