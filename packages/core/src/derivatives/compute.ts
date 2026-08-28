/**
 * The compute job: answer one registered question from local data and
 * write the answer as a derivative record (owner path, `$lineage` = the
 * source data points).
 */

import {
  DerivativeCycleError,
  DerivativeSourceNotGrantedError,
  ProtocolError,
} from "../errors/catalog.js";
import { resolveReadDeletion } from "../api/index.js";
import {
  LOCAL_SCOPE_SCAN_PAGE,
  readStoredLineage,
} from "../lineage/lineage.js";
import { uncoveredSourceScopes } from "./registration.js";
import { ingestDataContract } from "../contracts/data.js";
import { isBinaryEnvelope } from "../contracts/binary.js";
import { assertDerivedScopeNaming } from "../lineage/lineage.js";
import type { StoredLineage } from "../lineage/lineage.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import type { ScopeDeletionTracker } from "../sync/scope-deletions.js";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "../ports/index.js";
import {
  verifyDataWritePolicy,
  type DataWritePolicyPorts,
} from "../policy/data-write.js";
import { InferenceRequestError, type InferenceProvider } from "./inference.js";
import {
  buildQuestionMessages,
  parseAnswer,
  trimSourceData,
  type PromptSource,
} from "./prompt.js";
import type { QuestionRegistration, QuestionStore } from "./types.js";

export interface ComputeLogger {
  info?(payload: Record<string, unknown>, message: string): void;
  warn?(payload: Record<string, unknown>, message: string): void;
}

export interface ComputeSyncNotifier {
  notifyNewData?(): void;
  trigger?(): Promise<void>;
}

export interface QuestionComputeDeps {
  storage: DataStoragePort;
  store: QuestionStore;
  provider: InferenceProvider;
  /** Required: lineage ids are keccak256(owner, scope). */
  serverOwner: `0x${string}` | undefined;
  /** Newest-first items kept per source scope (default 50). */
  maxSourceItems?: number;
  maxSourceChars?: number;
  maxTokens?: number;
  /** Uploads the derivative after it is written locally. */
  syncManager?: ComputeSyncNotifier | null;
  /** Re-add marker, same as an HTTP ingest (see api/index.ts). */
  scopeDeletions?: ScopeDeletionTracker;
  /**
   * When present, a builder-registered question re-checks its write grant
   * before every compute (revoked / expired / scope no longer covered =>
   * failed, no inference call). Owner registrations skip the check.
   */
  writePolicyPorts?: DataWritePolicyPorts;
  /**
   * Called after the derivative is written and the question marked ready,
   * so a question that reads THIS derived scope recomputes in turn
   * (A -> B -> C chains). The compute path never goes through the HTTP
   * ingest hook.
   */
  onDerivedWritten?: (event: {
    scope: string;
    collectedAt: string;
    lineageSources: string[];
  }) => void;
  /** When unavailable the compute is skipped and the status left as is. */
  runtimeAvailability?: RuntimeAvailabilityPort;
  /**
   * Backoff between retries of a transient inference or gateway failure
   * (default 1s, 4s: three attempts). Tests pass zeros.
   */
  retryDelaysMs?: readonly number[];
  sleep?: (ms: number) => Promise<void>;
  now?: () => Date;
  logger?: ComputeLogger;
}

export type ComputeOutcome =
  | { status: "ready"; registration: QuestionRegistration }
  | { status: "failed"; registration: QuestionRegistration; error: string }
  | { status: "skipped"; reason: "unknown-question" | "runtime-unavailable" };

const DEFAULT_RETRY_DELAYS_MS: readonly number[] = [1_000, 4_000];

/**
 * Transient: no response, rate limited or a provider-side failure. An
 * explicit `retryable` hint (E2EE key verification or decryption failures
 * are permanent) wins over the status rule.
 */
function isRetryableInferenceError(err: unknown): boolean {
  if (!(err instanceof InferenceRequestError)) return false;
  if (err.retryable !== undefined) return err.retryable;
  return err.status === null || err.status === 429 || err.status >= 500;
}

/**
 * Run `attempt` up to `delays.length + 1` times while `retryable(err)`;
 * anything else (a ProtocolError, a permanent status) surfaces at once.
 */
async function withRetries<T>(
  deps: Pick<QuestionComputeDeps, "retryDelaysMs" | "sleep">,
  attempt: () => Promise<T>,
  retryable: (err: unknown) => boolean,
): Promise<T> {
  const delays = deps.retryDelaysMs ?? DEFAULT_RETRY_DELAYS_MS;
  const sleep =
    deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  for (let index = 0; ; index += 1) {
    try {
      return await attempt();
    } catch (err) {
      if (index >= delays.length || !retryable(err)) throw err;
      await sleep(delays[index]!);
    }
  }
}

/** The record written into the derived scope. */
export interface DerivativeAnswerRecord {
  questionId: string;
  question: string;
  answer: string;
  evidence: string | null;
  model: string;
  computedAt: string;
  sources: Array<{ scope: string; version: number; collectedAt: string }>;
  /** Caller-side lineage field, mirrored by the server into `$lineage`. */
  lineage: `0x${string}`[];
  inference?: { receiptId?: string; aciIdentity?: string };
  [key: string]: unknown;
}

/** A failure message safe to persist: never the prompt, never the data. */
class ComputeFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ComputeFailure";
  }
}

function shortError(err: unknown): string {
  if (err instanceof ComputeFailure) return err.message;
  if (err instanceof InferenceRequestError) return err.message;
  if (err instanceof ProtocolError) return `${err.errorCode}: ${err.message}`;
  // Unknown errors may quote data (a JSON parse error echoes its input);
  // keep the class name only.
  return `compute failed (${err instanceof Error ? err.name : "Error"})`;
}

/**
 * Version stamp for the derived record, second precision like an HTTP
 * ingest. A recompute inside the same second as the previous one would
 * collide on the (scope, collectedAt) path, so the stamp advances past any
 * version the scope already holds (bounded: at most one minute ahead).
 */
export function collectedAtStamp(
  now: () => Date,
  isTaken: (collectedAt: string) => boolean,
): string {
  const base = now();
  base.setUTCMilliseconds(0);
  for (let bump = 0; bump < 60; bump += 1) {
    const candidate = new Date(base.getTime() + bump * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, "Z");
    if (!isTaken(candidate)) return candidate;
  }
  throw new ComputeFailure("could not allocate a version stamp");
}

async function tombstoneMarker(
  scopeDeletions: ScopeDeletionTracker | undefined,
  scope: string,
): Promise<number | null> {
  if (!scopeDeletions) return null;
  const verdict = await scopeDeletions.resolve(scope);
  if (!verdict.deleted || verdict.version === null) return null;
  const version = Number(verdict.version);
  return Number.isSafeInteger(version) ? version : null;
}

/**
 * `dataPointId -> scope` for every scope in the local index, used to walk
 * stored lineage locally. Paged like the lineage resolver.
 */
function localScopesById(
  storage: Pick<DataStoragePort, "listScopes">,
  serverOwner: `0x${string}`,
): Map<string, string> {
  const byId = new Map<string, string>();
  for (let offset = 0; ; offset += LOCAL_SCOPE_SCAN_PAGE) {
    const { scopes, total } = storage.listScopes({
      limit: LOCAL_SCOPE_SCAN_PAGE,
      offset,
    });
    for (const summary of scopes) {
      byId.set(computeDataPointId(serverOwner, summary.scope), summary.scope);
    }
    if (scopes.length === 0 || offset + scopes.length >= total) break;
  }
  return byId;
}

/**
 * Cycle guard on ACTUAL lineage, for cycles the per-store registration
 * check cannot see (two replicas each holding one half: B <- A here, A <- B
 * there, ping-ponging through sync). Walks `$lineage` from every source's
 * latest local version through the local index; reaching the derived data
 * point id means this question would consume its own output. Bounded by
 * the visited set.
 */
async function assertNoLineageCycle(
  deps: QuestionComputeDeps,
  registration: QuestionRegistration,
  serverOwner: `0x${string}`,
  sourceLineage: ReadonlyMap<string, readonly string[]>,
): Promise<void> {
  const derivedId = computeDataPointId(serverOwner, registration.derivedScope);
  let byId: Map<string, string> | null = null;
  const visited = new Set<string>();
  const stack: Array<{ id: string; path: string[] }> = [];
  for (const [scope, sources] of sourceLineage) {
    for (const id of sources) stack.push({ id, path: [scope] });
  }
  while (stack.length > 0) {
    const { id, path } = stack.pop()!;
    if (id === derivedId) {
      throw new DerivativeCycleError({
        derivedScope: registration.derivedScope,
        path: [registration.derivedScope, ...path, registration.derivedScope],
      });
    }
    if (visited.has(id)) continue;
    visited.add(id);
    byId ??= localScopesById(deps.storage, serverOwner);
    const scope = byId.get(id);
    if (!scope) continue;
    const entry = deps.storage.findEntry({ scope });
    if (!entry) continue;
    let sources: readonly string[] = [];
    try {
      const envelope = await deps.storage.readEnvelope(
        scope,
        entry.collectedAt,
      );
      sources = readStoredLineage(envelope.data)?.sources ?? [];
    } catch {
      // Unreadable or malformed lineage: nothing further to walk here.
    }
    for (const next of sources)
      stack.push({ id: next, path: [...path, scope] });
  }
}

async function loadSource(
  deps: QuestionComputeDeps,
  scope: string,
): Promise<{ source: PromptSource; lineageSources: string[] }> {
  const entry = deps.storage.findEntry({ scope });
  // The same deletion gate a read applies: a tombstoned scope is refused
  // (410 on the read path) whether or not a stale local copy remains.
  const deletion = await resolveReadDeletion(
    { scopeDeletions: deps.scopeDeletions, serverOwner: deps.serverOwner },
    scope,
    entry,
  );
  if (deletion) {
    throw new ComputeFailure(`source scope ${scope} is deleted`);
  }
  if (!entry) {
    throw new ComputeFailure(`source scope ${scope} has no local data`);
  }
  let envelope;
  try {
    envelope = await deps.storage.readEnvelope(scope, entry.collectedAt);
  } catch {
    throw new ComputeFailure(`source scope ${scope} could not be read`);
  }
  let lineageSources: string[] = [];
  try {
    lineageSources = readStoredLineage(envelope.data)?.sources ?? [];
  } catch {
    // Malformed stored lineage: treated as a root for the cycle walk.
  }
  const raw = isBinaryEnvelope(envelope)
    ? {
        binary: true,
        note: "binary record; its content is not included in the prompt",
      }
    : envelope.data;
  const trimmed = trimSourceData(raw, {
    maxItems: deps.maxSourceItems,
    maxChars: deps.maxSourceChars,
  });
  return {
    source: {
      scope,
      collectedAt: entry.collectedAt,
      version: entry.version,
      data: trimmed.data,
      kept: trimmed.kept,
      total: trimmed.total,
      truncated: trimmed.truncated,
    },
    lineageSources,
  };
}

/**
 * A builder question re-checks its grant before every compute: the write
 * permission on the derived scope (revocation, expiry, coverage) AND read
 * coverage of every source scope, since the answer exposes the sources to
 * the builder. Gateway transport failures are retried; policy failures
 * (ProtocolErrors) fail closed at once.
 */
async function assertGrantStillValid(
  deps: QuestionComputeDeps,
  registration: QuestionRegistration,
): Promise<void> {
  if (registration.registeredBy.kind !== "builder") return;
  if (!deps.writePolicyPorts) {
    throw new ComputeFailure("builder grant verification is not configured");
  }
  if (!deps.serverOwner) {
    throw new ComputeFailure("server owner is not configured");
  }
  const { builder, grantId } = registration.registeredBy;
  const ports = deps.writePolicyPorts;
  const serverOwner = deps.serverOwner;
  const grant = await withRetries(
    deps,
    () =>
      verifyDataWritePolicy(
        {
          signer: builder,
          grantId,
          requestedScope: registration.derivedScope,
          serverOwner,
        },
        ports,
      ),
    (err) => !(err instanceof ProtocolError),
  );
  const uncovered = uncoveredSourceScopes(
    registration.sourceScopes,
    grant.scopes ?? [],
  );
  if (uncovered.length > 0) {
    throw new DerivativeSourceNotGrantedError({ scopes: uncovered });
  }
}

/**
 * Compute one question end to end. Never throws for a compute failure: the
 * registration is marked `failed` with a short reason and the outcome says
 * so. Throws only when the store itself fails.
 */
export async function computeQuestion(
  questionId: string,
  deps: QuestionComputeDeps,
): Promise<ComputeOutcome> {
  const now = deps.now ?? (() => new Date());
  if ((await deps.runtimeAvailability?.isAvailable()) === false) {
    return { status: "skipped", reason: "runtime-unavailable" };
  }
  const registration = await deps.store.get(questionId);
  if (!registration) return { status: "skipped", reason: "unknown-question" };

  try {
    if (!deps.serverOwner) {
      throw new ComputeFailure("server owner is not configured");
    }
    const serverOwner = deps.serverOwner;
    await assertGrantStillValid(deps, registration);
    // Defense in depth: the rule was checked at registration; a registration
    // row edited by hand must still not produce a leaking derivative.
    assertDerivedScopeNaming(
      registration.derivedScope,
      registration.sourceScopes,
    );

    const sources: PromptSource[] = [];
    const sourceLineage = new Map<string, readonly string[]>();
    for (const scope of registration.sourceScopes) {
      const loaded = await loadSource(deps, scope);
      sources.push(loaded.source);
      sourceLineage.set(scope, loaded.lineageSources);
    }
    await assertNoLineageCycle(deps, registration, serverOwner, sourceLineage);
    const messages = buildQuestionMessages({
      question: registration.question,
      sources,
    });
    const model = registration.model ?? deps.provider.defaultModel;
    const reply = await withRetries(
      deps,
      () => deps.provider.chat({ model, messages, maxTokens: deps.maxTokens }),
      isRetryableInferenceError,
    );
    const parsed = parseAnswer(reply.content);

    const computedAt = now().toISOString();
    const lineageIds = registration.sourceScopes.map((scope) =>
      computeDataPointId(serverOwner, scope),
    );
    const record: DerivativeAnswerRecord = {
      questionId: registration.questionId,
      question: registration.question,
      answer: parsed.answer,
      evidence: parsed.evidence,
      model,
      computedAt,
      sources: sources.map((source) => ({
        scope: source.scope,
        version: source.version,
        collectedAt: source.collectedAt,
      })),
      lineage: lineageIds,
      ...(reply.receiptId || reply.aciIdentity
        ? {
            inference: {
              ...(reply.receiptId ? { receiptId: reply.receiptId } : {}),
              ...(reply.aciIdentity ? { aciIdentity: reply.aciIdentity } : {}),
            },
          }
        : {}),
    };
    const lineage: StoredLineage = {
      sources: lineageIds,
      writtenAt: computedAt,
    };
    // `findEntry({ at })` may answer the closest version, so compare exactly.
    const collectedAt = collectedAtStamp(
      now,
      (candidate) =>
        deps.storage.findEntry({
          scope: registration.derivedScope,
          at: candidate,
        })?.collectedAt === candidate,
    );
    const written = await ingestDataContract({
      storage: deps.storage,
      scopeParam: registration.derivedScope,
      body: record,
      collectedAt,
      status: deps.syncManager ? "syncing" : "stored",
      lineage,
      afterTombstoneVersion: await tombstoneMarker(
        deps.scopeDeletions,
        registration.derivedScope,
      ),
    });
    if (!written.ok) {
      throw new ComputeFailure(
        `derived record rejected: ${written.body.error}`,
      );
    }
    const entry = deps.storage.findEntry({
      scope: registration.derivedScope,
      at: collectedAt,
    });
    const updated = await deps.store.update(questionId, {
      status: "ready",
      error: null,
      updatedAt: computedAt,
      lastComputedAt: computedAt,
      derivedVersion: entry?.version ?? null,
      derivedCollectedAt: collectedAt,
    });
    if (deps.syncManager?.notifyNewData) {
      deps.syncManager.notifyNewData();
    } else if (deps.syncManager?.trigger) {
      void deps.syncManager.trigger().catch(() => undefined);
    }
    try {
      deps.onDerivedWritten?.({
        scope: registration.derivedScope,
        collectedAt,
        lineageSources: lineageIds,
      });
    } catch (err) {
      deps.logger?.warn?.(
        {
          questionId,
          derivedScope: registration.derivedScope,
          error: err instanceof Error ? err.name : String(err),
        },
        "onDerivedWritten hook failed; derivative already written",
      );
    }
    deps.logger?.info?.(
      {
        questionId,
        derivedScope: registration.derivedScope,
        sourceScopes: registration.sourceScopes,
        model,
        version: entry?.version ?? null,
        receiptId: reply.receiptId ?? null,
      },
      "Derivative question computed",
    );
    return {
      status: "ready",
      registration: updated ?? { ...registration, status: "ready" },
    };
  } catch (err) {
    const error = shortError(err);
    const at = now().toISOString();
    const updated = await deps.store.update(questionId, {
      status: "failed",
      error,
      updatedAt: at,
    });
    deps.logger?.warn?.(
      { questionId, derivedScope: registration.derivedScope, error },
      "Derivative question compute failed",
    );
    return {
      status: "failed",
      registration: updated ?? { ...registration, status: "failed", error },
      error,
    };
  }
}
