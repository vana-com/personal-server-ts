/**
 * The compute job: answer one registered question from local data and
 * write the answer as a derivative record (owner path, `$lineage` = the
 * source data points).
 */

import { ProtocolError } from "../errors/catalog.js";
import { ingestDataContract } from "../contracts/data.js";
import { isBinaryEnvelope } from "../contracts/binary.js";
import { assertDerivedScopeNaming } from "../lineage/lineage.js";
import type { StoredLineage } from "../lineage/lineage.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import type { ScopeDeletionTracker } from "../sync/scope-deletions.js";
import type { DataStoragePort } from "../ports/index.js";
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
  now?: () => Date;
  logger?: ComputeLogger;
}

export type ComputeOutcome =
  | { status: "ready"; registration: QuestionRegistration }
  | { status: "failed"; registration: QuestionRegistration; error: string }
  | { status: "skipped"; reason: "unknown-question" };

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

async function loadSource(
  deps: QuestionComputeDeps,
  scope: string,
): Promise<PromptSource> {
  const entry = deps.storage.findEntry({ scope });
  if (!entry) {
    throw new ComputeFailure(`source scope ${scope} has no local data`);
  }
  let envelope;
  try {
    envelope = await deps.storage.readEnvelope(scope, entry.collectedAt);
  } catch {
    throw new ComputeFailure(`source scope ${scope} could not be read`);
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
    scope,
    collectedAt: entry.collectedAt,
    version: entry.version,
    data: trimmed.data,
    kept: trimmed.kept,
    total: trimmed.total,
    truncated: trimmed.truncated,
  };
}

async function assertGrantStillValid(
  deps: QuestionComputeDeps,
  registration: QuestionRegistration,
): Promise<void> {
  if (registration.registeredBy.kind !== "builder" || !deps.writePolicyPorts)
    return;
  if (!deps.serverOwner) {
    throw new ComputeFailure("server owner is not configured");
  }
  await verifyDataWritePolicy(
    {
      signer: registration.registeredBy.builder,
      grantId: registration.registeredBy.grantId,
      requestedScope: registration.derivedScope,
      serverOwner: deps.serverOwner,
    },
    deps.writePolicyPorts,
  );
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
    for (const scope of registration.sourceScopes) {
      sources.push(await loadSource(deps, scope));
    }
    const messages = buildQuestionMessages({
      question: registration.question,
      sources,
    });
    const model = registration.model ?? deps.provider.defaultModel;
    const reply = await deps.provider.chat({
      model,
      messages,
      maxTokens: deps.maxTokens,
    });
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
