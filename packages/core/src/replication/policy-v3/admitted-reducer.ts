import { canonicalJson } from "./canonical.js";
import type { ReplicaOperation } from "./envelope.js";
import {
  planAdmittedReplicaMerge as planReplicaMerge,
  type MergeContext,
  type ReplicaMergePlan,
} from "./policy-kernel.js";

/** A staging budget, NOT an authenticated transport/admission limit. */
export interface EvidenceBudget {
  maxOperations: number;
  maxCanonicalBytes: number;
}
export interface ReducerOptions {
  /** Must come from the existing replication.enabled flag. Missing is off. */
  replication?: { enabled?: boolean };
  budget: EvidenceBudget;
}
export type ReductionOutcome =
  | {
      status: "accepted";
      added: number;
      operationCount: number;
      canonicalBytes: number;
      plan: ReplicaMergePlan;
    }
  | {
      status: "refused";
      reason:
        | "replication_disabled"
        | "operation_capacity"
        | "byte_capacity"
        | "invalid_evidence";
    };

type FinalitySnapshot = Map<string, number | undefined>;
const copyJson = <T>(value: T): T => JSON.parse(canonicalJson(value));

/** Snapshot data facts; validateData MUST be a pure, immutable predicate. */
function snapshotContext(context: MergeContext): MergeContext {
  if (
    context.now !== undefined &&
    (!Number.isSafeInteger(context.now) || context.now < 0)
  )
    throw new Error("invalid grace clock");
  return {
    owner: context.owner,
    connectorPrincipals: copyJson(context.connectorPrincipals),
    declarations: context.declarations.map((entry) => ({
      sourceId: entry.sourceId,
      binding: copyJson(entry.binding),
      // Capture the function value, not a mutable property on the caller entry.
      // JavaScript closures cannot be cloned; their purity is a host contract.
      validateData: entry.validateData,
    })),
    ...(context.now === undefined ? {} : { now: context.now }),
    ...(context.reobservedRecords === undefined
      ? {}
      : { reobservedRecords: copyJson(context.reobservedRecords) }),
    ...(context.suppressionMarkers === undefined
      ? {}
      : { suppressionMarkers: copyJson(context.suppressionMarkers) }),
  };
}

/** Read each batch fact once per accepted snapshot; refuse invalid host facts. */
function captureFinality(
  provider: MergeContext["finalizedAt"],
  operations: readonly ReplicaOperation[],
  previous: FinalitySnapshot = new Map(),
): FinalitySnapshot {
  const result = new Map(previous);
  for (const batchId of [
    ...new Set(operations.map((operation) => operation.batchId)),
  ].sort()) {
    if (result.has(batchId)) continue;
    const value = provider?.(batchId);
    if (value !== undefined && (!Number.isSafeInteger(value) || value < 0))
      throw new Error("invalid authenticated finality");
    result.set(batchId, value);
  }
  return result;
}

/**
 * INTERNAL TRUSTED-INPUT CORE: the schema wrapper admits every input first.
 * Exact bounded evidence, not winner compaction. Every distinct canonical
 * operation variant is retained (including all equivocations and losers).
 * Thus for each accepted prefix S, decode(evidence) = set(S), and projecting
 * evidence equals the full-history oracle. There is no per-key filtering that
 * can hide cross-key collisions or late named parents/resolutions.
 *
 * Capacity refusal is atomic and is NOT acknowledgement of the new operation.
 * Hosts must retain/retry refused custody evidence outside this staging object;
 * they may not present the old plan as the view of a fully admitted larger set.
 * No persistence, host visibility, scheduling, erasure or checkpoint is done.
 */
export function createAdmittedReplicaReducer(
  context: MergeContext,
  options: ReducerOptions,
) {
  for (const limit of [
    options.budget.maxOperations,
    options.budget.maxCanonicalBytes,
  ])
    if (!Number.isSafeInteger(limit) || limit < 1)
      throw new Error("invalid evidence budget");
  const enabled = options.replication?.enabled === true;
  const budget = { ...options.budget };
  let evidence = new Map<string, string>();
  let bytes = 0;
  let currentContext = enabled ? snapshotContext(context) : undefined;
  let finalityProvider = enabled ? context.finalizedAt : undefined;
  let finality: FinalitySnapshot = new Map();
  let currentPlan = currentContext
    ? planReplicaMerge(currentContext, [])
    : undefined;
  const encoder = new TextEncoder();
  const decode = (values: Iterable<string>): ReplicaOperation[] =>
    [...values].map((encoded) => JSON.parse(encoded) as ReplicaOperation);
  const copyPlan = (plan: ReplicaMergePlan): ReplicaMergePlan =>
    JSON.parse(canonicalJson(plan));

  return {
    push(input: readonly ReplicaOperation[]): ReductionOutcome {
      if (!enabled)
        return { status: "refused", reason: "replication_disabled" };
      const additions = new Map<string, string>();
      let addedBytes = 0;
      try {
        for (const raw of input) {
          const operation = raw;
          const encoded = canonicalJson(operation);
          if (evidence.has(encoded) || additions.has(encoded)) continue;
          if (evidence.size + additions.size + 1 > budget.maxOperations)
            return { status: "refused", reason: "operation_capacity" };
          addedBytes += encoder.encode(encoded).byteLength;
          if (bytes + addedBytes > budget.maxCanonicalBytes)
            return { status: "refused", reason: "byte_capacity" };
          additions.set(encoded, encoded);
        }
        const nextEvidence = new Map([...evidence, ...additions]);
        const operations = decode(nextEvidence.values());
        const nextFinality = captureFinality(
          finalityProvider,
          operations,
          finality,
        );
        const nextPlan = planReplicaMerge(
          {
            ...currentContext!,
            finalizedAt: (batchId) => nextFinality.get(batchId),
          },
          operations,
        );
        // Obtain a detached receipt BEFORE committing, so no throw can expose a
        // half-accepted transaction. Caller mutation never modifies evidence.
        const receipt = copyPlan(nextPlan);
        evidence = nextEvidence;
        bytes += addedBytes;
        currentPlan = nextPlan;
        finality = nextFinality;
        return {
          status: "accepted",
          added: additions.size,
          operationCount: evidence.size,
          canonicalBytes: bytes,
          plan: receipt,
        };
      } catch {
        return { status: "refused", reason: "invalid_evidence" };
      }
    },
    /** Finality/declarations/markers can change without new operations. Atomic. */
    reproject(nextContext: MergeContext): ReductionOutcome {
      if (!enabled)
        return { status: "refused", reason: "replication_disabled" };
      try {
        const snapshot = snapshotContext(nextContext);
        const operations = decode(evidence.values());
        const nextFinality = captureFinality(
          nextContext.finalizedAt,
          operations,
        );
        const nextPlan = planReplicaMerge(
          { ...snapshot, finalizedAt: (batchId) => nextFinality.get(batchId) },
          operations,
        );
        const receipt = copyPlan(nextPlan);
        currentContext = snapshot;
        finalityProvider = nextContext.finalizedAt;
        finality = nextFinality;
        currentPlan = nextPlan;
        return {
          status: "accepted",
          added: 0,
          operationCount: evidence.size,
          canonicalBytes: bytes,
          plan: receipt,
        };
      } catch {
        return { status: "refused", reason: "invalid_evidence" };
      }
    },
    get plan(): ReplicaMergePlan | undefined {
      return currentPlan && copyPlan(currentPlan);
    },
    get operationCount(): number {
      return evidence.size;
    },
    get canonicalBytes(): number {
      return bytes;
    },
    /** Detached exact evidence for a future durable host transaction. */
    retainedOperations(): ReplicaOperation[] {
      return decode(evidence.values());
    },
  };
}
