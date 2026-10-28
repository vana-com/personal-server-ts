import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import { canonicalJson, replicaOperationSchema } from "./envelope.js";
import type {
  DeclarationBinding,
  RecordOperation,
  ReplicaOperation,
} from "./envelope.js";
import { connectionKey } from "./identity.js";
import { compareRevisions } from "./revision.js";

/** Provisional decisions: revise this profile here, then update the pinned vectors. */
export const REPLICA_POLICY = {
  mutableOrder: "lamport-writer-operation",
  retainLosers: true,
  laterUpsertResurrects: true,
  appendOnlyConflict: "quarantine-until-separately-authorized-repair",
  authorization: "single-issuer-data-and-connection-evidence-only",
} as const;

export interface MergeContext {
  owner: string;
  /** Retained, digest-verified declarations. Validation must use that exact schema. */
  declarations: readonly {
    sourceId: string;
    binding: DeclarationBinding;
    validateData: (data: Record<string, unknown>) => boolean;
  }[];
}
/**
 * Every reason a plan issue can carry. Hosts branch on these strings, so a new
 * reason is a profile change. The last group is added by the Node receiver to
 * its own copy of the plan; `visibility-engine.ts` states those decisions as
 * typed projection fields instead.
 */
export type MergeIssueReason =
  | "wrong_owner"
  | "operation_id_equivocation"
  | "connection_deleted"
  | "incompatible_connection_binding"
  | "missing_connection_registration"
  | "invalid_generation_reset"
  | "missing_generation_reset"
  | "old_generation"
  | "missing_declaration"
  | "append_only_delete"
  | "invalid_record_data"
  | "incompatible_record_declaration"
  | "append_only_content_conflict"
  // Host-added.
  | "missing_local_connection"
  | "missing_or_invalid_blob"
  | "unverified_completion"
  | "incompatible_completion_declaration";
export interface MergeIssue {
  reason: MergeIssueReason;
  operations: ReplicaOperation[];
}
export interface MergedRecord {
  identity: {
    owner: string;
    sourceId: string;
    connectionId: string;
    generation: number;
    stream: string;
    recordKey: string;
  };
  winner: RecordOperation | null;
  losers: RecordOperation[];
  quarantined: boolean;
}
export interface ReplicaMergePlan {
  records: MergedRecord[];
  conflicts: MergeIssue[];
  rejected: MergeIssue[];
  pending: MergeIssue[];
  suppressed: MergeIssue[];
}

/**
 * Recompute from the complete retained operation set, including lifecycle evidence.
 * The host must retain losers, conflicts, pending operations and tombstones across calls.
 * This is the full-history oracle: `evaluate` in `visibility-engine.ts` derives
 * the projection from it, and every bounded engine is tested against it.
 * This converges; it cannot establish which offline scrape is freshest upstream.
 * No I/O, local history version allocation, grant copying, or repair authorization.
 */
export function planReplicaMerge(
  context: MergeContext,
  input: readonly ReplicaOperation[],
): ReplicaMergePlan {
  const result: ReplicaMergePlan = {
    records: [],
    conflicts: [],
    rejected: [],
    pending: [],
    suppressed: [],
  };
  const issue = (
    bucket: MergeIssue[],
    reason: MergeIssueReason,
    operations: ReplicaOperation[],
  ) => bucket.push({ reason, operations });
  const byId = new Map<string, Map<string, ReplicaOperation>>();
  /** Every owned operation, equivocated variants included. */
  const evidence: ReplicaOperation[] = [];
  for (const raw of input) {
    const operation = replicaOperationSchema.parse(raw);
    if (operation.owner !== context.owner) {
      issue(result.rejected, "wrong_owner", [operation]);
      continue;
    }
    const id = canonicalJson([
      operation.revision.writerId,
      operation.revision.operationId,
    ]);
    evidence.push(operation);
    const variants = byId.get(id) ?? new Map();
    variants.set(canonicalJson(operation), operation);
    byId.set(id, variants);
  }
  const blockedConnections = new Set<string>();
  const operations: ReplicaOperation[] = [];
  for (const variants of byId.values()) {
    if (variants.size > 1) {
      const colliding = [...variants.values()];
      issue(result.conflicts, "operation_id_equivocation", colliding);
      for (const operation of colliding)
        blockedConnections.add(connectionKey(operation));
    } else operations.push([...variants.values()][0]);
  }
  const connections = new Map<string, ReplicaOperation[]>();
  for (const operation of operations) {
    const key = connectionKey(operation);
    const list = connections.get(key) ?? [];
    list.push(operation);
    connections.set(key, list);
  }
  // A logical id cannot be rebound to another producer, even when its source
  // differs. Equivocated variants still count as source evidence: dropping
  // them must not make a source-binding conflict disappear (#426).
  for (const entries of connections.values()) {
    const first = entries[0];
    const sources = new Set(
      evidence
        .filter((op) => op.connectionId === first.connectionId)
        .map((op) => op.sourceId),
    );
    if (sources.size > 1) blockedConnections.add(connectionKey(first));
  }
  for (const [key, entries] of connections) {
    if (entries.some((op) => op.kind === "connection-delete")) {
      issue(result.suppressed, "connection_deleted", entries);
      continue;
    }
    const methods = new Set(entries.map((op) => op.methodId));
    if (blockedConnections.has(key) || methods.size !== 1) {
      issue(result.conflicts, "incompatible_connection_binding", entries);
      continue;
    }
    if (!entries.some((op) => op.kind === "connection-register")) {
      issue(result.pending, "missing_connection_registration", entries);
      continue;
    }
    const resets = entries.filter((op) => op.kind === "connection-reset");
    if (resets.some((op) => op.generation !== op.previousGeneration + 1)) {
      issue(result.conflicts, "invalid_generation_reset", entries);
      continue;
    }
    const generation = Math.max(1, ...resets.map((op) => op.generation));
    const generations = new Set([1, ...resets.map((op) => op.generation)]);
    if (generations.size !== generation) {
      issue(result.pending, "missing_generation_reset", entries);
      continue;
    }
    const records = new Map<string, RecordOperation[]>();
    for (const operation of entries) {
      if (operation.kind !== "upsert" && operation.kind !== "delete") continue;
      if (operation.generation < generation) {
        issue(result.suppressed, "old_generation", [operation]);
        continue;
      }
      if (operation.generation > generation) {
        issue(result.pending, "missing_generation_reset", [operation]);
        continue;
      }
      const declaration = context.declarations.find(
        (entry) =>
          entry.sourceId === operation.sourceId &&
          canonicalJson(entry.binding) === canonicalJson(operation.declaration),
      );
      if (!declaration) {
        issue(result.pending, "missing_declaration", [operation]);
        continue;
      }
      if (
        operation.kind === "delete" &&
        declaration.binding.semantics === "append_only"
      ) {
        issue(result.rejected, "append_only_delete", [operation]);
        continue;
      }
      if (operation.kind === "upsert") {
        let valid = false;
        try {
          valid =
            computeRecordKeyFromData(
              operation.data,
              declaration.binding.primaryKey,
            ) === operation.recordKey &&
            declaration.validateData(operation.data);
        } catch {
          /* Invalid data/key cannot enter winner selection. */
        }
        if (!valid) {
          issue(result.rejected, "invalid_record_data", [operation]);
          continue;
        }
      }
      const recordId = canonicalJson([
        operation.declaration.stream,
        operation.recordKey,
      ]);
      const list = records.get(recordId) ?? [];
      list.push(operation);
      records.set(recordId, list);
    }
    for (const candidates of records.values()) {
      candidates.sort((a, b) => compareRevisions(a.revision, b.revision));
      const first = candidates[0];
      const bindings = new Set(
        candidates.map((op) => canonicalJson(op.declaration)),
      );
      const content = new Set(
        candidates.map((op) =>
          canonicalJson(
            op.kind === "upsert" ? { data: op.data, blobs: op.blobs } : null,
          ),
        ),
      );
      const quarantined =
        bindings.size > 1 ||
        (first.declaration.semantics === "append_only" && content.size > 1);
      if (quarantined)
        issue(
          result.conflicts,
          bindings.size > 1
            ? "incompatible_record_declaration"
            : "append_only_content_conflict",
          candidates,
        );
      result.records.push({
        identity: {
          owner: first.owner,
          sourceId: first.sourceId,
          connectionId: first.connectionId,
          generation,
          stream: first.declaration.stream,
          recordKey: first.recordKey,
        },
        winner: quarantined ? null : candidates[candidates.length - 1],
        losers: quarantined ? candidates : candidates.slice(0, -1),
        quarantined,
      });
    }
  }
  // Normalize every output, including diagnostics; replay multiplicity is unobservable.
  for (const bucket of [
    result.conflicts,
    result.rejected,
    result.pending,
    result.suppressed,
  ]) {
    const unique = new Map<string, MergeIssue>();
    for (const entry of bucket) {
      entry.operations = [
        ...new Map(
          entry.operations.map((op) => [canonicalJson(op), op]),
        ).values(),
      ].sort((a, b) => compareText(canonicalJson(a), canonicalJson(b)));
      unique.set(canonicalJson(entry), entry);
    }
    bucket.splice(
      0,
      bucket.length,
      ...[...unique.values()].sort((a, b) =>
        compareText(canonicalJson(a), canonicalJson(b)),
      ),
    );
  }
  result.records.sort((a, b) =>
    compareText(canonicalJson(a.identity), canonicalJson(b.identity)),
  );
  return result;
}
function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
