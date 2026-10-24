import {
  canonicalJson,
  type ReplicaOperation,
  type RecordOperation,
} from "./envelope.js";
import {
  planReplicaMerge,
  type MergeContext,
  type MergedRecord,
} from "./merge-plan.js";

/**
 * Bounded materialization evidence for ONE key. Original operations, including
 * losers, stay in the durable journal; this is not compaction. Every decision is
 * made by planReplicaMerge. Global identity equivocation and binding conflicts
 * must be detected by the caller's durable indexes before partitioning by key.
 */
export function createReplicaRecordReducer(
  context: MergeContext,
  lifecycle: readonly ReplicaOperation[],
) {
  let identity: string | undefined;
  let evidence: RecordOperation[] = [];
  let record: MergedRecord | undefined;
  return {
    push(operation: RecordOperation) {
      const key = canonicalJson([
        operation.owner,
        operation.sourceId,
        operation.connectionId,
        operation.declaration.stream,
        operation.recordKey,
      ]);
      if (identity !== undefined && identity !== key)
        throw new Error("mixed replica record partition");
      identity = key;
      const plan = planReplicaMerge(context, [
        ...lifecycle,
        ...evidence,
        operation,
      ]);
      record = plan.records[0];
      if (record?.current) evidence = [record.current];
      else if (record?.quarantined) {
        const first = record.candidates[0];
        const witness = record.candidates.find(
          (candidate) =>
            planReplicaMerge(context, [...lifecycle, first, candidate])
              .records[0]?.quarantined,
        );
        if (!witness) throw new Error("missing replica conflict witness");
        evidence = [first, witness];
      } else evidence = [];
    },
    get record() {
      return record;
    },
  };
}
