import { replicaOperationSchema, type ReplicaOperation } from "./envelope.js";
import type { MergeContext } from "./policy-kernel.js";
import {
  createAdmittedReplicaReducer,
  type ReducerOptions,
  type ReductionOutcome,
} from "./admitted-reducer.js";
export type {
  EvidenceBudget,
  ReducerOptions,
  ReductionOutcome,
} from "./admitted-reducer.js";

/** Validate every incoming operation before committing the exact bounded set. */
export function createBoundedReplicaReducer(
  context: MergeContext,
  options: ReducerOptions,
) {
  const enabled = options.replication?.enabled === true;
  const reducer = createAdmittedReplicaReducer(context, options);
  return {
    push(input: readonly ReplicaOperation[]): ReductionOutcome {
      if (!enabled)
        return { status: "refused", reason: "replication_disabled" };
      try {
        return reducer.push(
          input.map((operation) => replicaOperationSchema.parse(operation)),
        );
      } catch {
        return { status: "refused", reason: "invalid_evidence" };
      }
    },
    reproject: reducer.reproject,
    get plan() {
      return reducer.plan;
    },
    get operationCount() {
      return reducer.operationCount;
    },
    get canonicalBytes() {
      return reducer.canonicalBytes;
    },
    retainedOperations: reducer.retainedOperations,
  };
}
