import { replicaOperationSchema, type ReplicaOperation } from "./envelope.js";
import {
  planAdmittedReplicaMerge,
  type MergeContext,
  type ReplicaMergePlan,
} from "./policy-kernel.js";
export * from "./policy-kernel.js";

/** Schema-validating entry point; callers still authenticate the envelope first. */
export function planReplicaMerge(
  context: MergeContext,
  input: readonly ReplicaOperation[],
): ReplicaMergePlan {
  return planAdmittedReplicaMerge(
    context,
    input.map((operation) => replicaOperationSchema.parse(operation)),
  );
}
