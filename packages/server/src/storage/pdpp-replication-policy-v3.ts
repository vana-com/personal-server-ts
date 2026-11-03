import {
  createBoundedReplicaReducer,
  type MergeContext,
  type ReducerOptions,
} from "@opendatalabs/personal-server-ts-core/replication/policy-v3";

/** Node's bounded v3 staging index; does not write canonical rows or custody. */
export function createNodePolicyV3Reducer(
  context: MergeContext,
  options: ReducerOptions,
) {
  return createBoundedReplicaReducer(context, options);
}
