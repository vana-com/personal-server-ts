import {
  createBoundedReplicaReducer,
  type MergeContext,
  type ReducerOptions,
} from "@opendatalabs/personal-server-ts-core/replication/policy-v3";

/** Lite's identical bounded v3 staging index; no IndexedDB/canonical mutation. */
export function createLitePolicyV3Reducer(
  context: MergeContext,
  options: ReducerOptions,
) {
  return createBoundedReplicaReducer(context, options);
}
