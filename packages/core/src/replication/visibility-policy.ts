/** One policy for every replica read surface. Reader identity is supplied by the trusted host. */
export type ReplicaReader = "owner" | "grant";
export type ReplicaVisibilityState = "confirmed" | "pending" | "quarantined";
export interface ReplicaVisibilityPolicy {
  owner: "confirmed-only" | "include-pending";
  grant: "confirmed-only" | "include-pending";
}
export const DEFAULT_REPLICA_VISIBILITY_POLICY: Readonly<ReplicaVisibilityPolicy> =
  {
    owner: "include-pending",
    grant: "confirmed-only",
  };
export function replicaStateVisible(
  state: ReplicaVisibilityState,
  reader: ReplicaReader = "grant",
  policy: ReplicaVisibilityPolicy = DEFAULT_REPLICA_VISIBILITY_POLICY,
): boolean {
  return (
    state === "confirmed" ||
    (state === "pending" && policy[reader] === "include-pending")
  );
}
