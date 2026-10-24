/** One policy for every replica read surface. Reader identity is supplied by the trusted host. */
export type ReplicaReader = "owner" | "grant";
export type ReplicaVisibilityState =
  "confirmed" | "pending" | "quarantined" | "conflicted";
export type ReplicaRecordOrigin = "local" | "received";
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
  origin: ReplicaRecordOrigin = "received",
): boolean {
  if (state === "conflicted") return reader === "owner" && origin === "local";
  return (
    state === "confirmed" ||
    (state === "pending" && policy[reader] === "include-pending")
  );
}

/** The marker describes every pending effect, including a removal. */
export function replicaPendingMetadata() {
  return {
    confirmation: "not yet confirmed" as const,
    visibility: "pending" as const,
  };
}

/** Identity ambiguity is visible to the owner without declaring received data authoritative. */
export function replicaConflictMetadata() {
  return {
    visibility: "conflicted" as const,
    status: "account conflict" as const,
  };
}

/** The host supplies the durable identity-ambiguity fact, never a request parameter. */
export function replicaConnectionVisibility(bindingConflict: boolean) {
  return bindingConflict
    ? { state: "conflicted" as const, reason: "source_binding" as const }
    : undefined;
}
