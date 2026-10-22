import type { DeclarationBinding, ReplicaOperation } from "./envelope.js";

/** The persisted projection retains only the operation fields this rule needs. */
export type ReplicaStreamEffectOperation<
  T extends ReplicaOperation = ReplicaOperation,
> = T extends { declaration: DeclarationBinding }
  ? Pick<T, "kind"> & { declaration: Pick<DeclarationBinding, "stream"> }
  : Pick<T, "kind">;

/** Connection metadata and blob ownership do not change stream contents. */
export function replicaOperationAffectedStreams(
  op: ReplicaStreamEffectOperation,
): readonly string[] | "all" {
  switch (op.kind) {
    case "upsert":
    case "delete":
    case "stream-invalidate":
    case "stream-complete":
      return [op.declaration.stream];
    case "connection-reset":
    case "connection-delete":
      return "all";
    case "blob-claim":
    case "connection-register":
      return [];
    default: {
      const unknown: never = op;
      throw new Error(`Unknown replica operation: ${JSON.stringify(unknown)}`);
    }
  }
}

/** One policy for every replica read surface. Reader identity is supplied by the trusted host. */
export type ReplicaReader = "owner" | "grant";
export type ReplicaVisibilityState =
  "confirmed" | "pending" | "quarantined" | "conflicted";
export type ReplicaQuarantineReason =
  "copy_conflict" | "finalized_conflict" | "corruption";
/** Only the separate owner copy projection may show quarantined copy values. */
export const REPLICA_COPY_CONFLICT_POLICY = {
  copy_conflict: {
    visibility: "conflicted",
    status: "copy conflict",
    values: true,
  },
  finalized_conflict: {
    visibility: "conflicted",
    status: "integrity conflict",
    values: false,
  },
  corruption: null,
} as const;
export type ReplicaCopyConflictReason = {
  [
    R in ReplicaQuarantineReason
  ]: (typeof REPLICA_COPY_CONFLICT_POLICY)[R] extends null ? never : R;
}[ReplicaQuarantineReason];
export const OWNER_VISIBLE_COPY_REASONS = Object.keys(
  REPLICA_COPY_CONFLICT_POLICY,
).filter(
  (reason): reason is ReplicaCopyConflictReason =>
    REPLICA_COPY_CONFLICT_POLICY[reason as ReplicaQuarantineReason] !== null,
);
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
  reason?: ReplicaQuarantineReason,
): boolean {
  if (state === "quarantined")
    return (
      reader === "owner" &&
      reason !== undefined &&
      REPLICA_COPY_CONFLICT_POLICY[reason] !== null
    );
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

/** Copy values remain on the separate owner diagnostic path, never in the reducer. */
export function replicaCopyConflictMetadata(reason: ReplicaCopyConflictReason) {
  const { visibility, status } = REPLICA_COPY_CONFLICT_POLICY[reason];
  return { visibility, status };
}
