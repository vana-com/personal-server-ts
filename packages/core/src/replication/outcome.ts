/**
 * Closed outcome algebra for replication work. Every phase of the durable
 * coordinator returns exactly one of these. Diagnostics are closed codes and
 * bounded cause chains: exception text never crosses this boundary.
 */

export type ReplicaPhase =
  | "retain"
  | "prepare"
  | "publish"
  | "discover"
  | "download"
  | "confirm"
  | "revalidate"
  | "import"
  | "reconcile";

/** What a Wait waits for. A key is stable across restarts. */
export type ReplicaDependency =
  | { kind: "predecessor"; key: string }
  | { kind: "finality"; key: string; checkedBlock: string }
  | { kind: "fragments"; key: string }
  | { kind: "mapping"; key: string }
  | { kind: "declaration"; key: string }
  | { kind: "blob"; key: string }
  | { kind: "reset"; key: string }
  /**
   * Every retained copy of a batch is disproved and the refetch budget is
   * spent (copy_conflict_unresolved). A new finalized fact for the batch
   * wakes it; otherwise only the owner can resolve it.
   */
  | { kind: "owner"; key: string };

export const dependencyKey = (dependency: ReplicaDependency) =>
  `${dependency.kind}:${dependency.key}`;

/** Why a transient attempt failed. Never exception text. */
export type ReplicaProblem =
  | "evidence_unavailable"
  | "registration_unconfirmed"
  | "head_unavailable"
  | "publish_failed"
  | "download_failed"
  | "commitment_mismatch"
  | "payload_invalid"
  | "import_failed"
  | "prepare_failed"
  | "retain_failed"
  | "discovery_failed"
  | "reconcile_failed"
  | "deadline_exceeded"
  | "storage_failed"
  | "unknown";

/** Error class name plus optional code per level, at most four levels deep. */
export interface ReplicaCause {
  name: string;
  code?: string;
  cause?: ReplicaCause;
}

const MAX_CAUSE_DEPTH = 4;
const safe = (value: string) => value.replace(/[^\w.:-]/g, "").slice(0, 64);

/** Structured, bounded cause chain. Reads class names and codes, never messages. */
export function replicaCause(error: unknown, depth = 1): ReplicaCause {
  if (!(error instanceof Error))
    return { name: error === null ? "null" : typeof error };
  const code = (error as { code?: unknown }).code;
  const cause = error.cause;
  return {
    name: safe(error.name) || "Error",
    ...((typeof code === "string" || typeof code === "number") && {
      code: safe(String(code)),
    }),
    ...(cause !== undefined &&
      depth < MAX_CAUSE_DEPTH && { cause: replicaCause(cause, depth + 1) }),
  };
}

/** A failure whose closed problem code the thrower knows. */
export class ReplicaProblemError extends Error {
  readonly code: ReplicaProblem;
  constructor(
    readonly problem: ReplicaProblem,
    options?: { cause?: unknown },
  ) {
    super(problem, options);
    this.name = "ReplicaProblemError";
    this.code = problem;
  }
}

/**
 * The only error that may become Unsupported. Thrown where one encrypted
 * fragment is measured larger than the storage cap. The preparer may retry a
 * smaller chunk size; at the smallest size framing is proven impossible.
 */
export class ReplicaFramingUnsupported extends Error {
  readonly code = "replica_framing_unsupported";
  constructor(
    readonly actual: number,
    readonly limit: number,
    /** fragment_bytes: one encrypted fragment exceeds the cap. fragment_count: too many fragments. */
    readonly dimension: "fragment_bytes" | "fragment_count" = "fragment_bytes",
  ) {
    super("replica_framing_unsupported");
    this.name = "ReplicaFramingUnsupported";
  }
}

export interface ReplicaAdmission {
  reason: "replica_framing_unsupported";
  actual: number;
  limit: number;
  /** The admitted capability the decision was measured against. */
  capability: string;
}

export interface ReplicaQuarantineProof {
  reason:
    | "immutable_registration_conflict"
    /** Finalized facts contradict a batch, or its writer chain is terminal. */
    | "finalized_conflict"
    | "batch_equivocation"
    | "source_binding_conflict"
    | "local_mapping_conflict";
  key: string;
}

export interface ReplicaReceipt {
  phase: ReplicaPhase;
  key: string;
}

/** A phase verdict. Retry has no deadline yet: the schedule assigns it. */
export type ReplicaPhaseOutcome =
  | { tag: "progress"; receipt: ReplicaReceipt }
  | { tag: "wait"; dependency: ReplicaDependency }
  | { tag: "retry"; problem: ReplicaProblem; cause?: ReplicaCause }
  | { tag: "quarantine"; proof: ReplicaQuarantineProof }
  | { tag: "unsupported"; admission: ReplicaAdmission };

/** The durable outcome after scheduling. */
export type ReplicaOutcome =
  | Exclude<ReplicaPhaseOutcome, { tag: "retry" }>
  | {
      tag: "retry";
      problem: ReplicaProblem;
      cause?: ReplicaCause;
      nextEligible: number;
    };

/** The persisted reason code of an outcome. */
export function outcomeReason(outcome: ReplicaPhaseOutcome): string {
  switch (outcome.tag) {
    case "progress":
      return outcome.receipt.phase;
    case "wait":
      return outcome.dependency.kind;
    case "retry":
      return outcome.problem;
    case "quarantine":
      return outcome.proof.reason;
    case "unsupported":
      return outcome.admission.reason;
  }
}

/** Map any thrown value to Retry. Only a typed problem code chooses the problem. */
export function retryFromError(
  error: unknown,
  fallback: ReplicaProblem,
): Extract<ReplicaPhaseOutcome, { tag: "retry" }> {
  return {
    tag: "retry",
    problem: error instanceof ReplicaProblemError ? error.problem : fallback,
    cause: replicaCause(error),
  };
}
