import { canonicalJson, type ReplicaOperation } from "./envelope.js";

/** Logical accepted outbound work, not lifetime history or physical disk use.
 * The byte cap excludes SQLite/WAL overhead and extra ciphertext copies.
 */
export interface ReplicaPendingBudgetLimits {
  operations: number;
  /** UTF-8 canonical operation JSON plus unique blobs held by pending work. */
  logicalBytes: number;
}

export const REPLICA_PENDING_BUDGET_DEFAULTS: Readonly<ReplicaPendingBudgetLimits> =
  Object.freeze({ operations: 1_000_000, logicalBytes: 1024 ** 3 });

export function validateReplicaPendingBudgetLimits(
  limits: ReplicaPendingBudgetLimits,
): ReplicaPendingBudgetLimits {
  for (const [name, value] of Object.entries(limits))
    if (!Number.isSafeInteger(value) || value < 0)
      throw new RangeError(`invalid replica pending ${name} limit`);
  return { operations: limits.operations, logicalBytes: limits.logicalBytes };
}

export function replicaPendingOperationBytes(
  operation: ReplicaOperation,
): number {
  return new TextEncoder().encode(canonicalJson(operation)).byteLength;
}

export class ReplicaPendingCapacityError extends Error {
  readonly code = "replica_pending_capacity";
  readonly retryable = true;

  constructor(
    readonly limit: "operations" | "logicalBytes",
    readonly used: number,
    readonly requested: number,
    readonly maximum: number,
  ) {
    super(`replica pending ${limit} capacity exceeded`);
    this.name = "ReplicaPendingCapacityError";
  }
}

export function assertReplicaPendingCapacity(input: {
  limits: ReplicaPendingBudgetLimits;
  used: { operations: number; logicalBytes: number };
  requested: { operations: number; logicalBytes: number };
}): void {
  for (const counters of [input.used, input.requested])
    for (const [name, value] of Object.entries(counters))
      if (!Number.isSafeInteger(value) || value < 0)
        throw new RangeError(`invalid replica pending ${name}`);
  const operations = input.used.operations + input.requested.operations;
  const logicalBytes = input.used.logicalBytes + input.requested.logicalBytes;
  if (!Number.isSafeInteger(operations) || !Number.isSafeInteger(logicalBytes))
    throw new RangeError("replica pending counter exhausted");
  if (operations > input.limits.operations)
    throw new ReplicaPendingCapacityError(
      "operations",
      input.used.operations,
      input.requested.operations,
      input.limits.operations,
    );
  if (logicalBytes > input.limits.logicalBytes)
    throw new ReplicaPendingCapacityError(
      "logicalBytes",
      input.used.logicalBytes,
      input.requested.logicalBytes,
      input.limits.logicalBytes,
    );
}

export interface ReplicaPublishedOperationIdentity {
  writerId: string;
  operationId: string;
}

/** Proof tied to the exact finalized manifest that covers these survivors. */
export interface ReplicaPublishedBatch {
  batch: string;
  slot: string;
  scope: string;
  version: number;
  commitment: string;
  operations: readonly ReplicaPublishedOperationIdentity[];
}
