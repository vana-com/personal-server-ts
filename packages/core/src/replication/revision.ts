/** Persist with the mutation, never derive from a local query version or timestamp. */
export interface ReplicaRevision {
  counter: number;
  writerId: string;
  operationId: string;
  /**
   * Set on an operation a new writer identity re-issues in its rebaseline:
   * the original operation, whose counter it keeps. It orders as that
   * operation, so a re-issue neither outranks a newer write nor loses a tie
   * the original won.
   */
  origin?: { writerId: string; operationId: string };
}

/**
 * Counter, then the original writer and operation ids, then the operation's
 * own. Code-unit ordering is independent of runtime locale.
 */
export function compareRevisions(
  a: ReplicaRevision,
  b: ReplicaRevision,
): number {
  for (const [left, right] of [
    [a.counter, b.counter],
    [a.origin?.writerId ?? a.writerId, b.origin?.writerId ?? b.writerId],
    [
      a.origin?.operationId ?? a.operationId,
      b.origin?.operationId ?? b.operationId,
    ],
    [a.writerId, b.writerId],
    [a.operationId, b.operationId],
  ] as const) {
    if (left < right) return -1;
    if (left > right) return 1;
  }
  return 0;
}

/** Caller must persist the result atomically with its new local operation. */
export function nextLamportCounter(
  local: number,
  observed: readonly number[],
): number {
  let maximum = local;
  for (const counter of [local, ...observed]) {
    if (!Number.isSafeInteger(counter) || counter < 0)
      throw new Error("invalid Lamport counter");
    maximum = Math.max(maximum, counter);
  }
  if (maximum === Number.MAX_SAFE_INTEGER)
    throw new Error("Lamport counter exhausted");
  return maximum + 1;
}
