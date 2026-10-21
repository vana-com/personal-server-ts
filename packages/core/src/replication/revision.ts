/** Hybrid logical observation time persisted atomically with each operation. */
export interface ReplicaRevision {
  wallMs: number;
  logical: number;
  writerId: string;
  operationId: string;
}

/** Deterministic code-unit ordering for the final tie-break only. */
export function compareRevisions(
  a: ReplicaRevision,
  b: ReplicaRevision,
): number {
  for (const [left, right] of [
    [a.logical, b.logical],
    [a.writerId, b.writerId],
    [a.operationId, b.operationId],
  ] as const) {
    if (left < right) return -1;
    if (left > right) return 1;
  }
  return 0;
}

export function nextHlc(
  local: ReplicaRevision,
  observed: readonly ReplicaRevision[],
  now: number,
): Pick<ReplicaRevision, "wallMs" | "logical"> {
  if (!Number.isSafeInteger(now) || now < 0)
    throw new Error("invalid HLC wall time");
  const all = [local, ...observed];
  for (const revision of all) {
    if (
      !Number.isSafeInteger(revision.wallMs) ||
      revision.wallMs < 0 ||
      !Number.isSafeInteger(revision.logical) ||
      revision.logical < 0
    ) {
      throw new Error("invalid HLC revision");
    }
  }
  const wallMs = Math.max(now, ...all.map((revision) => revision.wallMs));
  const logical =
    all
      .filter((revision) => revision.wallMs === wallMs)
      .reduce((maximum, revision) => Math.max(maximum, revision.logical), -1) +
    1;
  if (!Number.isSafeInteger(logical))
    throw new Error("HLC logical counter exhausted");
  return { wallMs, logical };
}

/** Receiving clocks are bounded so a single bad clock cannot drag peers forward. */
export function receiveHlc(
  remote: ReplicaRevision,
  now: number,
  uncertaintyWindowMs: number,
): {
  revision: Pick<ReplicaRevision, "wallMs" | "logical">;
  clockAhead: boolean;
} {
  if (
    !Number.isSafeInteger(now) ||
    now < 0 ||
    !Number.isSafeInteger(uncertaintyWindowMs) ||
    uncertaintyWindowMs < 0 ||
    !Number.isSafeInteger(remote.wallMs) ||
    remote.wallMs < 0 ||
    !Number.isSafeInteger(remote.logical) ||
    remote.logical < 0
  )
    throw new Error("invalid received HLC revision");
  const maximum = now + uncertaintyWindowMs;
  if (!Number.isSafeInteger(maximum)) throw new Error("invalid HLC window");
  const wallMs = Math.min(remote.wallMs, maximum);
  return {
    revision: {
      wallMs,
      logical: wallMs === remote.wallMs ? remote.logical : 0,
    },
    clockAhead: remote.wallMs > maximum,
  };
}
