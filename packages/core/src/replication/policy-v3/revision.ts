/** Hybrid logical observation time persisted atomically with each operation. */
export interface ReplicaRevision {
  wallMs: number;
  /** Numbers stay convenient within the safe range; decimal strings preserve larger counters. */
  logical: number | string;
  writerId: string;
  operationId: string;
}
const MAX_LOGICAL_COUNTER = (1n << 64n) - 1n;

/** Deterministic code-unit ordering for the final tie-break only. */
export function compareRevisions(
  a: ReplicaRevision,
  b: ReplicaRevision,
): number {
  const logicalOrder = compareLogicalCounters(a.logical, b.logical);
  if (logicalOrder !== 0) return logicalOrder;
  for (const [left, right] of [
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
  for (const revision of [local, ...observed]) {
    if (
      !Number.isSafeInteger(revision.wallMs) ||
      revision.wallMs < 0 ||
      !isValidLogical(revision.logical)
    ) {
      throw new Error("invalid HLC revision");
    }
  }
  const all = [
    local,
    ...observed.map(
      (remote) => receiveHlc(remote, now, CLOCK_UNCERTAINTY_MS).revision,
    ),
  ];
  const wallMs = Math.max(now, ...all.map((revision) => revision.wallMs));
  const logical =
    all
      .filter((revision) => revision.wallMs === wallMs)
      .map((revision) => BigInt(revision.logical))
      .reduce(
        (maximum, counter) => (counter > maximum ? counter : maximum),
        -1n,
      ) + 1n;
  return { wallMs, logical: toLogicalCounter(logical) };
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
    !isValidLogical(remote.logical)
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

function isValidLogical(value: number | string): boolean {
  if (typeof value === "number")
    return Number.isSafeInteger(value) && value >= 0;
  return /^(0|[1-9]\d*)$/.test(value) && BigInt(value) <= MAX_LOGICAL_COUNTER;
}

export function compareLogicalCounters(
  a: number | string,
  b: number | string,
): number {
  const left = BigInt(a);
  const right = BigInt(b);
  return left < right ? -1 : left > right ? 1 : 0;
}

function toLogicalCounter(value: bigint): number | string {
  if (value > MAX_LOGICAL_COUNTER)
    throw new Error("HLC logical counter exhausted");
  return value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value.toString();
}

export type Hlc = Pick<ReplicaRevision, "wallMs" | "logical">;
export type RawFrontier = Readonly<Record<string, Hlc>>;
export const CLOCK_UNCERTAINTY_MS = 300_000;

/** Raw causal receipt is never replaced with receiveHlc's capped local clock. */
export function recordRawReceipt(
  frontier: RawFrontier,
  remote: ReplicaRevision,
): RawFrontier {
  if (
    !Number.isSafeInteger(remote.wallMs) ||
    remote.wallMs < 0 ||
    !isValidLogical(remote.logical) ||
    !remote.writerId ||
    !remote.operationId
  )
    throw new Error("invalid raw frontier revision");
  const previous = Object.hasOwn(frontier, remote.writerId)
    ? frontier[remote.writerId]
    : undefined;
  const latest =
    previous &&
    (previous.wallMs > remote.wallMs ||
      (previous.wallMs === remote.wallMs &&
        compareLogicalCounters(previous.logical, remote.logical) >= 0))
      ? previous
      : { wallMs: remote.wallMs, logical: remote.logical };
  return { ...frontier, [remote.writerId]: { ...latest } };
}

/** Host persists clock and rawFrontier atomically; this function performs no IO. */
export function observeRemoteClocks(
  local: ReplicaRevision,
  frontier: RawFrontier,
  observed: readonly ReplicaRevision[],
  now: number,
): { clock: Hlc; rawFrontier: RawFrontier; clockWarnings: string[] } {
  let rawFrontier = frontier;
  const clockWarnings = new Set<string>();
  for (const remote of observed) {
    if (remote.writerId !== local.writerId)
      rawFrontier = recordRawReceipt(rawFrontier, remote);
    if (receiveHlc(remote, now, CLOCK_UNCERTAINTY_MS).clockAhead)
      clockWarnings.add(remote.writerId);
  }
  return {
    clock: nextHlc(local, observed, now),
    rawFrontier,
    clockWarnings: [...clockWarnings].sort(),
  };
}
