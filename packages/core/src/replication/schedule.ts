import type { ReplicaOutcome, ReplicaPhaseOutcome } from "./outcome.js";

/** Delay before failure attempt n (n >= 1). */
export type ReplicaBackoff = (attempt: number) => number;

export const defaultReplicaBackoff: ReplicaBackoff = (attempt) =>
  Math.min(3_600_000, 1000 * 2 ** Math.min(Math.max(attempt, 1) - 1, 12));

/** Durable timing of one work item. Independent of payload and projection. */
export interface ReplicaWorkState {
  /** Consecutive failures only. A Wait is a successful read and resets it. */
  attempts: number;
  nextEligible: number;
  waitSince: number | null;
  /** Highest verified finalized height observed. Never a hint. */
  checkedBlock: string | null;
}

export const initialReplicaWorkState: ReplicaWorkState = {
  attempts: 0,
  nextEligible: 0,
  waitSince: null,
  checkedBlock: null,
};

/** Terminal items are never due again on a timer or dependency wake. */
export const REPLICA_TERMINAL = Number.MAX_SAFE_INTEGER;
const FINALITY_POLL_MS = 2_000;
const FINALITY_SLOW_POLL_MS = 30_000;
const LONG_WAIT_MS = 600_000;
const FINALITY_BACKOFF_CAP_MS = 16_000;
const DEPENDENCY_BACKOFF_CAP_MS = 300_000;
const DEPENDENCY_LONG_POLL_MS = 600_000;
/** Dependency waits also rescan on this bound, so a lost wake cannot strand work. */
export const REPLICA_WAIT_FALLBACK_MS = 60_000;

function growingWaitDelay(
  age: number,
  first: number,
  cap: number,
  long: number,
) {
  if (age >= LONG_WAIT_MS) return long;
  let interval = first;
  let elapsed = 0;
  while (interval < cap && age >= elapsed + interval) {
    elapsed += interval;
    interval = Math.min(cap, interval * 2);
  }
  return interval;
}

const maxHeight = (a: string | null, b: string) =>
  a === null || BigInt(b) > BigInt(a) ? b : a;

/**
 * Pure transition from a phase verdict to the next durable state.
 * `hints` is true when the host supplies finalized-head scheduling hints; a
 * hint can make a parked wait eligible early but never moves a Retry deadline.
 */
export function settleReplicaWork(
  previous: ReplicaWorkState,
  outcome: ReplicaPhaseOutcome,
  now: number,
  options: { backoff?: ReplicaBackoff; hints?: boolean } = {},
): { state: ReplicaWorkState; outcome: ReplicaOutcome } {
  const backoff = options.backoff ?? defaultReplicaBackoff;
  switch (outcome.tag) {
    case "progress":
      return {
        outcome,
        state: {
          attempts: 0,
          nextEligible: now,
          waitSince: null,
          checkedBlock: previous.checkedBlock,
        },
      };
    case "wait": {
      if (
        outcome.dependency.kind === "registration" &&
        outcome.dependency.reason === "own_key_conflict"
      )
        return {
          outcome,
          state: {
            ...previous,
            nextEligible: REPLICA_TERMINAL,
            waitSince: previous.waitSince ?? now,
          },
        };
      const since =
        previous.waitSince ??
        (outcome.dependency.kind === "registration_pending"
          ? outcome.dependency.since
          : now);
      if (
        outcome.dependency.kind !== "finality" &&
        outcome.dependency.kind !== "registration_pending"
      )
        return {
          outcome,
          state: {
            attempts: 0,
            nextEligible:
              now +
              growingWaitDelay(
                now - since,
                REPLICA_WAIT_FALLBACK_MS,
                DEPENDENCY_BACKOFF_CAP_MS,
                DEPENDENCY_LONG_POLL_MS,
              ),
            waitSince: since,
            checkedBlock: previous.checkedBlock,
          },
        };
      if (
        outcome.dependency.kind === "registration_pending" &&
        outcome.dependency.nextCheckAt !== undefined &&
        outcome.dependency.nextCheckAt > now
      )
        return {
          outcome,
          state: {
            attempts: 0,
            nextEligible: outcome.dependency.nextCheckAt,
            waitSince: since,
            checkedBlock: previous.checkedBlock,
          },
        };
      const observed = outcome.dependency.checkedBlock;
      if (observed === undefined)
        return {
          outcome,
          state: {
            attempts: 0,
            nextEligible:
              now +
              growingWaitDelay(
                now - since,
                FINALITY_POLL_MS,
                FINALITY_BACKOFF_CAP_MS,
                FINALITY_SLOW_POLL_MS,
              ),
            waitSince: since,
            checkedBlock: previous.checkedBlock,
          },
        };
      const progressed =
        previous.checkedBlock === null ||
        BigInt(observed) > BigInt(previous.checkedBlock);
      const delay =
        options.hints === true
          ? !progressed || now - since >= LONG_WAIT_MS
            ? FINALITY_SLOW_POLL_MS
            : FINALITY_POLL_MS
          : growingWaitDelay(
              now - since,
              FINALITY_POLL_MS,
              FINALITY_BACKOFF_CAP_MS,
              FINALITY_SLOW_POLL_MS,
            );
      return {
        outcome,
        state: {
          attempts: 0,
          nextEligible: now + delay,
          waitSince: since,
          checkedBlock: maxHeight(previous.checkedBlock, observed),
        },
      };
    }
    case "retry": {
      const attempts = Math.min(
        Number.MAX_SAFE_INTEGER - 1,
        previous.attempts + 1,
      );
      const nextEligible = now + backoff(attempts);
      return {
        outcome: { ...outcome, nextEligible },
        state: {
          attempts,
          nextEligible,
          waitSince: null,
          checkedBlock: previous.checkedBlock,
        },
      };
    }
    case "quarantine":
    case "unsupported":
      return {
        outcome,
        state: { ...previous, nextEligible: REPLICA_TERMINAL },
      };
  }
}

/**
 * What the coordinator knows when it selects work: its clock reading and the
 * optional finalized-head hint. A hint only parks finality waits; it never
 * makes anything eligible before its durable deadline.
 */
export interface ReplicaEligibility {
  now: number;
  /** Latest finalized-head hint, or undefined when none is known. */
  head: bigint | undefined;
  /** When the coordinator next refreshes the hint. Required with `head`. */
  hintRefreshAt: number | undefined;
}

/** Durable timing of one stored item, as the eligibility policy reads it. */
export interface ReplicaStoredTiming {
  /** True for a Wait whose dependency kind is finality. */
  finalityWait: boolean;
  nextEligible: number;
  waitSince: number | null;
  checkedBlock: string | null;
}

/**
 * When a stored item is next eligible, or undefined when it never is on a
 * timer (terminal or owner-resolved). The one policy behind both due
 * selection and nextWake: an item is due iff the result is <= now.
 *
 * A finality wait whose verified height is not below the hint is parked: a
 * re-read cannot succeed until the hint advances (seen at the next hint
 * refresh) or the wait reaches ten minutes, whichever is first.
 */
export function replicaEligibleAt(
  item: ReplicaStoredTiming,
  eligibility: ReplicaEligibility,
): number | undefined {
  if (item.nextEligible >= REPLICA_TERMINAL) return undefined;
  const { head, hintRefreshAt, now } = eligibility;
  if (
    !item.finalityWait ||
    head === undefined ||
    item.checkedBlock === null ||
    item.waitSince === null ||
    BigInt(item.checkedBlock) < head ||
    item.waitSince + LONG_WAIT_MS <= now
  )
    return item.nextEligible;
  return Math.max(
    item.nextEligible,
    Math.min(item.waitSince + LONG_WAIT_MS, hintRefreshAt ?? now),
  );
}

/**
 * replicaEligibleAt as an SQL expression over a work table's columns, so
 * selection filters parked and terminal rows before LIMIT. NULL = never on a
 * timer. Inputs are numbers and a bigint only; nothing is user text.
 */
export function replicaEligibleAtSql(
  eligibility: ReplicaEligibility,
  columns: {
    outcome: string;
    dependency: string;
    next: string;
    since: string;
    checked: string;
  } = {
    outcome: "outcome",
    dependency: "dependency",
    next: "next_attempt",
    since: "wait_since",
    checked: "checked_block",
  },
): string {
  const { outcome, dependency, next, since, checked } = columns;
  const { head, hintRefreshAt, now } = eligibility;
  const terminal = `${next} >= ${REPLICA_TERMINAL}`;
  if (head === undefined)
    return `(CASE WHEN ${terminal} THEN NULL ELSE ${next} END)`;
  const h = head.toString();
  const parked = `(${outcome} = 'wait' AND (${dependency} LIKE 'finality:%' OR ${dependency} LIKE 'registration_pending:%') AND ${checked} IS NOT NULL AND ${since} IS NOT NULL
    AND (length(${checked}) > ${h.length} OR (length(${checked}) = ${h.length} AND ${checked} >= '${h}'))
    AND ${since} + ${LONG_WAIT_MS} > ${now})`;
  return `(CASE WHEN ${terminal} THEN NULL WHEN ${parked} THEN max(${next}, min(${since} + ${LONG_WAIT_MS}, ${hintRefreshAt ?? now})) ELSE ${next} END)`;
}
