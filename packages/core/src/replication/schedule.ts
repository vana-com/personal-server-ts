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
/** Dependency waits also rescan on this bound, so a lost wake cannot strand work. */
export const REPLICA_WAIT_FALLBACK_MS = 60_000;

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
      const since = previous.waitSince ?? now;
      if (outcome.dependency.kind !== "finality")
        return {
          outcome,
          state: {
            attempts: 0,
            nextEligible: now + REPLICA_WAIT_FALLBACK_MS,
            waitSince: since,
            checkedBlock: previous.checkedBlock,
          },
        };
      const observed = outcome.dependency.checkedBlock;
      const progressed =
        previous.checkedBlock === null ||
        BigInt(observed) > BigInt(previous.checkedBlock);
      const slow =
        (options.hints === true && !progressed) || now - since >= LONG_WAIT_MS;
      return {
        outcome,
        state: {
          attempts: 0,
          nextEligible: now + (slow ? FINALITY_SLOW_POLL_MS : FINALITY_POLL_MS),
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
