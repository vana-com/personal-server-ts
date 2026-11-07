/**
 * §2.4 admission and generation rule.
 *
 * At run start the host stores `start`: a copy of the connector's control
 * states from the last registry listing completed in this app session, keyed
 * by ns, or `null` when no listing has completed. At publish,
 *
 *   S = start == null ? unknown : start[ns] ?? absent
 *   C = the authoritative control read
 *
 * and `decide(S, C)` gives the action. The target generation T depends on S
 * alone (absent → 1, active(g0) → g0, deleted(v0) → v0 + 1), so every stream
 * of one run publishes under the same T, or the run is discarded. A spool is
 * never re-bound to another generation.
 *
 * After a create or reconnect reply (2xx or `replayed`) the host re-reads
 * the control row and calls `decide` again with phase `after_write`; only
 * `publish` may follow, anything else discards. A replay proves only that the
 * row was written once.
 */

import type { ControlState } from "./control.js";
import { hasOwn } from "./json.js";

export type StartSnapshot = Readonly<Record<string, ControlState>> | null;

export type StartState = { readonly kind: "unknown" } | ControlState;

export function startState(start: StartSnapshot, ns: string): StartState {
  if (start === null) return { kind: "unknown" };
  return hasOwn(start, ns) ? start[ns]! : { kind: "absent" };
}

/**
 * `first`: first decision for this stream in this attempt.
 * `reread`: the host re-read control once after a `reread` decision.
 * `after_write`: the host re-read control after its create/reconnect reply.
 * `stale_base`: the host re-read control after `chooseBase` returned
 *   `stale_generation` (a stream head of a newer generation than T).
 */
export type DecidePhase = "first" | "reread" | "after_write" | "stale_base";

export interface DecideInput {
  readonly start: StartState;
  readonly current: ControlState;
  /** True only when an explicit connect action started this run. */
  readonly userConnect: boolean;
  /** The run used no checkpoint. */
  readonly full: boolean;
  readonly phase: DecidePhase;
}

export type Decision =
  | { readonly kind: "publish"; readonly target: number }
  /** POST control v1 ACTIVE (exclusive), then re-read and decide `after_write`. */
  | { readonly kind: "create"; readonly target: 1 }
  /** POST control v0+1 ACTIVE (exclusive), then re-read and decide `after_write`. */
  | { readonly kind: "reconnect"; readonly target: number }
  /** Re-read control once and decide with phase `reread`. */
  | { readonly kind: "reread" }
  | {
      readonly kind: "keep_pending";
      readonly reason: "registry_inconsistent" | "key_mismatch";
    }
  | {
      readonly kind: "discard";
      /** Start snapshot was unknown: collect again. */
      readonly recollect: boolean;
      /** Clear checkpoints for (c, ns). */
      readonly clearCheckpoints: boolean;
      /** A userConnect run discarded only for not being full: start a full run now. */
      readonly restartFull: boolean;
    };

const DISCARD = {
  kind: "discard",
  recollect: false,
  clearCheckpoints: false,
  restartFull: false,
} as const;

function table(input: DecideInput): Decision {
  const { start: s, current: c, userConnect, full, phase } = input;
  // `any | foreign` overrides the `other` cells (see DESIGN-QUESTIONS.md Q1).
  if (c.kind === "foreign")
    return { kind: "keep_pending", reason: "key_mismatch" };
  switch (s.kind) {
    case "unknown":
      return { ...DISCARD, recollect: true };
    case "absent":
      if (c.kind === "absent") return { kind: "create", target: 1 };
      if (c.kind === "active" && c.generation === 1) {
        return { kind: "publish", target: 1 };
      }
      return DISCARD;
    case "active": {
      const g0 = s.generation;
      if (c.kind === "active" && c.generation === g0) {
        return { kind: "publish", target: g0 };
      }
      if (c.kind === "absent" || (c.kind === "active" && c.generation < g0)) {
        return phase === "reread"
          ? { kind: "keep_pending", reason: "registry_inconsistent" }
          : { kind: "reread" };
      }
      return { ...DISCARD, clearCheckpoints: true };
    }
    case "deleted": {
      const v0 = s.version;
      const sameDelete = c.kind === "deleted" && c.version === v0;
      const reconnected = c.kind === "active" && c.generation === v0 + 1;
      if (userConnect && full) {
        if (sameDelete) return { kind: "reconnect", target: v0 + 1 };
        if (reconnected) return { kind: "publish", target: v0 + 1 };
      }
      return {
        ...DISCARD,
        restartFull: userConnect && !full && (sameDelete || reconnected),
      };
    }
    case "foreign":
      // No table row starts from foreign (DESIGN-QUESTIONS.md Q2).
      return DISCARD;
  }
}

export function decide(input: DecideInput): Decision {
  const decision = table(input);
  if (input.phase === "after_write" && decision.kind !== "publish") {
    // §2.4: after create/reconnect, C must re-read as active(T), else discard.
    return DISCARD;
  }
  if (input.phase === "stale_base") {
    // P0-RULINGS F1: a stream head of a newer generation than T exists, so
    // the start snapshot is older than the registry. The table normally
    // discards (with its §2.4 checkpoint rule). If control still admits T,
    // the registry contradicts itself: keep pending, never publish or write.
    if (decision.kind === "discard" || decision.kind === "keep_pending") {
      return decision;
    }
    return { kind: "keep_pending", reason: "registry_inconsistent" };
  }
  return decision;
}

/** The target generation a start state admits, or `null` (unknown, foreign). */
export function targetFor(start: StartState): number | null {
  switch (start.kind) {
    case "absent":
      return 1;
    case "active":
      return start.generation;
    case "deleted":
      return start.version + 1;
    default:
      return null;
  }
}

/** Per-stream result of one run, as kept in the outbox. */
export type StreamRunResult =
  | {
      readonly state: "committed" | "noop";
      readonly generation: number;
      /** `complete` of the committed (or unchanged) head. */
      readonly complete: boolean;
    }
  | {
      /** Not committed: still pending (including a visible failure) or discarded. */
      readonly state: "pending" | "discarded";
    };

export type CheckpointDecision =
  | { readonly kind: "save"; readonly generation: number }
  | {
      readonly kind: "skip";
      readonly reason:
        | "stream_not_committed"
        | "published_incomplete"
        | "seed_receipts_pending"
        | "control_changed";
    };

/**
 * §2.4 checkpoint save: after every stream of the run is committed or no-op
 * at T, re-read control. Save tagged (ns, T) only if it is `active(T)` and
 * no stream was published `complete:false` or left a `complete:false` head
 * unchanged (no-op, ruling Q9). A `record_too_large` exclusion
 * does not block; a `bucket_too_large` stream is not committed and does. §2.9:
 * the checkpoint also waits for every seed receipt of the run (a host merging its retained history).
 */
export function checkpointDecision(input: {
  readonly target: number;
  readonly streams: Readonly<Record<string, StreamRunResult>>;
  /** Control re-read after the last commit. */
  readonly control: ControlState;
  readonly seedReceiptsPending: boolean;
}): CheckpointDecision {
  const results = Object.values(input.streams);
  for (const result of results) {
    if (result.state !== "committed" && result.state !== "noop") {
      return { kind: "skip", reason: "stream_not_committed" };
    }
    if (result.generation !== input.target) {
      return { kind: "skip", reason: "stream_not_committed" };
    }
  }
  for (const result of results) {
    // Q9 ruling: a no-op onto a `complete:false` base blocks the checkpoint
    // the same as publishing `complete:false` (liveness L3).
    if ("complete" in result && !result.complete) {
      return { kind: "skip", reason: "published_incomplete" };
    }
  }
  if (input.seedReceiptsPending)
    return { kind: "skip", reason: "seed_receipts_pending" };
  if (
    input.control.kind !== "active" ||
    input.control.generation !== input.target
  ) {
    return { kind: "skip", reason: "control_changed" };
  }
  return { kind: "save", generation: input.target };
}
