/**
 * Which local runs a read shows on top of a stream's base. The writer's
 * publish plan (stream-sync/publish-plan.ts) decides what each run does; this
 * module only reads the plan. It decides nothing about publication.
 *
 * Two read rules sit on top of the plan:
 *
 * - **A key reset over the base is not shown before it is imported.** A grant
 *   reads that base until then, and the owner never reads fewer rows than a
 *   grant. The base stays, marked incomplete; the resetting run and every
 *   later run of the stream are withheld.
 * - **A run whose publish merges seed rows is withheld.** The overlay does not
 *   hold seed rows, so it cannot show the head that publish leaves.
 *
 * A run the plan refuses or defers is withheld with the plan's reason. A
 * deferred run, and every run after it, makes the view incomplete: the writer
 * will publish more than the view shows. A refused run changes nothing the
 * writer publishes, so it leaves completeness as the plan says.
 */

import type { HeadProfile } from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  DeferredReason,
  PlanHead,
  PlanStep,
  RefusedReason,
} from "../stream-sync/publish-plan.js";
import type { StreamSyncOverlayRun, StreamSyncOverlayStream } from "./ports.js";

export interface Contribution {
  readonly run: StreamSyncOverlayRun;
  readonly stream: StreamSyncOverlayStream;
}

/** Why the view does not show a run's rows. */
export type WithheldReason =
  | RefusedReason
  | DeferredReason
  /** The run replaces the imported base, which grants still read. */
  | "key_reset_pending"
  /** The run's publish merges seed rows the overlay does not hold. */
  | "seed_pending"
  /** The writer will publish the run, but the projector cannot project it to the requested name. */
  | "projection_unavailable";

export interface WithheldContribution extends Contribution {
  readonly reason: WithheldReason;
}

export interface Fold {
  /** Runs whose plan step the view shows (publish or no-op), in commit order. */
  readonly chain: readonly Contribution[];
  /** Runs whose rows the view shows on top of the base, in commit order. */
  readonly merged: readonly Contribution[];
  /** Runs whose rows the view does not show, with the reason. */
  readonly withheld: readonly WithheldContribution[];
  /** Runs with a stream that has no publish receipt yet. */
  readonly unpublished: readonly string[];
  /** Runs with a stream the writer published and the reader has not imported: no view shows them until it does. */
  readonly awaiting: readonly string[];
  /** Primary key and profile of the head the view shows; null with no base and no run. */
  readonly shape: {
    readonly primaryKey: readonly string[];
    readonly profile: HeadProfile;
  } | null;
  /** The view holds everything the writer will publish, and that head is complete. */
  readonly complete: boolean;
}

/** What the plan reads of an imported head. */
export function planHeadOf(head: {
  readonly generation: number;
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  readonly complete: boolean;
}): PlanHead {
  return {
    generation: head.generation,
    primaryKey: head.primaryKey,
    profile: head.profile,
    complete: head.complete,
  };
}

/**
 * The view of `candidates` over `base`, read from `steps`: the plan the
 * overlay source returned for exactly these runs from `base`.
 */
export function foldPlan(
  base: PlanHead | null,
  candidates: readonly Contribution[],
  steps: readonly PlanStep[],
): Fold {
  const byRun = new Map(candidates.map((c) => [c.run.runId, c]));
  const chain: Contribution[] = [];
  const withheld: WithheldContribution[] = [];
  let shown: PlanStep | null = null;
  let blocked = false;
  for (const step of steps) {
    const c = byRun.get(step.runId);
    if (!c) throw new Error("the plan names a run the read did not ask for");
    const { decision } = step;
    if (decision.kind === "refused") {
      withheld.push({ ...c, reason: decision.reason });
      continue;
    }
    if (blocked) {
      withheld.push({ ...c, reason: "earlier_run_pending" });
      continue;
    }
    const holdsBase = shown ? shown.rows.fromHead : base !== null;
    const reason: WithheldReason | null =
      decision.kind === "deferred"
        ? decision.reason
        : decision.kind === "publish" && decision.replacesBase && holdsBase
          ? "key_reset_pending"
          : decision.kind === "publish" && decision.seed
            ? "seed_pending"
            : null;
    if (reason) {
      withheld.push({ ...c, reason });
      blocked = true;
      continue;
    }
    chain.push(c);
    shown = step;
  }
  const head = shown ? shown.head : base;
  return {
    chain,
    merged: shown ? shown.rows.runs.map((id) => byRun.get(id)!) : [],
    withheld,
    unpublished: candidates
      .filter((c) => c.stream.receipt === undefined)
      .map((c) => c.run.runId),
    awaiting: candidates
      .filter((c) => c.stream.receipt !== undefined)
      .map((c) => c.run.runId),
    shape: head && { primaryKey: head.primaryKey, profile: head.profile },
    complete: !blocked && (head?.complete ?? false),
  };
}
