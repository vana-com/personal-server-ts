/**
 * Which local runs a read shows on top of a stream's base, decided exactly as
 * the writer will publish them (§2.5). The overlay shows what the writer will
 * publish, nothing else:
 *
 * - runs fold onto the base in publish order, `observedAt` then `runId`;
 * - each step asks the writer's own rule (`writerCompatibility`) with the
 *   writer's own version comparison, against the key and profile that the
 *   previous step would have published; a step the writer skips as a no-op
 *   publishes nothing, so it leaves the profile as it found it;
 * - the same key merges onto the base; a newer connector that changed the key
 *   starts from an empty base, so the view is complete only if that run is
 *   full; any other run is withheld: the writer will not publish it, so its
 *   rows are not shown, and the caller reports it instead of dropping it.
 */

import {
  writerCompatibility,
  type HeadProfile,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { compareConnectorVersions } from "../stream-sync/writer.js";
import type { StreamSyncOverlayRun, StreamSyncOverlayStream } from "./ports.js";

export interface Contribution {
  readonly run: StreamSyncOverlayRun;
  readonly stream: StreamSyncOverlayStream;
}

/** What the writer reads of the stream's current head. */
export interface FoldBase {
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  readonly complete: boolean;
}

export interface Fold {
  /**
   * Every run the writer will publish, in publish order, including those a
   * later key change replaced. `merged` is the tail of it that the view shows.
   */
  readonly chain: readonly Contribution[];
  /** Runs the view shows, in publish order. */
  readonly merged: readonly Contribution[];
  /** Runs the writer will not publish until the connector is newer. */
  readonly withheld: readonly Contribution[];
  /** A merged run replaced the base: none of the base's rows are shown. */
  readonly baseDropped: boolean;
  /** Primary key and profile of the head the writer would publish; null with no base and no run. */
  readonly shape: {
    readonly primaryKey: readonly string[];
    readonly profile: HeadProfile;
  } | null;
  /** The head the writer would publish is complete. */
  readonly complete: boolean;
}

/** Publish order: the order the writer takes runs in. */
export function publishOrder(a: Contribution, b: Contribution): number {
  if (a.run.observedAt !== b.run.observedAt) {
    return a.run.observedAt - b.run.observedAt;
  }
  return a.run.runId < b.run.runId ? -1 : a.run.runId > b.run.runId ? 1 : 0;
}

/**
 * The profiles of the head the writer may leave after this step. It mirrors
 * the writer's isNoop(base, parts, complete): over a base the writer skips the
 * publish when the parts and completeness are unchanged, and the head then
 * keeps the profile it had; otherwise it publishes the run's own profile.
 *
 * - no base (none, or replaced by `empty_base`): always published;
 * - completeness changes: published;
 * - the run holds no record: its parts equal the base's, so skipped;
 * - the run holds records, or the count is unknown: its parts equal the base's
 *   only when every row loses to a row the base already holds, which the
 *   overlay cannot see. Either profile is possible.
 */
function nextProfiles(
  base: FoldBase | null,
  c: Contribution,
  complete: boolean,
): readonly HeadProfile[] {
  if (base === null || complete !== base.complete) return [c.stream.profile];
  if (c.stream.recordCount === 0) return [base.profile];
  return [base.profile, c.stream.profile];
}

/** The profile the view shows when the overlay cannot tell: the higher version, which withholds more. */
function higherProfile(profiles: readonly HeadProfile[]): HeadProfile {
  return profiles.reduce((high, p) =>
    compareConnectorVersions(p.version, high.version) === "higher" ? p : high,
  );
}

/**
 * What the writer does with run `c` over head `state`: refuse it, or publish
 * it and leave these heads (more than one when the overlay cannot tell).
 */
function step(
  state: FoldBase | null,
  c: Contribution,
): {
  readonly refused: boolean;
  readonly replaces: boolean;
  readonly complete: boolean;
  readonly next: readonly FoldBase[];
} {
  const compat = writerCompatibility(
    state,
    c.stream.primaryKey,
    state === null
      ? "equal"
      : compareConnectorVersions(
          c.stream.profile.version,
          state.profile.version,
        ),
  );
  if (compat.kind === "connector_update_required") {
    return { refused: true, replaces: false, complete: false, next: [] };
  }
  // `complete` is `full || base complete`, and an empty base is not complete.
  // A run resumed from another namespace's checkpoint publishes an
  // incomplete head even over a complete base (writer.ts:1465). A descriptor
  // that does not say whether it did (`incompleteOverBase` absent) is taken
  // as one that may have: it is complete only by its own `complete`.
  const baseComplete =
    compat.kind === "use_base" && state !== null && state.complete;
  const over = c.stream.incompleteOverBase;
  const complete =
    over === true
      ? false
      : over === false
        ? c.stream.complete || baseComplete
        : c.stream.complete;
  const base = compat.kind === "empty_base" ? null : state;
  return {
    refused: false,
    replaces: compat.kind === "empty_base",
    complete,
    next: nextProfiles(base, c, complete).map((profile) => ({
      primaryKey: c.stream.primaryKey,
      profile,
      complete,
    })),
  };
}

const sameHead = (a: FoldBase, b: FoldBase): boolean =>
  a.complete === b.complete &&
  a.profile.version === b.profile.version &&
  a.profile.key === b.profile.key &&
  a.primaryKey.length === b.primaryKey.length &&
  a.primaryKey.every((field, i) => field === b.primaryKey[i]);

function addHeads(
  heads: readonly (FoldBase | null)[],
  more: readonly FoldBase[],
): (FoldBase | null)[] {
  const out = [...heads];
  for (const head of more) {
    if (!out.some((h) => h !== null && sameHead(h, head))) out.push(head);
  }
  return out;
}

/**
 * Fold the candidates onto the base in publish order.
 *
 * `state` is the head the view shows. `possible` is every head the writer
 * could hold at this point: where the overlay cannot tell whether the writer
 * published a run (it cannot see whether every row of a run loses to the
 * base), the head has more than one profile; a run the fold withholds may
 * have been published, which gives it the head that run would leave. A run is
 * merged only if the writer publishes it from every possible head and leaves
 * the same completeness; otherwise it is withheld. So the fold is never more
 * permissive than the writer, whichever head the writer is in.
 */
export function foldContributions(
  base: FoldBase | null,
  candidates: readonly Contribution[],
): Fold {
  let state: FoldBase | null = base;
  let possible: (FoldBase | null)[] = [base];
  let baseDropped = false;
  let merged: Contribution[] = [];
  const chain: Contribution[] = [];
  const withheld: Contribution[] = [];
  for (const c of [...candidates].sort(publishOrder)) {
    const steps = possible.map((head) => step(head, c));
    const mine = step(state, c);
    const agrees = steps.every(
      (s) =>
        !s.refused &&
        s.replaces === mine.replaces &&
        s.complete === mine.complete,
    );
    if (!agrees || mine.refused) {
      withheld.push(c);
      // The writer may still have published it from a head that accepts it.
      possible = addHeads(
        possible,
        steps.flatMap((s) => s.next),
      );
      continue;
    }
    possible = addHeads(
      [],
      steps.flatMap((s) => s.next),
    );
    if (mine.replaces) {
      baseDropped = true;
      merged = [];
    }
    chain.push(c);
    merged.push(c);
    state = {
      primaryKey: c.stream.primaryKey,
      profile: higherProfile(mine.next.map((n) => n.profile)),
      complete: mine.complete,
    };
  }
  return {
    chain,
    merged,
    withheld,
    baseDropped,
    shape: state && { primaryKey: state.primaryKey, profile: state.profile },
    complete: state?.complete ?? false,
  };
}
