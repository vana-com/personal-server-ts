/**
 * Which local runs a read shows on top of a stream's base, decided exactly as
 * the writer will publish them (§2.5). The overlay shows what the writer will
 * publish, nothing else:
 *
 * - runs fold onto the base in publish order, `observedAt` then `runId`;
 * - each step asks the writer's own rule (`writerCompatibility`) with the
 *   writer's own version comparison, against the key and profile that the
 *   previous step would have published;
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

export function foldContributions(
  base: FoldBase | null,
  candidates: readonly Contribution[],
): Fold {
  let state: FoldBase | null = base;
  let baseDropped = false;
  let merged: Contribution[] = [];
  const withheld: Contribution[] = [];
  for (const c of [...candidates].sort(publishOrder)) {
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
      withheld.push(c);
      continue;
    }
    // The writer's head carries the run's own key and profile; `complete` is
    // `full || base complete`, and an empty base is not complete.
    const baseComplete =
      compat.kind === "use_base" && state !== null && state.complete;
    if (compat.kind === "empty_base") {
      baseDropped = true;
      merged = [];
    }
    merged.push(c);
    state = {
      primaryKey: c.stream.primaryKey,
      profile: c.stream.profile,
      complete: c.stream.complete || baseComplete,
    };
  }
  return {
    merged,
    withheld,
    baseDropped,
    shape: state && { primaryKey: state.primaryKey, profile: state.profile },
    complete: state?.complete ?? false,
  };
}
