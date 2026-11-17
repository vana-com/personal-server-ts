// A registry whose log this device cannot continue: it names another segment
// at a position this device applied (a registry restored from a backup, then
// written by another device), or it holds none of the segments this device
// applied (it went back below the snapshot this device rests on). This
// device's rows are the fold of segments the log no longer names. Read on top
// of, they would mix two histories; dropped, they would lose what only those
// segments held and bring back what they deleted.
//
// So this device puts that history back as changes of its own. It reads the
// segments it applied that the log does not name (and its snapshot, when the
// two logs agree on no segment it holds), and queues every key they touched at
// what it holds of that key now (`seedFromHistory`). In the same commit its
// position moves back to the last one both logs agree on (0 for none). The
// next apply reads the registry's history from there, merged by stamp over its
// rows, and the next publish writes the queued changes on top of it. Every
// operation merges per key by stamp, so the log then holds, for every key, the
// greatest of both histories, and every reader converges on it.

import {
  foldLog,
  logScope,
  type SegmentRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import {
  fetchSegment,
  fetchSnapshotPart,
  type LogApplyContext,
} from "./log-apply.js";
import { seedFromHistory } from "./log-seed.js";
import { writeLogState, type LogState } from "./log-state.js";

/**
 * Queue what only this device's history holds and move its position back to
 * the last segment the registry's log (`registry`: the refs it names) agrees
 * on. Returns that position. Nothing is read from the registry here; the
 * caller applies its log next.
 */
export async function rebaseOnLog(
  deps: LocalSyncDeps,
  connectionId: string,
  context: LogApplyContext,
  local: LogState,
  registry: readonly SegmentRef[],
): Promise<number> {
  const scope = logScope(context.connector, context.ns);
  const named = new Map(
    registry.map((ref) => [ref.position, ref.dataHash.toLowerCase()]),
  );
  // A segment lists the ones before it, so the logs agree on every position
  // up to the last one at which they name the same segment.
  const fork = Math.max(
    0,
    ...local.refs
      .filter((ref) => named.get(ref.position) === ref.dataHash.toLowerCase())
      .map((ref) => ref.position),
  );
  const lost = local.refs.filter((ref) => ref.position > fork);
  const snapshot = fork === 0 ? local.snapshot : null;
  const [parts, segments] = await Promise.all([
    Promise.all(
      (snapshot?.parts ?? []).map((part) =>
        fetchSnapshotPart(
          deps,
          scope,
          context,
          part.dataHash,
          snapshot!.position,
        ),
      ),
    ),
    Promise.all(
      lost.map(
        async (ref) =>
          (await fetchSegment(deps, scope, context, ref.dataHash, ref.position))
            .segment,
      ),
    ),
  ]);
  const fold = foldLog({ snapshot: parts, segments });
  const primaryKeyOf = new Map(
    fold.streams.map((meta) => [meta.stream, meta.primaryKey]),
  );
  deps.logger.warn(
    {
      connectionId,
      device: local.position,
      fork,
      segments: lost.length,
      snapshot: snapshot !== null,
      keys: fold.entries.length,
    },
    "stream sync: the log registry holds another history than this device applied; queuing what only this device's history held, and reading the registry's from the last position both agree on",
  );
  await deps.db.batch([
    ...seedFromHistory(connectionId, fold.entries, primaryKeyOf),
    writeLogState(
      connectionId,
      fork === 0
        ? { position: 0, base: 0, refs: [], snapshot: null }
        : {
            position: fork,
            base: local.base,
            refs: local.refs.filter((ref) => ref.position <= fork),
            snapshot: local.snapshot,
          },
    ),
  ]);
  return fork;
}
