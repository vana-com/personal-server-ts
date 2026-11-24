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
//
// A stream cursor the lost segments carried is lost from the log with them.
// The stream's checkpoint entry queues again too, and like every cursor
// waiting to publish it waits for the queued rows (`cursorsRequeued`).
//
// The fold of the lost history is as large as what the device holds, so it is
// built in the database (`log-fold-workspace.ts`) and seeded a page at a time.
// The seeding is idempotent, and the position moves in the last statement
// batch: a crash before it leaves the device at the old position, and the
// next rebase finds the seeded keys pending and skips them.

import {
  logScope,
  type SegmentRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { cursorsRequeued, foldAppliedCursors } from "./cursor.js";
import type { LocalSyncDeps } from "./deps.js";
import {
  fetchWireSegment,
  fetchWireSnapshotPart,
  type LogApplyContext,
} from "./log-apply.js";
import { openFoldWorkspace } from "./log-fold-workspace.js";
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
  // The fold of the lost history is kept in the database, not in memory: it
  // is as large as what the device holds. Parts and segments are read one at
  // a time. No body is read: a seed names a key and reads the record this
  // device holds of it, so the bodies the history names are of no use here.
  const workspace = await openFoldWorkspace(deps.db, connectionId, "rebase");
  try {
    for (const part of snapshot?.parts ?? [])
      await workspace.addPart(
        await fetchWireSnapshotPart(
          deps,
          scope,
          context,
          part.dataHash,
          snapshot!.position,
        ),
      );
    for (const ref of lost)
      await workspace.addSegment(
        (
          await fetchWireSegment(
            deps,
            scope,
            context,
            ref.dataHash,
            ref.position,
          )
        ).segment,
      );
    const streams = workspace.streams();
    await foldAppliedCursors(deps.db, connectionId);
    const cursors = await cursorsRequeued(
      deps.db,
      connectionId,
      streams.filter((meta) => meta.cursor).map((meta) => meta.stream),
    );
    const primaryKeyOf = new Map(
      streams.map((meta) => [meta.stream, meta.primaryKey]),
    );
    // A page of the fold is seeded at a time. Seeding is idempotent: a key
    // with a change pending is left alone, so a crash between a page and the
    // move of the position below only has the next rebase skip what was seeded.
    let keys = 0;
    for await (const page of workspace.pages()) {
      keys += page.length;
      const seed = seedFromHistory(connectionId, page, primaryKeyOf);
      if (seed.length > 0) await deps.db.batch(seed);
    }
    deps.logger.warn(
      {
        connectionId,
        device: local.position,
        fork,
        segments: lost.length,
        snapshot: snapshot !== null,
        keys,
      },
      "stream sync: the log registry holds another history than this device applied; queuing what only this device's history held, and reading the registry's from the last position both agree on",
    );
    await deps.db.batch([
      ...cursors,
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
  } finally {
    await workspace.close();
  }
  return fork;
}
