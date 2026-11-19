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
// what it holds of that key now (the workspace seed transaction). The same
// commit moves its position back to the last one both logs agree on (0 for none). The
// next apply reads the registry's history from there, merged by stamp over its
// rows, and the next publish writes the queued changes on top of it. Every
// operation merges per key by stamp, so the log then holds, for every key, the
// greatest of both histories, and every reader converges on it.

import {
  logScope,
  type SegmentRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import {
  fetchWireSegment,
  fetchWireSnapshotPart,
  type LogApplyContext,
} from "./log-apply.js";
import { openDiskFold } from "./log-disk-fold.js";
import { type LogState } from "./log-state.js";

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
  const fold = await openDiskFold(
    deps,
    connectionId,
    context.keyCheck,
    JSON.stringify(local),
    context.generation,
  );
  let complete = false;
  try {
    let position = 0;
    for (const part of snapshot?.parts ?? []) {
      const input = await fetchWireSnapshotPart(
        deps,
        scope,
        context,
        part.dataHash,
        snapshot!.position,
      );
      await fold.ingest(
        `snapshot:${position}`,
        part.dataHash,
        position++,
        input,
        scope,
      );
    }
    for (const ref of [...lost].sort((a, b) => a.position - b.position)) {
      const { segment } = await fetchWireSegment(
        deps,
        scope,
        context,
        ref.dataHash,
        ref.position,
      );
      await fold.ingest(
        `segment:${ref.position}`,
        ref.dataHash,
        position++,
        segment,
        scope,
      );
    }
    for await (const entry of fold.entries(false)) {
      if (entry.kind === "upsert-ref")
        throw new Error("seed_requires_resolved_entry");
      const pk =
        entry.kind === "upsert" ? [] : await fold.primaryKey(entry.stream);
      await fold.seedEntry(entry, pk);
    }
    await fold.ws.transition("collect", "folded");
    await fold.ws.promoteSeed(
      local,
      fork === 0
        ? { position: 0, base: 0, refs: [], snapshot: null }
        : {
            position: fork,
            base: local.base,
            refs: local.refs.filter((ref) => ref.position <= fork),
            snapshot: local.snapshot,
          },
      fold.controlVersion,
    );
    deps.logger.warn(
      {
        connectionId,
        device: local.position,
        fork,
        segments: lost.length,
        snapshot: snapshot !== null,
      },
      "stream sync: queued divergent history and reset the local cursor",
    );
    complete = true;
    return fork;
  } finally {
    await fold.close(complete);
  }
}
