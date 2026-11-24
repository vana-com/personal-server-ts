// Compaction of the stream-sync log (stream-sync/src/log.ts, "Compaction").
//
// The writer that is about to commit a segment first asks whether the log has
// grown past the point where replaying it costs more than reading a snapshot
// (`shouldCompact`, from measured primitives), or is at the head's hard bound
// (`compactionRequired`). If so, it folds the log up to its own position into
// snapshot parts, and the segment it commits carries the snapshot pointer, the
// new `base`, and no refs at or below it. The compaction therefore rides the
// batch's own commit: no extra registry write, and the compare-and-set on the
// log row decides between it and any other writer's commit at that position.
//
// The fold comes from the LOG (the previous snapshot's parts and the segments
// after it), never from this device's database. The database holds state the
// log does not (streams published before the log began, local observations),
// so it is not the fold of the prefix.
//
// What a snapshot cannot drop: tombstones. A reader behind the snapshot may
// hold the record a tombstone deletes, and the registry does not know which
// positions readers hold. Nothing in the existing state proves that no reader
// is behind a given deletion, so every tombstone is kept. The log's size is
// therefore bounded by live keys plus deleted keys, not by live keys alone.
//
// Old segments and parts are not deleted from storage here: a reader mid-way
// through the old lineage may still fetch them. Collecting them is a later
// slice.

import {
  DEFAULT_PART_TARGET_BYTES,
  compactionRequired,
  createPartitioner,
  digestSnapshotPart,
  encodeSnapshotPart,
  shouldCompact,
  snapshotPartBlobName,
  type SnapshotPointer,
  type WireSegment,
  type WireSnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import { keccakOf } from "../stream-sync/crypto-port.js";
import {
  fetchWireSegment,
  fetchWireSnapshotPart,
  type LogState,
} from "./log-apply.js";
import { putBodiesOutOfLine } from "./log-bodies.js";
import { openFoldWorkspace } from "./log-fold-workspace.js";
import type { Spool, SpooledObject } from "./log-spool.js";
import { readPartsAhead } from "./part-readahead.js";

export interface CompactionPlan {
  /** What the next segment's `snapshot` is. Its position is the next `base`. */
  readonly snapshot: SnapshotPointer;
  /**
   * Objects to upload before the segment, by blob name: the parts, and the
   * pieces of the out-of-line bodies they name that are not in storage yet.
   * They are in the spool the caller gave, not in memory.
   */
  readonly objects: readonly SpooledObject[];
}

interface CompactionInput {
  readonly connectionId: string;
  readonly connector: string;
  readonly ns: string;
  readonly generation: number;
  readonly keyCheck: string;
  readonly scope: string;
  readonly log: LogState;
}

/**
 * The compaction to carry in the next segment, or `null` when the log should
 * not be compacted yet.
 */
export async function planCompaction(
  deps: LocalSyncDeps,
  input: CompactionInput,
  spool: Spool,
): Promise<CompactionPlan | null> {
  const { log } = input;
  if (log.refs.length === 0) return null;
  const previous = log.snapshot?.parts ?? [];
  const target = deps.partTargetBytes ?? DEFAULT_PART_TARGET_BYTES;
  const required = compactionRequired(log.refs.length, previous.length);
  if (
    !required &&
    !shouldCompact({
      tailSegments: log.refs.length,
      tailBytes: log.refs.reduce((sum, ref) => sum + ref.bytes, 0),
      snapshotBytes: previous.reduce((sum, part) => sum + part.bytes, 0),
      partTargetBytes: target,
    })
  )
    return null;
  return compactLog(deps, input, spool);
}

/**
 * Fold the log up to its position into snapshot parts, whether or not the
 * cost model asks for it. Memory does not grow with the log: the history
 * passes through a disk workspace a segment or part at a time (read ahead
 * within the store's byte budget), and the winners come back in key order a
 * page at a time into parts that go to the spool as each is cut.
 *
 * A body the fold carries forward stays out of line and is not fetched: its
 * pieces are in storage and the part names them. (A fold that read every
 * body, including the ones a later upsert replaced, held each of them at once.)
 * What this gives up is a check at compaction time that those pieces exist:
 * a reader checks them when it applies the record, as it does for the
 * segment that first named them.
 */
export async function compactLog(
  deps: LocalSyncDeps,
  input: CompactionInput,
  spool: Spool,
): Promise<CompactionPlan> {
  const { log } = input;
  const previous = log.snapshot?.parts ?? [];
  const target = deps.partTargetBytes ?? DEFAULT_PART_TARGET_BYTES;
  const context = {
    connector: input.connector,
    ns: input.ns,
    keyCheck: input.keyCheck,
  };
  type Source =
    | { readonly part: (typeof previous)[number]; readonly bytes: number }
    | { readonly ref: (typeof log.refs)[number]; readonly bytes: number };
  const sources: Source[] = [
    ...previous.map((part) => ({ part, bytes: part.bytes })),
    ...[...log.refs]
      .sort((a, b) => a.position - b.position)
      .map((ref) => ({ ref, bytes: ref.bytes })),
  ];
  const workspace = await openFoldWorkspace(deps.db, input.connectionId);
  try {
    const reader = readPartsAhead<Source, WireSnapshotPart | WireSegment>(
      deps.blobs,
      sources,
      async (source) =>
        "part" in source
          ? fetchWireSnapshotPart(
              deps,
              input.scope,
              context,
              source.part.dataHash,
              log.snapshot!.position,
            )
          : (
              await fetchWireSegment(
                deps,
                input.scope,
                context,
                source.ref.dataHash,
                source.ref.position,
              )
            ).segment,
    );
    try {
      for (const [index, source] of sources.entries()) {
        const fetched = await reader.load(source, index);
        if ("part" in source)
          await workspace.addPart(fetched as WireSnapshotPart);
        else await workspace.addSegment(fetched as WireSegment);
        reader.committed(index);
      }
    } finally {
      reader.close();
    }
    const partitioner = createPartitioner(
      workspace.streams(),
      {
        connector: input.connector,
        ns: input.ns,
        generation: input.generation,
        keyCheck: input.keyCheck,
        position: log.position,
      },
      target,
    );
    const pointer: { dataHash: `0x${string}`; bytes: number }[] = [];
    const seal = async (part: WireSnapshotPart) => {
      const clear = encodeSnapshotPart(part);
      const { dataHash } = await digestSnapshotPart(
        keccakOf(deps.streamCrypto),
        clear,
      );
      pointer.push({ dataHash, bytes: clear.length });
      await spool.add(
        snapshotPartBlobName(dataHash),
        await deps.keys.encryptPart(input.scope, clear),
      );
    };
    for await (const page of workspace.pages()) {
      const outOfLine = await putBodiesOutOfLine(
        deps,
        input.scope,
        page,
        target,
      );
      for (const piece of outOfLine.pieces)
        await spool.add(piece.name, piece.cipher);
      for (const entry of outOfLine.ops) {
        const closed = partitioner.push(entry);
        if (closed) await seal(closed);
      }
    }
    await seal(partitioner.finish());
    return {
      snapshot: { position: log.position, parts: pointer },
      objects: spool.objects(),
    };
  } finally {
    await workspace.close();
  }
}
