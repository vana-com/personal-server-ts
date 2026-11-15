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

import { keccak_256 } from "@noble/hashes/sha3";
import {
  DEFAULT_PART_TARGET_BYTES,
  compactionRequired,
  digestSnapshotPart,
  encodeSnapshotPart,
  foldLog,
  partitionFold,
  shouldCompact,
  snapshotPartBlobName,
  type SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import { fetchSegment, fetchSnapshotPart, type LogState } from "./log-apply.js";

const keccak = async (bytes: Uint8Array) => keccak_256(bytes);

export interface CompactionPlan {
  /** What the next segment's `snapshot` is. Its position is the next `base`. */
  readonly snapshot: SnapshotPointer;
  /** The part objects to upload before the segment, by blob name. */
  readonly parts: readonly {
    readonly name: string;
    readonly cipher: Uint8Array;
  }[];
}

/**
 * The compaction to carry in the next segment, or `null` when the log should
 * not be compacted yet.
 */
export async function planCompaction(
  deps: LocalSyncDeps,
  input: {
    readonly connector: string;
    readonly ns: string;
    readonly generation: number;
    readonly keyCheck: string;
    readonly scope: string;
    readonly log: LogState;
  },
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

  const context = {
    connector: input.connector,
    ns: input.ns,
    keyCheck: input.keyCheck,
  };
  const [parts, segments] = await Promise.all([
    Promise.all(
      previous.map((part) =>
        fetchSnapshotPart(
          deps,
          input.scope,
          context,
          part.dataHash,
          log.snapshot!.position,
        ),
      ),
    ),
    Promise.all(
      log.refs.map(
        async (ref) =>
          (
            await fetchSegment(
              deps,
              input.scope,
              context,
              ref.dataHash,
              ref.position,
            )
          ).segment,
      ),
    ),
  ]);
  const fold = foldLog({ snapshot: parts, segments });
  const folded = partitionFold(
    fold,
    {
      connector: input.connector,
      ns: input.ns,
      generation: input.generation,
      keyCheck: input.keyCheck,
      position: log.position,
    },
    target,
  );
  const built: { name: string; cipher: Uint8Array }[] = [];
  const pointer: { dataHash: `0x${string}`; bytes: number }[] = [];
  for (const part of folded) {
    const clear = encodeSnapshotPart(part);
    const { dataHash } = await digestSnapshotPart(keccak, clear);
    pointer.push({ dataHash, bytes: clear.length });
    built.push({
      name: snapshotPartBlobName(dataHash),
      cipher: await deps.keys.encryptPart(input.scope, clear),
    });
  }
  return {
    snapshot: { position: log.position, parts: pointer },
    parts: built,
  };
}
