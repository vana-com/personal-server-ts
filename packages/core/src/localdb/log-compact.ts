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
  controlScope,
  digestSnapshotPart,
  encodeSnapshotPart,
  foldEntryBytes,
  LOG_FORMAT,
  type WireEntry,
  type LogStreamMeta,
  type WireSnapshotPart,
  shouldCompact,
  snapshotPartBlobName,
  type SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import { keccakOf } from "../stream-sync/crypto-port.js";
import { fetchSegmentWire, fetchSnapshotPartWire } from "./log-input.js";
import type { LogState } from "./log-state.js";
import { openDiskFold } from "./log-disk-fold.js";
import { putBodiesOutOfLine } from "./log-bodies.js";
import { outputProducer, sealOutputs, type OutputSet } from "./log-output.js";

export interface CompactionPlan {
  /** What the next segment's `snapshot` is. Its position is the next `base`. */
  readonly snapshot: SnapshotPointer;
  /**
   * The parts, and the pieces of the out-of-line bodies they name, as sealed
   * disk values in the compaction's workspace. No ciphertext lives in the plan.
   */
  readonly outputs: OutputSet;
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
  const fold = await openDiskFold(
    deps,
    controlScope(input.connector, input.ns),
    input.keyCheck,
    JSON.stringify(log),
    input.generation,
  );
  let handedOff = false;
  try {
    let position = 0;
    for (const part of previous) {
      const unit = await fetchSnapshotPartWire(
        deps,
        input.scope,
        context,
        part.dataHash,
        log.snapshot!.position,
      );
      await fold.ingest(
        `snapshot:${position}`,
        part.dataHash,
        position++,
        unit,
        input.scope,
      );
    }
    for (const ref of [...log.refs].sort((a, b) => a.position - b.position)) {
      const { segment } = await fetchSegmentWire(
        deps,
        input.scope,
        context,
        ref.dataHash,
        ref.position,
      );
      await fold.ingest(
        `segment:${ref.position}`,
        ref.dataHash,
        position++,
        segment,
        input.scope,
      );
    }
    await fold.ws.transition("collect", "folded");
    const streams: LogStreamMeta[] = [];
    for await (const meta of fold.metadata()) streams.push(meta);
    const metaBytes =
      JSON.stringify(streams.map((m) => m.stream)).length +
      200 * streams.length;
    const out = outputProducer(deps, fold.ws, fold.lease);
    const pointer: { dataHash: `0x${string}`; bytes: number }[] = [];
    let current: WireEntry[] = [],
      size = metaBytes;
    async function flush() {
      const part: WireSnapshotPart = {
        format: LOG_FORMAT,
        connector: input.connector,
        ns: input.ns,
        generation: input.generation,
        keyCheck: input.keyCheck,
        position: log.position,
        index: pointer.length,
        streams,
        entries: current,
      };
      const clear = encodeSnapshotPart(part);
      const { dataHash } = await digestSnapshotPart(
        keccakOf(deps.streamCrypto),
        clear,
      );
      pointer.push({ dataHash, bytes: clear.length });
      await out.put(
        snapshotPartBlobName(dataHash),
        await deps.keys.encryptPart(input.scope, clear),
      );
      current = [];
      size = metaBytes;
    }
    for await (const entry of fold.entries(true)) {
      // Original references survive on disk; inline winners use the existing piece encoder.
      const bodies = await putBodiesOutOfLine(
        deps,
        input.scope,
        [entry],
        target,
      );
      for (const piece of bodies.pieces)
        await out.put(piece.name, piece.cipher);
      const wire = bodies.ops[0]!;
      const bytes = foldEntryBytes(wire);
      if (current.length > 0 && size + bytes > target) await flush();
      current.push(wire);
      size += bytes;
    }
    await flush();
    await sealOutputs(fold.ws);
    await fold.handOff();
    handedOff = true;
    return {
      snapshot: { position: log.position, parts: pointer },
      outputs: { ws: fold.ws, count: out.count },
    };
  } finally {
    if (!handedOff) await fold.close(false);
  }
}
