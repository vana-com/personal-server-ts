import { fetchSegment, fetchSnapshotPart } from "./log-input.js";
export { fetchSegment, fetchSnapshotPart } from "./log-input.js";
import { loadProgressively } from "./log-progressive-workspace.js";
import { loadBootstrap, discardBootstrap } from "./log-bootstrap.js";
// The reader of the stream-sync log (stream-sync/src/log.ts).
//
// One registry read says the log's position. A device at position n fetches
// the newest segment (the head: it lists the older ones) and then only the
// segments after n, and applies them in position order, one batch each. A
// segment's operations are order- and duplicate-insensitive: an upsert merges
// by greatest observation stamp, and every delete and omission leaves a
// tombstone `(stream, pk_hash, stamp, rank)` that an upsert below it cannot
// pass (see `OMISSION_RANK`: an observation at an omission's cutoff passes, one
// at an explicit delete's stamp does not). So the order of delivery matters only for gap detection: position n+1
// is never applied before n, and a segment that cannot be fetched stops the
// pass there (the position stays; the next pass tries again).
//
// A device that is behind the log's `base` installs the snapshot the head
// names, then applies the tail. A registry that is BEHIND this device (a
// rollback or restore) whose row is one this device applied lost only rows:
// this device commits the segments it applied above it again, in order
// (`log-recommit.ts`). A registry that names another segment at a position
// this device applied is not a continuation: the rows, tombstones and
// checkpoints this device holds came from segments the log no longer has.
// This device queues what only those segments held as changes of its own and
// reads the registry's log from the last position both agree on
// (`log-rebase.ts`).

import {
  classifyStreamRow,
  digestSegment,
  digestSnapshotPart,
  encodeSegment,
  encodeSnapshotPart,
  logScope,
  planOpsSince,
  segmentBlobName,
  snapshotPartBlobName,
  type ControlHashes,
  type Segment,
  type SegmentRef,
  type SnapshotPart,
  type SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf } from "../stream-sync/crypto-port.js";
import { rebaseOnLog } from "./log-rebase.js";
import { seedFromRecords } from "./log-seed.js";
import { announceApplied } from "./apply-progress.js";
import type { LocalSyncDeps } from "./deps.js";
import {
  applyBatch,
  applyInGroups,
  stageBatch,
  streamStateStatement,
  type PassItem,
} from "./log-batch.js";
import {
  loadKeyed,
  keyedLoadBlocked,
  planKeyedLoad,
  rebaselineKeyedLoad,
  unfinishedKeyedLoad,
  type KeyedSource,
} from "./log-keyed.js";
import {
  LogDivergedError,
  readKeyedPending,
  readLogState,
  writeLogState,
  type LogState,
} from "./log-state.js";
import { recommitApplied } from "./log-recommit.js";
import {
  failedRowStatement,
  failureCode,
  partialRowStatement,
  type PartialIdentity,
} from "./partial-load.js";

export { recordKeyOfKey } from "./log-batch.js";
export {
  LogDivergedError,
  readLogState,
  writeLogState,
  type LogState,
} from "./log-state.js";

/**
 * Apply one segment's operations to local state, in one batch (origin
 * `remote`). Safe to repeat and to run in any order against other segments:
 * see the file comment. With `state`, the log position is written in the same
 * batch, so a position never runs ahead of the rows it stands for.
 */

export async function applySegmentOperations(
  deps: LocalSyncDeps,
  connectionId: string,
  segment: Segment,
  state?: LogState,
): Promise<void> {
  const { dataHash, blobName } = await digestSegment(
    keccakOf(deps.streamCrypto),
    encodeSegment(segment),
  );
  await applyBatch(deps, connectionId, segment, { dataHash, blobName }, state);
}

/**
 * Apply one snapshot part: its entries are upserts and deletes, applied as the
 * operations of a segment are (in any order, any number of times).
 */
export async function applySnapshotPart(
  deps: LocalSyncDeps,
  connectionId: string,
  part: SnapshotPart,
  state?: LogState,
): Promise<void> {
  const bytes = encodeSnapshotPart(part);
  const { dataHash, blobName } = await digestSnapshotPart(
    keccakOf(deps.streamCrypto),
    bytes,
  );
  await applyBatch(
    deps,
    connectionId,
    {
      generation: part.generation,
      observedAt: 0,
      streams: part.streams,
      operations: part.entries,
    },
    { dataHash, blobName },
    state,
  );
}

export interface LogApplyContext {
  readonly connector: string;
  readonly ns: string;
  readonly generation: number;
  readonly keyCheck: string;
  readonly hashes: ControlHashes;
  /**
   * The registry's row for the log from a listing the caller holds. A row
   * behind this device's position is read again (see `applyLog`).
   */
  readonly read?: Awaited<ReturnType<LocalSyncDeps["registry"]["read"]>>;
}

/**
 * Bring this device to the log's position. One registry read (or the one the
 * caller holds), one GET for the newest segment, one GET for each older segment
 * this device lacks.
 */
export async function applyLog(
  deps: LocalSyncDeps,
  connectionId: string,
  context: LogApplyContext,
  rebased = false,
): Promise<{ readonly applied: number }> {
  const scope = logScope(context.connector, context.ns);
  const local = await readLogState(deps, connectionId);
  // A log that does not continue this device's history: put back what only
  // that history held, then read the log from where both agree. Once per
  // pass: a log that diverges again under the second read is refused.
  const rebase = async (registry: readonly SegmentRef[], why: string) => {
    if (rebased) throw new LogDivergedError(why);
    await rebaseOnLog(deps, connectionId, context, local, registry);
    return applyLog(deps, connectionId, context, true);
  };
  // A listed row is a hint taken before this apply. One behind this device can
  // be a listing taken before this device's own later commit, so it is read
  // again before it is believed.
  const listed = context.read;
  const read =
    listed === undefined || (listed.found && listed.version < local.position)
      ? await deps.registry.read(scope)
      : listed;
  const classification = classifyStreamRow(read, context.hashes);
  const [bootstrap] = await deps.db.query<{ generation: number; base: number }>(
    "SELECT generation,base FROM bootstrap_load WHERE connection_id=?",
    [connectionId],
  );
  if (
    bootstrap &&
    (classification !== "present" ||
      bootstrap.generation !== context.generation ||
      deps.bootstrapFirstLoad === false ||
      deps.progressiveFirstLoad !== true)
  )
    await discardBootstrap(deps, connectionId);
  if (!read.found || classification === "absent") return { applied: 0 };
  // Rows an unfinished key-ordered load left (see `log-keyed.ts`) lie beyond
  // this device's position, and only a key-ordered load that covers them may
  // move it. So while the marker stands, no branch below may write a cursor:
  // not the lifetime branches, which write `log_state` without applying
  // anything, and not a device that somehow holds both a cursor and the marker.
  // A log that cannot finish that load (`keyedLoadBlocked`) ends it instead:
  // the marker and its rows go, and the first load starts again from the log.
  let pending = await readKeyedPending(deps, connectionId);
  if (pending !== null && local.position !== 0)
    throw unfinishedKeyedLoad(pending, "this device holds a cursor above 0");

  if (classification === "tombstoned") {
    if (pending !== null)
      throw unfinishedKeyedLoad(pending, "the log is of an ended lifetime");
    // The log of an ended lifetime. A new one begins after its version.
    if (read.version > local.position)
      await deps.db.batch([
        writeLogState(connectionId, {
          position: read.version,
          base: read.version,
          refs: [],
          snapshot: null,
        }),
      ]);
    return { applied: 0 };
  }

  // A registry behind this device is a rollback or a restore. The segments
  // above its position are still in storage, and this device applied them: it
  // commits them again, in order (`recommitApplied`), so the log is the one
  // this device's rows are the fold of. A registry row this device did not
  // apply is another history, which this device rebases onto.
  if (local.position > read.version) {
    try {
      await recommitApplied(deps, connectionId, context, local, read);
      return { applied: 0 };
    } catch (error) {
      if (!(error instanceof LogDivergedError)) throw error;
      const named = await fetchSegment(
        deps,
        scope,
        context,
        read.dataHash,
        read.version,
      );
      return rebase(
        [
          ...named.segment.refs,
          {
            position: read.version,
            dataHash: read.dataHash.toLowerCase() as `0x${string}`,
            bytes: named.bytes,
          },
        ],
        error.message,
      );
    }
  }

  const lastRef = local.refs.at(-1);
  if (
    read.version === local.position &&
    lastRef?.dataHash.toLowerCase() === read.dataHash.toLowerCase()
  )
    return { applied: 0 };

  const newest = await fetchSegment(
    deps,
    scope,
    context,
    read.dataHash,
    read.version,
    deps.progressiveFirstLoad === true,
  );
  const head = newest.segment;
  if (head.generation < context.generation) {
    if (pending !== null)
      throw unfinishedKeyedLoad(pending, "the log is of an earlier lifetime");
    // A log of an earlier lifetime holds none of this one.
    await deps.db.batch([
      writeLogState(connectionId, {
        position: read.version,
        base: read.version,
        refs: [],
        snapshot: null,
      }),
    ]);
    return { applied: 0 };
  }
  if (head.generation > context.generation) return { applied: 0 };
  // This device's first install of the connection's log. What it holds from
  // before goes into the log with its next publish (`log-seed.ts`). An
  // unfinished key-ordered load already passed here at its start.
  if (local.position === 0 && pending === null)
    await seedFromRecords(deps, connectionId);

  const headRef: SegmentRef = {
    position: head.position,
    dataHash: read.dataHash.toLowerCase() as `0x${string}`,
    bytes: newest.bytes,
    removes: newest.removes,
  };
  const allRefs: SegmentRef[] = [...head.refs, headRef];
  // The segment this device applied last must be the one the log names at that
  // position. Another history that reuses the position (a rolled-back log that
  // grew again) is not a tail to apply on top of what this device holds.
  if (lastRef && lastRef.position === local.position) {
    const named = allRefs.find((ref) => ref.position === lastRef.position);
    if (
      named &&
      named.dataHash.toLowerCase() !== lastRef.dataHash.toLowerCase()
    )
      return rebase(
        allRefs,
        `apply: the log names a different segment at position ${lastRef.position} than this device applied`,
      );
  }
  let since = local.position;
  let plan = planOpsSince(head, headRef, since);
  let snapshot: SnapshotPointer | null = null;
  let gap = false;
  if (plan.kind === "gap") {
    if (plan.reason === "ahead_of_head")
      return rebase(
        allRefs,
        `apply: the log's newest position ${head.position} is behind this device at ${since}`,
      );
    // A full check. Behind `base` the log no longer holds the prefix: a
    // snapshot does, and it is installed first. Without one the log holds
    // nothing below `base`, and the pass applies the tail alone.
    gap = true;
    since = head.base;
    plan = planOpsSince(head, headRef, since);
    // Behind `base` the snapshot is installed first, then the tail: one pass.
    snapshot = head.snapshot ?? null;
  }
  const tail = plan.kind === "segments" ? plan.refs : [];
  if (pending !== null) {
    const last = tail.at(-1);
    const blocked = keyedLoadBlocked(deps, pending, {
      snapshotPresent: snapshot !== null,
      target: last
        ? {
            position: last.position,
            base: head.base,
            refs: allRefs.filter((ref) => ref.position <= last.position),
            snapshot: head.snapshot,
          }
        : null,
    });
    if (blocked !== null) {
      await rebaselineKeyedLoad(deps, connectionId, blocked);
      pending = null;
    }
  }
  // A first load of a log too big for one commit loads key by key (see
  // `log-keyed.ts`), whether or not the host shows streams while they load. On a
  // log whose keys arrive in no key order, a segment-by-segment load rewrites a
  // table's random-hash indexes in every commit: on a 198k-row source it writes
  // 1.6x the pages the key ranges do and keeps the Web worker busy about twice
  // as long. The segment-by-segment load takes the logs that fit one commit's budget, and
  // what a key-ordered load cannot take (a snapshot, a device that holds
  // streams). The key-ordered load lists the source at the head all the same.
  if (bootstrap) {
    const staged = await deps.db.query<{ position: number; data_hash: string }>(
      "SELECT position,data_hash FROM bootstrap_segments",
    );
    if (
      snapshot !== null ||
      bootstrap.base !== head.base ||
      staged.some(
        (row) =>
          !allRefs.some(
            (ref) =>
              ref.position === row.position &&
              ref.dataHash.toLowerCase() === row.data_hash,
          ),
      )
    )
      await discardBootstrap(deps, connectionId);
  }
  if (
    deps.bootstrapFirstLoad !== false &&
    deps.progressiveFirstLoad === true &&
    local.position === 0 &&
    snapshot === null &&
    pending === null &&
    tail.length
  ) {
    const applied = await loadBootstrap({
      deps,
      connectionId,
      generation: context.generation,
      base: head.base,
      head: (
        await fetchSegment(
          deps,
          scope,
          context,
          headRef.dataHash,
          head.position,
        )
      ).segment,
      refs: tail,
      fetch: async (ref) =>
        (await fetchSegment(deps, scope, context, ref.dataHash, ref.position))
          .segment,
      state: {
        position: head.position,
        base: head.base,
        refs: allRefs,
        snapshot: head.snapshot,
      },
    });
    if (applied !== null) return { applied };
  }
  const buckets = await planKeyedLoad(
    deps,
    connectionId,
    local,
    snapshot !== null,
    tail,
    pending,
  );
  const progressive =
    deps.progressiveFirstLoad === true && pending === null && buckets === null;
  if (gap && progressive) {
    const after = planOpsSince(head, headRef, head.base);
    return {
      applied: await loadProgressively(
        deps,
        connectionId,
        scope,
        context,
        head,
        allRefs,
        head.snapshot ?? null,
        after.kind === "segments" ? after.refs : [],
      ),
    };
  }
  if (tail.length === 0 && snapshot === null && pending === null)
    return { applied: 0 };
  if (progressive)
    return {
      applied: await loadProgressively(
        deps,
        connectionId,
        scope,
        context,
        head,
        allRefs,
        snapshot,
        tail,
      ),
    };

  if (buckets !== null) {
    const listing =
      deps.progressiveFirstLoad === true
        ? await listKeyedLoad(deps, connectionId, context, head, tail)
        : null;
    try {
      await loadKeyed(
        deps,
        connectionId,
        tail.map((ref) =>
          segmentSource(deps, scope, context, head, allRefs, ref),
        ),
        buckets,
      );
    } catch (error) {
      await listing?.failed(error);
      throw error;
    }
    return { applied: tail.length };
  }

  const items: PassItem[] = [
    ...snapshotItems(
      deps,
      connectionId,
      scope,
      context,
      head,
      allRefs,
      snapshot,
    ),
    ...tail.map((ref) =>
      segmentItem(deps, connectionId, scope, context, head, allRefs, ref),
    ),
  ];
  await applyInGroups(deps, items, { firstAlone: false });
  return { applied: items.length };
}

/**
 * One segment of the tail as a batch of the pass: fetched (the newest is
 * already in hand), verified, staged, with the position it carries.
 */
function segmentItem(
  deps: LocalSyncDeps,
  connectionId: string,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  head: Segment,
  allRefs: readonly SegmentRef[],
  ref: SegmentRef,
): PassItem {
  return {
    bytes: ref.bytes,
    stage: async () => {
      const segment =
        ref.position === head.position
          ? deps.progressiveFirstLoad
            ? (
                await fetchSegment(
                  deps,
                  scope,
                  context,
                  ref.dataHash,
                  ref.position,
                )
              ).segment
            : head
          : (
              await fetchSegment(
                deps,
                scope,
                context,
                ref.dataHash,
                ref.position,
              )
            ).segment;
      return stageBatch(
        deps,
        connectionId,
        segment,
        {
          dataHash: ref.dataHash.toLowerCase(),
          blobName: segmentBlobName(ref.dataHash),
        },
        {
          position: ref.position,
          base: head.base,
          refs: allRefs.filter((r) => r.position <= ref.position),
          snapshot: head.snapshot,
        },
      );
    },
  };
}

/** One segment of the tail as a source of the keyed load. */
function segmentSource(
  deps: LocalSyncDeps,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  head: Segment,
  allRefs: readonly SegmentRef[],
  ref: SegmentRef,
): KeyedSource {
  return {
    bytes: ref.bytes,
    load: async () => ({
      batch:
        ref.position === head.position
          ? deps.progressiveFirstLoad
            ? (
                await fetchSegment(
                  deps,
                  scope,
                  context,
                  ref.dataHash,
                  ref.position,
                )
              ).segment
            : head
          : (
              await fetchSegment(
                deps,
                scope,
                context,
                ref.dataHash,
                ref.position,
              )
            ).segment,
      identity: {
        dataHash: ref.dataHash.toLowerCase(),
        blobName: segmentBlobName(ref.dataHash),
      },
    }),
    state: {
      position: ref.position,
      base: head.base,
      refs: allRefs.filter((r) => r.position <= ref.position),
      snapshot: head.snapshot,
    },
  };
}

/**
 * The parts of the snapshot a reader behind `head.base` installs, as batches
 * of the pass. The position moves to the snapshot's only with the last part,
 * in the same batch, so an interrupted install is repeated, never half
 * believed. Idempotent.
 */
function snapshotItems(
  deps: LocalSyncDeps,
  connectionId: string,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  head: Segment,
  allRefs: readonly SegmentRef[],
  snapshot: SnapshotPointer | null,
): PassItem[] {
  if (snapshot === null) return [];
  return snapshot.parts.map((ref, index) => ({
    bytes: ref.bytes,
    stage: async () => {
      const part = await fetchSnapshotPart(
        deps,
        scope,
        context,
        ref.dataHash,
        snapshot.position,
      );
      if (part.index !== index)
        throw new Error("apply: invalid log snapshot part (inconsistent)");
      return stageBatch(
        deps,
        connectionId,
        {
          generation: part.generation,
          observedAt: 0,
          streams: part.streams,
          operations: part.entries,
        },
        {
          dataHash: ref.dataHash.toLowerCase(),
          blobName: snapshotPartBlobName(ref.dataHash),
        },
        index === snapshot.parts.length - 1
          ? {
              position: snapshot.position,
              base: head.base,
              refs: allRefs.filter((r) => r.position <= snapshot.position),
              snapshot,
            }
          : undefined,
      );
    },
  }));
}

/**
 * List the streams a key-ordered first load will publish, before it fetches a
 * segment: each is a stream state with a partial row at 0 of the segments, so a
 * host that lists loading sources shows the source from the head on. The rows
 * the key ranges merge are final rows (a range merges every segment's
 * operations on its keys), so a reader that shows partial rows shows only keys
 * the finished log keeps. The last range's commit writes the heads, which ends
 * these rows (`partial_complete_au`). A load that stops marks them failed.
 */
async function listKeyedLoad(
  deps: LocalSyncDeps,
  connectionId: string,
  context: LogApplyContext,
  head: Segment,
  tail: readonly SegmentRef[],
): Promise<{ failed: (error: unknown) => Promise<void> }> {
  const last = tail.at(-1);
  if (!last) return { failed: async () => undefined };
  const stored = await deps.db.query<{
    stream: string;
    head_version: number;
    last_delete_version: number;
  }>(
    "SELECT stream, head_version, last_delete_version FROM stream_state WHERE connection_id = ?",
    [connectionId],
  );
  const versions = new Map(
    stored.map((row) => [
      row.stream,
      Math.max(row.head_version, row.last_delete_version) + 1,
    ]),
  );
  const identities = head.streams.map((meta): PartialIdentity => ({
    connectionId,
    stream: meta.stream,
    version: versions.get(meta.stream) ?? 1,
    generation: context.generation,
    dataHash: last.dataHash.toLowerCase(),
    headBlob: segmentBlobName(last.dataHash),
    observedAt: head.observedAt,
  }));
  await deps.db.batch(
    head.streams.flatMap((meta, index) => [
      streamStateStatement(connectionId, meta),
      partialRowStatement(identities[index]!, 0, tail.length, 0),
    ]),
  );
  announceApplied(deps, connectionId);
  return {
    failed: async (error) => {
      const code = failureCode(error);
      await deps.db
        .batch(identities.map((identity) => failedRowStatement(identity, code)))
        .then(
          () => announceApplied(deps, connectionId),
          () => undefined,
        );
    },
  };
}
