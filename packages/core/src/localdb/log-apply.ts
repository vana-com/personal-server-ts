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
// rollback or restore), or that names another segment at a position this
// device already applied, is not a continuation: the rows, tombstones and
// checkpoints this device holds came from segments the log no longer has, and
// replaying into them is not the log's fold. That fails closed
// (`LogDivergedError`, nothing applied, the position unchanged). A rebaseline
// that rebuilds them from the log, with the local overlay kept apart, is later
// work. What the log does not hold below `base` (a log that began after the
// streams were published) is read by the per-stream path.

import { keccak_256 } from "@noble/hashes/sha3";
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
  verifySegment,
  verifySnapshotPart,
  type ControlHashes,
  type Segment,
  type SegmentRef,
  type SnapshotPart,
  type SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { announceApplied } from "./apply-progress.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import {
  applyBatch,
  applyInGroups,
  stageBatch,
  type BatchStep,
  type OperationBatch,
  type PassItem,
} from "./log-batch.js";
import {
  loadKeyed,
  planKeyedLoad,
  unfinishedKeyedLoad,
  type KeyedSource,
} from "./log-keyed.js";
import { heldKeys, planLogLoad, type PlannedBatch } from "./log-progressive.js";
import {
  LogDivergedError,
  readKeyedPending,
  readLogState,
  writeLogState,
  type LogState,
} from "./log-state.js";
import { UpdateRequiredError } from "./update-required.js";
import {
  failedRowStatement,
  failureCode,
  type PartialIdentity,
} from "./partial-load.js";

export { recordKeyOfKey } from "./log-batch.js";
export {
  LogDivergedError,
  readLogState,
  writeLogState,
  type LogState,
} from "./log-state.js";

const keccak = async (bytes: Uint8Array) => keccak_256(bytes);

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
    keccak,
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
  const { dataHash, blobName } = await digestSnapshotPart(keccak, bytes);
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
  /** The registry's row for the log, if the caller already holds a fresh one. */
  readonly read?: Awaited<ReturnType<LocalSyncDeps["registry"]["read"]>>;
}

/**
 * Bring this device to the log's position. One registry read, one GET for the
 * newest segment, one GET for each older segment this device lacks.
 */
export async function applyLog(
  deps: LocalSyncDeps,
  connectionId: string,
  context: LogApplyContext,
): Promise<{ readonly applied: number }> {
  const scope = logScope(context.connector, context.ns);
  const read = context.read ?? (await deps.registry.read(scope));
  const classification = classifyStreamRow(read, context.hashes);
  if (!read.found || classification === "absent") return { applied: 0 };
  const local = await readLogState(deps, connectionId);
  // Rows an unfinished key-ordered load left (see `log-keyed.ts`) lie beyond
  // this device's position, and only a key-ordered load that covers them may
  // move it. So while the marker stands, no branch below may write a cursor:
  // not the lifetime branches, which write `log_state` without applying
  // anything, and not a device that somehow holds both a cursor and the marker.
  const pending = await readKeyedPending(deps, connectionId);
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

  // A registry behind this device is a rollback or a restore. What this device
  // applied from the segments above the registry's position is still in its
  // rows, tombstones and checkpoints, and replaying the log into them does not
  // give the log's fold. Failing closed keeps the position true: it is not
  // moved back, and nothing is applied.
  if (local.position > read.version)
    throw new LogDivergedError(
      `apply: the log registry is at position ${read.version}, behind this device at ${local.position}`,
    );

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

  const headRef: SegmentRef = {
    position: head.position,
    dataHash: read.dataHash.toLowerCase() as `0x${string}`,
    bytes: newest.bytes,
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
      throw new LogDivergedError(
        `apply: the log names a different segment at position ${lastRef.position} than this device applied`,
      );
  }
  let since = local.position;
  let plan = planOpsSince(head, headRef, since);
  let snapshot: SnapshotPointer | null = null;
  if (plan.kind === "gap") {
    if (plan.reason === "ahead_of_head")
      throw new LogDivergedError(
        `apply: the log's newest position ${head.position} is behind this device at ${since}`,
      );
    // A full check. Behind `base` the log no longer holds the prefix: a
    // snapshot does, and it is installed first. Without one (a log that began
    // after the streams were published) the per-stream path holds it.
    if (deps.progressiveFirstLoad === true && pending === null) {
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
    since = head.base;
    plan = planOpsSince(head, headRef, since);
    // Behind `base` the snapshot is installed first, then the tail: one pass.
    snapshot = head.snapshot ?? null;
  }
  const tail = plan.kind === "segments" ? plan.refs : [];
  if (tail.length === 0 && snapshot === null && pending === null)
    return { applied: 0 };
  if (deps.progressiveFirstLoad === true && pending === null)
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

  // A first load of a log too big for one commit loads key by key (see
  // `log-keyed.ts`); the segments are the same, and so is their order.
  const buckets = await planKeyedLoad(
    deps,
    connectionId,
    local,
    snapshot !== null,
    tail,
    pending,
  );
  if (buckets !== null) {
    await loadKeyed(
      deps,
      connectionId,
      tail.map((ref) =>
        segmentSource(deps, scope, context, head, allRefs, ref),
      ),
      buckets,
    );
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
          ? head
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
          ? head
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

/** One segment, fetched, decrypted and verified against the hash and position. */
export async function fetchSegment(
  deps: LocalSyncDeps,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  dataHash: string,
  position: number,
): Promise<{ segment: Segment; bytes: number }> {
  const cipher = await deps.blobs.get(`${scope}/${segmentBlobName(dataHash)}`);
  if (cipher === null)
    throw new Error(`apply: missing log segment ${position}`);
  const verified = await verifySegment(
    keccak,
    await deps.keys.decrypt(scope, cipher),
    {
      dataHash,
      connector: context.connector,
      ns: context.ns,
      keyCheck: context.keyCheck,
      position,
    },
  );
  if (verified.kind === "unsupported_format")
    throw new UpdateRequiredError(
      `apply: invalid log segment ${position} (unsupported_format)`,
      verified.format,
    );
  if (verified.kind !== "ok")
    throw new Error(
      `apply: invalid log segment ${position} (${verified.kind})`,
    );
  return verified;
}

/** One snapshot part, fetched, decrypted and verified. */
export async function fetchSnapshotPart(
  deps: LocalSyncDeps,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  dataHash: string,
  position: number,
): Promise<SnapshotPart> {
  const cipher = await deps.blobs.get(
    `${scope}/${snapshotPartBlobName(dataHash)}`,
  );
  if (cipher === null) throw new Error("apply: missing log snapshot part");
  const verified = await verifySnapshotPart(
    keccak,
    await deps.keys.decrypt(scope, cipher),
    {
      dataHash,
      connector: context.connector,
      ns: context.ns,
      keyCheck: context.keyCheck,
      position,
    },
  );
  if (verified.kind === "unsupported_format")
    throw new UpdateRequiredError(
      "apply: invalid log snapshot part (unsupported_format)",
      verified.format,
    );
  if (verified.kind !== "ok")
    throw new Error(`apply: invalid log snapshot part (${verified.kind})`);
  return verified.part;
}

/**
 * The pass of `applyLog` for a device that serves a first load while it
 * applies (`progressiveFirstLoad`): the same batches in the same order, with
 * `stream_partial` rows between them. See `log-progressive.ts` for which
 * streams load so and why a row of a key a later batch removes stays hidden.
 *
 * Every segment of the tail is fetched, and the first snapshot part with it,
 * before the first batch applies: the pass then knows what each later batch
 * removes. The other parts arrive a few ahead of the one applying.
 */
async function loadProgressively(
  deps: LocalSyncDeps,
  connectionId: string,
  scope: string,
  context: LogApplyContext,
  head: Segment,
  allRefs: readonly SegmentRef[],
  snapshot: SnapshotPointer | null,
  tail: readonly SegmentRef[],
): Promise<number> {
  const partRefs = snapshot?.parts ?? [];
  // A part is fetched once, whoever asks first: the plan asks for the first,
  // the pass for the others as read-ahead reaches them.
  const parts: (Promise<SnapshotPart> | undefined)[] = [];
  const partAt = (index: number) => {
    if (!parts[index]) {
      const fetching = fetchSnapshotPart(
        deps,
        scope,
        context,
        partRefs[index]!.dataHash,
        snapshot!.position,
      );
      fetching.catch(() => undefined);
      parts[index] = fetching;
    }
    return parts[index]!;
  };
  if (partRefs.length > 0) void partAt(0);

  const fetched = new Map<number, Segment>([[head.position, head]]);
  const [firstPart] = await Promise.all([
    partRefs.length > 0 ? partAt(0) : Promise.resolve(undefined),
    Promise.all(
      tail
        .filter((ref) => ref.position !== head.position)
        .map(async (ref) => {
          fetched.set(
            ref.position,
            (
              await fetchSegment(
                deps,
                scope,
                context,
                ref.dataHash,
                ref.position,
              )
            ).segment,
          );
        }),
    ),
  ]);
  const tailSegments = tail.map((ref) => fetched.get(ref.position)!);

  // Every batch's identity: the hash and blob its stream head will name.
  const identities = [
    ...partRefs.map((ref) => ({
      dataHash: ref.dataHash.toLowerCase(),
      blobName: snapshotPartBlobName(ref.dataHash),
    })),
    ...tail.map((ref) => ({
      dataHash: ref.dataHash.toLowerCase(),
      blobName: segmentBlobName(ref.dataHash),
    })),
  ];
  const observedAts = [
    ...partRefs.map(() => 0),
    ...tailSegments.map((segment) => segment.observedAt),
  ];
  const planned: PlannedBatch[] = [
    // The parts of one snapshot all carry the fold's streams. Their entries
    // are one fold, which names a key once: nothing in them is removed later.
    ...partRefs.map(() => ({ streams: firstPart!.streams, operations: [] })),
    ...tailSegments,
  ];

  const stored = await deps.db.query<{
    stream: string;
    complete: number;
    head_generation: number;
    head_version: number;
    last_delete_version: number;
  }>(
    `SELECT stream, complete, head_generation, head_version, last_delete_version
       FROM stream_state WHERE connection_id = ?`,
    [connectionId],
  );
  const complete = new Set(
    stored
      .filter(
        (row) =>
          row.complete === 1 &&
          row.head_generation === context.generation &&
          row.head_version > row.last_delete_version,
      )
      .map((row) => row.stream),
  );
  const versionOf = new Map(
    stored.map((row) => [
      row.stream,
      Math.max(row.head_version, row.last_delete_version) + 1,
    ]),
  );
  const plans = planLogLoad(planned, complete);

  // The row a stream's load shows is the head it ends as: the version its
  // last batch writes, that batch's hash and blob. A body that is reading
  // when the load completes then goes on to its end.
  const heads = new Map<string, PartialIdentity>();
  for (const plan of plans.values())
    heads.set(plan.stream, {
      connectionId,
      stream: plan.stream,
      version: versionOf.get(plan.stream) ?? 1,
      generation: context.generation,
      dataHash: identities[plan.last]!.dataHash,
      headBlob: identities[plan.last]!.blobName,
      observedAt: observedAts[plan.last]!,
    });
  // A load of the same head that stopped continues: its rows keep showing.
  const markers = await deps.db.query<{
    stream: string;
    version: number;
    generation: number;
    data_hash: string;
    parts_applied: number;
    parts_total: number;
  }>(
    `SELECT stream, version, generation, data_hash, parts_applied, parts_total
       FROM stream_partial WHERE connection_id = ?`,
    [connectionId],
  );
  const resumed = new Map<string, { applied: number; total: number }>();
  const ended: SqlStatement[] = [];
  for (const marker of markers) {
    const mine = heads.get(marker.stream);
    if (
      mine &&
      marker.version === mine.version &&
      marker.generation === mine.generation &&
      marker.data_hash === mine.dataHash
    )
      resumed.set(marker.stream, {
        applied: marker.parts_applied,
        total: marker.parts_total,
      });
    else if (
      !mine &&
      planned.some((b) => b.streams.some((m) => m.stream === marker.stream))
    )
      // A load this pass does not continue, of a stream it now writes whole.
      ended.push({
        sql: "DELETE FROM stream_partial WHERE connection_id = ? AND stream = ?",
        params: [connectionId, marker.stream],
      });
  }
  if (ended.length > 0) await deps.db.batch(ended);

  // What each batch does for the streams that load progressively: a function
  // of its place in the pass and its own operations, so the batches can be
  // staged in any order and are committed in this one. A part's operations
  // are known once it is fetched, so its steps are made when it is staged.
  const seen = new Map<string, number>();
  const counts: ReadonlyMap<string, number>[] = planned.map((batch) => {
    const here = new Map<string, number>();
    for (const meta of batch.streams) {
      const count = (seen.get(meta.stream) ?? 0) + 1;
      seen.set(meta.stream, count);
      here.set(meta.stream, count);
    }
    return here;
  });
  const stepsOf: ReadonlyMap<string, BatchStep>[] = [];
  const stepsFor = (
    index: number,
    batch: OperationBatch,
  ): ReadonlyMap<string, BatchStep> => {
    const steps = new Map<string, BatchStep>();
    for (const meta of batch.streams) {
      const plan = plans.get(meta.stream);
      if (!plan) continue;
      const resume = resumed.get(meta.stream);
      const count = counts[index]!.get(meta.stream)!;
      const final = index === plan.last;
      const total = resume?.total ?? plan.total;
      steps.set(meta.stream, {
        begin: index === plan.first && resume === undefined,
        final,
        held: final ? [] : heldKeys(plan, index, batch.operations),
        row: final
          ? undefined
          : {
              head: heads.get(meta.stream)!,
              applied: Math.min((resume?.applied ?? 0) + count, total - 1),
              total,
            },
      });
    }
    stepsOf[index] = steps;
    return steps;
  };
  const stateOf = (index: number): LogState | undefined => {
    const lastPart = index === partRefs.length - 1;
    const position = index - partRefs.length;
    return index < partRefs.length
      ? lastPart
        ? {
            position: snapshot!.position,
            base: head.base,
            refs: allRefs.filter((r) => r.position <= snapshot!.position),
            snapshot,
          }
        : undefined
      : {
          position: tail[position]!.position,
          base: head.base,
          refs: allRefs.filter((r) => r.position <= tail[position]!.position),
          snapshot: head.snapshot,
        };
  };
  const items: PassItem[] = planned.map((_, index) => ({
    bytes:
      index < partRefs.length
        ? partRefs[index]!.bytes
        : tail[index - partRefs.length]!.bytes,
    // The batch that completes a stream commits that stream's last rows.
    closesGroup: [...plans.values()].some((plan) => plan.last === index),
    stage: async () => {
      let batch: OperationBatch;
      if (index < partRefs.length) {
        const part = await partAt(index);
        if (
          part.index !== index ||
          JSON.stringify(part.streams) !== JSON.stringify(firstPart!.streams)
        )
          throw new Error("apply: invalid log snapshot part (inconsistent)");
        batch = {
          generation: part.generation,
          observedAt: 0,
          streams: part.streams,
          operations: part.entries,
        };
      } else batch = tailSegments[index - partRefs.length]!;
      return stageBatch(
        deps,
        connectionId,
        batch,
        identities[index]!,
        stateOf(index),
        stepsFor(index, batch),
      );
    },
  }));

  const begun = new Map<string, PartialIdentity>();
  const finished = new Set<string>();
  try {
    await applyInGroups(deps, items, {
      // The first batch commits alone: it is the first screen.
      firstAlone: true,
      onCommit: (first, last) => {
        let shown = false;
        for (let index = first; index <= last; index++)
          for (const [stream, step] of stepsOf[index]!) {
            shown = true;
            if (step.final) finished.add(stream);
            else begun.set(stream, heads.get(stream)!);
          }
        if (shown) announceApplied(deps, connectionId);
      },
    });
  } catch (error) {
    // The load stopped short of its last batch: say so on its rows, for a
    // reader to tell this from a load that is still going. The next batch
    // clears it. A failure here must not hide the one being thrown.
    const code = failureCode(error);
    const stopped = [...begun.values()].filter(
      (identity) => !finished.has(identity.stream),
    );
    if (stopped.length > 0)
      await deps.db
        .batch(stopped.map((identity) => failedRowStatement(identity, code)))
        .then(
          () => announceApplied(deps, connectionId),
          () => undefined,
        );
    throw error;
  }
  return planned.length;
}
