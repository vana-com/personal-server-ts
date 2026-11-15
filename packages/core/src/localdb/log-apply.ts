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

import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  HEAD_FORMAT,
  canonicalJson,
  classifyStreamRow,
  digestSegment,
  digestSnapshotPart,
  encodeSegment,
  encodeSnapshotPart,
  firstDeletionKeyMismatch,
  logScope,
  pkHash,
  planOpsSince,
  segmentBlobName,
  snapshotPartBlobName,
  toHex,
  verifySegment,
  verifySnapshotPart,
  type ControlHashes,
  type LogOmitted,
  type LogOperation,
  type LogStreamMeta,
  type Segment,
  type SegmentRef,
  type SnapshotPart,
  type SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import { announceApplied } from "./apply-progress.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { heldKeys, planLogLoad, type PlannedBatch } from "./log-progressive.js";
import { mergeIncoming, seenPair, withOrigin } from "./merge.js";
import {
  failedRowStatement,
  failureCode,
  holdKeys,
  partialRowStatement,
  showIncomingKeys,
  hideStoredRows,
  type PartialIdentity,
} from "./partial-load.js";

const sha = async (bytes: Uint8Array) => sha256(bytes);
const keccak = async (bytes: Uint8Array) => keccak_256(bytes);

/**
 * The rank of a tombstone beside its stamp (`log_tombstones.rank`), as the
 * model orders them: an omission's cutoff, then an observation at that stamp,
 * then an explicit delete at that stamp.
 */
const OMISSION_RANK = 0;
const UPSERT_RANK = 1;
const EXPLICIT_DELETE_RANK = 2;

/** Rows a statement list binds at most; a long omitted set goes in chunks. */
const KEYS_PER_STATEMENT = 400;

export interface LogState {
  readonly position: number;
  readonly base: number;
  /** Refs of positions base+1..position: the list the next segment carries. */
  readonly refs: readonly SegmentRef[];
  /** The snapshot the log rests on; `null` before its first compaction. */
  readonly snapshot: SnapshotPointer | null;
}

const NO_LOG: LogState = { position: 0, base: 0, refs: [], snapshot: null };

export async function readLogState(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
): Promise<LogState> {
  const [row] = await deps.db.query<{
    position: number;
    base: number;
    refs: string;
    snapshot: string | null;
  }>(
    "SELECT position, base, refs, snapshot FROM log_state WHERE connection_id = ?",
    [connectionId],
  );
  return row
    ? {
        position: row.position,
        base: row.base,
        refs: JSON.parse(row.refs) as SegmentRef[],
        snapshot: row.snapshot
          ? (JSON.parse(row.snapshot) as SnapshotPointer)
          : null,
      }
    : NO_LOG;
}

export function writeLogState(
  connectionId: string,
  state: LogState,
): SqlStatement {
  return {
    sql: `INSERT OR REPLACE INTO log_state (connection_id, position, base, refs, snapshot)
          VALUES (?, ?, ?, ?, ?)`,
    params: [
      connectionId,
      state.position,
      state.base,
      JSON.stringify(state.refs),
      state.snapshot ? JSON.stringify(state.snapshot) : null,
    ],
  };
}

const chunks = <T>(items: readonly T[], size: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size)
    out.push(items.slice(i, i + size));
  return out;
};

/**
 * Apply one segment's operations to local state, in one batch (origin
 * `remote`). Safe to repeat and to run in any order against other segments:
 * see the file comment. With `state`, the log position is written in the same
 * batch, so a position never runs ahead of the rows it stands for.
 */
/** What `applyBatch` needs of a segment or of a snapshot part. */
interface OperationBatch {
  readonly generation: number;
  readonly observedAt: number;
  readonly streams: readonly LogStreamMeta[];
  readonly operations: readonly (LogOperation | LogOmitted)[];
}

/**
 * What one batch does for a stream that loads progressively (see
 * `log-progressive.ts`). The stream's head, and with it `complete`, is written
 * only by the batch that `final` names.
 */
interface BatchStep {
  /** The first batch of a load that is not a resumed one hides the stored rows. */
  readonly begin: boolean;
  readonly final: boolean;
  /** Keys of this batch a later, fetched batch deletes or omits. */
  readonly held: readonly string[];
  /** The stream's row after this batch; absent in the final batch. */
  readonly row?: {
    readonly head: PartialIdentity;
    readonly applied: number;
    readonly total: number;
  };
}

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

/**
 * The canonical record key of a deletion's typed primary-key values: the key
 * `computeRecordKeyFromData` gives a record holding these values, which is how
 * an upsert's key derives. The values are already checked against the hash.
 */
export function recordKeyOfKey(
  primaryKey: readonly string[],
  key: readonly unknown[],
): string {
  return computeRecordKeyFromData(
    Object.fromEntries(primaryKey.map((field, i) => [field, key[i]])),
    [...primaryKey],
  );
}

async function applyBatch(
  deps: LocalSyncDeps,
  connectionId: string,
  segment: OperationBatch,
  identity: { readonly dataHash: string; readonly blobName: string },
  state?: LogState,
  steps: ReadonlyMap<string, BatchStep> = new Map(),
): Promise<void> {
  const { dataHash, blobName } = identity;
  const op = deps.newOp();
  const primaryKeyOf = new Map(
    segment.streams.map((meta) => [meta.stream, meta.primaryKey]),
  );
  const statements: SqlStatement[] = [];

  // A deletion names its record by hash and by canonical key. Check that they
  // name the same record before anything is built or written: the hash picks
  // the row removed, the key is what a record-level reader deletes. Segments
  // and snapshot parts both come through here.
  const mismatch = await firstDeletionKeyMismatch(
    sha,
    segment.streams,
    segment.operations,
  );
  if (mismatch)
    throw new Error(
      `apply: log deletion key does not match its hash (${mismatch.stream}/${mismatch.pkHash})`,
    );

  for (const meta of segment.streams)
    statements.push({
      sql: `INSERT OR IGNORE INTO stream_state (connection_id, stream, primary_key, semantics, incremental)
            VALUES (?, ?, ?, 'mutable_state', 1)`,
      params: [connectionId, meta.stream, JSON.stringify(meta.primaryKey)],
    });
  // A progressive load's first batch hides what the stream held, in the same
  // transaction as its first rows (see `hideStoredRows`).
  for (const [stream, step] of steps)
    if (step.begin) statements.push(...hideStoredRows(connectionId, stream));

  // 1. Tombstones first, so the upserts of this very segment see them. A
  // tombstone has a rank beside its stamp, the model's order: an omission's
  // cutoff ranks below an observation at its stamp (a pass proved a key absent
  // only before its cutoff), an explicit delete above it. A key keeps the
  // greatest (stamp, rank), which is the one that refuses the most.
  // The tombstone also keeps the deletion's canonical record key, derived from
  // the typed key the operation names (as an upsert's derives from its value),
  // so a record-level reader of this table needs no map from hash to key (a
  // key this device never held has no row to ask).
  const tombstone = (
    stream: string,
    pk: string,
    key: readonly unknown[],
    o: number,
    r: string,
    rank: number,
  ): SqlStatement[] => {
    const recordKey = recordKeyOfKey(primaryKeyOf.get(stream)!, key);
    return [
      {
        sql: `INSERT OR IGNORE INTO log_tombstones (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, rank)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
        params: [connectionId, stream, pk, recordKey, o, r, rank],
      },
      {
        sql: `UPDATE log_tombstones SET record_key = ?, stamp_o = ?, stamp_r = ?, rank = ?
             WHERE connection_id = ? AND stream = ? AND pk_hash = ?
               AND (stamp_o, stamp_r, rank) < (?, ?, ?)`,
        params: [recordKey, o, r, rank, connectionId, stream, pk, o, r, rank],
      },
    ];
  };
  for (const operation of segment.operations) {
    if (operation.kind === "delete")
      statements.push(
        ...tombstone(
          operation.stream,
          operation.pkHash,
          operation.key,
          operation.stamp.o,
          operation.stamp.r,
          EXPLICIT_DELETE_RANK,
        ),
      );
    else if (operation.kind === "omitted")
      statements.push(
        ...tombstone(
          operation.stream,
          operation.pkHash,
          operation.key,
          operation.stamp.o,
          operation.stamp.r,
          OMISSION_RANK,
        ),
      );
    else if (operation.kind === "complete")
      for (const omission of operation.omitted)
        statements.push(
          ...tombstone(
            operation.stream,
            omission.pkHash,
            omission.key,
            operation.cutoff.o,
            operation.cutoff.r,
            OMISSION_RANK,
          ),
        );
  }

  // 2. Deletes and omissions of rows this device holds, before the upserts: a
  // resurrection that follows a deletion then merges into no row, so its row
  // has the resurrection's own first-seen checkpoint, as it does for a reader
  // that applied the two in separate segments. A row some run of this
  // device observed at or after the stamp survives, and is published again
  // under that observation (as `applyDelete` does for a head that omits it).
  const survivors = (
    stream: string,
    keys: readonly string[],
    o: number,
    r: string,
    inclusive: boolean,
  ): SqlStatement[] => {
    const out: SqlStatement[] = [];
    const cmp = inclusive ? "<=" : "<";
    for (const group of chunks(keys, KEYS_PER_STATEMENT)) {
      const marks = group.map(() => "?").join(",");
      out.push(
        {
          sql: `UPDATE write_ctx SET origin = 'local' WHERE id = 1 AND origin = 'remote'`,
          params: [],
        },
        {
          sql: `UPDATE records SET stamp_o = seen_o, stamp_r = seen_r
                 WHERE connection_id = ? AND stream = ? AND pk_hash IN (${marks})
                   AND seen_o IS NOT NULL AND NOT (${seenPair()} ${cmp} (?, ?))`,
          params: [connectionId, stream, ...group, o, r],
        },
        {
          sql: `UPDATE write_ctx SET origin = 'remote' WHERE id = 1 AND origin = 'local'`,
          params: [],
        },
        {
          sql: `DELETE FROM records
                 WHERE connection_id = ? AND stream = ? AND pk_hash IN (${marks})
                   AND ${seenPair()} ${cmp} (?, ?)`,
          params: [connectionId, stream, ...group, o, r],
        },
      );
    }
    return out;
  };
  for (const operation of segment.operations) {
    if (operation.kind === "delete")
      statements.push(
        ...survivors(
          operation.stream,
          [operation.pkHash],
          operation.stamp.o,
          operation.stamp.r,
          true,
        ),
      );
    else if (operation.kind === "omitted")
      statements.push(
        ...survivors(
          operation.stream,
          [operation.pkHash],
          operation.stamp.o,
          operation.stamp.r,
          false,
        ),
      );
    else if (operation.kind === "complete")
      statements.push(
        ...survivors(
          operation.stream,
          operation.omitted.map((omission) => omission.pkHash),
          operation.cutoff.o,
          operation.cutoff.r,
          false,
        ),
      );
  }

  // 3. Upserts: staged, filtered by the tombstones, merged by stamp.
  let staged = 0;
  for (const operation of segment.operations) {
    if (operation.kind !== "upsert") continue;
    const primaryKey = primaryKeyOf.get(operation.stream)!;
    // The body the merge compares is the value's canonical form.
    const canonical = canonicalJson(operation.value);
    if ((await pkHash(sha, operation.value, primaryKey)) !== operation.pkHash)
      throw new Error("apply: invalid log record key");
    statements.push({
      sql: `INSERT OR REPLACE INTO temp.incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      params: [
        op,
        operation.stream,
        operation.pkHash,
        computeRecordKeyFromData(operation.value, [...primaryKey]),
        operation.stamp.o,
        operation.stamp.r,
        canonical,
        toHex(sha256(new TextEncoder().encode(canonical))),
        operation.firstSeen,
      ],
    });
    staged++;
  }
  if (staged > 0) {
    statements.push({
      // An upsert ranks between the two tombstone kinds at its stamp: an
      // explicit delete at the stamp refuses it, an omission there does not.
      sql: `DELETE FROM temp.incoming WHERE op = ? AND EXISTS (
                SELECT 1 FROM log_tombstones t
                 WHERE t.connection_id = ? AND t.stream = incoming.stream
                   AND t.pk_hash = incoming.pk_hash
                   AND (t.stamp_o, t.stamp_r, t.rank) > (incoming.stamp_o, incoming.stamp_r, ${UPSERT_RANK}))`,
      params: [op, connectionId],
    });
    // The rows this batch writes show in a progressive view, but for the keys
    // a later batch removes.
    for (const [stream, step] of steps)
      if (!step.final)
        statements.push(
          showIncomingKeys(connectionId, stream, op),
          ...holdKeys(connectionId, stream, step.held),
        );
    statements.push(
      ...mergeIncoming(op, connectionId, {
        promoteSeen: true,
        firstSeenOfWinner: true,
      }),
    );
  }

  // 4. Each stream the segment touched now reads from it: a local version
  // above anything the registry's own stream row holds, so the per-stream
  // path never replaces what the log wrote (see `applyOneOnce`).
  for (const meta of segment.streams) {
    // A stream still loading progressively has no head yet; its last batch
    // writes it, with `complete`.
    if (steps.get(meta.stream)?.final === false) continue;
    statements.push(
      {
        sql: `INSERT OR REPLACE INTO stream_versions (connection_id, stream, version, generation,
                head_blob, head_format, record_count, observed_at, complete, kind)
              SELECT ?, ?, MAX(s.head_version, s.last_delete_version) + 1, ?, ?, ?,
                     (SELECT COUNT(*) FROM records r WHERE r.connection_id = ? AND r.stream = ?),
                     ?, ?, 'applied'
                FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?`,
        params: [
          connectionId,
          meta.stream,
          segment.generation,
          blobName,
          HEAD_FORMAT,
          connectionId,
          meta.stream,
          segment.observedAt,
          meta.complete ? 1 : 0,
          connectionId,
          meta.stream,
        ],
      },
      {
        sql: `UPDATE stream_state SET primary_key = ?, profile_key = ?, profile_version = ?, complete = ?,
                head_version = MAX(head_version, last_delete_version) + 1,
                head_generation = ?, head_data_hash = ?, head_blob = ?
              WHERE connection_id = ? AND stream = ?`,
        params: [
          JSON.stringify(meta.primaryKey),
          meta.profile.key,
          meta.profile.version,
          meta.complete ? 1 : 0,
          segment.generation,
          dataHash,
          blobName,
          connectionId,
          meta.stream,
        ],
      },
    );
  }
  for (const step of steps.values())
    if (step.row)
      statements.push(
        partialRowStatement(step.row.head, step.row.applied, step.row.total, 0),
      );
  if (state) statements.push(writeLogState(connectionId, state));

  try {
    await deps.db.batch(withOrigin("remote", statements));
  } finally {
    await deps.db.batch([
      { sql: "DELETE FROM temp.incoming WHERE op = ?", params: [op] },
    ]);
  }
}

/**
 * The registry's log is not a continuation of the one this device applied: it
 * is behind this device, or names another segment at a position this device
 * holds. A real rebaseline (rows, tombstones and checkpoints rebuilt from the
 * log, the local overlay kept apart) is not built; until it is, the device
 * refuses to read on top of state the log no longer vouches for.
 */
export class LogDivergedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LogDivergedError";
  }
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

  if (classification === "tombstoned") {
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
  let applied = 0;
  if (plan.kind === "gap") {
    if (plan.reason === "ahead_of_head")
      throw new LogDivergedError(
        `apply: the log's newest position ${head.position} is behind this device at ${since}`,
      );
    // A full check. Behind `base` the log no longer holds the prefix: a
    // snapshot does, and it is installed first. Without one (a log that began
    // after the streams were published) the per-stream path holds it.
    if (deps.progressiveFirstLoad === true) {
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
    if (head.snapshot) {
      await installSnapshot(deps, connectionId, scope, context, head, allRefs);
      applied += head.snapshot.parts.length;
    }
    since = head.base;
    plan = planOpsSince(head, headRef, since);
  }
  if (plan.kind !== "segments") return { applied };
  if (deps.progressiveFirstLoad === true)
    return {
      applied: await loadProgressively(
        deps,
        connectionId,
        scope,
        context,
        head,
        allRefs,
        null,
        plan.refs,
      ),
    };

  // Older segments in parallel; they are applied strictly in position order.
  const fetched = new Map<number, Segment>();
  fetched.set(head.position, head);
  await Promise.all(
    plan.refs
      .filter((ref) => ref.position !== head.position)
      .map(async (ref) => {
        fetched.set(
          ref.position,
          (await fetchSegment(deps, scope, context, ref.dataHash, ref.position))
            .segment,
        );
      }),
  );
  for (const ref of plan.refs) {
    const segment = fetched.get(ref.position)!;
    await applySegmentOperations(deps, connectionId, segment, {
      position: ref.position,
      base: head.base,
      refs: allRefs.filter((r) => r.position <= ref.position),
      snapshot: head.snapshot,
    });
    applied++;
  }
  return { applied };
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
  if (verified.kind !== "ok")
    throw new Error(`apply: invalid log snapshot part (${verified.kind})`);
  return verified.part;
}

/**
 * Bring a reader that is behind `head.base` to the snapshot: fetch every part
 * (in parallel), then apply them in index order. The position moves to the
 * snapshot's only with the last part, in the same batch, so an interrupted
 * install is repeated, never half believed. Idempotent.
 */
async function installSnapshot(
  deps: LocalSyncDeps,
  connectionId: string,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  head: Segment,
  allRefs: readonly SegmentRef[],
): Promise<void> {
  const snapshot = head.snapshot!;
  const parts = await Promise.all(
    snapshot.parts.map((ref) =>
      fetchSnapshotPart(deps, scope, context, ref.dataHash, snapshot.position),
    ),
  );
  parts.sort((a, b) => a.index - b.index);
  for (let i = 0; i < parts.length; i++)
    await applySnapshotPart(
      deps,
      connectionId,
      parts[i]!,
      i === parts.length - 1
        ? {
            position: snapshot.position,
            base: head.base,
            refs: allRefs.filter((r) => r.position <= snapshot.position),
            snapshot,
          }
        : undefined,
    );
}

/** Snapshot parts fetched ahead of the one being applied. */
const PART_WINDOW = 4;

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
  const parts: (Promise<SnapshotPart> | undefined)[] = [];
  const startPart = (index: number) => {
    if (index >= partRefs.length || parts[index]) return;
    const fetching = fetchSnapshotPart(
      deps,
      scope,
      context,
      partRefs[index]!.dataHash,
      snapshot!.position,
    );
    fetching.catch(() => undefined);
    parts[index] = fetching;
  };
  for (let i = 0; i < PART_WINDOW; i++) startPart(i);

  const fetched = new Map<number, Segment>([[head.position, head]]);
  const [firstPart] = await Promise.all([
    parts[0] ?? Promise.resolve(undefined),
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

  const seen = new Map<string, number>();
  const begun = new Map<string, PartialIdentity>();
  const finished = new Set<string>();
  try {
    for (let index = 0; index < planned.length; index++) {
      let batch: OperationBatch;
      const isPart = index < partRefs.length;
      if (isPart) {
        const part = await parts[index]!;
        startPart(index + PART_WINDOW);
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

      const steps = new Map<string, BatchStep>();
      for (const meta of batch.streams) {
        const plan = plans.get(meta.stream);
        if (!plan) continue;
        const resume = resumed.get(meta.stream);
        const count = (seen.get(meta.stream) ?? 0) + 1;
        seen.set(meta.stream, count);
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

      const lastPart = isPart && index === partRefs.length - 1;
      const position = index - partRefs.length;
      const state: LogState | undefined = lastPart
        ? {
            position: snapshot!.position,
            base: head.base,
            refs: allRefs.filter((r) => r.position <= snapshot!.position),
            snapshot,
          }
        : !isPart
          ? {
              position: tail[position]!.position,
              base: head.base,
              refs: allRefs.filter(
                (r) => r.position <= tail[position]!.position,
              ),
              snapshot: head.snapshot,
            }
          : undefined;
      await applyBatch(
        deps,
        connectionId,
        batch,
        identities[index]!,
        state,
        steps,
      );
      for (const [stream, step] of steps)
        if (step.final) finished.add(stream);
        else begun.set(stream, heads.get(stream)!);
      if (steps.size > 0) announceApplied(deps, connectionId);
    }
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
