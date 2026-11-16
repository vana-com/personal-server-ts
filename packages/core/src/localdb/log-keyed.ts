// The keyed first load: a device with no rows loads a log it has never read key
// by key, not segment by segment.
//
// Why. The keys of a log are in publish order and `records` is in key order, so
// a segment's rows land across the whole table and its secondary indexes, and a
// commit rewrites about as many pages as the table has leaves (the log's keys
// are hashes; see `pk_hash`). A host whose every page write costs a call (the
// Web's OPFS) pays for each. Committing segments together (`applyInGroups`)
// divides the commits, but each one still rewrites most of the table: the cost
// is the number of commits times the table, and the memory budget sets the
// number of commits. Loading in key order writes each page once.
//
// How. Two phases; the cursor (`log_state`) and the streams' heads move only in
// the last commit, so no reader sees a state between them.
//
//   1. Stage. The segments are fetched, checked and hashed as `applyInGroups`
//      does it (read-ahead against the memory budget), and each operation is
//      appended to the stage table of its key range ("bucket": a range of the
//      first digits of the key's hash). Appending to P tables is sequential
//      writing; nothing touches `records`.
//   2. Apply. One bucket at a time, in one transaction: the keys that have one
//      operation, an upsert (nearly all of a first import), merge in one batch
//      that the merge reads in key order; the keys that have several or a
//      deletion go through the same statements a segment-by-segment load uses,
//      one position at a time, so what the merge does for them is not
//      re-derived here. The bucket's stage table is dropped in the same
//      transaction.
//
// Why it is the same fold: an operation changes only its own key's row and
// tombstone, so keys are independent and a key's operations apply in position
// order in both. What differs is the order in which two keys are written, so
// `record_changes` holds the same changes per key in another order across keys.
// The model: `KeyedLoad` and `KeyedPublish` in docs/formal/log-protocol.
//
// How many buckets is not a number here: the rows of a bucket are in the stage
// table and in `temp.incoming` while it applies, so a bucket is half the
// memory budget, and the buckets are the log's bytes over that (`keyedBuckets`).
// A log that fits in the budget has one commit's worth of rows and gains
// nothing from this: it takes the pass of `applyInGroups`.
//
// What a stopped load leaves. Each bucket's commit makes its rows and
// tombstones durable in `records` and `log_tombstones`, but the streams have no
// version row, so no reader serves them, and the cursor is where it was. Those
// rows are bound to the position the load meant to publish: bucket 0's commit
// also writes `log_keyed_pending` (that position, the base and the segment
// refs), and the commit that publishes deletes it. A retry may publish only a
// target that `pendingAdmits` accepts (same base, no shorter, same data hashes
// at the pending refs): a retry that can fetch fewer segments than the stopped
// load wrote would otherwise publish rows from beyond its cursor. A refused
// retry writes nothing and raises. While the marker exists `applyLog` takes
// this path whatever the flags say, and fails closed (`LogDivergedError`) if it
// cannot: a snapshot, a compaction or a different log has no key-ordered load
// that could finish what was written, and the rows left cannot be told apart
// from rows of the live log. The marker holds back every other way to move the
// position, not only the load plan: the lifetime branches of `applyLog` (a log
// read as ended, a log of an earlier lifetime) write a cursor without applying
// anything, and a device that holds a cursor above 0 beside the marker is not
// one this load made, so each of them raises with the marker kept. The model:
// `KeyedBucket`, `KeyedPage`, `PendingAdmits`, `NoPending`.
//
// A per-stream head admitted while the marker stands may drop rows the load
// wrote (a full head omits the keys of its stream it did not carry). The marker
// stays: rows beyond the cursor can remain, and a retry that holds a shorter
// prefix must still not publish over them. The retry stages the whole log again
// and the merge is order-insensitive per key, so it ends in the rows of a device
// that read the head and then the log.
//
// The way out of a refused retry. A log that compacted, or was rewritten, after
// a stopped load has nothing a key-ordered load can finish, and the rows the
// stopped load left are not told apart from rows of the live log (no per-key
// record says which position wrote a row). Such a connection stays refused
// until its local data is purged, which deletes the marker with the rows. A
// journal of positions per key, or a key-ordered load that also reads a
// snapshot, would remove that wait; neither is built.
//
// A segment that cannot be fetched ends staging there: if no bucket has
// committed yet, the segments before it load, the cursor stands at the last of
// them, and the error is raised, as it is when they apply one by one.
//
// What a bucket holds. Its simple keys (one upsert) merge from the stage table
// in SQL, so they hold nothing in memory. Its complex keys (several operations,
// deletes, omissions) are read into memory to build statements. `STAGE_ROW_BYTES`
// counts every row by what it holds (key, hash and body in UTF-8 bytes, NULL
// bodies and tombstone rows included), and a bucket whose complex rows exceed
// the room is applied a page at a time (`complexPages`: a hash range, or a
// position slice of one key), each page in its own commit. This is weighted
// in-flight accounting against the governor's budget, not a hard memory bound:
// the SQLite driver and the statements a page builds are not counted, and a
// page is held at twice its row bytes to cover them.

import { sha256 } from "@noble/hashes/sha2";
import {
  toHex,
  type LogStreamMeta,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement, SqlValue } from "./driver.js";
import {
  applyInGroups,
  KEYS_PER_STATEMENT,
  commitStaged,
  mergeStaged,
  operationStatements,
  prepareOperations,
  streamHeadStatements,
  streamStateStatement,
  type BatchIdentity,
  type OperationBatch,
  type PassItem,
  type PreparedOperation,
  type StagedBatch,
} from "./log-batch.js";
import {
  clearKeyedPending,
  LogDivergedError,
  readKeyedPending,
  writeKeyedPending,
  writeLogState,
  type LogState,
} from "./log-state.js";
import { holdMemory } from "./transfer-memory.js";

/** Hex digits of a key's hash that place it in a bucket: the key space is 16^4. */
const PLACING_DIGITS = 4;
const KEY_SPACE = 16 ** PLACING_DIGITS;

/** One batch of the load: how it is fetched, and the state that stands for it. */
export interface KeyedSource {
  /** The clear length of the segment. */
  readonly bytes: number;
  readonly load: () => Promise<{
    readonly batch: OperationBatch;
    readonly identity: BatchIdentity;
  }>;
  /** The log position after it, written by the last commit that holds it. */
  readonly state: LogState;
}

/**
 * How many key ranges a log of `totalBytes` splits into so that one range
 * (twice: its stage rows and the rows being merged) fits in the memory budget.
 */
export function keyedBuckets(
  segmentBytes: readonly number[],
  budgetBytes: number,
): number {
  const total = segmentBytes.reduce((sum, bytes) => sum + bytes, 0);
  // A budget under two segments (the read-ahead holds a segment as plain and
  // as encrypted bytes) still admits one alone, so a range holds one at least.
  const room = Math.max(budgetBytes, 2 * Math.max(0, ...segmentBytes));
  return Math.min(KEY_SPACE, Math.max(1, Math.ceil((2 * total) / room)));
}

/**
 * Whether this pass loads key by key, and into how many ranges. It does when
 * the device holds nothing of the log's streams (no stream version, so no
 * reader serves a row, and no position) and the log is more than the memory
 * budget can apply in one commit. Not for a progressive load, which shows a
 * stream while it loads (`progressiveFirstLoad`), nor with a snapshot: its
 * parts are key-ordered already and load as they are.
 */
export async function planKeyedLoad(
  deps: Pick<
    LocalSyncDeps,
    "db" | "blobs" | "progressiveFirstLoad" | "keyedFirstLoad"
  >,
  connectionId: string,
  local: LogState,
  snapshotPresent: boolean,
  tail: readonly { readonly bytes: number }[],
  pending: LogState | null = null,
): Promise<number | null> {
  const buckets = keyedBuckets(
    tail.map((ref) => ref.bytes),
    deps.blobs.governor.limitBytes,
  );
  if (pending !== null) {
    // An unfinished key-ordered load left rows in `records` that only a
    // key-ordered load that covers them may publish over. The rest of the
    // gate (a flag, the size of the log) decided how the first attempt began;
    // it does not decide how to end it.
    if (snapshotPresent || tail.length === 0 || deps.keyedFirstLoad === false)
      throw unfinishedKeyedLoad(
        pending,
        snapshotPresent
          ? "the log has a snapshot now"
          : tail.length === 0
            ? "the log holds no segment past it"
            : "the key-ordered first load is off",
      );
    return buckets;
  }
  if (
    deps.keyedFirstLoad === false ||
    deps.progressiveFirstLoad === true ||
    snapshotPresent ||
    local.position !== 0 ||
    tail.length < 2
  )
    return null;
  if (buckets < 2) return null;
  const [held] = await deps.db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM (SELECT 1 FROM stream_versions WHERE connection_id = ? LIMIT 1)",
    [connectionId],
  );
  return held?.n === 0 ? buckets : null;
}

/**
 * The refusal of every path that cannot finish an unfinished key-ordered load
 * of this connection. Its rows are in `records` and `log_tombstones` and
 * belong to no published position; the way out is a key-ordered load of the
 * same log, or purging the connection's rows.
 */
export function unfinishedKeyedLoad(
  pending: LogState,
  why: string,
): LogDivergedError {
  return new LogDivergedError(
    `apply: an earlier key-ordered load of this connection wrote rows up to position ${pending.position} and did not finish; only a key-ordered load of the same log can finish it (${why})`,
  );
}

/**
 * Whether the rows an unfinished key-ordered load left (`pending`) lie inside
 * the prefix that a load ending at `target` publishes: the same log (the same
 * segment at every position they name) and no shorter. A load that holds less
 * (a segment it cannot fetch now) must leave the cursor where it is, because
 * the rows beyond it would become visible, or hide a row of the prefix, under
 * a cursor that does not cover them.
 */
export function pendingAdmits(
  pending: LogState | null,
  target: LogState,
): boolean {
  if (pending === null) return true;
  if (pending.base !== target.base || pending.position > target.position)
    return false;
  const hashes = new Map(
    target.refs.map((ref) => [ref.position, ref.dataHash.toLowerCase()]),
  );
  return pending.refs.every(
    (ref) => hashes.get(ref.position) === ref.dataHash.toLowerCase(),
  );
}

/** The stage tables of one connection: its id hashed, so any id is a name. */
const tagOf = (connectionId: string) =>
  toHex(sha256(new TextEncoder().encode(connectionId)));
const stageTable = (tag: string, bucket: number) =>
  `log_stage_${tag}_${bucket}`;

const bucketOf = (pkHash: string, buckets: number) =>
  Math.floor(
    (Number.parseInt(pkHash.slice(0, PLACING_DIGITS), 16) * buckets) /
      KEY_SPACE,
  );

/** What a stage row is: an upsert, a delete or an omission. */
type StageKind = "u" | "d" | "o";

type StageRow = {
  readonly position: number;
  readonly kind: StageKind;
  readonly stream: string;
  readonly pk_hash: string;
  readonly record_key: string;
  readonly stamp_o: number;
  readonly stamp_r: string;
  readonly body: string | null;
  readonly body_sha256: string | null;
  readonly first_o: number | null;
  readonly stamp_n: number;
};

const STAGE_COLUMNS =
  "position, kind, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, stamp_n";

/**
 * The keys of a stage table that are not one upsert: written more than once, or
 * deleted or omitted. Those apply through the statements of a segment, one
 * position at a time.
 */
const complexKeys = (table: string) =>
  `SELECT stream, pk_hash FROM ${table} GROUP BY stream, pk_hash
     HAVING COUNT(*) > 1 OR MAX(kind <> 'u')`;

async function dropStages(
  deps: Pick<LocalSyncDeps, "db">,
  tag: string,
): Promise<void> {
  const stale = await deps.db.query<{ name: string }>(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE ? ESCAPE '\\'",
    [`log\\_stage\\_${tag}\\_%`],
  );
  if (stale.length > 0)
    await deps.db.batch(
      stale.map(({ name }) => ({
        sql: `DROP TABLE IF EXISTS ${name}`,
        params: [],
      })),
    );
}

/** Variables a stage row binds. */
const STAGE_FIELDS = STAGE_COLUMNS.split(",").length;

/**
 * The rows a batch's operations add to the stage tables, each in its key's
 * bucket. A bucket's rows go in multi-row inserts, in the order they came: a
 * statement costs the host a call, a row is a few variables.
 */
function stageStatements(
  tag: string,
  buckets: number,
  position: number,
  operations: readonly PreparedOperation[],
): SqlStatement[] {
  const rowsOf = new Map<number, SqlValue[][]>();
  const add = (
    kind: StageKind,
    stream: string,
    pkHash: string,
    recordKey: string,
    stampO: number,
    stampR: string,
    upsert?: {
      body: string;
      bodySha256: string;
      firstO: number | null;
      ordinal: number;
    },
  ) => {
    const bucket = bucketOf(pkHash, buckets);
    const row = [
      position,
      kind,
      stream,
      pkHash,
      recordKey,
      stampO,
      stampR,
      upsert?.body ?? null,
      upsert?.bodySha256 ?? null,
      upsert?.firstO ?? null,
      upsert?.ordinal ?? 0,
    ];
    const rows = rowsOf.get(bucket);
    if (rows) rows.push(row);
    else rowsOf.set(bucket, [row]);
  };
  for (const operation of operations) {
    if (operation.kind === "upsert")
      add(
        "u",
        operation.stream,
        operation.pkHash,
        operation.recordKey,
        operation.stampO,
        operation.stampR,
        operation,
      );
    else if (operation.kind === "complete")
      for (const omission of operation.omitted)
        add(
          "o",
          operation.stream,
          omission.pkHash,
          omission.recordKey,
          operation.stampO,
          operation.stampR,
        );
    else
      add(
        operation.kind === "delete" ? "d" : "o",
        operation.stream,
        operation.pkHash,
        operation.recordKey,
        operation.stampO,
        operation.stampR,
      );
  }
  const perStatement = Math.max(
    1,
    Math.floor(KEYS_PER_STATEMENT / STAGE_FIELDS),
  );
  const statements: SqlStatement[] = [];
  for (const [bucket, rows] of rowsOf)
    for (let i = 0; i < rows.length; i += perStatement) {
      const group = rows.slice(i, i + perStatement);
      statements.push({
        sql: `INSERT INTO ${stageTable(tag, bucket)} (${STAGE_COLUMNS}) VALUES ${group
          .map(() => `(${"?, ".repeat(STAGE_FIELDS - 1)}?)`)
          .join(", ")}`,
        params: group.flat(),
      });
    }
  return statements;
}

/** A stage row as the operation it stands for. */
function operationOf(row: StageRow): PreparedOperation {
  if (row.kind === "u")
    return {
      kind: "upsert",
      stream: row.stream,
      pkHash: row.pk_hash,
      recordKey: row.record_key,
      stampO: row.stamp_o,
      stampR: row.stamp_r,
      body: row.body!,
      bodySha256: row.body_sha256!,
      firstO: row.first_o,
      ordinal: row.stamp_n,
    };
  return {
    kind: row.kind === "d" ? "delete" : "omitted",
    stream: row.stream,
    pkHash: row.pk_hash,
    recordKey: row.record_key,
    stampO: row.stamp_o,
    stampR: row.stamp_r,
  };
}

/** What the last batch that named a stream says of it. */
interface HeadInfo {
  readonly meta: LogStreamMeta;
  readonly generation: number;
  readonly observedAt: number;
  readonly identity: BatchIdentity;
}

/**
 * Load `sources` (the segments after the device's position, in order) key by
 * key into `buckets` key ranges, and move the cursor to the last one loaded.
 * Throws the error that ended the staging, after loading what came before it.
 */
export async function loadKeyed(
  deps: LocalSyncDeps,
  connectionId: string,
  sources: readonly KeyedSource[],
  buckets: number,
): Promise<void> {
  const tag = tagOf(connectionId);
  await dropStages(deps, tag);
  try {
    await deps.db.batch([
      {
        sql: `CREATE TEMP TABLE IF NOT EXISTS log_complex (stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
                PRIMARY KEY (stream, pk_hash)) WITHOUT ROWID`,
        params: [],
      },
      ...Array.from({ length: buckets }, (_, bucket) => ({
        sql: `CREATE TABLE ${stageTable(tag, bucket)} (position INTEGER NOT NULL, kind TEXT NOT NULL,
                stream TEXT NOT NULL, pk_hash TEXT NOT NULL, record_key TEXT NOT NULL,
                stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL, body TEXT, body_sha256 TEXT, first_o INTEGER,
                stamp_n INTEGER NOT NULL DEFAULT 0)`,
        params: [],
      })),
    ]);

    // Phase 1: stage.
    const infos: (Omit<HeadInfo, "meta"> & {
      readonly streams: readonly LogStreamMeta[];
    })[] = [];
    const items: PassItem[] = sources.map((source, position) => ({
      bytes: source.bytes,
      stage: async (): Promise<StagedBatch> => {
        const { batch, identity } = await source.load();
        const operations = await prepareOperations(
          batch.streams,
          batch.operations,
        );
        // Only what the heads need: the operations are not kept.
        infos[position] = {
          streams: batch.streams,
          generation: batch.generation,
          observedAt: batch.observedAt,
          identity,
        };
        return {
          op: deps.newOp(),
          statements: stageStatements(tag, buckets, position, operations),
        };
      },
    }));
    let staged = 0;
    let stopped: { readonly error: unknown } | undefined;
    try {
      await applyInGroups(deps, items, {
        firstAlone: false,
        onCommit: (_first, last) => {
          staged = last + 1;
        },
      });
    } catch (error) {
      stopped = { error };
    }
    if (staged === 0) throw stopped?.error;

    // Phase 2: apply, one bucket per transaction.
    const heads = new Map<string, HeadInfo>();
    const primaryKeys = new Map<string, LogStreamMeta>();
    for (const info of infos.slice(0, staged))
      for (const meta of info!.streams) {
        if (!primaryKeys.has(meta.stream)) primaryKeys.set(meta.stream, meta);
        heads.set(meta.stream, { ...info!, meta });
      }
    const last = sources[staged - 1]!.state;
    // What an unfinished load of this connection wrote must lie inside the
    // prefix this one publishes; if it does not, write nothing.
    if (!pendingAdmits(await readKeyedPending(deps, connectionId), last)) {
      if (stopped) throw stopped.error;
      throw new LogDivergedError(
        "apply: the log is not the one an earlier key-ordered load of this connection wrote rows from",
      );
    }
    for (let bucket = 0; bucket < buckets; bucket++)
      await applyBucket(deps, connectionId, tag, bucket, {
        // The first range creates the streams' rows and names the position
        // the rows it and the later ranges write belong to.
        first:
          bucket === 0
            ? { primaryKeys: [...primaryKeys.values()], target: last }
            : undefined,
        last:
          bucket === buckets - 1
            ? { heads: [...heads.values()], state: last }
            : undefined,
      });
    if (stopped) throw stopped.error;
  } finally {
    await dropStages(deps, tag).catch(() => undefined);
  }
}

/**
 * What a stage row holds in memory, in bytes: every text field as UTF-8 (a
 * body or a key of non-ASCII text is more bytes than characters) and each
 * number as 8. A deletion or an omission has no body and still holds its keys.
 */
const STAGE_ROW_BYTES = `(
  LENGTH(CAST(kind AS BLOB)) + LENGTH(CAST(stream AS BLOB)) + LENGTH(CAST(pk_hash AS BLOB))
  + LENGTH(CAST(record_key AS BLOB)) + LENGTH(CAST(stamp_r AS BLOB))
  + COALESCE(LENGTH(CAST(body AS BLOB)), 0) + COALESCE(LENGTH(CAST(body_sha256 AS BLOB)), 0)
  + 4 * 8)`;

/** A slice of one bucket's complex rows: a range of key hashes, and of positions. */
interface ComplexPage {
  readonly from: string;
  /** Exclusive: above every hex digit, so `prefix + "g"` ends a prefix's range. */
  readonly to: string;
  readonly firstPosition: number;
  readonly lastPosition: number;
  /** What `weighPage` counts for the rows of the slice. */
  readonly bytes: number;
}

const PAGE_FILTER = "pk_hash >= ? AND pk_hash < ? AND position BETWEEN ? AND ?";
const pageParams = (page: ComplexPage): SqlValue[] => [
  page.from,
  page.to,
  page.firstPosition,
  page.lastPosition,
];

async function weighPage(
  deps: Pick<LocalSyncDeps, "db">,
  table: string,
  page: ComplexPage,
): Promise<{ n: number; bytes: number }> {
  const [weight] = await deps.db.query<{ n: number; bytes: number }>(
    `SELECT COUNT(*) AS n, COALESCE(SUM(${STAGE_ROW_BYTES}), 0) AS bytes
       FROM ${table} WHERE ${PAGE_FILTER}
        AND (stream, pk_hash) IN (${complexKeys(table)})`,
    pageParams(page),
  );
  return weight!;
}

/**
 * The slices the complex rows of a bucket are applied in, each holding at most
 * `room` bytes (as `weighPage` counts them, twice: the rows and the statements
 * made from them). One slice for a bucket that fits, which is nearly always: the
 * bucket count already divides the log's bytes by the budget. A bucket whose
 * keys cluster (their hashes share a prefix) splits by the next hex digit of
 * the hash until each piece fits. A single key whose operations are over the
 * room splits by position: its operations apply in position order, and a slice
 * is a run of them.
 */
export async function complexPages(
  deps: Pick<LocalSyncDeps, "db">,
  table: string,
  room: number,
): Promise<ComplexPage[]> {
  const all: ComplexPage = {
    from: "",
    to: "g",
    firstPosition: 0,
    lastPosition: Number.MAX_SAFE_INTEGER,
    bytes: 0,
  };
  const split = async (prefix: string): Promise<ComplexPage[]> => {
    const page = { ...all, from: prefix, to: `${prefix}g` };
    const weight = await weighPage(deps, table, page);
    if (weight.n === 0) return [];
    if (2 * weight.bytes <= room) return [{ ...page, bytes: weight.bytes }];
    if (prefix.length < 64) {
      const pieces: ComplexPage[] = [];
      for (const digit of "0123456789abcdef")
        pieces.push(...(await split(prefix + digit)));
      return pieces;
    }
    // One key: slice its positions.
    const byPosition = await deps.db.query<{ position: number; bytes: number }>(
      `SELECT position, SUM(${STAGE_ROW_BYTES}) AS bytes FROM ${table}
        WHERE pk_hash = ? AND (stream, pk_hash) IN (${complexKeys(table)})
        GROUP BY position ORDER BY position`,
      [prefix],
    );
    const slices: ComplexPage[] = [];
    let start = byPosition[0]!.position;
    let held = 0;
    for (const { position, bytes } of byPosition) {
      if (held > 0 && 2 * (held + bytes) > room) {
        slices.push({
          ...page,
          firstPosition: start,
          lastPosition: position - 1,
          bytes: held,
        });
        start = position;
        held = 0;
      }
      held += bytes;
    }
    slices.push({
      ...page,
      firstPosition: start,
      lastPosition: Number.MAX_SAFE_INTEGER,
      bytes: held,
    });
    return slices;
  };
  return split("");
}

/**
 * One key range. A bucket whose complex rows fit the memory budget commits in
 * one transaction. The single-upsert keys merge in one batch from the stage
 * table; the others (see `complexKeys`) apply as the segments they came from,
 * in position order, restricted to these keys. A bucket whose complex rows do
 * not fit commits the single-upsert keys first, then the complex rows a page
 * at a time (`complexPages`), then the clean-up: the rows are held in memory
 * for a page, not for the bucket.
 */
async function applyBucket(
  deps: LocalSyncDeps,
  connectionId: string,
  tag: string,
  bucket: number,
  edges: {
    /** The first range creates the streams' rows and names the position the rows written from here on belong to. */
    readonly first?: {
      readonly primaryKeys: readonly Pick<
        LogStreamMeta,
        "stream" | "primaryKey"
      >[];
      readonly target: LogState;
    };
    /** The last range writes the streams' heads and the cursor. */
    readonly last?: {
      readonly heads: readonly HeadInfo[];
      readonly state: LogState;
    };
  },
): Promise<void> {
  const table = stageTable(tag, bucket);
  const pages = await complexPages(deps, table, deps.blobs.governor.limitBytes);
  const simpleOp = deps.newOp();
  const simple: SqlStatement[] = [
    ...(edges.first
      ? [
          // In the commit of the first rows the load writes, or before it: the
          // position those rows lie within. A load that is one commit has no
          // rows to fence.
          ...(edges.last && pages.length <= 1
            ? []
            : [writeKeyedPending(connectionId, edges.first.target)]),
          ...edges.first.primaryKeys.map((meta) =>
            streamStateStatement(connectionId, meta),
          ),
        ]
      : []),
    { sql: `INSERT INTO temp.log_complex ${complexKeys(table)}`, params: [] },
    {
      sql: `INSERT INTO temp.incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, stamp_n)
            SELECT ?, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, stamp_n
              FROM ${table} s
             WHERE s.kind = 'u' AND NOT EXISTS (
               SELECT 1 FROM temp.log_complex c WHERE c.stream = s.stream AND c.pk_hash = s.pk_hash)`,
      params: [simpleOp],
    },
    ...mergeStaged(connectionId, simpleOp),
    { sql: "DELETE FROM temp.log_complex", params: [] },
  ];
  const closing: SqlStatement[] = [{ sql: `DROP TABLE ${table}`, params: [] }];
  if (edges.last) {
    for (const head of edges.last.heads)
      closing.push(
        ...streamHeadStatements(connectionId, [head.meta], head, head.identity),
      );
    closing.push(
      writeLogState(connectionId, edges.last.state),
      clearKeyedPending(connectionId),
    );
  }

  // The complex rows of a page, as the batches that apply them: one per
  // position, in position order (the rows came out in the order they were staged).
  const batchesOf = async (page: ComplexPage): Promise<StagedBatch[]> => {
    const rows = await deps.db.query<StageRow>(
      `SELECT ${STAGE_COLUMNS} FROM ${table}
        WHERE ${PAGE_FILTER} AND (stream, pk_hash) IN (${complexKeys(table)}) ORDER BY rowid`,
      pageParams(page),
    );
    const byPosition = new Map<number, PreparedOperation[]>();
    for (const row of rows) {
      const operations = byPosition.get(row.position);
      if (operations) operations.push(operationOf(row));
      else byPosition.set(row.position, [operationOf(row)]);
    }
    return [...byPosition.values()].map((operations) => {
      const op = deps.newOp();
      return {
        op,
        statements: operationStatements(connectionId, op, operations),
      };
    });
  };
  // The rows of a page and the statements made from them: twice its bytes.
  const hold = (page: ComplexPage) => holdMemory(deps.blobs, 2 * page.bytes, 0);

  if (pages.length <= 1) {
    const release = pages[0] ? await hold(pages[0]) : undefined;
    try {
      await commitStaged(deps, [
        { op: simpleOp, statements: simple },
        ...(pages[0] ? await batchesOf(pages[0]) : []),
        { op: deps.newOp(), statements: closing },
      ]);
    } finally {
      release?.();
    }
    return;
  }
  await commitStaged(deps, [{ op: simpleOp, statements: simple }]);
  for (const page of pages) {
    const release = await hold(page);
    try {
      await commitStaged(deps, await batchesOf(page));
    } finally {
      release();
    }
  }
  await commitStaged(deps, [{ op: deps.newOp(), statements: closing }]);
}
