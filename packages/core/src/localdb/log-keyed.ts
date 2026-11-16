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
// What a stopped load leaves. Before the last commit the streams have no
// version row, so no reader serves their rows, and the cursor is where it was.
// The next pass finds no version row (the gate below) and loads again; the
// stage tables of the stopped load are dropped first, and the rows it merged
// merge again to the same rows (a segment applies any number of times). A
// segment that cannot be fetched ends staging there: the segments before it
// load, the cursor stands at the last of them, and the error is raised, as it
// is when they apply one by one.

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
import { writeLogState, type LogState } from "./log-state.js";
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
): Promise<number | null> {
  if (
    deps.keyedFirstLoad === false ||
    deps.progressiveFirstLoad === true ||
    snapshotPresent ||
    local.position !== 0 ||
    tail.length < 2
  )
    return null;
  const buckets = keyedBuckets(
    tail.map((ref) => ref.bytes),
    deps.blobs.governor.limitBytes,
  );
  if (buckets < 2) return null;
  const [held] = await deps.db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM (SELECT 1 FROM stream_versions WHERE connection_id = ? LIMIT 1)",
    [connectionId],
  );
  return held?.n === 0 ? buckets : null;
}

/** The stage tables of one connection: its id hashed, so any id is a name. */
const tagOf = (connectionId: string) =>
  toHex(sha256(new TextEncoder().encode(connectionId))).slice(0, 16);
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
    for (let bucket = 0; bucket < buckets; bucket++)
      await applyBucket(deps, connectionId, tag, bucket, {
        first: bucket === 0 ? [...primaryKeys.values()] : [],
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
 * One key range, in one transaction. The single-upsert keys merge in one batch
 * from the stage table; the others (see `complexKeys`) apply as the segments
 * they came from, in position order, restricted to these keys.
 */
async function applyBucket(
  deps: LocalSyncDeps,
  connectionId: string,
  tag: string,
  bucket: number,
  edges: {
    /** The first range creates the streams' rows. */
    readonly first: readonly Pick<LogStreamMeta, "stream" | "primaryKey">[];
    /** The last range writes the streams' heads and the cursor. */
    readonly last?: {
      readonly heads: readonly HeadInfo[];
      readonly state: LogState;
    };
  },
): Promise<void> {
  const table = stageTable(tag, bucket);
  const [weight] = await deps.db.query<{ n: number; bytes: number }>(
    `SELECT COUNT(*) AS n,
            COALESCE(SUM(LENGTH(body) + LENGTH(pk_hash) + LENGTH(record_key) + LENGTH(stream)), 0) AS bytes
       FROM ${table} WHERE (stream, pk_hash) IN (${complexKeys(table)})`,
  );
  // The rows of the keys that need their own statements are in memory while
  // the bucket commits: they come out of the same budget the staging used.
  const hold =
    weight!.n > 0
      ? await holdMemory(deps.blobs, 2 * weight!.bytes, 0)
      : undefined;
  try {
    const rows =
      weight!.n > 0
        ? await deps.db.query<StageRow>(
            `SELECT ${STAGE_COLUMNS} FROM ${table}
              WHERE (stream, pk_hash) IN (${complexKeys(table)}) ORDER BY rowid`,
          )
        : [];
    const byPosition = new Map<number, PreparedOperation[]>();
    for (const row of rows) {
      const operations = byPosition.get(row.position);
      if (operations) operations.push(operationOf(row));
      else byPosition.set(row.position, [operationOf(row)]);
    }

    const simpleOp = deps.newOp();
    const batches: StagedBatch[] = [
      {
        op: simpleOp,
        statements: [
          ...edges.first.map((meta) =>
            streamStateStatement(connectionId, meta),
          ),
          {
            sql: `INSERT INTO temp.log_complex ${complexKeys(table)}`,
            params: [],
          },
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
        ],
      },
    ];
    // Positions ascend (a Map keeps the order its keys were set in, and the
    // rows came out in the order they were staged).
    for (const [, operations] of byPosition) {
      const op = deps.newOp();
      batches.push({
        op,
        statements: operationStatements(connectionId, op, operations),
      });
    }
    const closing: SqlStatement[] = [
      { sql: `DROP TABLE ${table}`, params: [] },
    ];
    if (edges.last) {
      for (const head of edges.last.heads)
        closing.push(
          ...streamHeadStatements(
            connectionId,
            [head.meta],
            head,
            head.identity,
          ),
        );
      closing.push(writeLogState(connectionId, edges.last.state));
    }
    batches.push({ op: deps.newOp(), statements: closing });
    await commitStaged(deps, batches);
  } finally {
    hold?.();
  }
}
