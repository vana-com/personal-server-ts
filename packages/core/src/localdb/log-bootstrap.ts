import { copyBootstrapRecords } from "./bootstrap-copy.js";
import {
  followMeta,
  segmentBlobName,
  segmentRemoves,
  type Segment,
  type SegmentRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import type { LogState } from "./log-state.js";
import { writeLogState } from "./log-state.js";
import { BootstrapKeys, type StagedKey } from "./bootstrap-keys.js";
import { bootstrapSchema, swapBootstrapRecords } from "./bootstrap-swap.js";
import {
  prepareOperations,
  stageBatch,
  commitStaged,
  rowsPerStatement,
  streamStateStatement,
  streamHeadStatements,
} from "./log-batch.js";
import {
  partialRowStatement,
  failedRowStatement,
  noteMarkedFailed,
  hideStoredRows,
  type PartialIdentity,
} from "./partial-load.js";
import { withOrigin } from "./merge.js";
import { announceApplied } from "./apply-progress.js";
import { readPartsAhead, type PartReader } from "./part-readahead.js";

export class FalseRemovalFact extends Error {
  constructor() {
    super(
      "apply: invalid log segment (removes a key its ref says it does not)",
    );
  }
}
interface Receipt extends Record<string, string | number> {
  position: number;
  data_hash: string;
  first_row: number;
  last_row: number;
  observed_at: number;
  metas: string;
  removes: number;
}
interface Load extends Record<string, string | number> {
  connection_id: string;
  generation: number;
  base: number;
  preview_done: number;
}
const bodyColumns = [
  "connection_id",
  "stream",
  "pk_hash",
  "record_key",
  "stamp_o",
  "stamp_r",
  "body",
  "body_sha256",
  "first_o",
  "seen_o",
  "seen_r",
  "body_bytes",
  "stamp_n",
];
const bodyMeta = `b.rowid seq,b.connection_id,b.stream,b.pk_hash,'u' kind,1 rank,b.stamp_o,b.stamp_r,b.stamp_n,b.body_sha256`;
const delMeta = `-rowid seq,connection_id,stream,pk_hash,'d' kind,rank,stamp_o,stamp_r,0 stamp_n,NULL body_sha256,position,entry_order`;

/** One disk-backed first image. Only keys and row pointers survive a segment. */
async function runBootstrap(input: {
  deps: LocalSyncDeps;
  connectionId: string;
  generation: number;
  base: number;
  head: Segment;
  refs: readonly SegmentRef[];
  fetch: (ref: SegmentRef) => Promise<Segment>;
  state: LogState;
}): Promise<number | null> {
  const { deps, connectionId, generation, base, head, refs } = input;
  let [load] = await deps.db.query<Load>(
    "SELECT * FROM bootstrap_load WHERE id=1",
  );
  if (load && load.connection_id !== connectionId) return 0;
  if (!load) {
    const [held] = await deps.db.query<{ n: number }>(
      `SELECT
      EXISTS(SELECT 1 FROM records WHERE connection_id=?) OR EXISTS(SELECT 1 FROM stream_versions WHERE connection_id=?)
      OR EXISTS(SELECT 1 FROM runs WHERE connection_id=? AND state='collecting')
      OR EXISTS(SELECT 1 FROM record_changes WHERE connection_id=? AND origin IS NOT 'remote') AS n`,
      [connectionId, connectionId, connectionId, connectionId],
    );
    if (held!.n) return null;
  }
  // Audit before acquiring ownership and again before the final DDL.
  let schema;
  try {
    schema = await bootstrapSchema(deps.db, false);
  } catch (error) {
    if (load) throw error;
    return null;
  }
  if (load && (load.generation !== generation || load.base !== base))
    throw new Error("bootstrap: different log lifetime");
  let receipts = await deps.db.query<Receipt>(
    "SELECT * FROM bootstrap_segments ORDER BY position",
  );
  const byPosition = new Map(refs.map((ref) => [ref.position, ref]));
  for (const receipt of receipts)
    if (
      byPosition.get(receipt.position)?.dataHash.toLowerCase() !==
      receipt.data_hash
    )
      throw new Error("bootstrap: the staged prefix is not in this head");
  if (!load) {
    await deps.db.batch([
      {
        sql: "INSERT INTO bootstrap_load(id,connection_id,generation,base) VALUES(1,?,?,?)",
        params: [connectionId, generation, base],
      },
      { sql: schema.table },
    ]);
    load = { connection_id: connectionId, generation, base, preview_done: 0 };
  }
  const target = refs.at(-1)!;
  const versions = new Map(
    (
      await deps.db.query<{ stream: string; v: number }>(
        "SELECT stream,MAX(head_version,last_delete_version)+1 v FROM stream_state WHERE connection_id=?",
        [connectionId],
      )
    ).map((row) => [row.stream, row.v]),
  );
  const identity = (stream: string): PartialIdentity => ({
    connectionId,
    stream,
    version: versions.get(stream) ?? 1,
    generation,
    dataHash: target.dataHash.toLowerCase(),
    headBlob: segmentBlobName(target.dataHash),
    observedAt: head.observedAt,
  });
  const known = new Map<string, Segment["streams"][number]>();
  for (const receipt of receipts)
    for (const meta of JSON.parse(receipt.metas)) known.set(meta.stream, meta);
  for (const meta of head.streams) known.set(meta.stream, meta);
  const seed = () =>
    [...known.values()].flatMap((meta) => [
      streamStateStatement(connectionId, meta),
      partialRowStatement(
        identity(meta.stream),
        load!.preview_done ? 1 : 0,
        refs.length,
        0,
      ),
    ]);
  let ahead: PartReader<SegmentRef, Segment> | undefined;
  let indexes = new Map<number, number>();
  try {
    await deps.db.batch(seed());
    announceApplied(deps, connectionId);
    let previewSegment: Segment | undefined;
    const stage = async (ref: SegmentRef) => {
      const old = receipts.find((r) => r.position === ref.position);
      if (old) {
        if (ref.removes === false && old.removes) throw new FalseRemovalFact();
        return;
      }
      const index = indexes.get(ref.position);
      const segment =
        ahead && index !== undefined
          ? await ahead.load(ref, index)
          : ref.position === head.position
            ? head
            : await input.fetch(ref);
      if (ref.position === refs[0]!.position && !load!.preview_done)
        previewSegment = segment;
      const removes = segmentRemoves(segment.operations);
      if (ref.removes === false && removes) throw new FalseRemovalFact();
      const prepared = await prepareOperations(
        segment.streams,
        segment.operations,
      );
      const [{ n: first }] = await deps.db.query<{ n: number }>(
        "SELECT COALESCE(MAX(rowid),0)+1 n FROM bootstrap_records",
      );
      const values = prepared
        .filter((op) => op.kind === "upsert")
        .map((op) => [
          connectionId,
          op.stream,
          op.pkHash,
          op.recordKey,
          op.stampO,
          op.stampR,
          op.body,
          op.bodySha256,
          op.firstO,
          null,
          null,
          new TextEncoder().encode(op.body).length,
          op.ordinal,
        ]);
      const statements: SqlStatement[] = [];
      const groupSize = rowsPerStatement(bodyColumns.length);
      for (let i = 0; i < values.length; i += groupSize) {
        const group = values.slice(i, i + groupSize);
        statements.push({
          sql: `INSERT INTO bootstrap_records(${bodyColumns.join(",")}) VALUES ${group.map(() => `(${bodyColumns.map(() => "?").join(",")})`).join(",")}`,
          params: group.flat(),
        });
      }
      for (const [order, op] of prepared.entries()) {
        if (op.kind === "upsert") continue;
        const keys = op.kind === "complete" ? op.omitted : [op];
        for (const key of keys)
          statements.push({
            sql: "INSERT INTO bootstrap_deletions(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,rank,position,entry_order) VALUES(?,?,?,?,?,?,?,?,?)",
            params: [
              connectionId,
              op.stream,
              key.pkHash,
              key.recordKey,
              op.stampO,
              op.stampR,
              op.kind === "delete" ? 2 : 0,
              ref.position,
              order,
            ],
          });
      }
      const receipt: Receipt = {
        position: ref.position,
        data_hash: ref.dataHash.toLowerCase(),
        first_row: first!,
        last_row: first! + values.length - 1,
        observed_at: segment.observedAt,
        metas: JSON.stringify(segment.streams),
        removes: removes ? 1 : 0,
      };
      statements.push({
        sql: "INSERT INTO bootstrap_segments(position,data_hash,first_row,last_row,observed_at,metas,removes) VALUES(?,?,?,?,?,?,?)",
        params: [
          receipt.position,
          receipt.data_hash,
          receipt.first_row,
          receipt.last_row,
          receipt.observed_at,
          receipt.metas,
          receipt.removes,
        ],
      });
      await deps.db.batch(statements);
      if (ahead && index !== undefined) ahead.committed(index);
      receipts.push(receipt);
      for (const meta of segment.streams) known.set(meta.stream, meta);
    };
    // Unknown facts remain conservative. Prerequisite errors are inside the
    // same failure boundary as append, preview and final publication.
    for (const ref of refs) if (ref.removes !== false) await stage(ref);
    const first = refs[0]!;
    await stage(first);
    if (!load.preview_done) {
      const segment =
        previewSegment ??
        (first.position === head.position ? head : await input.fetch(first));
      const held = new Map<string, string[]>();
      for (const row of await deps.db.query<{
        stream: string;
        pk_hash: string;
      }>("SELECT stream,pk_hash FROM bootstrap_deletions WHERE position>?", [
        first.position,
      ]))
        held.set(row.stream, [...(held.get(row.stream) ?? []), row.pk_hash]);
      await deps.db.batch(seed());
      const staged = await stageBatch(
        deps,
        connectionId,
        segment,
        { dataHash: first.dataHash, blobName: segmentBlobName(first.dataHash) },
        undefined,
        new Map(
          segment.streams.map((meta) => [
            meta.stream,
            {
              begin: true,
              final: false,
              held: held.get(meta.stream) ?? [],
              row: {
                head: identity(meta.stream),
                applied: 1,
                total: refs.length,
              },
            },
          ]),
        ),
      );
      await commitStaged(deps, [
        {
          ...staged,
          statements: [
            ...staged.statements,
            {
              sql: "INSERT OR IGNORE INTO bootstrap_preview SELECT connection_id,stream,pk_hash FROM records WHERE connection_id=?",
              params: [connectionId],
            },
            { sql: "UPDATE bootstrap_load SET preview_done=1 WHERE id=1" },
          ],
        },
      ]);
      load.preview_done = 1;
      previewSegment = undefined;
      announceApplied(deps, connectionId);
    }
    const receipted = new Set(receipts.map((receipt) => receipt.position));
    const remaining = refs.filter((ref) => !receipted.has(ref.position));
    indexes = new Map(remaining.map((ref, index) => [ref.position, index]));
    ahead = readPartsAhead(deps.blobs, remaining, async (ref) =>
      ref.position === head.position ? head : input.fetch(ref),
    );
    for (const ref of refs) await stage(ref);
    // Rebuildable narrow index: no downloaded segment promise/body is retained.
    receipts = receipts.sort((a, b) => a.position - b.position);
    const lookup = async (seq: number) => {
      const [row] =
        seq > 0
          ? await deps.db.query<StagedKey>(
              `SELECT ${bodyMeta},s.position,b.rowid-s.first_row entry_order FROM bootstrap_records b JOIN bootstrap_segments s ON b.rowid BETWEEN s.first_row AND s.last_row WHERE b.rowid=?`,
              [seq],
            )
          : await deps.db.query<StagedKey>(
              `SELECT ${delMeta} FROM bootstrap_deletions WHERE rowid=?`,
              [-seq],
            );
      if (!row) throw new Error("bootstrap: missing winner metadata");
      return row;
    };
    const keys = new BootstrapKeys(deps.db, lookup);
    for (const receipt of receipts) {
      const rows = await deps.db.query<StagedKey>(
        `SELECT ${bodyMeta},? position,b.rowid-? entry_order FROM bootstrap_records b WHERE b.rowid BETWEEN ? AND ? ORDER BY b.rowid`,
        [
          receipt.position,
          receipt.first_row,
          receipt.first_row,
          receipt.last_row,
        ],
      );
      for (const row of rows) await keys.add(row);
      for (const row of await deps.db.query<StagedKey>(
        `SELECT ${delMeta} FROM bootstrap_deletions WHERE position=? ORDER BY rowid`,
        [receipt.position],
      ))
        await keys.add(row);
    }
    const groups = await keys.sorted();
    const live = groups.flatMap((g) =>
      g.keys.filter((k) => k[1] > 0).map((k) => k[1]),
    );
    const total = receipts.reduce(
      (n, r) => n + r.last_row - r.first_row + 1,
      0,
    );
    const [{ n: outside }] = await deps.db.query<{ n: number }>(
      "SELECT EXISTS(SELECT 1 FROM records WHERE connection_id<>?) n",
      [connectionId],
    );
    let swap = !outside && deps.bootstrapFirstLoadFinish !== "copy";
    if (swap)
      try {
        await bootstrapSchema(deps.db);
      } catch {
        swap = false;
      }
    const finish: SqlStatement[] = [
      {
        sql: "CREATE TEMP TABLE bootstrap_guard(ok INTEGER NOT NULL CHECK(ok=1))",
      },
      {
        sql: `INSERT INTO temp.bootstrap_guard SELECT NOT EXISTS(SELECT 1 FROM records r WHERE r.connection_id=? AND NOT EXISTS(SELECT 1 FROM bootstrap_preview p WHERE p.connection_id=r.connection_id AND p.stream=r.stream AND p.pk_hash=r.pk_hash))
        ${swap ? "AND NOT EXISTS(SELECT 1 FROM records r WHERE NOT EXISTS(SELECT 1 FROM bootstrap_preview p WHERE p.connection_id=r.connection_id AND p.stream=r.stream AND p.pk_hash=r.pk_hash))" : ""}
        AND NOT EXISTS(SELECT 1 FROM record_changes WHERE connection_id=? AND origin IS NOT 'remote')
        AND EXISTS(SELECT 1 FROM connections c WHERE c.connection_id=? AND c.generation=? AND c.control_state='active' AND c.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM delete_intents d WHERE d.connector=c.connector))`,
        params: [connectionId, connectionId, connectionId, generation],
      },
      { sql: "DROP TABLE temp.bootstrap_guard" },
    ];
    if (swap && total !== live.length) {
      finish.push({
        sql: "CREATE TEMP TABLE bootstrap_live(row_id INTEGER PRIMARY KEY)",
      });
      const size = rowsPerStatement(1);
      for (let i = 0; i < live.length; i += size) {
        const group = live.slice(i, i + size);
        finish.push({
          sql: `INSERT INTO temp.bootstrap_live VALUES ${group.map(() => "(?)").join(",")}`,
          params: group,
        });
      }
      finish.push(
        {
          sql: "DELETE FROM bootstrap_records WHERE rowid NOT IN(SELECT row_id FROM temp.bootstrap_live)",
        },
        { sql: "DROP TABLE temp.bootstrap_live" },
      );
    }
    for (const group of groups)
      for (const [, , deletion] of group.keys)
        if (deletion)
          finish.push({
            sql: "INSERT OR REPLACE INTO log_tombstones(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,rank) SELECT connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,rank FROM bootstrap_deletions WHERE rowid=?",
            params: [-deletion],
          });
    finish.push(
      ...(swap
        ? swapBootstrapRecords(await bootstrapSchema(deps.db), connectionId)
        : await copyBootstrapRecords(deps.db, schema, groups)),
    );
    const latest = new Map<
      string,
      { receipt: Receipt; meta: Segment["streams"][number] }
    >();
    // The last meta of each stream gives its head; the last one that carried
    // a cursor gives its cursor.
    for (const receipt of receipts)
      for (const meta of JSON.parse(receipt.metas))
        latest.set(meta.stream, {
          receipt,
          meta: followMeta(latest.get(meta.stream)?.meta, meta),
        });
    for (const { receipt, meta } of latest.values()) {
      finish.push(
        ...streamHeadStatements(
          connectionId,
          [meta],
          { generation, observedAt: receipt.observed_at },
          {
            dataHash: receipt.data_hash,
            blobName: segmentBlobName(receipt.data_hash),
          },
        ),
      );
      finish.push({
        sql: "DELETE FROM stream_partial WHERE connection_id=? AND stream=?",
        params: [connectionId, meta.stream],
      });
    }
    finish.push(
      writeLogState(connectionId, input.state),
      { sql: "DELETE FROM bootstrap_preview" },
      { sql: "DELETE FROM bootstrap_deletions" },
      { sql: "DELETE FROM bootstrap_segments" },
      { sql: "DELETE FROM bootstrap_load" },
    );
    await deps.db.batch(withOrigin("remote", finish));
    announceApplied(deps, connectionId);
    return refs.length;
  } catch (error) {
    const stopped = await deps.db.query<{ stream: string }>(
      "SELECT stream FROM stream_partial WHERE connection_id=?",
      [connectionId],
    );
    const statements = stopped.flatMap((row) => [
      ...(error instanceof FalseRemovalFact
        ? hideStoredRows(connectionId, row.stream)
        : []),
      failedRowStatement(
        identity(row.stream),
        error instanceof FalseRemovalFact ? "invalid_segment" : "apply_failed",
      ),
    ]);
    if (statements.length)
      await deps.db.batch(statements).then(
        () => {
          noteMarkedFailed(
            deps.attemptFailures,
            stopped.map((row) => row.stream),
            error instanceof FalseRemovalFact
              ? "invalid_segment"
              : "apply_failed",
          );
          announceApplied(deps, connectionId);
        },
        () => undefined,
      );
    throw error;
  } finally {
    ahead?.close();
  }
}

const bootstraps = new WeakMap<object, Promise<unknown>>();
/** Serialize first-source images across the connection queues of one DB. */
export function loadBootstrap(
  input: Parameters<typeof runBootstrap>[0],
): Promise<number | null> {
  const key = input.deps.db.info;
  const previous = bootstraps.get(key) ?? Promise.resolve();
  const result = previous
    .catch(() => undefined)
    .then(() => runBootstrap(input));
  const settled = result.finally(() => {
    if (bootstraps.get(key) === settled) bootstraps.delete(key);
  });
  bootstraps.set(key, settled);
  return settled;
}

/** A snapshot, new lifetime or divergent head cannot inherit an old heap. */
export async function discardBootstrap(
  deps: LocalSyncDeps,
  connectionId: string,
) {
  const [owned] = await deps.db.query(
    "SELECT 1 FROM bootstrap_load WHERE connection_id=?",
    [connectionId],
  );
  if (!owned) return;
  await deps.db.batch(
    withOrigin("remote", [
      {
        sql: "DELETE FROM records WHERE connection_id=? AND (stream,pk_hash) IN(SELECT stream,pk_hash FROM bootstrap_preview WHERE connection_id=?)",
        params: [connectionId, connectionId],
      },
      {
        sql: "DELETE FROM stream_partial WHERE connection_id=?",
        params: [connectionId],
      },
      { sql: "DROP TABLE IF EXISTS bootstrap_records" },
      { sql: "DELETE FROM bootstrap_preview" },
      { sql: "DELETE FROM bootstrap_deletions" },
      { sql: "DELETE FROM bootstrap_segments" },
      { sql: "DELETE FROM bootstrap_load" },
    ]),
  );
  announceApplied(deps, connectionId);
}
