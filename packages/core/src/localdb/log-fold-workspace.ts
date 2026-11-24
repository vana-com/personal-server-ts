// The fold of a log history held on disk (stream-sync `foldLog`, which holds it
// in memory). A compaction or a rebase folds the whole history of a log: every
// winner of every key, with its body. That is the size of the data, not of the
// round, so it cannot live in the process.
//
// A workspace keeps one cell per key in the local database. Each operation
// updates its key's cell in SQL, so the history passes through memory a segment
// or a part at a time, and the winners are read back in key order, a page at a
// time. The rules are `foldLog`'s, in the same input order:
//
//  - Per key the greatest upsert and the greatest deletion are kept apart. An
//    upsert replaces the cell's when it is strictly after it (`upsertAfter`:
//    stamp, then `ordinal ?? 0`, then body hash), so of two equal upserts the
//    first stays. That is the row-value comparison `(o, r, ordinal, hash) >`.
//  - A deletion replaces the cell's when it is strictly after it by stamp, or
//    ties it and is an explicit delete over an omission: the row-value
//    comparison `(o, r, explicit) >`.
//  - What a cell says once every operation is in is `foldCellEntries`, the one
//    rule `foldLog` also ends with.
//
// A body is stored as it arrived: inline, or by reference (the pieces that hold
// it stay in storage). A reference is not fetched here: a fold that only
// carries a body forward has no use for its bytes, and its hash is in the
// reference.
//
// Strings compare as bytes in SQLite and as UTF-16 units in JavaScript. They
// agree on stream names, key hashes and run ids (ASCII); `foldLog` and the
// workspace are tested against each other on such input.
//
// The rows are scratch of one operation, keyed by connection and purpose. The
// operation empties them when it is done; a crash leaves rows that the next
// operation of the same purpose deletes before it starts.

import {
  followMeta,
  foldCellEntries,
  upsertBodyHash,
  type FoldDeletion,
  type LogBodyRef,
  type LogKey,
  type LogStreamMeta,
  type Segment,
  type WireEntry,
  type WireOperation,
  type WireSnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlDriver, SqlStatement } from "./driver.js";

/** What one page of folded entries holds, about: the bodies' JSON length. */
const PAGE_BYTES = 2 * 1024 * 1024;
/** Operations written per batch: a bound on a batch, not on the history. */
const OPS_PER_BATCH = 200;
/** Rows of the first page, before a row's size is known. */
const FIRST_PAGE_ROWS = 32;
const MAX_PAGE_ROWS = 2048;

export interface FoldWorkspace {
  /** Fold a snapshot part in. Parts go in the order the pointer lists them, before any segment. */
  addPart(part: WireSnapshotPart): Promise<void>;
  /** Fold a segment in. Segments go in ascending position. */
  addSegment(segment: Segment<WireOperation>): Promise<void>;
  /** The stream metas of everything added, as `foldLog` returns them. */
  streams(): LogStreamMeta[];
  /**
   * The folded entries in (stream, pkHash) order, a page at a time: pages
   * hold about `PAGE_BYTES` of bodies, or one entry.
   */
  pages(): AsyncGenerator<WireEntry[], void, void>;
  /** Delete the workspace's rows. */
  close(): Promise<void>;
}

type CellRow = {
  stream: string;
  pk_hash: string;
  up_o: number | null;
  up_r: string | null;
  up_ordinal: number | null;
  up_first_seen: number | null;
  up_ref: number | null;
  up_body: string | null;
  del_o: number | null;
  del_r: string | null;
  del_explicit: number | null;
  del_key: string | null;
};

export async function openFoldWorkspace(
  db: Pick<SqlDriver, "batch" | "query">,
  connectionId: string,
  purpose: string,
): Promise<FoldWorkspace> {
  const mine = [connectionId, purpose] as const;
  const clear = () =>
    db.batch([
      {
        sql: "DELETE FROM log_fold_cells WHERE connection_id = ? AND workspace = ?",
        params: mine,
      },
    ]);
  await clear();
  const metas = new Map<string, LogStreamMeta>();
  const follow = (meta: LogStreamMeta) =>
    metas.set(meta.stream, followMeta(metas.get(meta.stream), meta));

  const cell = (stream: string, pk: string): SqlStatement => ({
    sql: `INSERT OR IGNORE INTO log_fold_cells(connection_id, workspace, stream, pk_hash)
          VALUES (?, ?, ?, ?)`,
    params: [...mine, stream, pk],
  });
  const where =
    "connection_id = ? AND workspace = ? AND stream = ? AND pk_hash = ?";
  const upsert = (
    op: Extract<WireOperation, { kind: "upsert" | "upsert-ref" }>,
  ): SqlStatement[] => {
    const byRef = op.kind === "upsert-ref";
    const hash = (
      byRef ? op.body.sha256 : upsertBodyHash(op.value)
    ).toLowerCase();
    const ordinal = op.ordinal ?? null;
    return [
      cell(op.stream, op.pkHash),
      {
        sql: `UPDATE log_fold_cells
                 SET up_o = ?, up_r = ?, up_ordinal = ?, up_hash = ?,
                     up_first_seen = ?, up_ref = ?, up_body = ?
               WHERE ${where}
                 AND (up_o IS NULL
                      OR (?, ?, ?, ?) > (up_o, up_r, COALESCE(up_ordinal, 0), up_hash))`,
        params: [
          op.stamp.o,
          op.stamp.r,
          ordinal,
          hash,
          op.firstSeen,
          byRef ? 1 : 0,
          JSON.stringify(byRef ? op.body : op.value),
          ...mine,
          op.stream,
          op.pkHash,
          op.stamp.o,
          op.stamp.r,
          ordinal ?? 0,
          hash,
        ],
      },
    ];
  };
  const deletion = (
    stream: string,
    pk: string,
    stamp: { o: number; r: string },
    explicit: boolean,
    key: LogKey,
  ): SqlStatement[] => [
    cell(stream, pk),
    {
      sql: `UPDATE log_fold_cells
               SET del_o = ?, del_r = ?, del_explicit = ?, del_key = ?
             WHERE ${where}
               AND (del_o IS NULL OR (?, ?, ?) > (del_o, del_r, del_explicit))`,
      params: [
        stamp.o,
        stamp.r,
        explicit ? 1 : 0,
        JSON.stringify(key),
        ...mine,
        stream,
        pk,
        stamp.o,
        stamp.r,
        explicit ? 1 : 0,
      ],
    },
  ];

  /** The statements of `ops`, written `OPS_PER_BATCH` operations at a time. */
  const write = async (statements: Iterable<SqlStatement[]>) => {
    let batch: SqlStatement[] = [];
    let n = 0;
    for (const group of statements) {
      batch.push(...group);
      if (++n % OPS_PER_BATCH === 0) {
        await db.batch(batch);
        batch = [];
      }
    }
    if (batch.length > 0) await db.batch(batch);
  };

  return {
    async addPart(part) {
      for (const meta of part.streams) follow(meta);
      await write(
        (function* () {
          for (const entry of part.entries)
            if (entry.kind === "upsert" || entry.kind === "upsert-ref")
              yield upsert(entry);
            else
              yield deletion(
                entry.stream,
                entry.pkHash,
                entry.stamp,
                entry.kind === "delete",
                entry.key,
              );
        })(),
      );
    },
    async addSegment(segment) {
      for (const meta of segment.streams) follow(meta);
      await write(
        (function* () {
          for (const op of segment.operations)
            if (op.kind === "upsert" || op.kind === "upsert-ref")
              yield upsert(op);
            else if (op.kind === "delete")
              yield deletion(op.stream, op.pkHash, op.stamp, true, op.key);
            else
              for (const o of op.omitted)
                yield deletion(op.stream, o.pkHash, op.cutoff, false, o.key);
        })(),
      );
    },
    streams: () =>
      [...metas.values()].sort((a, b) =>
        a.stream < b.stream ? -1 : a.stream > b.stream ? 1 : 0,
      ),
    async *pages() {
      let after: readonly [string, string] | null = null;
      let rows = FIRST_PAGE_ROWS;
      for (;;) {
        const page: CellRow[] = await db.query<CellRow>(
          `SELECT stream, pk_hash, up_o, up_r, up_ordinal, up_first_seen, up_ref, up_body,
                  del_o, del_r, del_explicit, del_key
             FROM log_fold_cells
            WHERE connection_id = ? AND workspace = ?${
              after ? " AND (stream, pk_hash) > (?, ?)" : ""
            }
            ORDER BY stream, pk_hash LIMIT ${rows}`,
          after ? [...mine, ...after] : [...mine],
        );
        if (page.length === 0) return;
        const entries: WireEntry[] = [];
        let bytes = 0;
        for (const row of page) {
          bytes +=
            (row.up_body?.length ?? 0) + (row.del_key?.length ?? 0) + 100;
          entries.push(...entriesOf(row));
        }
        yield entries;
        if (page.length < rows) return;
        const last = page[page.length - 1]!;
        after = [last.stream, last.pk_hash];
        rows = Math.max(
          1,
          Math.min(
            MAX_PAGE_ROWS,
            Math.floor(PAGE_BYTES / (bytes / page.length)),
          ),
        );
      }
    },
    close: async () => {
      await clear();
    },
  };
}

function entriesOf(row: CellRow): WireEntry[] {
  const upsert =
    row.up_o === null
      ? null
      : {
          stamp: { o: row.up_o, r: row.up_r! },
          ...(row.up_ordinal === null ? {} : { ordinal: row.up_ordinal }),
          firstSeen: row.up_first_seen,
          ...(row.up_ref === 1
            ? {
                kind: "upsert-ref" as const,
                body: JSON.parse(row.up_body!) as LogBodyRef,
              }
            : {
                kind: "upsert" as const,
                value: JSON.parse(row.up_body!),
              }),
        };
  const deletion: FoldDeletion | null =
    row.del_o === null
      ? null
      : {
          stamp: { o: row.del_o, r: row.del_r! },
          explicit: row.del_explicit === 1,
          key: JSON.parse(row.del_key!) as LogKey,
        };
  return foldCellEntries(
    row.stream,
    row.pk_hash,
    upsert,
    deletion,
  ) as WireEntry[];
}
