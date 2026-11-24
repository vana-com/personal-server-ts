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
// Strings compare as UTF-8 bytes in SQLite and as UTF-16 code units in
// JavaScript; they disagree for U+E000..U+FFFF against a supplementary
// character, and TEXT cannot hold a lone surrogate. A stream name and a run
// id are stored as BLOBs of their UTF-16BE code units, whose `memcmp` order is
// the order of code units. Key hashes and body hashes are ASCII hex and stay
// TEXT. `foldLog` and the workspace are tested against each other on names
// where the two orders differ.
//
// The rows are scratch of one session, one fold (`log-scratch.ts`): the
// session deletes its own rows when it ends, the next open of the file
// deletes those another process left, and a purge deletes the connection's.
// A second handle on the same file opens its own session and touches no one
// else's rows.
//
// Reads are cut by what the reply holds (`byte-pages.ts`): a body is read as
// a blob, a cell too large for a page is read alone in chunks.

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
import {
  fitsPage,
  readChunked,
  replyBytes,
  rowsWithin,
  SIZE_ROWS,
  textOf,
} from "./byte-pages.js";
import type { SqlDriver, SqlStatement } from "./driver.js";
import {
  deleteSession,
  FOLD_CELLS,
  newSession,
  PROCESS,
} from "./log-scratch.js";
import { utf8Length, writeInBatches } from "./write-batches.js";

export interface FoldWorkspace {
  /** Fold a snapshot part in. Parts go in the order the pointer lists them, before any segment. */
  addPart(part: WireSnapshotPart): Promise<void>;
  /** Fold a segment in. Segments go in ascending position. */
  addSegment(segment: Segment<WireOperation>): Promise<void>;
  /** The stream metas of everything added, as `foldLog` returns them. */
  streams(): LogStreamMeta[];
  /**
   * The folded entries in (stream, pkHash) order, a page at a time: the
   * rows of a page hold at most `PAGE_BYTES` of bodies and keys (by the sizes
   * the cells keep), or one cell.
   */
  pages(): AsyncGenerator<WireEntry[], void, void>;
  /** Delete the workspace's rows. */
  close(): Promise<void>;
}

type CellRow = {
  stream: Uint8Array;
  pk_hash: string;
  up_o: number | null;
  up_r: Uint8Array | null;
  up_ordinal: number | null;
  up_first_seen: number | null;
  up_ref: number | null;
  up_body: Uint8Array | null;
  del_o: number | null;
  del_r: Uint8Array | null;
  del_explicit: number | null;
  del_key: Uint8Array | null;
};

/** A string as the bytes of its UTF-16BE code units, lone surrogates kept: byte order is code-unit order. */
export function utf16Key(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length * 2);
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    bytes[2 * i] = unit >> 8;
    bytes[2 * i + 1] = unit & 0xff;
  }
  return bytes;
}

function fromUtf16Key(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i + 1 < bytes.length; i += 2)
    out += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
  return out;
}

export async function openFoldWorkspace(
  db: Pick<SqlDriver, "batch" | "query">,
  connectionId: string,
): Promise<FoldWorkspace> {
  const session = newSession();
  const mine = [connectionId, session] as const;
  const metas = new Map<string, LogStreamMeta>();
  const follow = (meta: LogStreamMeta) =>
    metas.set(meta.stream, followMeta(metas.get(meta.stream), meta));

  const cell = (stream: string, pk: string): SqlStatement => ({
    sql: `INSERT OR IGNORE INTO ${FOLD_CELLS}(connection_id, session, process, stream, pk_hash)
          VALUES (?, ?, ?, ?, ?)`,
    params: [...mine, PROCESS, utf16Key(stream), pk],
  });
  const where =
    "connection_id = ? AND session = ? AND stream = ? AND pk_hash = ?";
  const upsert = (
    op: Extract<WireOperation, { kind: "upsert" | "upsert-ref" }>,
  ): SqlStatement[] => {
    const byRef = op.kind === "upsert-ref";
    const hash = (
      byRef ? op.body.sha256 : upsertBodyHash(op.value)
    ).toLowerCase();
    const ordinal = op.ordinal ?? null;
    const body = JSON.stringify(byRef ? op.body : op.value);
    const run = utf16Key(op.stamp.r);
    return [
      cell(op.stream, op.pkHash),
      {
        sql: `UPDATE ${FOLD_CELLS}
                 SET up_o = ?, up_r = ?, up_ordinal = ?, up_hash = ?,
                     up_first_seen = ?, up_ref = ?, up_bytes = ?, up_body = ?
               WHERE ${where}
                 AND (up_o IS NULL
                      OR (?, ?, ?, ?) > (up_o, up_r, COALESCE(up_ordinal, 0), up_hash))`,
        params: [
          op.stamp.o,
          run,
          ordinal,
          hash,
          op.firstSeen,
          byRef ? 1 : 0,
          utf8Length(body),
          body,
          ...mine,
          utf16Key(op.stream),
          op.pkHash,
          op.stamp.o,
          run,
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
  ): SqlStatement[] => {
    const run = utf16Key(stamp.r);
    const body = JSON.stringify(key);
    return [
      cell(stream, pk),
      {
        sql: `UPDATE ${FOLD_CELLS}
                 SET del_o = ?, del_r = ?, del_explicit = ?, del_bytes = ?, del_key = ?
               WHERE ${where}
                 AND (del_o IS NULL OR (?, ?, ?) > (del_o, del_r, del_explicit))`,
        params: [
          stamp.o,
          run,
          explicit ? 1 : 0,
          utf8Length(body),
          body,
          ...mine,
          utf16Key(stream),
          pk,
          stamp.o,
          run,
          explicit ? 1 : 0,
        ],
      },
    ];
  };

  /**
   * The cells after `after`, in key order, that one reply holds: from their
   * sizes alone (small columns, kept before the bodies in a row) the cost of
   * each is what its blobs take in base64, then the longest run that fits a
   * page. A cell whose values alone overflow a page is read by itself, its
   * values in chunks. Nothing for no cells left.
   */
  const nextCells = async (
    after: readonly [Uint8Array, string] | null,
  ): Promise<CellRow[]> => {
    const range = `connection_id = ? AND session = ?${
      after ? " AND (stream, pk_hash) > (?, ?)" : ""
    }`;
    const params = after ? [...mine, ...after] : [...mine];
    const sizes: { up: number; del: number; keys: number }[] = await db.query(
      `SELECT COALESCE(up_bytes, 0) AS up, COALESCE(del_bytes, 0) AS del,
              LENGTH(stream) + LENGTH(pk_hash) + COALESCE(LENGTH(up_r), 0)
                + COALESCE(LENGTH(del_r), 0) AS keys
         FROM ${FOLD_CELLS} WHERE ${range}
        ORDER BY stream, pk_hash LIMIT ${SIZE_ROWS}`,
      params,
    );
    if (sizes.length === 0) return [];
    const costs = sizes.map(
      (row) =>
        replyBytes(Number(row.up)) +
        replyBytes(Number(row.del)) +
        replyBytes(Number(row.keys)),
    );
    const take = rowsWithin(costs);
    if (take > 1 || fitsPage(costs[0]!))
      return db.query<CellRow>(
        `SELECT stream, pk_hash, up_o, up_r, up_ordinal, up_first_seen, up_ref,
                del_o, del_r, del_explicit,
                CAST(up_body AS BLOB) AS up_body, CAST(del_key AS BLOB) AS del_key
           FROM ${FOLD_CELLS} WHERE ${range}
          ORDER BY stream, pk_hash LIMIT ${take}`,
        params,
      );
    const [cell] = await db.query<CellRow>(
      `SELECT stream, pk_hash, up_o, up_r, up_ordinal, up_first_seen, up_ref,
              del_o, del_r, del_explicit, NULL AS up_body, NULL AS del_key
         FROM ${FOLD_CELLS} WHERE ${range}
        ORDER BY stream, pk_hash LIMIT 1`,
      params,
    );
    const value = (column: "up_body" | "del_key", bytes: number) =>
      readChunked(db, bytes, (offset, length) => ({
        sql: `SELECT substr(CAST(${column} AS BLOB), ?, ?) AS c FROM ${FOLD_CELLS}
               WHERE connection_id = ? AND session = ? AND stream = ? AND pk_hash = ?`,
        params: [offset, length, ...mine, cell!.stream, cell!.pk_hash],
      }));
    if (Number(sizes[0]!.up) > 0)
      cell!.up_body = await value("up_body", Number(sizes[0]!.up));
    if (Number(sizes[0]!.del) > 0)
      cell!.del_key = await value("del_key", Number(sizes[0]!.del));
    return [cell!];
  };

  return {
    async addPart(part) {
      for (const meta of part.streams) follow(meta);
      await writeInBatches(
        db,
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
      await writeInBatches(
        db,
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
      let after: readonly [Uint8Array, string] | null = null;
      for (;;) {
        const cells: CellRow[] = await nextCells(after);
        if (cells.length === 0) return;
        yield cells.flatMap(entriesOf);
        const last: CellRow = cells[cells.length - 1]!;
        after = [last.stream, last.pk_hash];
      }
    },
    close: async () => {
      await db.batch([deleteSession(FOLD_CELLS, connectionId, session)]);
    },
  };
}

function entriesOf(row: CellRow): WireEntry[] {
  const stream = fromUtf16Key(row.stream);
  const upsert =
    row.up_o === null
      ? null
      : {
          stamp: { o: row.up_o, r: fromUtf16Key(row.up_r!) },
          ...(row.up_ordinal === null ? {} : { ordinal: row.up_ordinal }),
          firstSeen: row.up_first_seen,
          ...(row.up_ref === 1
            ? {
                kind: "upsert-ref" as const,
                body: JSON.parse(textOf(row.up_body!)) as LogBodyRef,
              }
            : {
                kind: "upsert" as const,
                value: JSON.parse(textOf(row.up_body!)),
              }),
        };
  const deletion: FoldDeletion | null =
    row.del_o === null
      ? null
      : {
          stamp: { o: row.del_o, r: fromUtf16Key(row.del_r!) },
          explicit: row.del_explicit === 1,
          key: JSON.parse(textOf(row.del_key!)) as LogKey,
        };
  return foldCellEntries(stream, row.pk_hash, upsert, deletion) as WireEntry[];
}
