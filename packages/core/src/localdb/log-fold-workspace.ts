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
// The rows are scratch of one operation, keyed by connection and purpose
// (`log-scratch.ts`). The operation empties them when it is done; the table
// is created again on every open, and a purge deletes the connection's rows.

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
import { rowsWithin, SIZE_ROWS } from "./byte-pages.js";
import type { SqlDriver, SqlStatement } from "./driver.js";
import { FOLD_CELLS } from "./log-scratch.js";

/** Operations written per batch: a bound on a batch, not on the history. */
const OPS_PER_BATCH = 200;

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
  up_body: string | null;
  del_o: number | null;
  del_r: Uint8Array | null;
  del_explicit: number | null;
  del_key: string | null;
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

/** The bytes `value` takes as UTF-8, the unit SQLite's `LENGTH(CAST(x AS BLOB))` counts. */
function utf8Length(value: string): number {
  let bytes = 0;
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (
      unit >= 0xd800 &&
      unit <= 0xdbff &&
      i + 1 < value.length &&
      (value.charCodeAt(i + 1) & 0xfc00) === 0xdc00
    ) {
      bytes += 4;
      i += 1;
    } else bytes += 3;
  }
  return bytes;
}

export async function openFoldWorkspace(
  db: Pick<SqlDriver, "batch" | "query">,
  connectionId: string,
  purpose: string,
): Promise<FoldWorkspace> {
  const mine = [connectionId, purpose] as const;
  const clear = () =>
    db.batch([
      {
        sql: `DELETE FROM ${FOLD_CELLS} WHERE connection_id = ? AND workspace = ?`,
        params: mine,
      },
    ]);
  await clear();
  const metas = new Map<string, LogStreamMeta>();
  const follow = (meta: LogStreamMeta) =>
    metas.set(meta.stream, followMeta(metas.get(meta.stream), meta));

  const cell = (stream: string, pk: string): SqlStatement => ({
    sql: `INSERT OR IGNORE INTO ${FOLD_CELLS}(connection_id, workspace, stream, pk_hash)
          VALUES (?, ?, ?, ?)`,
    params: [...mine, utf16Key(stream), pk],
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
      let after: readonly [Uint8Array, string] | null = null;
      const range = () =>
        `connection_id = ? AND workspace = ?${
          after ? " AND (stream, pk_hash) > (?, ?)" : ""
        }`;
      for (;;) {
        const params = after ? [...mine, ...after] : [...mine];
        // The sizes of the next cells first (small rows: they come before the
        // bodies in a row), then the longest run of them that fits the budget.
        const sizes: { n: number }[] = await db.query<{ n: number }>(
          `SELECT COALESCE(up_bytes, 0) + COALESCE(del_bytes, 0) AS n
             FROM ${FOLD_CELLS} WHERE ${range()}
            ORDER BY stream, pk_hash LIMIT ${SIZE_ROWS}`,
          params,
        );
        if (sizes.length === 0) return;
        const take = rowsWithin(sizes.map((row) => Number(row.n)));
        const page: CellRow[] = await db.query<CellRow>(
          `SELECT stream, pk_hash, up_o, up_r, up_ordinal, up_first_seen, up_ref,
                  del_o, del_r, del_explicit, up_body, del_key
             FROM ${FOLD_CELLS} WHERE ${range()}
            ORDER BY stream, pk_hash LIMIT ${take}`,
          params,
        );
        yield page.flatMap(entriesOf);
        if (
          page.length < take ||
          (take === sizes.length && sizes.length < SIZE_ROWS)
        )
          return;
        const last = page[page.length - 1]!;
        after = [last.stream, last.pk_hash];
      }
    },
    close: async () => {
      await clear();
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
          stamp: { o: row.del_o, r: fromUtf16Key(row.del_r!) },
          explicit: row.del_explicit === 1,
          key: JSON.parse(row.del_key!) as LogKey,
        };
  return foldCellEntries(stream, row.pk_hash, upsert, deletion) as WireEntry[];
}
