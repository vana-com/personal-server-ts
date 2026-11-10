import type { SqlDriver } from "./driver.js";

/** One stored record as reads see it. `emittedAt` is `stamp_o`. */
export interface StoredRecord {
  readonly stream: string;
  readonly recordKey: string;
  readonly pkHash: string;
  readonly body: string;
  readonly emittedAt: number;
}

export interface RecordPage {
  readonly records: readonly StoredRecord[];
  /** The last `record_key` of the page; `null` when there is no more. */
  readonly nextCursor: string | null;
}

export interface ChangePage {
  readonly changes: readonly {
    readonly seq: number;
    readonly op: "upsert" | "remove";
    readonly recordKey: string;
    readonly record: StoredRecord | null;
  }[];
  readonly nextCursor: number | null;
}

/**
 * D: paged reads over `records` and `record_changes`. `listRecords`: cursor
 * `record_key`, default 25, max 100. `getRecord`: string key; on a `1` vs
 * `"1"` collision, the first match in `pk_hash` order. `changesSince`: cursor
 * `seq`; a cursor below the compaction floor answers `"gone"` (route = 410).
 * `streamRecords` yields every record of a stream in `pk_hash` order, one page
 * in memory at a time (the #564 memory gate). Reads only.
 */
export interface RecordQuery {
  listRecords(input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly cursor?: string;
    readonly limit?: number;
  }): Promise<RecordPage>;
  getRecord(input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly recordKey: string;
  }): Promise<StoredRecord | null>;
  changesSince(input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly cursor: number;
    readonly limit?: number;
  }): Promise<ChangePage | "gone">;
  streamRecords(
    connectionId: string,
    stream: string,
  ): AsyncIterable<StoredRecord>;
}

type RecordRow = {
  stream: string;
  record_key: string;
  pk_hash: string;
  body: string;
  stamp_o: number;
};

const RECORD_COLUMNS = "stream, record_key, pk_hash, body, stamp_o";
const STREAM_PAGE_SIZE = 100;

function pageLimit(limit: number | undefined): number {
  return limit === undefined || !Number.isFinite(limit)
    ? 25
    : Math.max(1, Math.min(100, Math.floor(limit)));
}

function stored(row: RecordRow): StoredRecord {
  return {
    stream: row.stream,
    recordKey: row.record_key,
    pkHash: row.pk_hash,
    body: row.body,
    emittedAt: row.stamp_o,
  };
}

export function createRecordQuery(db: SqlDriver): RecordQuery {
  return {
    async listRecords({ connectionId, stream, cursor, limit }) {
      const size = pageLimit(limit);
      const rows = await db.query<RecordRow>(
        `SELECT ${RECORD_COLUMNS} FROM records
         WHERE connection_id = ? AND stream = ?
           ${cursor === undefined ? "" : "AND record_key > ?"}
         ORDER BY record_key, pk_hash LIMIT ?`,
        cursor === undefined
          ? [connectionId, stream, size + 1]
          : [connectionId, stream, cursor, size + 1],
      );
      const more = rows.length > size;
      const page = rows.slice(0, size);
      return {
        records: page.map(stored),
        nextCursor: more ? page[page.length - 1]!.record_key : null,
      };
    },

    async getRecord({ connectionId, stream, recordKey }) {
      const rows = await db.query<RecordRow>(
        `SELECT ${RECORD_COLUMNS} FROM records
         WHERE connection_id = ? AND stream = ? AND record_key = ?
         ORDER BY pk_hash LIMIT 1`,
        [connectionId, stream, recordKey],
      );
      return rows[0] ? stored(rows[0]) : null;
    },

    async changesSince({ connectionId, stream, cursor, limit }) {
      const size = pageLimit(limit);
      // The log's sequence is database-wide, so a stream's first event is not
      // a compaction floor. Preserve the high-water mark even for an empty log.
      // Read the floor and page in one statement so compaction cannot race them.
      const rows = await db.query<{
        floor: number;
        seq: number | null;
        op: "upsert" | "remove" | null;
        change_key: string | null;
        stream: string | null;
        record_key: string | null;
        pk_hash: string | null;
        body: string | null;
        stamp_o: number | null;
      }>(
        `WITH floor AS (
           SELECT COALESCE(MIN(seq) - 1,
             (SELECT seq FROM sqlite_sequence WHERE name = 'record_changes'),
             0) AS floor FROM record_changes
         ), page AS (
           SELECT seq, op, record_key, pk_hash FROM record_changes
           WHERE connection_id = ? AND stream = ? AND seq > ?
             AND ? >= (SELECT floor FROM floor)
           ORDER BY seq LIMIT ?
         )
         SELECT floor.floor, page.seq, page.op, page.record_key AS change_key,
                r.stream, r.record_key, r.pk_hash, r.body, r.stamp_o
         FROM floor LEFT JOIN page ON 1 = 1
         LEFT JOIN records r ON page.op = 'upsert'
           AND r.connection_id = ? AND r.stream = ? AND r.pk_hash = page.pk_hash
         ORDER BY page.seq`,
        [connectionId, stream, cursor, cursor, size + 1, connectionId, stream],
      );
      if (cursor < rows[0]!.floor) return "gone";
      const events = rows.filter((row) => row.seq !== null);
      const more = events.length > size;
      const page = events.slice(0, size);
      return {
        changes: page.map((row) => ({
          seq: row.seq!,
          op: row.op!,
          recordKey: row.change_key!,
          record:
            row.pk_hash === null
              ? null
              : stored({
                  stream: row.stream!,
                  record_key: row.record_key!,
                  pk_hash: row.pk_hash,
                  body: row.body!,
                  stamp_o: row.stamp_o!,
                }),
        })),
        nextCursor: more ? page[page.length - 1]!.seq : null,
      };
    },

    async *streamRecords(connectionId, stream) {
      let cursor: string | undefined;
      for (;;) {
        const page = await db.query<RecordRow>(
          `SELECT ${RECORD_COLUMNS} FROM records
           WHERE connection_id = ? AND stream = ?
             ${cursor === undefined ? "" : "AND pk_hash > ?"}
           ORDER BY pk_hash LIMIT ?`,
          cursor === undefined
            ? [connectionId, stream, STREAM_PAGE_SIZE]
            : [connectionId, stream, cursor, STREAM_PAGE_SIZE],
        );
        for (const row of page) yield stored(row);
        if (page.length < STREAM_PAGE_SIZE) return;
        cursor = page[page.length - 1]!.pk_hash;
      }
    },
  };
}
