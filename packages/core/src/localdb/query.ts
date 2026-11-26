import {
  decodeBase64UrlUtf8,
  encodeBase64UrlUtf8,
} from "../encoding/base64url.js";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { encodeCursor, decodeCursor } from "../storage/pdpp-records/cursor.js";
import {
  CursorExpiredError,
  type ChangesSinceOptions,
  type ChangesSincePage,
  type ListSort,
  type PdppRecordRow,
  type PdppStoredRecord,
} from "../storage/pdpp-records/types.js";
import {
  compareListPositions,
  listPosition,
  type ListPosition,
} from "../storage/pdpp-records/list-page.js";
import type { ConnectionLink } from "./connection-link.js";

import type { SqlReader, SqlValue } from "./driver.js";
import { SEEN_O, seenStamp } from "./merge.js";

/**
 * One stored record as reads see it. `emittedAt` is when a run last observed
 * the body (the SEEN stamp), so an unchanged refresh still reads as collected.
 */
export interface StoredRecord {
  readonly stream: string;
  readonly recordKey: string;
  readonly pkHash: string;
  readonly body: string;
  readonly emittedAt: number;
}

export interface RecordPage {
  readonly records: readonly StoredRecord[];
  /** Resumes after the page's last row (see `listCursor`); `null` when there is no more. */
  readonly nextCursor: string | null;
  /**
   * How many records the connection holds in the stream, whatever the cursor.
   * Present only when `listRecords` was asked for it, and read in the same
   * statement as the page, so it always covers the page's rows.
   */
  readonly total?: number;
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
 * `(record_key, pk_hash)`, default 25, max 100. `getRecord`: string key; on a `1` vs
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
    /** Also state the stream's `total` (see `RecordPage`). */
    readonly withTotal?: boolean;
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

/**
 * What a paged alias read needs of the database beyond a `RecordQuery`: the
 * sizes of rows, so the read sizes its memory before it holds any body, and
 * rows by key hash. Only the local resolver asks for it; a host that serves
 * the records routes implements `RecordQuery` alone.
 */
export interface AliasRecordQuery extends RecordQuery {
  /**
   * How many records a stream holds, how many bytes their bodies take and the
   * largest body, from one statement over the stored sizes: no body is read.
   */
  streamStats(
    connectionId: string,
    stream: string,
  ): Promise<{
    readonly rows: number;
    readonly bytes: number;
    readonly maxBytes: number;
  }>;
  /**
   * Every record of a stream as the identity and size of its body, in
   * `pk_hash` order: no body is read.
   */
  recordSizes(connectionId: string, stream: string): AsyncIterable<SizedRecord>;
  /**
   * The bodies of records that were sized, in `pk_hash` order. The statement
   * that returns a body checks it against its `SizedRecord`: the row must
   * still have the sized hash and be no larger. A record that was deleted,
   * changed or grown since it was sized is absent from the answer, so no
   * statement returns more bytes than the sizes it was given add up to.
   */
  recordsByHash(
    connectionId: string,
    stream: string,
    sized: readonly SizedRecord[],
    guard?: StatementGuard,
  ): Promise<StoredRecord[]>;
}

/**
 * Whether `query` answers sizes and records by key hash. A caller may pass a
 * plain `RecordQuery` (the shape the resolver took before alias paging); an
 * alias read over one is built in memory and refused above `ARRAY_BUDGET`.
 */
export const isAliasRecordQuery = (
  query: RecordQuery,
): query is AliasRecordQuery => {
  const candidate = query as Partial<AliasRecordQuery>;
  return (
    typeof candidate.streamStats === "function" &&
    typeof candidate.recordSizes === "function" &&
    typeof candidate.recordsByHash === "function"
  );
};

/** A record as it was sized: its key hash, its body's hash and its body's bytes. */
export interface SizedRecord {
  readonly pkHash: string;
  readonly sha256: string;
  readonly bytes: number;
}

/**
 * A condition on the database's state, as SQL with its `?` parameters, that a
 * read of bodies carries in its own statement (`AND (sql)`). The statement
 * reads one snapshot: if the condition holds, the rows are the rows it was
 * decided on, and if it does not the statement returns none.
 */
export interface StatementGuard {
  readonly sql: string;
  readonly params: readonly SqlValue[];
}

type RecordRow = {
  stream: string;
  record_key: string;
  pk_hash: string;
  body: string;
  stamp_o: number;
};

const RECORD_COLUMNS = `stream, record_key, pk_hash, body, ${SEEN_O} AS stamp_o`;
const STREAM_PAGE_SIZE = 100;
/** Sizes per statement: a row of them is a hash and a number, not a body. */
const SIZE_PAGE_SIZE = 1000;
/** A stored body's size in bytes; a row written before `body_bytes` has none. */
const BODY_BYTES = "COALESCE(body_bytes, LENGTH(CAST(body AS BLOB)))";
/**
 * Bound parameters one statement may carry: SQLite before 3.32 rejects more
 * than 999 (the driver contract targets 3.22).
 */
export const MAX_STATEMENT_PARAMS = 999;
/** Sized records per statement at most, three bound parameters each. */
const SIZED_PER_STATEMENT = 250;

const LIST_CURSOR_PREFIX = "v2.";

/**
 * The cursor that resumes `listRecords` after one row. Listing orders by
 * `(record_key, pk_hash)` and a `1` and a `"1"` share a record_key, so the
 * key alone would skip the second of them. A cursor without this prefix is a
 * plain record_key from before; it still resumes after that key.
 */
export function listCursor(recordKey: string, pkHash: string): string {
  return (
    LIST_CURSOR_PREFIX +
    encodeBase64UrlUtf8(JSON.stringify([recordKey, pkHash]))
  );
}

function parseListCursor(cursor: string): {
  recordKey: string;
  pkHash: string | null;
} {
  if (cursor.startsWith(LIST_CURSOR_PREFIX)) {
    try {
      const value: unknown = JSON.parse(
        decodeBase64UrlUtf8(cursor.slice(LIST_CURSOR_PREFIX.length)),
      );
      if (
        Array.isArray(value) &&
        value.length === 2 &&
        typeof value[0] === "string" &&
        typeof value[1] === "string"
      )
        return { recordKey: value[0], pkHash: value[1] };
    } catch {
      // Not ours: a record_key that happens to start with the prefix.
    }
  }
  return { recordKey: cursor, pkHash: null };
}

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

export function createRecordQuery(db: SqlReader): AliasRecordQuery {
  return {
    async listRecords({ connectionId, stream, cursor, limit, withTotal }) {
      const size = pageLimit(limit);
      const after = cursor === undefined ? null : parseListCursor(cursor);
      const pageSql = `SELECT ${RECORD_COLUMNS} FROM records
         WHERE connection_id = ? AND stream = ?
           ${
             after === null
               ? ""
               : after.pkHash === null
                 ? "AND record_key > ?"
                 : "AND (record_key, pk_hash) > (?, ?)"
           }
         ORDER BY record_key, pk_hash LIMIT ?`;
      const pageParams = [
        connectionId,
        stream,
        ...(after === null
          ? []
          : after.pkHash === null
            ? [after.recordKey]
            : [after.recordKey, after.pkHash]),
        size + 1,
      ];
      let total: number | undefined;
      let rows: RecordRow[];
      if (withTotal) {
        // The count and the page are one statement, so they read one
        // snapshot: a row admitted or removed meanwhile is in both or neither.
        // The count row survives an empty page through the LEFT JOIN.
        const joined = await db.query<
          { total: number } & { [K in keyof RecordRow]: RecordRow[K] | null }
        >(
          `WITH total AS (
             SELECT COUNT(*) AS total FROM records
             WHERE connection_id = ? AND stream = ?
           ), page AS (${pageSql})
           SELECT total.total AS total, page.* FROM total LEFT JOIN page ON 1 = 1
           ORDER BY page.record_key, page.pk_hash`,
          [connectionId, stream, ...pageParams],
        );
        total = Number(joined[0]?.total ?? 0);
        rows = joined.filter((row) => row.record_key !== null) as RecordRow[];
      } else rows = await db.query<RecordRow>(pageSql, pageParams);
      const more = rows.length > size;
      const page = rows.slice(0, size);
      const last = page[page.length - 1];
      return {
        records: page.map(stored),
        nextCursor: more ? listCursor(last!.record_key, last!.pk_hash) : null,
        ...(total !== undefined && { total }),
      };
    },

    async getRecord({ connectionId, stream, recordKey }) {
      // `+pk_hash`: no index may supply this order. Otherwise the planner
      // walks the whole stream in key order to stop at the first match,
      // rather than finding the few rows of the record key in
      // `records_by_key` and sorting them.
      const rows = await db.query<RecordRow>(
        `SELECT ${RECORD_COLUMNS} FROM records
         WHERE connection_id = ? AND stream = ? AND record_key = ?
         ORDER BY +pk_hash LIMIT 1`,
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
           SELECT MAX(COALESCE((SELECT change_floor FROM db_meta WHERE id=1),0), COALESCE(MIN(seq) - 1,
             (SELECT seq FROM sqlite_sequence WHERE name = 'record_changes'),
             0)) AS floor FROM record_changes
         ), page AS (
           SELECT seq, op, record_key, pk_hash FROM record_changes
           WHERE connection_id = ? AND stream = ? AND seq > ?
             AND ? >= (SELECT floor FROM floor)
           ORDER BY seq LIMIT ?
         )
         SELECT floor.floor, page.seq, page.op, page.record_key AS change_key,
                r.stream, r.record_key, r.pk_hash, r.body, ${seenStamp("r.").o} AS stamp_o
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

    async streamStats(connectionId, stream) {
      const [row] = await db.query<{
        rows: number;
        bytes: number | null;
        max_bytes: number | null;
      }>(
        `SELECT COUNT(*) AS rows, SUM(${BODY_BYTES}) AS bytes,
                MAX(${BODY_BYTES}) AS max_bytes
         FROM records WHERE connection_id = ? AND stream = ?`,
        [connectionId, stream],
      );
      return {
        rows: Number(row?.rows ?? 0),
        bytes: Number(row?.bytes ?? 0),
        maxBytes: Number(row?.max_bytes ?? 0),
      };
    },

    async *recordSizes(connectionId, stream) {
      let cursor: string | undefined;
      for (;;) {
        const page = await db.query<{
          pk_hash: string;
          body_sha256: string;
          bytes: number;
        }>(
          `SELECT pk_hash, body_sha256, ${BODY_BYTES} AS bytes FROM records
           WHERE connection_id = ? AND stream = ?
             ${cursor === undefined ? "" : "AND pk_hash > ?"}
           ORDER BY pk_hash LIMIT ?`,
          cursor === undefined
            ? [connectionId, stream, SIZE_PAGE_SIZE]
            : [connectionId, stream, cursor, SIZE_PAGE_SIZE],
        );
        for (const row of page) {
          yield {
            pkHash: row.pk_hash,
            sha256: row.body_sha256,
            bytes: Number(row.bytes),
          };
        }
        if (page.length < SIZE_PAGE_SIZE) return;
        cursor = page[page.length - 1]!.pk_hash;
      }
    },

    async recordsByHash(connectionId, stream, sized, guard) {
      const out: StoredRecord[] = [];
      // A statement binds its sized rows, the connection and stream, and the
      // guard's parameters; the rows take what the other two leave.
      const perStatement = Math.min(
        SIZED_PER_STATEMENT,
        Math.floor(
          (MAX_STATEMENT_PARAMS - 2 - (guard?.params.length ?? 0)) / 3,
        ),
      );
      if (sized.length > 0 && perStatement < 1) {
        throw new Error(
          `recordsByHash: the guard binds ${guard?.params.length} parameters, and a statement may bind ${MAX_STATEMENT_PARAMS}`,
        );
      }
      for (let i = 0; i < sized.length; i += perStatement) {
        const group = sized.slice(i, i + perStatement);
        // The statement joins the rows it returns to what was sized: the
        // identity and the size are checked where the body is read.
        const rows = await db.query<RecordRow>(
          `WITH sized(want_hash, want_sha, want_bytes) AS (VALUES ${group
            .map(() => "(?, ?, ?)")
            .join(", ")})
           SELECT ${RECORD_COLUMNS} FROM records JOIN sized ON want_hash = pk_hash
           WHERE connection_id = ? AND stream = ?
             AND body_sha256 = want_sha AND ${BODY_BYTES} <= want_bytes
             ${guard ? `AND ${guard.sql}` : ""}`,
          [
            ...group.flatMap((r) => [r.pkHash, r.sha256, r.bytes]),
            connectionId,
            stream,
            ...(guard?.params ?? []),
          ],
        );
        for (const row of rows) out.push(stored(row));
      }
      return out.sort((a, b) => (a.pkHash < b.pkHash ? -1 : 1));
    },
  };
}

/** Frozen grant projections over the current table. Lost bodies expire the cursor;
 * no older body is kept: the connection log holds none per stream.
 */
export function createGrantHistory(db: SqlReader, link: ConnectionLink) {
  return async (
    stream: string,
    options: ChangesSinceOptions,
  ): Promise<ChangesSincePage> => {
    const instances = [...new Set(options.instanceIds)].sort();
    // Owner sessions: a record removed between the horizons is a tombstone,
    // not an expired session (spec-core §4 "Visibility"; RS items 7, 20).
    // The owner reads whole records, so an overwrite needs no h0 body: the
    // record is returned when it was written between the horizons.
    const removals = options.removals === true;
    const targets: { instance: string; id: string; generation: number }[] = [];
    for (const instance of instances) {
      const resolved = link(instance, stream);
      if (!resolved) {
        if (options.purpose === "listing" && !options.cursor)
          return { data: [], hasMore: false };
        throw new CursorExpiredError();
      }
      const id = controlScope(resolved.connector, resolved.namespace);
      const [row] = await db.query<{ generation: number }>(
        `SELECT generation FROM connections WHERE connection_id=? AND control_state='active'
        AND NOT EXISTS (SELECT 1 FROM delete_intents WHERE connector=connections.connector)`,
        [id],
      );
      if (!row) {
        if (options.purpose === "listing" && !options.cursor)
          return { data: [], hasMore: false };
        throw new CursorExpiredError();
      }
      targets.push({ instance, id, generation: row.generation });
    }
    const [meta] = await db.query<{
      owner: string;
      network: string;
      created_at: number;
    }>("SELECT owner,network,created_at FROM db_meta WHERE id=1");
    const signature = JSON.stringify([
      meta,
      stream,
      targets,
      options.fields?.slice().sort() ?? null,
      options.purpose ?? "changes",
      options.order ?? "asc",
      ...(options.purpose === "listing" ? [options.sort ?? null] : []),
      options.removals === true,
    ]);
    const clock = async () => {
      const [row] = await db.query<{
        seq: number;
        floor: number;
      }>(`SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='record_changes'),0) AS seq,
        MAX(COALESCE((SELECT change_floor FROM db_meta WHERE id=1),0),COALESCE((SELECT MIN(seq)-1 FROM record_changes),(SELECT seq FROM sqlite_sequence WHERE name='record_changes'),0)) AS floor`);
      return row!;
    };
    const now = await clock();
    let horizon = now.seq,
      since: number | null = null,
      offset = 0;
    const token = options.cursor ?? options.changesSince;
    if (token) {
      // Malformed syntax keeps the protocol's 400; a valid but obsolete
      // snapshot below is 410 and requires a fresh listing.
      const payload = decodeCursor(token);
      if (
        payload.kind !== "changes_since" ||
        payload.epoch !== "ps2-current" ||
        payload.query !== signature ||
        payload.stream !== stream
      )
        throw new CursorExpiredError();
      const pinned = Number(payload.horizon);
      if (
        !Number.isSafeInteger(pinned) ||
        pinned < now.floor ||
        pinned > now.seq
      )
        throw new CursorExpiredError();
      if (options.cursor) {
        horizon = pinned;
        since =
          payload.sinceHorizon === null ? null : Number(payload.sinceHorizon);
        offset = payload.offset;
      } else since = pinned;
      if (
        !Number.isSafeInteger(offset) ||
        offset < 0 ||
        (since !== null &&
          (!Number.isSafeInteger(since) ||
            since < now.floor ||
            since > horizon))
      )
        throw new CursorExpiredError();
    }
    const assertExact = async () => {
      const currentClock = await clock();
      if (
        horizon < currentClock.floor ||
        (since !== null && since < currentClock.floor)
      )
        throw new CursorExpiredError();
      for (const target of targets) {
        const resolved = link(target.instance, stream);
        if (
          !resolved ||
          controlScope(resolved.connector, resolved.namespace) !== target.id
        )
          throw new CursorExpiredError();
        if (currentClock.floor > 0) {
          // Compaction removed the proof that a changed key was absent at the
          // earlier horizon. Current bodies cannot establish that old visibility.
          const uncertain = await db.query<{ seq: number }>(
            "SELECT seq FROM record_changes WHERE connection_id=? AND stream=? AND seq>? LIMIT 1",
            [target.id, stream, since ?? horizon],
          );
          if (uncertain.length) throw new CursorExpiredError();
        }
        const [state] = await db.query<{
          generation: number;
          control_state: string;
        }>(
          `SELECT generation,control_state FROM connections WHERE connection_id=?
          AND NOT EXISTS (SELECT 1 FROM delete_intents WHERE connector=connections.connector)`,
          [target.id],
        );
        if (
          !state ||
          state.generation !== target.generation ||
          state.control_state !== "active"
        )
          throw new CursorExpiredError();
        // An overwrite or removal destroyed a body required at either frozen horizon.
        const missing = await db.query<{ seq: number }>(
          `SELECT later.seq FROM record_changes later WHERE later.connection_id=? AND later.stream=?
          AND ((later.seq>? AND EXISTS (SELECT 1 FROM record_changes prior WHERE prior.connection_id=later.connection_id AND prior.stream=later.stream AND prior.pk_hash=later.pk_hash AND prior.seq<=?))
          ${since === null || removals ? "" : "OR (later.seq>? AND later.seq<=? AND EXISTS (SELECT 1 FROM record_changes prior WHERE prior.connection_id=later.connection_id AND prior.stream=later.stream AND prior.pk_hash=later.pk_hash AND prior.seq<=?))"}) LIMIT 1`,
          since === null || removals
            ? [target.id, stream, horizon, horizon]
            : [target.id, stream, horizon, horizon, since, horizon, since],
        );
        if (missing.length) throw new CursorExpiredError();
      }
    };
    await assertExact();
    const rows: PdppRecordRow[] = [];
    let visibleCount = 0;
    const limit = Math.max(1, Math.min(100, options.limit));
    // The scan runs in `(instance_id, canonical key)` order, which is the
    // `changes_since` order (spec-core §9 RS item 21) and the ascending key
    // list order. A listing in another order (descending, or by the frozen
    // `sort_field`) ranks every visible position, then reads the page's
    // bodies (spec-core §8 "Stable sort"; RS item 33).
    // A `changes_since` session uses `(instance_id, key)` in the direction
    // `order` selects (spec-core §8 "Stable sort"; RS item 21).
    const listing = options.purpose === "listing";
    const sort: ListSort = listing ? (options.sort ?? { by: "key" }) : { by: "key" };
    const order = options.order ?? "asc";
    const ranked =
      order === "desc" || sort.by === "field" || (removals && !listing);
    const positions: (ListPosition & {
      connectionId: string;
      pkHash: string;
      removedAt?: number;
    })[] = [];
    let after: [string, string, string] | undefined;
    while (targets.length > 0) {
      const current = await db.query<{
        instance: string;
        connection_id: string;
        record_key: string;
        pk_hash: string;
        body: string;
        stamp_o: number;
      }>(
        `WITH targets(instance,connection_id) AS (VALUES ${targets.map(() => "(?,?)").join(",")})
         SELECT t.instance,r.connection_id,r.record_key,r.pk_hash,r.body,${seenStamp("r.").o} AS stamp_o FROM records r JOIN targets t ON t.connection_id=r.connection_id
         WHERE r.stream=? ${after ? "AND (t.instance,r.record_key,r.pk_hash)>(?,?,?)" : ""}
         ${since === null ? "" : "AND EXISTS (SELECT 1 FROM record_changes c WHERE c.connection_id=r.connection_id AND c.stream=r.stream AND c.pk_hash=r.pk_hash AND c.seq<=? AND c.seq>?)"}
         AND NOT EXISTS (SELECT 1 FROM record_changes c WHERE c.connection_id=r.connection_id AND c.stream=r.stream AND c.pk_hash=r.pk_hash AND c.seq>?)
         ORDER BY t.instance,r.record_key,r.pk_hash LIMIT 100`,
        [
          ...targets.flatMap((t) => [t.instance, t.id]),
          stream,
          ...(after ?? []),
          ...(since === null ? [] : [horizon, since]),
          horizon,
        ],
      );
      for (const row of current) {
        const value: PdppStoredRecord = {
          instance: row.instance,
          stream,
          recordKey: row.record_key,
          data: JSON.parse(row.body),
          emittedAt: new Date(row.stamp_o).toISOString(),
          version: 1,
          deleted: false,
        };
        if (!options.isVisible || options.isVisible(value)) {
          if (ranked) {
            positions.push({
              ...listPosition(value, sort),
              connectionId: row.connection_id,
              pkHash: row.pk_hash,
            });
          } else if (visibleCount >= offset && rows.length <= limit) {
            rows.push(value);
          }
          visibleCount++;
        }
      }
      if (current.length < 100) break;
      const last = current.at(-1)!;
      after = [last.instance, last.record_key, last.pk_hash];
    }
    if (removals && !listing && since !== null) {
      // Tombstones: the key's last change at h1 is a removal inside the
      // session, and its last change at h0 was an upsert, so the record was
      // visible at h0 and is not at h1. No other key gets one, including a
      // record created and removed between the horizons (spec-core §4).
      const removed = await db.query<{
        instance: string;
        connection_id: string;
        record_key: string;
        pk_hash: string;
        stamp_o: number;
      }>(
        `WITH targets(instance,connection_id) AS (VALUES ${targets.map(() => "(?,?)").join(",")})
         SELECT t.instance,c.connection_id,c.record_key,c.pk_hash,c.stamp_o FROM record_changes c JOIN targets t ON t.connection_id=c.connection_id
         WHERE c.stream=? AND c.op='remove' AND c.seq>? AND c.seq<=?
           AND c.seq=(SELECT MAX(c2.seq) FROM record_changes c2 WHERE c2.connection_id=c.connection_id AND c2.stream=c.stream AND c2.pk_hash=c.pk_hash AND c2.seq<=?)
           AND (SELECT c3.op FROM record_changes c3 WHERE c3.connection_id=c.connection_id AND c3.stream=c.stream AND c3.pk_hash=c.pk_hash AND c3.seq<=? ORDER BY c3.seq DESC LIMIT 1)='upsert'`,
        [
          ...targets.flatMap((t) => [t.instance, t.id]),
          stream,
          since,
          horizon,
          horizon,
          since,
        ],
      );
      for (const row of removed) {
        positions.push({
          sortKey: null,
          instance: row.instance,
          recordKey: row.record_key,
          connectionId: row.connection_id,
          pkHash: row.pk_hash,
          removedAt: row.stamp_o,
        });
        visibleCount++;
      }
    }
    if (ranked) {
      positions.sort((a, b) => compareListPositions(a, b, order, sort));
      for (const position of positions.slice(offset, offset + limit + 1)) {
        if (position.removedAt !== undefined) {
          // The removal's stamp is the deletion time (an explicit delete
          // stamps its observation time; merge.ts `deleteRunRecords`).
          const at = new Date(position.removedAt).toISOString();
          rows.push({
            instance: position.instance,
            stream,
            recordKey: position.recordKey,
            version: 1,
            deletedAt: at,
            emittedAt: at,
            deleted: true,
          });
          continue;
        }
        const [row] = await db.query<{ body: string; stamp_o: number }>(
          `SELECT r.body,${seenStamp("r.").o} AS stamp_o FROM records r
           WHERE r.connection_id=? AND r.stream=? AND r.pk_hash=?`,
          [position.connectionId, stream, position.pkHash],
        );
        // The final exactness check below expires a page whose body moved.
        if (!row) throw new CursorExpiredError();
        rows.push({
          instance: position.instance,
          stream,
          recordKey: position.recordKey,
          data: JSON.parse(row.body),
          emittedAt: new Date(row.stamp_o).toISOString(),
          version: 1,
          deleted: false,
        });
      }
    }
    await assertExact();
    const data = rows.slice(0, limit),
      hasMore = visibleCount > offset + limit;
    const cursor = encodeCursor({
      kind: "changes_since",
      epoch: "ps2-current",
      query: signature,
      stream,
      horizon: String(horizon),
      sinceHorizon: since === null ? null : String(since),
      offset: hasMore ? offset + limit : 0,
      orderKey: "code-point",
    });
    return {
      data,
      hasMore,
      ...(hasMore ? { nextCursor: cursor } : { nextChangesSince: cursor }),
      ...(listing && { total: visibleCount }),
    };
  };
}
