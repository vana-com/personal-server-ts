import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { encodeCursor, decodeCursor } from "../storage/pdpp-records/cursor.js";
import {
  CursorExpiredError,
  type ChangesSinceOptions,
  type ChangesSincePage,
  type PdppStoredRecord,
} from "../storage/pdpp-records/types.js";
import type { ConnectionLink } from "./connection-link.js";

import type { SqlReader } from "./driver.js";
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

const RECORD_COLUMNS = `stream, record_key, pk_hash, body, ${SEEN_O} AS stamp_o`;
const STREAM_PAGE_SIZE = 100;

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
    Buffer.from(JSON.stringify([recordKey, pkHash])).toString("base64url")
  );
}

function parseListCursor(cursor: string): {
  recordKey: string;
  pkHash: string | null;
} {
  if (cursor.startsWith(LIST_CURSOR_PREFIX)) {
    try {
      const value: unknown = JSON.parse(
        Buffer.from(
          cursor.slice(LIST_CURSOR_PREFIX.length),
          "base64url",
        ).toString("utf8"),
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

export function createRecordQuery(db: SqlReader): RecordQuery {
  return {
    async listRecords({ connectionId, stream, cursor, limit }) {
      const size = pageLimit(limit);
      const after = cursor === undefined ? null : parseListCursor(cursor);
      const rows = await db.query<RecordRow>(
        `SELECT ${RECORD_COLUMNS} FROM records
         WHERE connection_id = ? AND stream = ?
           ${
             after === null
               ? ""
               : after.pkHash === null
                 ? "AND record_key > ?"
                 : "AND (record_key, pk_hash) > (?, ?)"
           }
         ORDER BY record_key, pk_hash LIMIT ?`,
        [
          connectionId,
          stream,
          ...(after === null
            ? []
            : after.pkHash === null
              ? [after.recordKey]
              : [after.recordKey, after.pkHash]),
          size + 1,
        ],
      );
      const more = rows.length > size;
      const page = rows.slice(0, size);
      const last = page[page.length - 1];
      return {
        records: page.map(stored),
        nextCursor: more ? listCursor(last!.record_key, last!.pk_hash) : null,
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
  };
}

/** Frozen grant projections over the current table. Lost bodies expire the cursor;
 * published older bodies remain owned by older-versions, never a local archive.
 */
export function createGrantHistory(db: SqlReader, link: ConnectionLink) {
  return async (
    stream: string,
    options: ChangesSinceOptions,
  ): Promise<ChangesSincePage> => {
    const instances = [...new Set(options.instanceIds)].sort();
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
          ${since === null ? "" : "OR (later.seq>? AND later.seq<=? AND EXISTS (SELECT 1 FROM record_changes prior WHERE prior.connection_id=later.connection_id AND prior.stream=later.stream AND prior.pk_hash=later.pk_hash AND prior.seq<=?))"}) LIMIT 1`,
          since === null
            ? [target.id, stream, horizon, horizon]
            : [target.id, stream, horizon, horizon, since, horizon, since],
        );
        if (missing.length) throw new CursorExpiredError();
      }
    };
    await assertExact();
    const rows: PdppStoredRecord[] = [];
    let visibleCount = 0;
    const limit = Math.max(1, Math.min(100, options.limit));
    let after: [string, string, string] | undefined;
    while (targets.length > 0) {
      const current = await db.query<{
        instance: string;
        record_key: string;
        pk_hash: string;
        body: string;
        stamp_o: number;
      }>(
        `WITH targets(instance,connection_id) AS (VALUES ${targets.map(() => "(?,?)").join(",")})
         SELECT t.instance,r.record_key,r.pk_hash,r.body,${seenStamp("r.").o} AS stamp_o FROM records r JOIN targets t ON t.connection_id=r.connection_id
         WHERE r.stream=? ${after ? "AND (r.record_key,t.instance,r.pk_hash)>(?,?,?)" : ""}
         ${since === null ? "" : "AND EXISTS (SELECT 1 FROM record_changes c WHERE c.connection_id=r.connection_id AND c.stream=r.stream AND c.pk_hash=r.pk_hash AND c.seq<=? AND c.seq>?)"}
         AND NOT EXISTS (SELECT 1 FROM record_changes c WHERE c.connection_id=r.connection_id AND c.stream=r.stream AND c.pk_hash=r.pk_hash AND c.seq>?)
         ORDER BY r.record_key,t.instance,r.pk_hash LIMIT 100`,
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
          if (visibleCount++ >= offset && rows.length <= limit)
            rows.push(value);
        }
      }
      if (current.length < 100) break;
      const last = current.at(-1)!;
      after = [last.record_key, last.instance, last.pk_hash];
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
    };
  };
}
