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

export function createRecordQuery(db: SqlDriver): RecordQuery {
  void db;
  throw new Error("PS-2: not built");
}
