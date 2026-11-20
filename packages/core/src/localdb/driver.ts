/**
 * The SQL-level port of the local database. Every host (Node, Web, phone)
 * supplies one `SqlDriver`; the schema, merge rules and migrations are shared
 * code on top of it.
 *
 * Rules every driver follows:
 * - One process holds one database at a time.
 * - `batch` runs all statements in one IMMEDIATE transaction: all or nothing.
 *   A failing statement rolls back the whole batch and rejects.
 * - `query` reads only. It sees committed batches.
 * - A driver that exports `reads` keeps the one-writer rule: every write and
 *   every read that is followed by a write goes through the driver itself.
 * - Parameters are positional (`?`). Statements may not use ATTACH, DETACH or
 *   `load_extension`.
 * - Shared SQL keeps to SQLite 3.22 (no UPSERT, RETURNING, JSON1 or window
 *   functions).
 */
export type SqlValue = string | number | bigint | null | Uint8Array;

export interface SqlStatement {
  readonly sql: string;
  readonly params?: readonly SqlValue[];
}

/**
 * The read half of a driver: `query` only, so code that takes it cannot write.
 * Every `SqlDriver` is one.
 */
export type SqlReader = Pick<SqlDriver, "query">;

export interface SqlDriver {
  readonly info: {
    readonly sqliteVersion: string;
    readonly host: "node" | "web" | "phone";
    readonly persistent: boolean;
  };
  query<R extends Record<string, SqlValue>>(
    sql: string,
    params?: readonly SqlValue[],
  ): Promise<R[]>;
  /** All statements in one IMMEDIATE transaction; all or nothing. `changes[i]` is the row count of statement i. */
  batch(
    statements: readonly SqlStatement[],
  ): Promise<{ readonly changes: readonly number[] }>;
  close(): Promise<void>;
  /**
   * A second, read-only connection to the same database, when the host can
   * offer one. A read that needs no order against a write (an HTTP read)
   * takes it from here, so it does not queue behind a long `batch`. It sees
   * the last committed state, never a transaction in progress. `close()`
   * closes it too. Absent: use the driver itself (see `readerOf`).
   */
  readonly reads?: SqlReader;
}

/** The connection an HTTP read uses: the read connection if the host has one. */
export const readerOf = (db: SqlDriver): SqlReader => db.reads ?? db;
