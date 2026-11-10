import Database from "better-sqlite3";
import type {
  SqlDriver,
  SqlStatement,
  SqlValue,
} from "@opendatalabs/personal-server-ts-core/localdb";

const bind = (params: readonly SqlValue[] = []) =>
  params.map((v) => (v instanceof Uint8Array ? Buffer.from(v) : v));

/** Shared bounded native-statement owner for local SQL and borrowed legacy
 * handles. Callers clear the cache when their access lifetime ends. */
export function createStatementCache(db: Database.Database): {
  prepare(sql: string): Database.Statement;
  clear(): void;
} {
  // Recompiling every row's SQL leaves native statement allocations waiting
  // for V8 collection through long synchronous merge loops. Reuse a bounded,
  // connection-local set; run/all reset statements and clear their bindings.
  const statements = new Map<string, Database.Statement>();
  const prepare = (sql: string) => {
    let statement = statements.get(sql);
    if (statement && !statement.busy) {
      statements.delete(sql);
      statements.set(sql, statement);
      return statement;
    }
    statement = db.prepare(sql);
    statements.set(sql, statement);
    if (statements.size > 64)
      statements.delete(statements.keys().next().value!);
    return statement;
  };
  return { prepare, clear: () => statements.clear() };
}

/**
 * Node and Desktop driver. `batch` is a synchronous BEGIN IMMEDIATE ... COMMIT.
 * The process holds the file exclusively (`locking_mode=EXCLUSIVE`).
 * `path` is a file path, or `:memory:`.
 */
export function openBetterSqlite3(path: string): SqlDriver {
  const db = new Database(path);
  const cache = createStatementCache(db);
  const { prepare } = cache;
  db.pragma("locking_mode = EXCLUSIVE");
  const { v } = db.prepare("SELECT sqlite_version() AS v").get() as {
    v: string;
  };
  return {
    info: {
      sqliteVersion: v,
      host: "node",
      persistent: path !== ":memory:",
    },
    async query<R extends Record<string, SqlValue>>(
      sql: string,
      params?: readonly SqlValue[],
    ) {
      const stmt = prepare(sql);
      if (stmt.reader) return stmt.all(...bind(params)) as R[];
      stmt.run(...bind(params));
      return [];
    },
    async batch(statements: readonly SqlStatement[]) {
      db.exec("BEGIN IMMEDIATE");
      try {
        const changes = statements.map((s) => {
          const stmt = prepare(s.sql);
          return stmt.reader
            ? (stmt.all(...bind(s.params)), 0)
            : stmt.run(...bind(s.params)).changes;
        });
        db.exec("COMMIT");
        return { changes };
      } catch (error) {
        if (db.inTransaction) db.exec("ROLLBACK");
        throw error;
      }
    },
    async close() {
      cache.clear();
      db.close();
    },
  };
}
