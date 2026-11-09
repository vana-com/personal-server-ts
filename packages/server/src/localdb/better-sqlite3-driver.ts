import Database from "better-sqlite3";
import type {
  SqlDriver,
  SqlStatement,
  SqlValue,
} from "@opendatalabs/personal-server-ts-core/localdb";

const bind = (params: readonly SqlValue[] = []) =>
  params.map((v) => (v instanceof Uint8Array ? Buffer.from(v) : v));

/**
 * Node and Desktop driver. `batch` is a synchronous BEGIN IMMEDIATE ... COMMIT.
 * The process holds the file exclusively (`locking_mode=EXCLUSIVE`).
 * `path` is a file path, or `:memory:`.
 */
export function openBetterSqlite3(path: string): SqlDriver {
  const db = new Database(path);
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
      const stmt = db.prepare(sql);
      if (stmt.reader) return stmt.all(...bind(params)) as R[];
      stmt.run(...bind(params));
      return [];
    },
    async batch(statements: readonly SqlStatement[]) {
      db.exec("BEGIN IMMEDIATE");
      try {
        const changes = statements.map((s) => {
          const stmt = db.prepare(s.sql);
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
      db.close();
    },
  };
}
