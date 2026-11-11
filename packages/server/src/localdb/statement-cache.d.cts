import type Database from "better-sqlite3";

export function createStatementCache(db: Database.Database): {
  prepare(sql: string): Database.Statement;
  clear(): void;
};
