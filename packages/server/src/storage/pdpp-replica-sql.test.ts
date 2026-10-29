/**
 * The Node replica SQL adapter keeps a bounded statement cache: engine
 * queries that embed the step's clock must not grow it every step.
 */
import Database from "better-sqlite3";
import { expect, it, vi } from "vitest";
import {
  nodeReplicaSql,
  REPLICA_STATEMENT_CACHE_SIZE,
} from "./pdpp-replica-sql.js";

it("keeps at most REPLICA_STATEMENT_CACHE_SIZE prepared statements, least recently used out", () => {
  const db = new Database(":memory:");
  const prepare = vi.spyOn(db, "prepare");
  const sql = nodeReplicaSql(db);
  const text = (now: number) => `SELECT ${now} AS now`;
  // One query text per step, as `due(e)` builds with `e.now`.
  for (let now = 0; now < 4 * REPLICA_STATEMENT_CACHE_SIZE; now++)
    expect(sql.get(text(now), [])).toEqual({ now });
  expect(prepare).toHaveBeenCalledTimes(4 * REPLICA_STATEMENT_CACHE_SIZE);
  // The most recent texts are still prepared; the oldest was evicted.
  sql.get(text(4 * REPLICA_STATEMENT_CACHE_SIZE - 1), []);
  expect(prepare).toHaveBeenCalledTimes(4 * REPLICA_STATEMENT_CACHE_SIZE);
  sql.get(text(0), []);
  expect(prepare).toHaveBeenCalledTimes(4 * REPLICA_STATEMENT_CACHE_SIZE + 1);
  db.close();
});
