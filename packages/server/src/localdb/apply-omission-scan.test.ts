// Apply drops the rows a head omits with one delete per stream. It must find
// them from the stream's keys, an index read, and reach only those rows by
// key: a test of every row would read every row's body, which on a host whose
// page reads are calls (the Web's OPFS) costs a read of the whole stream even
// when no row is omitted.
import { afterEach, describe, expect, it } from "vitest";
import {
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  applyDelete,
  TEMP_TABLES,
  withOrigin,
} from "../../../core/src/localdb/merge.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const pkOf = (n: number) => n.toString(16).padStart(64, "0");

async function streamOf(count: number, bodyBytes: number | null = 10) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "omission-device",
  });
  drivers.push(db);
  await db.batch(TEMP_TABLES.map((sql) => ({ sql })));
  await db.batch(
    Array.from({ length: count }, (_, n) => ({
      sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, body_bytes)
            VALUES ('c1', 's', ?, ?, 1, 'r1', ?, ?, NULL, ?)`,
      params: [
        pkOf(n),
        `k${n}`,
        JSON.stringify({ id: n }),
        `sha${n}`,
        bodyBytes,
      ],
    })),
  );
  return db as unknown as LocalSyncDeps["db"];
}

const plan = async (db: LocalSyncDeps["db"], sql: string, params: unknown[]) =>
  (
    await db.query<{ detail: string }>(
      `EXPLAIN QUERY PLAN ${sql}`,
      params as never,
    )
  ).map((row) => row.detail);

describe("the delete of rows a head omits", () => {
  it("reads the stream's keys from an index and reaches rows by key", async () => {
    const db = await streamOf(500);
    const statements = applyDelete("op1", "c1", "s", 5).filter(
      (s) =>
        s.sql.startsWith("UPDATE records") ||
        s.sql.startsWith("DELETE FROM records"),
    );
    expect(statements).toHaveLength(2);
    for (const statement of statements) {
      const text = (
        await plan(db, statement.sql, [...(statement.params ?? [])])
      ).join("\n");
      // The keys of the stream: an index alone, no row, so no body page.
      expect(text).toMatch(/SEARCH records USING COVERING INDEX records_size/);
      // The rows the keys name: one search by key each, never a range scan.
      expect(text).toMatch(
        /SEARCH records USING (COVERING )?INDEX \w+ \(connection_id=\? AND stream=\? AND pk_hash=\?\)/,
      );
      expect(text).not.toMatch(/SCAN records/);
    }
  });

  it("still drops exactly the rows the head does not hold, and keeps ranges", async () => {
    const db = await streamOf(10);
    await db.batch([
      // Rows 0-3 are in the head; rows 4-5 sit in a kept range.
      ...[0, 1, 2, 3].map((n) => ({
        sql: "INSERT INTO temp.apply_keys (op, pk_hash) VALUES ('op1', ?)",
        params: [pkOf(n)],
      })),
      {
        sql: "INSERT INTO temp.keep_ranges (op, lo, hi) VALUES ('op1', ?, ?)",
        params: [pkOf(4), pkOf(6)],
      },
    ]);
    await db.batch(withOrigin("remote", applyDelete("op1", "c1", "s", 5)));
    const left = await db.query<{ pk_hash: string }>(
      "SELECT pk_hash FROM records WHERE connection_id = 'c1' AND stream = 's' ORDER BY pk_hash",
    );
    expect(left.map((r) => r.pk_hash)).toEqual([0, 1, 2, 3, 4, 5].map(pkOf));
  });

  it.each([null, 0])(
    "drops an omitted row whose recorded size is %s",
    async (size) => {
      const db = await streamOf(6, size);
      await db.batch(
        [0, 1].map((n) => ({
          sql: "INSERT INTO temp.apply_keys (op, pk_hash) VALUES ('op1', ?)",
          params: [pkOf(n)],
        })),
      );
      await db.batch(withOrigin("remote", applyDelete("op1", "c1", "s", 5)));
      const left = await db.query<{ pk_hash: string }>(
        "SELECT pk_hash FROM records WHERE connection_id = 'c1' AND stream = 's' ORDER BY pk_hash",
      );
      expect(left.map((r) => r.pk_hash)).toEqual([0, 1].map(pkOf));
    },
  );
});
