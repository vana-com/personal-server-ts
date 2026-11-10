import Database from "better-sqlite3";
import { afterEach, expect, it, vi } from "vitest";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const opened: SqlDriver[] = [];
afterEach(async () => {
  for (const db of opened.splice(0)) await db.close();
  vi.restoreAllMocks();
});
function fixture() {
  const db = openBetterSqlite3(":memory:");
  opened.push(db);
  return db;
}

it("reuses prepared reads and writes while rebinding every call", async () => {
  const prepare = vi.spyOn(Database.prototype, "prepare");
  const db = fixture();
  await db.batch([
    { sql: "CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)" },
  ]);
  const insert = "INSERT INTO items VALUES (?, ?)";
  const select = "SELECT body FROM items WHERE id = ?";
  for (let i = 0; i < 500; i++) {
    await db.batch([{ sql: insert, params: [i, `body-${i}`] }]);
    expect(await db.query(select, [i])).toEqual([{ body: `body-${i}` }]);
  }
  expect(prepare.mock.calls.filter(([sql]) => sql === insert)).toHaveLength(1);
  expect(prepare.mock.calls.filter(([sql]) => sql === select)).toHaveLength(1);
});

it("evicts old SQL instead of retaining every distinct statement", async () => {
  const prepare = vi.spyOn(Database.prototype, "prepare");
  const db = fixture();
  const oldest = "SELECT ? AS value /* oldest */";
  await db.query(oldest, [0]);
  for (let i = 0; i < 256; i++)
    await db.query(`SELECT ? AS value /* ${i} */`, [i]);
  const recent = "SELECT ? AS value /* 255 */";
  expect(await db.query(recent, [1000])).toEqual([{ value: 1000 }]);
  expect(await db.query(oldest, [2000])).toEqual([{ value: 2000 }]);
  expect(prepare.mock.calls.filter(([sql]) => sql === recent)).toHaveLength(1);
  expect(prepare.mock.calls.filter(([sql]) => sql === oldest)).toHaveLength(2);
});

it("keeps statement ownership local to each connection", async () => {
  const first = fixture();
  const second = fixture();
  for (const [db, value] of [
    [first, 1],
    [second, 2],
  ] as const) {
    await db.batch([
      { sql: "CREATE TABLE items (value INTEGER)" },
      { sql: "INSERT INTO items VALUES (?)", params: [value] },
    ]);
  }
  expect(await first.query("SELECT * FROM items")).toEqual([{ value: 1 }]);
  expect(await second.query("SELECT * FROM items")).toEqual([{ value: 2 }]);
});

it("reprepares cached reads after schema changes", async () => {
  const db = fixture();
  await db.batch([
    { sql: "CREATE TABLE items (id INTEGER)" },
    { sql: "INSERT INTO items VALUES (1)" },
  ]);
  expect(await db.query("SELECT * FROM items")).toEqual([{ id: 1 }]);
  await db.batch([
    { sql: "ALTER TABLE items ADD COLUMN body TEXT" },
    { sql: "UPDATE items SET body = 'changed'" },
  ]);
  expect(await db.query("SELECT * FROM items")).toEqual([
    { id: 1, body: "changed" },
  ]);
});

it("rolls back a failed batch and reuses its statements on the next batch", async () => {
  const db = fixture();
  const insert = "INSERT INTO items VALUES (?)";
  await db.batch([
    { sql: "CREATE TABLE items (id INTEGER PRIMARY KEY)" },
    { sql: insert, params: [1] },
  ]);
  await expect(
    db.batch([
      { sql: insert, params: [2] },
      { sql: insert, params: [1] },
    ]),
  ).rejects.toThrow("UNIQUE constraint failed");
  expect(await db.query("SELECT * FROM items")).toEqual([{ id: 1 }]);
  await db.batch([
    { sql: insert, params: [2] },
    { sql: insert, params: [3] },
  ]);
  expect(await db.query("SELECT * FROM items ORDER BY id")).toEqual([
    { id: 1 },
    { id: 2 },
    { id: 3 },
  ]);
});
