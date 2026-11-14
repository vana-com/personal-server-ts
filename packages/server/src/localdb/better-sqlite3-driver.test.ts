import { Worker } from "node:worker_threads";
import Database from "better-sqlite3";
import { afterEach, expect, it, vi } from "vitest";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import {
  createStatementCache,
  openBetterSqlite3,
} from "./better-sqlite3-driver.js";

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

// The worker thread runs this same cache, so its reuse and eviction rules are
// checked on the shared function, where Database.prototype can be spied on.
function cacheFixture() {
  const native = new Database(":memory:");
  const cache = createStatementCache(native);
  const run = (sql: string, ...params: unknown[]) => {
    const stmt = cache.prepare(sql);
    return stmt.reader ? stmt.all(...params) : stmt.run(...params);
  };
  return { run, close: () => native.close() };
}

it("reuses prepared reads and writes while rebinding every call", () => {
  const prepare = vi.spyOn(Database.prototype, "prepare");
  const { run, close } = cacheFixture();
  run("CREATE TABLE items (id INTEGER PRIMARY KEY, body TEXT)");
  const insert = "INSERT INTO items VALUES (?, ?)";
  const select = "SELECT body FROM items WHERE id = ?";
  for (let i = 0; i < 500; i++) {
    run(insert, i, `body-${i}`);
    expect(run(select, i)).toEqual([{ body: `body-${i}` }]);
  }
  expect(prepare.mock.calls.filter(([sql]) => sql === insert)).toHaveLength(1);
  expect(prepare.mock.calls.filter(([sql]) => sql === select)).toHaveLength(1);
  close();
});

it("evicts old SQL instead of retaining every distinct statement", () => {
  const prepare = vi.spyOn(Database.prototype, "prepare");
  const { run, close } = cacheFixture();
  const oldest = "SELECT ? AS value /* oldest */";
  run(oldest, 0);
  for (let i = 0; i < 256; i++) run(`SELECT ? AS value /* ${i} */`, i);
  const recent = "SELECT ? AS value /* 255 */";
  expect(run(recent, 1000)).toEqual([{ value: 1000 }]);
  expect(run(oldest, 2000)).toEqual([{ value: 2000 }]);
  expect(prepare.mock.calls.filter(([sql]) => sql === recent)).toHaveLength(1);
  expect(prepare.mock.calls.filter(([sql]) => sql === oldest)).toHaveLength(2);
  close();
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

it("hands blobs back as Buffers and keeps a native error's code", async () => {
  const db = fixture();
  await db.batch([
    { sql: "CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)" },
    {
      sql: "INSERT INTO blobs VALUES (1, ?)",
      params: [new Uint8Array([1, 2])],
    },
  ]);
  const [row] = await db.query<{ data: Uint8Array }>("SELECT data FROM blobs");
  expect(Buffer.isBuffer(row!.data)).toBe(true);
  expect([...row!.data]).toEqual([1, 2]);
  await expect(
    db.batch([{ sql: "INSERT INTO blobs VALUES (1, NULL)" }]),
  ).rejects.toMatchObject({ code: "SQLITE_CONSTRAINT_PRIMARYKEY" });
});

it("runs calls made without awaiting in the order they were made", async () => {
  const db = fixture();
  await db.batch([{ sql: "CREATE TABLE log (n INTEGER)" }]);
  await Promise.all(
    Array.from({ length: 50 }, (_, n) =>
      db.batch([{ sql: "INSERT INTO log VALUES (?)", params: [n] }]),
    ),
  );
  const rows = await db.query<{ n: number }>(
    "SELECT n FROM log ORDER BY rowid",
  );
  expect(rows.map((r) => r.n)).toEqual(Array.from({ length: 50 }, (_, n) => n));
});

it("rejects calls after close and reports a database that cannot open", async () => {
  const db = openBetterSqlite3(":memory:");
  await db.close();
  await expect(db.query("SELECT 1")).rejects.toThrow("sqlite_driver_closed");
  const broken = openBetterSqlite3("/nonexistent-directory/x.sqlite");
  await expect(broken.query("SELECT 1")).rejects.toThrow();
});

it("sends each statement's text to the worker once, then only its id", async () => {
  const post = vi.spyOn(Worker.prototype, "postMessage");
  const db = fixture();
  await db.batch([{ sql: "CREATE TABLE items (id INTEGER, body TEXT)" }]);
  const insert = "INSERT INTO items VALUES (?, ?)";
  const select = "SELECT body FROM items WHERE id = ?";
  for (let i = 0; i < 50; i++) {
    await db.batch([{ sql: insert, params: [i, `body-${i}`] }]);
    expect(await db.query(select, [i])).toEqual([{ body: `body-${i}` }]);
  }
  const sent = post.mock.calls.map(([message]) => JSON.stringify(message));
  const copies = (sql: string) =>
    sent.filter((message) => message.includes(JSON.stringify(sql))).length;
  expect(copies(insert)).toBe(1);
  expect(copies(select)).toBe(1);
});

it("keeps later statement ids valid when an earlier batch statement fails", async () => {
  const db = fixture();
  await db.batch([{ sql: "CREATE TABLE items (id INTEGER)" }]);
  const insert = "INSERT INTO items VALUES (?)";
  await expect(
    db.batch([
      { sql: "INSERT INTO missing VALUES (1)" },
      { sql: insert, params: [1] },
    ]),
  ).rejects.toThrow();
  await db.batch([{ sql: insert, params: [2] }]);
  expect(await db.query("SELECT id FROM items")).toEqual([{ id: 2 }]);
});

it("falls back to inline text past the id limit", async () => {
  const db = fixture();
  for (let i = 0; i < 300; i++)
    expect(await db.query(`SELECT ? AS value /* ${i} */`, [i])).toEqual([
      { value: i },
    ]);
  expect(await db.query("SELECT ? AS value /* 299 */", [7])).toEqual([
    { value: 7 },
  ]);
});
