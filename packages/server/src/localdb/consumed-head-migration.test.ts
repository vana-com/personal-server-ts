// The consumed registry head (`stream_state.consumed_*`) arrives with the last
// schema migration. A connection with no log took its head as consumed; one
// that followed a log did not, and reopening changes neither.
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import { openLocalDb } from "../../../core/src/localdb/index.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const dirs: string[] = [];
const open = new Set<SqlDriver>();
afterEach(async () => {
  try {
    for (const db of open) await db.close();
  } finally {
    open.clear();
    for (const dir of dirs.splice(0))
      rmSync(dir, { recursive: true, force: true });
  }
});

const OWNER = `0x${"11".repeat(20)}` as const;
const options = { owner: OWNER, network: "test", deviceId: "d" } as const;
const triples = (db: SqlDriver) =>
  db.query(
    "SELECT connection_id, stream, head_version, consumed_version, consumed_generation, consumed_data_hash FROM stream_state ORDER BY connection_id, stream",
  );

it("a populated no-log head is consumed after the upgrade; a head of a connection with a log is not; reopening keeps both", async () => {
  const dir = mkdtempSync(join(process.cwd(), ".consumed-head-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  // The database as the build before the last migration left it.
  const old = openBetterSqlite3(path);
  open.add(old);
  for (let i = 0; i < MIGRATIONS.length - 1; i++)
    await old.batch([
      ...MIGRATIONS[i]!.map((sql) => ({ sql })),
      { sql: `PRAGMA user_version = ${i + 1}` },
    ]);
  const stream = (
    connection: string,
    version: number,
    hash: string | null,
  ) => ({
    sql: `INSERT INTO stream_state (connection_id, stream, primary_key, semantics, incremental, head_version, head_generation, head_data_hash)
          VALUES (?, 's', '["id"]', 'mutable_state', 1, ?, ?, ?)`,
    params: [connection, version, version > 0 ? 1 : null, hash],
  });
  await old.batch([
    stream("unlogged", 3, `0x${"aa".repeat(32)}`),
    stream("unlogged-empty", 0, null),
    stream("logged", 5, `0x${"bb".repeat(32)}`),
    {
      sql: "INSERT INTO log_state (connection_id, position, base, refs, snapshot) VALUES ('logged', 2, 0, '[]', NULL)",
    },
  ]);
  await old.close();
  open.delete(old);

  const want = [
    {
      connection_id: "logged",
      stream: "s",
      head_version: 5,
      consumed_version: 0,
      consumed_generation: null,
      consumed_data_hash: null,
    },
    {
      connection_id: "unlogged",
      stream: "s",
      head_version: 3,
      consumed_version: 3,
      consumed_generation: 1,
      consumed_data_hash: `0x${"aa".repeat(32)}`,
    },
    {
      connection_id: "unlogged-empty",
      stream: "s",
      head_version: 0,
      consumed_version: 0,
      consumed_generation: null,
      consumed_data_hash: null,
    },
  ];
  for (let round = 0; round < 2; round++) {
    const db = await openLocalDb(openBetterSqlite3(path), options);
    open.add(db);
    expect(await triples(db)).toEqual(want);
    await db.close();
    open.delete(db);
  }
});
