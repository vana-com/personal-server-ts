import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import { openLogWorkspace } from "../../../core/src/localdb/workspace-consumer.js";
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close();
});
it("freezes one indexed change per key in sequence order with bounded receipts", async () => {
  const dir = await mkdtemp(join(process.cwd(), ".changes-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(dir, "db"));
  cleanup.push(() => db.close());
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
  ]);
  const ws = await openLogWorkspace(db, {
    owner: "o",
    databaseIncarnation: "db",
    connection: "c",
    generation: 1,
    keyCheck: "k",
    expectedHead: "h",
    operation: "op",
    codecVersion: 1,
  });
  for (let i = 1; i <= 30; i++)
    await db.batch([
      {
        sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin) VALUES('c','s',?,?,'upsert',1,'r','local')`,
        params: [String(i % 7), String(i)],
      },
    ]);
  await ws.freezeChanges("s", 0, 30);
  const lease = await ws.acquire(2 * 1024 * 1024);
  try {
    for (let pass = 0; pass < 2; pass++) {
      const cursor = ws.changeCursor();
      const seen = [];
      for (
        let unit = await cursor.next(lease);
        unit;
        unit = await cursor.next(lease)
      ) {
        seen.push(unit.value);
        expect(unit.encodedBytes).toBeLessThan(1024);
        await expect(cursor.next(lease)).rejects.toThrow("owned");
        await unit.release();
      }
      await cursor.close();
      expect(seen).toEqual(
        Array.from({ length: 7 }, (_, i) => ({
          pk: String((24 + i) % 7),
          seq: 24 + i,
        })),
      );
    }
    await expect(ws.freezeChanges("s", 0, 31)).rejects.toThrow();
    await ws.freezeChanges("s", 0, 30);
  } finally {
    await lease.release();
  }
});
