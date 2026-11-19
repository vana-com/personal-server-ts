import type { SqlValue } from "../../../core/src/localdb/driver.js";
import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  setWorkspaceAuthority,
  readWorkspaceAuthority,
} from "../../../core/src/localdb/workspace.js";
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
  await db.query("PRAGMA journal_mode=WAL");
  await db.query("PRAGMA synchronous=NORMAL");
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
  ]);
  let freezeSql:
    | {
        sql: string;
        params?: readonly SqlValue[];
      }
    | undefined;
  const batch = db.batch.bind(db);
  db.batch = (statements) => {
    freezeSql ??= statements.find((s) => s.sql.includes("SELECT ?, 'changes'"));
    return batch(statements);
  };
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
  expect(await readWorkspaceAuthority(db, "c")).toEqual({
    databaseIncarnation: "db",
    keyCheck: "k",
    expectedHead: "h",
  });
  for (let i = 1; i <= 30; i++)
    await db.batch([
      {
        sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin) VALUES('c','s',?,?,'upsert',1,'r','local')`,
        params: [String(i % 7), String(i)],
      },
    ]);
  await ws.freezeChanges("s", 0, 30);
  const plan = await db.query<{ detail: string }>(
    "EXPLAIN QUERY PLAN " + freezeSql!.sql,
    freezeSql!.params,
  );
  expect(plan.some((row) => row.detail.includes("record_changes_by_key"))).toBe(
    true,
  );
  expect(plan.some((row) => /TEMP B-TREE/.test(row.detail))).toBe(false);
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
          recordBytes: 0,
        })),
      );
    }
    await expect(ws.freezeChanges("s", 0, 31)).rejects.toThrow();
    await ws.freezeChanges("s", 0, 30);
    await expect(ws.admit(lease, 3 * 1024 * 1024)).rejects.toMatchObject({
      reason: "admission",
      retryable: true,
    });
    await db.batch([
      {
        sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o) VALUES('c','s','gone','gone',1,'r','{\"id\":\"雪\"}','hash',NULL)",
      },
    ]);
    await ws.freezeMembership("s", { o: 2, r: "next" });
    expect(await ws.membershipCount()).toBe(1);
    const members = ws.membershipCursor();
    const member = await members.next(lease);
    expect(member!.value).toEqual({
      pkHash: "gone",
      recordBytes: Buffer.byteLength(JSON.stringify({ id: "雪" })) + 1,
    });
    await member!.release();
    expect(await members.next(lease)).toBeNull();
    await members.close();
    await ws.freezeChanges("s", 0, 30);
    const replay = await ws.replayableUnit("typed", "digest");
    if (replay.state !== "staging") throw new Error("expected staging");
    await replay.stage("membership", {
      stream: "s",
      pkHash: "gone",
      key: ["雪"],
      changed: false,
    });
    await replay.commit();
    expect((await ws.replayableUnit("typed", "digest")).state).toBe(
      "receipted",
    );
    const binding = {
      ...ws.binding,
      operation: "first",
      expectedHead: "null",
      controlState: "absent" as const,
    };
    await db.batch([
      {
        sql: "UPDATE connections SET control_state='absent' WHERE connection_id='c'",
      },
    ]);
    await setWorkspaceAuthority(db, binding);
    const first = await openLogWorkspace(db, binding);
    await first.freezeChanges("s", 0, 30);
    await db.batch([
      {
        sql: "UPDATE connections SET control_state='active' WHERE connection_id='c'",
      },
    ]);
    const unit = await first.unit("selection", "d", 0);
    if (unit.state !== "staging") throw new Error("expected staging");
    await expect(
      unit.stage("publication", {
        stream: "s",
        watermark: 30,
        complete: true,
        published: false,
        completesAfterPublish: true,
        from: null,
        to: null,
      } as never),
    ).rejects.toThrow("early_completion");
    await unit.stage("publication", {
      stream: "s",
      watermark: 30,
      complete: false,
      completesAfterPublish: false,
      published: false,
      from: null,
      to: null,
    });
    await unit.commit();
    await lease.release();
    const pagesWs = await openLogWorkspace(db, {
      ...binding,
      operation: "pages",
    });
    await pagesWs.freezeChanges("s", 0, 31);
    const pageLease = await pagesWs.acquire(2 * 1024 * 1024);
    const pages = pagesWs.changeRecordPages("s", 1);
    try {
      const empty = await pages.next(pageLease);
      expect(empty!.value.recordCount).toBe(7);
      expect(
        [...empty!.value.records()].every((row) => row.record === null),
      ).toBe(true);
      await expect(pages.next(pageLease)).rejects.toThrow("owned");
      await empty!.release();
      const single = await pages.next(pageLease);
      expect(single!.value.recordCount).toBe(1);
      expect(single!.value.records().next().value!.record!.body).toBe(
        JSON.stringify({ id: "雪" }),
      );
      expect(single!.encodedBytes).toBeGreaterThan(1);
      await single!.release();
      expect(await pages.next(pageLease)).toBeNull();
    } finally {
      await pages.close();
      await pageLease.release();
    }
    await pagesWs.cleanupReplacement();
    await ws.cleanupReplacement();
    expect(
      await db.query("SELECT key FROM workspace_cells WHERE operation='op'"),
    ).toEqual([]);
    await expect(
      openLogWorkspace(db, { ...binding, operation: "invalid", generation: 2 }),
    ).rejects.toThrow("control_creation_binding");
  } finally {
    await lease.release();
  }
});

it("pages seven latest change identities across thirty thousand historical versions", async () => {
  const dir = await mkdtemp(join(process.cwd(), ".changes-history-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(dir, "db"));
  cleanup.push(() => db.close());
  await db.query("PRAGMA journal_mode=WAL");
  await db.query("PRAGMA synchronous=NORMAL");
  await migrate(db);
  let maxStatements = 0;
  const batch = db.batch.bind(db);
  db.batch = (ss) => {
    maxStatements = Math.max(maxStatements, ss.length);
    return batch(ss);
  };
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
    {
      sql: `WITH RECURSIVE versions(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM versions WHERE n<30000)
      INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin)
      SELECT 'c','s',CAST(n%7 AS TEXT),CAST(n%7 AS TEXT),'upsert',n,'r','local' FROM versions`,
    },
  ]);
  const ws = await openLogWorkspace(db, {
    owner: "o",
    databaseIncarnation: "db",
    connection: "c",
    generation: 1,
    keyCheck: "k",
    expectedHead: "h",
    operation: "history",
    codecVersion: 1,
  });
  await ws.freezeChanges("s", 0, 30000);
  const lease = await ws.acquire(2 * 1024 * 1024),
    cursor = ws.changeCursor();
  try {
    const seen = [];
    for (
      let unit = await cursor.next(lease);
      unit;
      unit = await cursor.next(lease)
    ) {
      expect(unit.encodedBytes).toBeLessThan(256);
      seen.push(unit.value);
      await unit.release();
    }
    expect(seen).toEqual(
      Array.from({ length: 7 }, (_, i) => ({
        pk: String((29994 + i) % 7),
        seq: 29994 + i,
        recordBytes: 0,
      })),
    );
    expect(maxStatements).toBeLessThanOrEqual(20);
  } finally {
    await cursor.close();
    await lease.release();
  }
}, 60000);
