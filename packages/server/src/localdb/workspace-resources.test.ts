import { awaitWorkspaceMemoryAdmission } from "./workspace-memory-admission.test-utils.js";
import { expect, it } from "vitest";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  workspaceResourceBudget,
  runtimeAdmission,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openWorkspace } from "../../../core/dist/localdb/workspace.js";

it("configures file SQLite caches and bounds every workspace metadata reply by the charged ledger", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workspace-budget-")),
    db = openBetterSqlite3(join(dir, "db"), { workspaceCacheKiB: 512 });
  try {
    await db.query("PRAGMA journal_mode=WAL");
    await db.query("PRAGMA synchronous=NORMAL");
    await migrate(db);
    await db.batch([
      {
        sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','t','d',0)",
      },
      {
        sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','t','','active')",
      },
    ]);
    const budget = workspaceResourceBudget({
      cacheKiB: 512,
      frameBytes: 65536,
      connections: 2,
    });
    expect((await db.query("PRAGMA cache_size"))[0]).toEqual({
      cache_size: -512,
    });
    expect((await db.query("PRAGMA mmap_size"))[0]).toEqual({ mmap_size: 0 });
    expect((await db.query("PRAGMA temp_store"))[0]).toEqual({ temp_store: 1 });
    await db.query("PRAGMA journal_mode=WAL");
    expect((await db.reads!.query("PRAGMA cache_size"))[0]).toEqual({
      cache_size: -512,
    });
    const ws = await openWorkspace(db, {
      owner: "o",
      databaseIncarnation: "db",
      connection: "c",
      generation: 1,
      keyCheck: "k",
      operation: "op",
      expectedHead: "h",
      codecVersion: 1,
    });
    await db.batch([
      {
        sql: "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO workspace_cells SELECT 'op','membership',printf('%06d',x),printf('%01000d',x) FROM n",
      },
    ]);
    for (const plan of [
      {
        sql: "EXPLAIN QUERY PLAN SELECT id,unit,action FROM workspace_attempts WHERE operation=? AND id>? ORDER BY id LIMIT 1",
        params: ["op", 0],
      },
      {
        sql: "EXPLAIN QUERY PLAN SELECT substr(body,1,100) FROM body_value_chunks WHERE value_id=? AND offset<=? ORDER BY offset DESC LIMIT 1",
        params: ["v", 0],
      },
      {
        sql: "EXPLAIN QUERY PLAN INSERT OR REPLACE INTO workspace_cells SELECT operation,relation,key,payload FROM workspace_stage WHERE operation=? AND unit=?",
        params: ["op", "u"],
      },
    ]) {
      const rows = await db.query<{ detail: string }>(plan.sql, plan.params);
      expect(rows.some((row) => row.detail.includes("TEMP B-TREE"))).toBe(
        false,
      );
      expect(rows.some((row) => row.detail.includes("SEARCH"))).toBe(true);
    }
    const cursor = ws.cursor("membership"),
      lease = await runtimeAdmission.acquire("op", budget.metadataBuffers);
    try {
      let count = 0;
      for (;;) {
        const row = await cursor.next(lease);
        if (!row) break;
        expect(row.encodedBytes * 6).toBeLessThanOrEqual(
          budget.metadataBuffers,
        );
        await row.release();
        count++;
      }
      expect(count).toBe(1000);
    } finally {
      await cursor.close();
      await lease.release();
    }
    expect(budget.chargedBytes).toBe(
      2 * 512 * 1024 +
        budget.metadataBuffers +
        budget.statementFrames +
        budget.workerGarbageBuffers +
        budget.statementTextBuffers,
    );
    expect(budget.sqliteNativeOverhead).toBe("unmeasured");
  } finally {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});

it.skipIf(process.env.STREAM_SYNC_WORKSPACE_MEMORY !== "1")(
  "Node file SQLite RSS stays inside the declared charged budget plus fixed allocator allowance",
  async () => {
    const admission = await awaitWorkspaceMemoryAdmission(
      async () => {
        const mem = await readFile("/proc/meminfo", "utf8"),
          pressure = await readFile("/proc/pressure/memory", "utf8");
        return {
          availableGiB:
            Number(/MemAvailable:\s+(\d+)/.exec(mem)![1]) / 1024 / 1024,
          fullAvg60: Number(/^full .*?avg60=([\d.]+)/m.exec(pressure)![1]),
        };
      },
      () => new Promise((resolve) => setTimeout(resolve, 60000)),
    );
    expect(admission.availableGiB).toBeGreaterThanOrEqual(16);
    expect(admission.fullAvg60).toBeLessThan(1);
    const dir = await mkdtemp(join(tmpdir(), "workspace-rss-"));
    const baseline = process.memoryUsage().rss,
      budget = workspaceResourceBudget({
        cacheKiB: 512,
        frameBytes: 65536,
        connections: 1,
      });
    const db = openBetterSqlite3(join(dir, "db"), { workspaceCacheKiB: 512 });
    let peak = process.memoryUsage().rss;
    const sample = setInterval(() => {
      peak = Math.max(peak, process.memoryUsage().rss);
    }, 10);
    try {
      await db.query("PRAGMA journal_mode=WAL");
      await db.query("PRAGMA synchronous=NORMAL");
      await migrate(db);
      await db.batch([
        {
          sql: "CREATE TABLE resource_probe(id INTEGER PRIMARY KEY, body BLOB)",
        },
        {
          sql: "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<1024) INSERT INTO resource_probe SELECT x,zeroblob(16384) FROM n",
        },
      ]);
      for (let id = 1; id <= 1024; id++) {
        const row = (
          await db.query<{ body: Uint8Array }>(
            "SELECT body FROM resource_probe WHERE id=?",
            [id],
          )
        )[0]!;
        expect(row.body.length).toBe(16384);
        peak = Math.max(peak, process.memoryUsage().rss);
      }
      // Predeclared headroom for a Node worker/V8/SQLite allocator, not fitted to this run.
      expect(peak - baseline).toBeLessThanOrEqual(
        budget.chargedBytes + 64 * 1024 * 1024,
      );
      console.info(
        JSON.stringify({
          admission,
          baseline,
          peak,
          chargedBytes: budget.chargedBytes,
          fixedAllocatorAllowance: 64 * 1024 * 1024,
        }),
      );
    } finally {
      clearInterval(sample);
      await db.close();
      await rm(dir, { recursive: true, force: true });
    }
  },
  300000,
);

it("RSS admission waits through startup pressure and low availability before measuring", async () => {
  const samples = [
    { availableGiB: 36, fullAvg60: 1.76 },
    { availableGiB: 15, fullAvg60: 0.2 },
    { availableGiB: 36, fullAvg60: 0.2 },
  ];
  let waits = 0,
    reads = 0;
  const admission = await awaitWorkspaceMemoryAdmission(
    async () => samples[reads++]!,
    async () => {
      waits++;
    },
  );
  expect(admission).toEqual(samples[2]);
  expect(reads).toBe(3);
  expect(waits).toBe(2);
});
it("RSS admission refuses exhausted gates without starting a measurement", async () => {
  let waits = 0;
  await expect(
    awaitWorkspaceMemoryAdmission(
      async () => ({ availableGiB: 36, fullAvg60: 1 }),
      async () => {
        waits++;
      },
    ),
  ).rejects.toThrow("no measurement started");
  expect(waits).toBe(3);
});
