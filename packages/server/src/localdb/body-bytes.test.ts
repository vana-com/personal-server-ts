// The stored size of a row (`records.body_bytes`), which the log's snapshot
// pages read to cut pages without reading bodies, and the driver's frozen read
// view (`SqlDriver.snapshot`). A file database and the real driver.
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  MemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"11".repeat(20)}` as const;
const dirs: string[] = [];
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

async function world() {
  const dir = mkdtempSync(join(process.cwd(), ".localdb-snapshot-"));
  dirs.push(dir);
  const db = openBetterSqlite3(join(dir, "db.sqlite"));
  drivers.push(db);
  await openLocalDb(db, { owner, network: "test", deviceId: "d" });
  let op = 0;
  let clock = 1000;
  const deps: LocalSyncDeps = {
    db,
    registry: new MemoryStreamSyncRegistry(),
    blobs: createMemoryStreamSyncBlobs(),
    queue: connectionQueue(),
    ownerAddress: owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => ++clock,
    newOp: () => `op-${++op}`,
  };
  const sync = createLocalSync(deps, {
    resolveArtifact: () => ({
      connector: "fixture",
      version: "1",
      streams: [
        { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
      ],
    }),
    declaredStreams: () => ["items"],
    olderVersionReads: () => true,
  });
  const request = {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
  };
  const load = async (runId: string, ids: string[], tag = "", pad = 300) => {
    await sync.intake.begin(runId, request);
    await sync.intake.batch(runId, {
      batch: 0,
      records: ids.map((id) => ({
        stream: "items",
        data: { id, text: `${id}:${tag}`.padEnd(pad, "x") },
      })),
    });
    await sync.intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: ["items"],
      lastBatch: 0,
    });
  };
  return { sync, db, load };
}
const ids = (n: number) => Array.from({ length: n }, (_, i) => `row-${i}`);

it("holds the WAL while a view is open, lets writes commit, and frees it on release", async () => {
  const dir = mkdtempSync(join(process.cwd(), ".localdb-snapshot-"));
  dirs.push(dir);
  const path = join(dir, "wal.sqlite");
  const db = openBetterSqlite3(path);
  drivers.push(db);
  await db.query("PRAGMA journal_mode = WAL", []);
  await db.batch([{ sql: "CREATE TABLE t (k INTEGER PRIMARY KEY, v BLOB)" }]);
  const write = (from: number) =>
    db.batch(
      Array.from({ length: 100 }, (_, j) => ({
        sql: "INSERT INTO t VALUES (?, randomblob(10000))",
        params: [from + j],
      })),
    );
  await write(0);
  const view = await db.snapshot!();
  for (let i = 1; i <= 10; i++) await write(i * 1000); // 10 MB while open
  expect(await view.query("SELECT COUNT(*) AS n FROM t", [])).toEqual([
    { n: 100 },
  ]);
  await db.query("PRAGMA wal_checkpoint(PASSIVE)", []);
  expect(statSync(`${path}-wal`).size).toBeGreaterThan(10_000_000);
  await view.release();
  await db.query("PRAGMA wal_checkpoint(TRUNCATE)", []);
  expect(statSync(`${path}-wal`).size).toBe(0);
});

const sizes = (w: Awaited<ReturnType<typeof world>>) =>
  w.db.query<{ k: string; stored: number | null; real: number }>(
    `SELECT record_key AS k, body_bytes AS stored,
            LENGTH(CAST(body AS BLOB)) AS real FROM records ORDER BY record_key`,
    [],
  );

it("records the stored size on insert, on a body change and on a restamp", async () => {
  const w = await world();
  // "é" is two bytes, so a length in characters would be wrong.
  const multibyte = "é".repeat(150);
  await w.sync.intake.begin("r1", {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
  });
  await w.sync.intake.batch("r1", {
    batch: 0,
    records: [
      { stream: "items", data: { id: "a", text: multibyte } },
      { stream: "items", data: { id: "b", text: "plain" } },
    ],
  });
  await w.sync.intake.end("r1", {
    outcome: "succeeded",
    coveredStreams: ["items"],
    lastBatch: 0,
  });
  const inserted = await sizes(w);
  expect(inserted.map((r) => r.k)).toEqual(["a", "b"]);
  for (const row of inserted) expect(row.stored).toBe(row.real);
  const [first] = inserted;
  const chars = (
    await w.db.query<{ n: number }>(
      "SELECT LENGTH(body) AS n FROM records WHERE record_key = 'a'",
      [],
    )
  )[0]!.n;
  expect(first!.stored).toBeGreaterThan(chars);

  await w.load("r2", ["a"], "longer", 900); // a changed body
  await w.load("r3", ["a"], "longer", 900); // the same body, newer stamp
  for (const row of await sizes(w)) expect(row.stored).toBe(row.real);
  expect((await sizes(w))[0]!.real).toBeGreaterThan(900);
});

it("logs no change when only the stored size is written", async () => {
  const w = await world();
  await w.load("r1", ids(40));
  const changes = () =>
    w.db.query<{ n: number }>("SELECT COUNT(*) AS n FROM record_changes", []);
  const before = (await changes())[0]!.n;
  expect(before).toBeGreaterThan(0);
  await w.db.query("UPDATE records SET body_bytes = NULL", []);
  await w.db.query(
    "UPDATE records SET body_bytes = LENGTH(CAST(body AS BLOB)) WHERE body_bytes IS NULL",
    [],
  );
  expect((await changes())[0]!.n).toBe(before);
  for (const row of await sizes(w)) expect(row.stored).toBe(row.real);
});
