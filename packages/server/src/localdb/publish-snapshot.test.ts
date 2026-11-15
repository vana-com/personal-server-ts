// A publish on a host with a frozen read view (`SqlDriver.snapshot`) reads
// `records` in the view and copies nothing. These tests use a file database
// and the real driver. The same publish with the view hidden (the spool path)
// is the oracle.
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
  type SqlSnapshot,
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

type Hooks = {
  onPut?: (key: string) => Promise<void>;
  /** Runs before the transfer's first page read of `records` (view or live). */
  onFirstPage?: () => Promise<void>;
};
const PAGE = /SELECT pk_hash, stamp_o/;

async function world(options: { view: boolean; journal?: string } & Hooks) {
  const dir = mkdtempSync(join(process.cwd(), ".localdb-snapshot-"));
  dirs.push(dir);
  const inner = openBetterSqlite3(join(dir, "db.sqlite"));
  const counts = { opened: 0, released: 0 };
  let paged = false;
  const beforePage = async (sql: string) => {
    if (paged || !PAGE.test(sql)) return;
    paged = true;
    await options.onFirstPage?.();
  };
  const db: SqlDriver = {
    ...inner,
    reads: {
      query: async (sql, params) => {
        await beforePage(sql);
        return inner.reads!.query(sql, params);
      },
    },
    query: (sql, params) => inner.query(sql, params),
    batch: (statements) => inner.batch(statements),
    close: () => inner.close(),
  };
  if (options.view) {
    db.snapshot = async (): Promise<SqlSnapshot> => {
      const view = await inner.snapshot!();
      counts.opened += 1;
      return {
        query: async (sql, params) => {
          await beforePage(sql);
          return view.query(sql, params);
        },
        release: async () => {
          counts.released += 1;
          await view.release();
        },
      };
    };
  } else delete db.snapshot;
  drivers.push(db);
  await openLocalDb(db, { owner, network: "test", deviceId: "d" });
  // A host on another journal mode: the driver still offers a view, and refuses it.
  if (options.journal)
    await inner.query(`PRAGMA journal_mode = ${options.journal}`, []);
  const memory = createMemoryStreamSyncBlobs();
  const puts = new Map<string, Uint8Array>();
  const blobs = {
    ...memory,
    governor: memory.governor,
    put: async (key: string, bytes: Uint8Array) => {
      await options.onPut?.(key);
      puts.set(key, bytes.slice());
      await memory.put(key, bytes);
    },
    get: (key: string) => memory.get(key),
    exists: (key: string) => memory.exists(key),
  };
  let op = 0;
  let clock = 1000;
  const deps: LocalSyncDeps = {
    db,
    registry: new MemoryStreamSyncRegistry(),
    blobs,
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
    partTargetBytes: 4096, // many prefixes and parts
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
  const rows = (ids: string[]) =>
    ids.map((id) => ({
      stream: "items",
      data: { id, text: `${id}:`.padEnd(300, "x") },
    }));
  const end = {
    outcome: "succeeded" as const,
    coveredStreams: ["items"],
    lastBatch: 0,
  };
  const load = async (runId: string, ids: string[], finish = true) => {
    await sync.intake.begin(runId, request);
    await sync.intake.batch(runId, { batch: 0, records: rows(ids) });
    if (finish) await sync.intake.end(runId, end);
  };
  const text = () =>
    [...puts.values()].map((b) => Buffer.from(b).toString("latin1")).join("\n");
  return {
    sync,
    load,
    finish: (runId: string) => sync.intake.end(runId, end),
    counts,
    puts,
    text,
  };
}

const ids = (n: number) => Array.from({ length: n }, (_, i) => `row-${i}`);

it("stores the same blobs as the same publish through the spool", async () => {
  const view = await world({ view: true });
  const spool = await world({ view: false });
  await view.load("r1", ids(600));
  await spool.load("r1", ids(600));
  await view.sync.cycle();
  await spool.sync.cycle();
  expect(view.counts.opened).toBeGreaterThan(0);
  expect(view.counts.released).toBe(view.counts.opened);
  expect(spool.counts.opened).toBe(0);
  expect(view.puts.size).toBeGreaterThan(3);
  expect([...view.puts.keys()].sort()).toEqual([...spool.puts.keys()].sort());
  for (const [key, bytes] of view.puts)
    expect(Buffer.from(spool.puts.get(key)!)).toEqual(Buffer.from(bytes));
});

it("leaves a run that ends during the transfer out of this version", async () => {
  let release!: () => void;
  const parked = new Promise<void>((resolve) => (release = resolve));
  let reached!: () => void;
  const atFirstRead = new Promise<void>((resolve) => (reached = resolve));
  const w = await world({
    view: true,
    onFirstPage: async () => {
      reached();
      await parked;
    },
  });
  await w.load("r1", ids(600));
  await w.load("late", ["late-marker-row"], false);
  const publishing = w.sync.cycle();
  await atFirstRead; // the view is open, nothing is read yet, the slot is free
  expect(w.counts.opened).toBeGreaterThan(0);
  await w.finish("late");
  release();
  await publishing;
  expect(w.text()).toContain("row-1:");
  expect(w.text()).not.toContain("late-marker-row");
  await w.sync.cycle(); // it stayed pending: the next publish carries it
  expect(w.text()).toContain("late-marker-row");
  expect(w.counts.released).toBe(w.counts.opened);
});

it("releases every view when a PUT fails", async () => {
  const w = await world({
    view: true,
    onPut: async () => {
      throw new Error("storage refused");
    },
  });
  await w.load("r1", ids(200));
  await w.sync.cycle().catch(() => undefined);
  expect(w.counts.opened).toBeGreaterThan(0);
  expect(w.counts.released).toBe(w.counts.opened);
});

it("opens no view when nothing is pending", async () => {
  const w = await world({ view: true });
  await w.load("r1", ids(50));
  await w.sync.cycle();
  const before = w.counts.opened;
  await w.sync.cycle();
  expect(w.counts.opened).toBe(before);
});

it("keeps the copy when the database is not WAL", async () => {
  const w = await world({ view: true, journal: "DELETE" });
  await w.load("r1", ids(200));
  const first = await w.sync.cycle();
  expect(first.connections[0]?.published[0]?.outcome).toBe("published");
  expect(w.counts.opened).toBe(0);
  expect(w.puts.size).toBeGreaterThan(1);
});

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
