// A publish on a host with a frozen read view (`SqlDriver.snapshot`) reads
// `records` in the view and copies nothing. These tests use a file database
// and the real driver. The same publish with the view hidden (the spool path)
// is the oracle. The last group is the stored row size, `records.body_bytes`,
// which the view's page cuts read.
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
import { endRequest } from "../../../core/src/test-utils/run-end.js";
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

async function world(
  options: {
    view: boolean;
    journal?: string;
    partTargetBytes?: number;
  } & Hooks,
) {
  const dir = mkdtempSync(join(process.cwd(), ".localdb-snapshot-"));
  dirs.push(dir);
  const inner = openBetterSqlite3(join(dir, "db.sqlite"));
  const counts = { opened: 0, released: 0, metadataRows: [] as number[] };
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
        query: async <T>(
          sql: string,
          params?: Parameters<SqlSnapshot["query"]>[1],
        ) => {
          await beforePage(sql);
          const rows = await view.query<T>(sql, params);
          if (/SELECT pk_hash, body_bytes FROM records/.test(sql))
            counts.metadataRows.push(rows.length);
          return rows;
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
    partTargetBytes: options.partTargetBytes ?? 4096, // many prefixes and parts
  };
  const sync = createLocalSync(deps, {
    resolveArtifact: () => ({
      connector: "fixture",
      version: "1",
      streams: [
        { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
      ],
    }),
    olderVersionReads: () => true,
  });
  const request = {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
  };
  const rows = (ids: string[], tag = "", pad = 300) =>
    ids.map((id) => ({
      stream: "items",
      data: { id, text: `${id}:${tag}`.padEnd(pad, "x") },
    }));
  const end = endRequest({ lastBatch: 0, live: ["items"] });
  const load = async (
    runId: string,
    ids: string[],
    finish = true,
    tag = "",
    pad = 300,
  ) => {
    await sync.intake.begin(runId, request);
    await sync.intake.batch(runId, {
      batch: 0,
      records: rows(ids, tag, pad),
    });
    if (finish) await sync.intake.end(runId, end);
  };
  /** A run that deletes `keys` explicitly; it commits when finished. */
  const loadDeletes = async (runId: string, keys: string[], finish = true) => {
    await sync.intake.begin(runId, request);
    await sync.intake.batch(runId, {
      batch: 0,
      records: keys.map((key) => ({
        stream: "items",
        op: "delete" as const,
        key,
        data: { id: key },
      })),
    });
    if (finish) await sync.intake.end(runId, end);
  };
  const text = (from = new Set<string>()) =>
    [...puts]
      .filter(([key]) => !from.has(key))
      .map(([, b]) => Buffer.from(b).toString("latin1"))
      .join("\n");
  return {
    sync,
    db: inner,
    load,
    loadDeletes,
    finish: (runId: string) => sync.intake.end(runId, end),
    counts,
    puts,
    text,
    /** The blobs stored so far, for `text` to leave out later. */
    stored: () => new Set(puts.keys()),
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

/** Park the transfer at its first read of `records`, with the view open. */
async function parkedWorld() {
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
  return { w, release, atFirstRead };
}

it("keeps the version's row when a run updates it after the view opens", async () => {
  const { w, release, atFirstRead } = await parkedWorld();
  await w.load("r1", ids(600));
  await w.load("late", ["row-3"], false, "UPDATED", 2000);
  const publishing = w.sync.cycle();
  await atFirstRead;
  await w.finish("late"); // a longer body, committed while the view is open
  release();
  await publishing;
  expect(w.text()).toContain("row-3:");
  expect(w.text()).not.toContain("UPDATED");
  const first = w.stored();
  await w.sync.cycle();
  expect(w.text(first)).toContain("row-3:UPDATED");
  expect(w.counts.released).toBe(w.counts.opened);
});

it("rebuilds the version when a run deletes a row after the view opens", async () => {
  const { w, release, atFirstRead } = await parkedWorld();
  await w.load("r1", ids(600));
  await w.loadDeletes("late", ["row-3"], false);
  const publishing = w.sync.cycle();
  await atFirstRead;
  await w.finish("late"); // a removal above the snapshot's watermark
  release();
  const [first] = (await publishing).connections[0]!.published;
  // The view held the row, so the publish read a second view and re-planned.
  expect(first).toMatchObject({ outcome: "published", watermark: 601 });
  expect(w.counts.opened).toBe(2);
  expect(w.counts.released).toBe(2);
  // Only the part the first view built holds the row; the rebuilt one does not.
  const holding = [...w.puts.values()].filter((bytes) =>
    Buffer.from(bytes).toString("latin1").includes("row-3:"),
  );
  expect(holding).toHaveLength(1);
  expect(w.text()).toContain("row-4:");
  expect((await w.sync.cycle()).connections[0]?.published[0]?.outcome).toBe(
    "noop",
  );
});

const sizes = (w: Awaited<ReturnType<typeof world>>) =>
  w.db.query<{ k: string; stored: number | null; real: number }>(
    `SELECT record_key AS k, body_bytes AS stored,
            LENGTH(CAST(body AS BLOB)) AS real FROM records ORDER BY record_key`,
    [],
  );

it("records the stored size on insert, on a body change and on a restamp", async () => {
  const w = await world({ view: true });
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
  await w.sync.intake.end("r1", endRequest({ lastBatch: 0, live: ["items"] }));
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

  await w.load("r2", ["a"], true, "longer", 900); // a changed body
  await w.load("r3", ["a"], true, "longer", 900); // the same body, newer stamp
  for (const row of await sizes(w)) expect(row.stored).toBe(row.real);
  expect((await sizes(w))[0]!.real).toBeGreaterThan(900);
});

it("logs no change when only the stored size is written", async () => {
  const w = await world({ view: true });
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

it("publishes the same blobs for rows with no stored size", async () => {
  const sized = await world({ view: true });
  const old = await world({ view: true });
  await sized.load("r1", ids(600));
  await old.load("r1", ids(600));
  // Rows from before the column: NULL, measured from the body when read.
  await old.db.query("UPDATE records SET body_bytes = NULL", []);
  await sized.sync.cycle();
  await old.sync.cycle();
  expect(old.counts.opened).toBeGreaterThan(0);
  expect(sized.puts.size).toBeGreaterThan(3);
  expect([...old.puts.keys()].sort()).toEqual([...sized.puts.keys()].sort());
  for (const [key, bytes] of sized.puts)
    expect(Buffer.from(old.puts.get(key)!)).toEqual(Buffer.from(bytes));
});

for (const mode of ["null", "mixed"] as const) {
  it(`publishes byte-identical UTF-8 blobs across metadata windows and a large frame with ${mode} sizes`, async () => {
    // One planned bucket makes 2051 keys cross the 2048-key metadata window.
    const sized = await world({ view: true, partTargetBytes: 8 * 1024 * 1024 });
    const fallback = await world({
      view: true,
      partTargetBytes: 8 * 1024 * 1024,
    });
    const records = [
      ...ids(2050).map((id) => ({
        stream: "items",
        data: { id, text: "é".repeat(32) },
      })),
      { stream: "items", data: { id: "large", text: "é".repeat(1200000) } },
    ];
    const largeBody = JSON.stringify(records[records.length - 1]!.data);
    expect(largeBody.length).toBeLessThan(2 * 1024 * 1024);
    expect(new TextEncoder().encode(largeBody).length).toBeGreaterThan(
      2 * 1024 * 1024,
    );
    for (const w of [sized, fallback]) {
      await w.sync.intake.begin("utf8", {
        connector: "fixture",
        artifactDigest: "fixture",
        owner: { address: owner, leaseId: null },
      });
      await w.sync.intake.batch("utf8", { batch: 0, records });
      await w.sync.intake.end(
        "utf8",
        endRequest({ lastBatch: 0, live: ["items"] }),
      );
      expect(await sizes(w)).toHaveLength(2051);
    }
    await fallback.db.query(
      mode === "null"
        ? "UPDATE records SET body_bytes = NULL"
        : "UPDATE records SET body_bytes = NULL WHERE record_key = 'large' OR CAST(SUBSTR(record_key, 5) AS INTEGER) % 2 = 0",
      [],
    );
    const metadata = await sizes(fallback);
    expect(metadata.some(({ stored }) => stored === null)).toBe(true);
    expect(metadata.some(({ stored }) => stored !== null)).toBe(
      mode === "mixed",
    );
    await sized.sync.cycle();
    await fallback.sync.cycle();
    expect(sized.counts.metadataRows).toEqual([2048, 3]);
    expect(fallback.counts.metadataRows).toEqual([2048, 3]);
    expect(sized.puts.size).toBeGreaterThan(0);
    expect([...fallback.puts.keys()].sort()).toEqual(
      [...sized.puts.keys()].sort(),
    );
    for (const [key, bytes] of sized.puts)
      expect(Buffer.from(fallback.puts.get(key)!)).toEqual(Buffer.from(bytes));
    expect(fallback.counts.released).toBe(fallback.counts.opened);
    expect(sized.counts.released).toBe(sized.counts.opened);
  });
}
