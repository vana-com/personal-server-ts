import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
  createImportLedger,
  createLocalSeed,
  createLocalSync,
  createSeedIntake,
  importLegacySource,
  openLocalDb,
  connectionQueue,
  syncBeforeBegin,
  type ImportSource,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { createSeedStaging } from "../../../core/src/stream-sync/seed-staging.js";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

// A stream's one-time seed window closes at its first real write. These tests
// drive real runs, publication and compaction, then seed from another install.

const drivers: SqlDriver[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
const owner = `0x${"11".repeat(20)}` as const;
const connectionId = "pdpp.fixture~";

function newDeps(
  db: SqlDriver,
  registry: ReturnType<typeof createMemoryStreamSyncRegistry>,
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>,
  id: string,
  clock: { now: number },
): LocalSyncDeps {
  let op = 0;
  return {
    db,
    queue: connectionQueue(),
    registry,
    blobs,
    ownerAddress: owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => clock.now,
    newOp: () => `${id}-${++op}`,
  };
}

async function openDevice(
  registry: ReturnType<typeof createMemoryStreamSyncRegistry>,
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>,
  deviceId: string,
  clock: { now: number },
  path = ":memory:",
  streams = ["items"],
) {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner,
    network: "test",
    deviceId,
  });
  drivers.push(db);
  const deps = newDeps(db, registry, blobs, deviceId, clock);
  const sync = createLocalSync(deps, {
    resolveArtifact: () => ({
      connector: "fixture",
      version: "1",
      streams: streams.map((name) => ({
        name,
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
        coverageStrategy: "full_inventory" as const,
      })),
    }),
    declaredStreams: () => streams,
    olderVersionReads: () => true,
  });
  const keys = async (stream = "items") =>
    (await sync.query.listRecords({ connectionId, stream, limit: 100 })).records
      .map((r) => r.recordKey)
      .sort();
  return {
    db,
    deps,
    sync,
    keys,
    /** A real run: a proven full refresh, or explicit deletes of `rows`. */
    async run(
      id: string,
      rows: string[],
      options: { remove?: boolean; stream?: string; observedAt?: number } = {},
    ) {
      clock.now++;
      const stream = options.stream ?? "items";
      await sync.intake.begin(id, {
        connector: "fixture",
        artifactDigest: "fixture",
        streams: [{ name: stream }],
        wantFull: !options.remove,
        observedAt: options.observedAt,
        owner: { address: owner, leaseId: null },
      });
      await sync.intake.batch(id, {
        batch: 0,
        records: rows.map((key) => ({
          stream,
          ...(options.remove ? { op: "delete" as const } : {}),
          data: { id: key },
        })),
      });
      await sync.intake.end(id, {
        outcome: "succeeded",
        coveredStreams: [stream],
        lastBatch: 0,
        ...(options.remove ? {} : { provenFullStreams: [stream] }),
      });
    },
    async publish() {
      expect(
        (await sync.cycle()).connections.every((c) => c.error === null),
      ).toBe(true);
    },
    /** Seed `rows` the way a host's staged upload from one install would. */
    async seed(
      install: string,
      rows: string[],
      stream = "items",
    ): Promise<ReturnType<typeof importLegacySource>> {
      await syncBeforeBegin(deps, "fixture");
      const source: ImportSource = {
        source: JSON.stringify([install, "fixture"]),
        owner,
        network: "test",
        revision: `${install}-upload`,
        target: {
          connectionId,
          connector: "fixture",
          stream,
          primaryKey: ["id"],
          semantics: "mutable_state",
          incremental: true,
        },
        exclusions: [],
        async *records() {
          for (const id of rows) yield { id };
        },
      };
      return importLegacySource(deps, createImportLedger(db), source);
    },
    async snapshot(stream = "items") {
      return db.query(
        "SELECT record_key, stamp_o, stamp_r, first_o, body FROM records WHERE stream = ? ORDER BY record_key",
        [stream],
      );
    },
  };
}
async function world() {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  const clock = { now: 1000 };
  return {
    registry,
    blobs,
    clock,
    device: (id: string, path?: string, streams?: string[]) =>
      openDevice(registry, blobs, id, clock, path, streams),
  };
}

const refused = { kind: "refused", reason: "seed_window_closed" } as const;

it("a full refresh that omitted a seeded record keeps a later install's seed from bringing it back", async () => {
  const w = await world();
  const a = await w.device("a");
  expect((await a.seed("install-1", ["A", "B"])).kind).toBe("imported");
  await a.run("refresh", ["B"]);
  await a.publish();
  expect(await a.keys()).toEqual(["B"]);
  expect(await a.seed("install-2", ["A"])).toEqual(refused);
  expect(await a.keys()).toEqual(["B"]);
  // A real write still wins afterwards, and brings A back as real data.
  await a.run("later", ["A", "B"]);
  await a.publish();
  expect(await a.keys()).toEqual(["A", "B"]);
  expect(
    await a.db.query(
      "SELECT stamp_r FROM records WHERE record_key = 'A' AND stream = 'items'",
    ),
  ).toEqual([{ stamp_r: "later" }]);
});

it("an empty full refresh removes every seeded record for good", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.seed("install-1", ["A", "B"]);
  await a.run("empty", []);
  await a.publish();
  expect(await a.keys()).toEqual([]);
  expect(await a.seed("install-2", ["A", "B"])).toEqual(refused);
  expect(await a.keys()).toEqual([]);
});

it("a publication whose head already matches the registry still closes the window", async () => {
  const w = await world();
  const a = await w.device("a");
  const b = await w.device("b");
  await a.seed("install-1", ["A"]);
  await b.run("refresh", ["B"], { observedAt: 5000 });
  await b.publish();
  await a.run("refresh", ["B"], { observedAt: 5000 });
  const report = await a.sync.cycle();
  expect(report.connections[0]!.published[0]!.outcome).toBe("noop");
  expect(await a.keys()).toEqual(["B"]);
  expect(await a.seed("install-2", ["A"])).toEqual(refused);
  expect(await a.keys()).toEqual(["B"]);
});

it("an explicit delete that was published and compacted keeps a later seed out across a restart", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".seed-window-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await w.device("a", path);
  await first.run("real", ["A", "B"]);
  await first.publish();
  await first.run("delete", ["A"], { remove: true });
  await first.publish();
  await first.publish();
  expect(await first.keys()).toEqual(["B"]);
  // Compaction dropped the tombstone: no explicit-delete event remains.
  expect(
    await first.db.query(
      "SELECT count(*) AS n FROM record_changes WHERE explicit_delete = 1 AND record_key = 'A' AND stream = 'items'",
    ),
  ).toEqual([{ n: 0 }]);
  await first.db.close();
  drivers.splice(drivers.indexOf(first.db), 1);
  const reopened = await w.device("a", path);
  expect(await reopened.seed("install-2", ["A"])).toEqual(refused);
  expect(await reopened.keys()).toEqual(["B"]);
});

it("a seed after a real upsert of the same record changes nothing", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A"]);
  const before = await a.snapshot();
  const changes = await a.db.query("SELECT * FROM record_changes");
  expect(await a.seed("install-1", ["A"])).toEqual(refused);
  expect(await a.snapshot()).toEqual(before);
  expect(await a.db.query("SELECT * FROM record_changes")).toEqual(changes);
});

it("a seed before any real write still imports", async () => {
  const w = await world();
  const a = await w.device("a", ":memory:", ["items", "other"]);
  expect((await a.seed("install-1", ["A", "B"])).kind).toBe("imported");
  expect(await a.keys()).toEqual(["A", "B"]);
  // The first install's own seed does not close its other streams.
  expect((await a.seed("install-1", ["C"], "other")).kind).toBe("imported");
  expect(await a.keys("other")).toEqual(["C"]);
});

it("a real write to one stream leaves a stream that run did not declare open to its seed", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A"]);
  expect(await a.seed("install-1", ["Z"], "items")).toEqual(refused);
  // A run floors every stream its artifact declares, so "other" is outside it.
  expect((await a.seed("install-1", ["X"], "other")).kind).toBe("imported");
  expect(await a.snapshot("other")).toMatchObject([
    { record_key: "X", stamp_o: 0, stamp_r: "seed" },
  ]);
});

it("a published seed-only head closes the window for a later install", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.seed("install-1", ["A"]);
  await a.publish();
  expect(
    await a.db.query(
      "SELECT head_version FROM stream_state WHERE stream = 'items'",
    ),
  ).toEqual([{ head_version: 1 }]);
  expect(await a.seed("install-2", ["B"])).toEqual(refused);
});

it("the transactional guard aborts a batch when the window closes after the early read", async () => {
  const w = await world();
  const a = await w.device("a", ":memory:", ["items", "other"]);
  await a.seed("install-0", ["Z"], "other"); // connection exists, items is open
  const batch = a.db.batch.bind(a.db);
  let closed = false;
  a.db.batch = async (statements) => {
    if (
      !closed &&
      statements.some((s) => s.sql.startsWith("INSERT INTO records"))
    ) {
      closed = true;
      await batch([
        {
          sql: "INSERT OR IGNORE INTO stream_state (connection_id, stream, primary_key, semantics, incremental) VALUES ('pdpp.fixture~', 'items', '[\"id\"]', 'mutable_state', 1)",
        },
        {
          sql: "UPDATE stream_state SET floor_version = '1', floor_o = 2000, floor_r = 'real' WHERE stream = 'items'",
        },
      ]);
    }
    return batch(statements);
  };
  expect(await a.seed("install-1", ["A", "B"])).toEqual(refused);
  expect(await a.snapshot()).toEqual([]);
  expect(
    await a.db.query("SELECT * FROM import_ledger WHERE stream = 'items'"),
  ).toEqual([]);
});

it("a closed window refuses at the final receipt transaction too", async () => {
  const w = await world();
  const a = await w.device("a", ":memory:", ["items", "other"]);
  await a.seed("install-0", ["Z"], "other");
  const batch = a.db.batch.bind(a.db);
  a.db.batch = async (statements) => {
    if (statements.some((s) => s.sql.includes("INTO import_ledger"))) {
      await batch([
        {
          sql: "UPDATE stream_state SET head_version = 1 WHERE stream = 'items'",
        },
      ]);
    }
    return batch(statements);
  };
  const result = await a.seed("install-1", ["A"]);
  expect(result).toEqual(refused);
  expect(
    await a.db.query("SELECT * FROM import_ledger WHERE stream = 'items'"),
  ).toEqual([]);
});

it("replaying a completed import after a real write adds nothing and keeps its receipt", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".seed-window-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await w.device("a", path);
  expect((await first.seed("install-1", ["A", "B"])).kind).toBe("imported");
  await first.run("refresh", ["B"]);
  await first.publish();
  const changes = await first.db.query("SELECT * FROM record_changes");
  const ledger = await first.db.query("SELECT * FROM import_ledger");
  await first.db.close();
  drivers.splice(drivers.indexOf(first.db), 1);
  const reopened = await w.device("a", path);
  const replay = await reopened.seed("install-1", ["A", "B"]);
  expect(replay.kind).toBe("already-imported");
  expect(await reopened.keys()).toEqual(["B"]);
  expect(await reopened.db.query("SELECT * FROM record_changes")).toEqual(
    changes,
  );
  expect(await reopened.db.query("SELECT * FROM import_ledger")).toEqual(
    ledger,
  );
});

const manifest = JSON.stringify({
  connector_key: "fixture",
  version: "1",
  streams: ["items", "other"].map((name) => ({
    name,
    primary_key: ["id"],
    semantics: "mutable_state",
  })),
});
async function* upload(ids: string[]) {
  const lines = [
    JSON.stringify({
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      records: ids.length,
    }),
    ...ids.map((id) => JSON.stringify({ id })),
  ];
  yield new TextEncoder().encode(lines.join("\n") + "\n");
}
function seedHost(
  device: Awaited<ReturnType<typeof openDevice>>,
  root: string,
) {
  const staging = createSeedStaging(createFsStreamSyncFiles(root));
  return createSeedIntake(
    createLocalSeed({
      getDeps: async () => device.deps,
      manifests: () => [manifest],
      staging,
    }),
  );
}

it("a staged seed that arrives after a real write is excluded for good, even across a restart", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".seed-window-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await w.device("a", path);
  await first.run("refresh", ["B"]);
  await first.publish();
  const intake = seedHost(first, join(dir, "staging"));
  await intake.put("fixture", "items", upload(["A", "B"]));
  // The other stream of the connector has no real write; its seed still lands.
  await intake.put("fixture", "other", upload(["X"]));
  expect(await intake.status("fixture")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" }, other: { state: "merged" } },
  });
  const ledger = () =>
    first.db.query(
      "SELECT stream, state, reason, rows FROM import_ledger ORDER BY stream",
    );
  expect(await ledger()).toEqual([
    {
      stream: "items",
      state: "excluded",
      reason: "seed_window_closed",
      rows: 0,
    },
    { stream: "other", state: "imported", reason: null, rows: 1 },
  ]);
  expect(await first.keys()).toEqual(["B"]);
  expect(await first.snapshot("other")).toMatchObject([{ record_key: "X" }]);
  const changes = await first.db.query("SELECT * FROM record_changes");
  const before = await ledger();

  await first.db.close();
  drivers.splice(drivers.indexOf(first.db), 1);
  const reopened = await w.device("a", path);
  const again = seedHost(reopened, join(dir, "staging"));
  // The same upload again: the receipts answer and no body is consumed.
  expect(await again.put("fixture", "items", upload(["A", "B"]))).toEqual({
    state: "merged",
  });
  expect(await again.status("fixture")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" }, other: { state: "merged" } },
  });
  expect(await reopened.keys()).toEqual(["B"]);
  expect(await reopened.db.query("SELECT * FROM record_changes")).toEqual(
    changes,
  );
  expect(
    await reopened.db.query(
      "SELECT stream, state, reason, rows FROM import_ledger ORDER BY stream",
    ),
  ).toEqual(before);
});
