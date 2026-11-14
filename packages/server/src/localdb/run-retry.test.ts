import { afterEach, expect, it, vi } from "vitest";
import {
  createLocalSync,
  connectionQueue,
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
const control = "pdpp.fixture~";
const stream = control + ".items";
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
const request = (extra: Record<string, unknown> = {}) => ({
  connector: "fixture",
  artifactDigest: "fixture",
  owner: { address: owner, leaseId: null },
  ...extra,
});
async function world() {
  const registry = new MemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  let now = 1000;
  const make = async (deviceId: string) => {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner,
      network: "test",
      deviceId,
    });
    drivers.push(db);
    let op = 0;
    const deps: LocalSyncDeps = {
      db,
      registry,
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
      now: () => ++now,
      newOp: () => `${deviceId}-${++op}`,
    };
    const reopen = () =>
      createLocalSync(deps, {
        resolveArtifact: () => ({
          connector: "fixture",
          version: "1",
          streams: [
            {
              name: "items",
              semantics: "mutable_state",
              primaryKey: ["id"],
              coverageStrategy: "checkpoint_window",
            },
          ],
        }),
        declaredStreams: () => ["items"],
        olderVersionReads: () => true,
      });
    return { db, sync: reopen(), reopen };
  };
  const a = await make("a"),
    b = await make("b");
  await a.sync.intake.begin("seed", request());
  await a.sync.intake.batch("seed", {
    batch: 0,
    records: [{ stream: "items", data: { id: "seed" } }],
  });
  await a.sync.intake.end("seed", {
    outcome: "succeeded",
    coveredStreams: ["items"],
    lastBatch: 0,
  });
  await a.sync.cycle();
  await b.sync.apply();
  return { a, b, registry };
}
const endRequest = {
  outcome: "succeeded" as const,
  coveredStreams: ["items"],
  lastBatch: 0,
};

it("refuses a stale retry basis when another device deleted after the caller read", async () => {
  const { a, b, registry } = await world();
  const observed = await registry.read(control);
  if (!observed.found) throw new Error("missing control");
  await b.sync.deleter.requestConnectionDelete("fixture");
  expect(await b.sync.deleter.resumeDeletes()).toEqual([]);
  const posts = registry.log.length;
  await expect(
    a.sync.intake.begin(
      "stale-retry",
      request({ connect: true, expectedControlVersion: observed.version }),
    ),
  ).rejects.toMatchObject({ code: "control_basis_mismatch", status: 409 });
  expect(registry.log).toHaveLength(posts);
  expect(await registry.read(control)).toMatchObject({ version: 2 });
  expect(
    await a.db.query("SELECT run_id FROM runs WHERE run_id='stale-retry'"),
  ).toEqual([]);
});

it("replays the original queued local receipt after publication without a second head", async () => {
  const { a, registry } = await world();
  const begin = request();
  await a.sync.intake.begin("work", begin);
  await a.sync.intake.batch("work", {
    batch: 0,
    records: [{ stream: "items", data: { id: "work" } }],
  });
  const ended = await a.sync.intake.end("work", endRequest);
  expect(ended.result).toBe("queued");
  await a.sync.cycle();
  const published = await registry.read(stream);
  const restarted = a.reopen();
  const replay = await restarted.intake.begin("work", {
    ...begin,
    observedAt: 2000,
  });
  expect(replay).toMatchObject({ status: "ended", receipt: ended });
  expect(await restarted.intake.end("work", endRequest)).toEqual(ended);
  await restarted.cycle();
  expect(await registry.read(stream)).toEqual(published);
  expect(
    await a.db.query(
      "SELECT count(*) AS n FROM record_changes WHERE stamp_r='work' AND origin='local'",
    ),
  ).toEqual([{ n: 0 }]);
});

it("replays a discarded receipt after a fresh facade without reconnecting", async () => {
  const { a, b, registry } = await world();
  const begin = request();
  await a.sync.intake.begin("discarded", begin);
  await a.sync.intake.batch("discarded", {
    batch: 0,
    records: [{ stream: "items", data: { id: "discarded" } }],
  });
  await b.sync.deleter.requestConnectionDelete("fixture");
  await b.sync.deleter.resumeDeletes();
  await a.sync.apply();
  const ended = await a.sync.intake.end("discarded", endRequest);
  expect(ended.result).toBe("discarded");
  const posts = registry.log.length;
  const restarted = a.reopen();
  expect(
    await restarted.intake.begin(
      "discarded",
      request({ connect: true, expectedControlVersion: 1 }),
    ),
  ).toMatchObject({ status: "ended", receipt: ended });
  expect(await restarted.intake.end("discarded", endRequest)).toEqual(ended);
  expect(registry.log).toHaveLength(posts);
  expect(await registry.read(control)).toMatchObject({ version: 2 });
});

it("checks the observed control version in the run insertion transaction", async () => {
  const { a, b, registry } = await world();
  let arrive!: () => void, release!: () => void;
  const arrived = new Promise<void>((r) => {
    arrive = r;
  });
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const batch = a.db.batch.bind(a.db);
  let held = false;
  vi.spyOn(a.db, "batch").mockImplementation(async (statements) => {
    if (
      !held &&
      statements.some(({ sql }) => sql.startsWith("INSERT INTO runs"))
    ) {
      held = true;
      arrive();
      await gate;
    }
    return batch(statements);
  });
  const retry = a.sync.intake.begin(
    "raced",
    request({ connect: true, expectedControlVersion: 1 }),
  );
  await arrived;
  try {
    await b.sync.deleter.requestConnectionDelete("fixture");
    await b.sync.deleter.resumeDeletes();
    await b.sync.intake.begin(
      "new-generation",
      request({ connect: true, expectedControlVersion: 2 }),
    );
    await a.sync.apply();
  } finally {
    release();
  }
  await expect(retry).rejects.toMatchObject({ code: "control_basis_mismatch" });
  expect(
    await a.db.query("SELECT run_id FROM runs WHERE run_id='raced'"),
  ).toEqual([]);
  expect(await registry.read(control)).toMatchObject({ version: 3 });
});

it("an explicit retry basis fails closed when the registry cannot be read", async () => {
  const { a, registry } = await world();
  const posts = registry.log.length;
  registry.beforeRead = async () => {
    throw new Error("offline fixture");
  };
  await expect(
    a.sync.intake.begin(
      "unverifiable",
      request({ connect: true, expectedControlVersion: 1 }),
    ),
  ).rejects.toMatchObject({ code: "control_basis_unavailable", status: 503 });
  expect(registry.log).toHaveLength(posts);
});
it("an offline end remains queued and its local receipt replays without publication", async () => {
  const { a, registry } = await world();
  registry.beforeRead = async () => {
    throw new Error("offline fixture");
  };
  const posts = registry.log.length;
  await a.sync.intake.begin("offline", request());
  await a.sync.intake.batch("offline", {
    batch: 0,
    records: [{ stream: "items", data: { id: "offline" } }],
  });
  const ended = await a.sync.intake.end("offline", endRequest);
  expect(ended.result).toBe("queued");
  const restarted = a.reopen();
  expect(await restarted.intake.begin("offline", request())).toMatchObject({
    status: "ended",
    receipt: ended,
  });
  expect(await restarted.intake.end("offline", endRequest)).toEqual(ended);
  expect(registry.log).toHaveLength(posts);
});
