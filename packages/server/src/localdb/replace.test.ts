import { afterEach, describe, expect, it } from "vitest";
import {
  createLocalSync,
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const connection = "pdpp.fixture-source~";
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function world(seed = true) {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const devices = [];
  for (let device = 0; device < 2; device++) {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner,
      network: "test",
      deviceId: `replace-device-${device}`,
    });
    drivers.push(db);
    let now = 1000,
      op = 0;
    const deps: LocalSyncDeps = {
      db,
      queue: connectionQueue(),
      keys,
      registry,
      blobs,
      ownerAddress: owner,
      signer: { signAddData: async () => "0x00" },
      logger: { info() {}, warn() {} },
      now: () => now,
      newOp: () => `device-${device}-${++op}`,
    };
    const sync = createLocalSync(deps, {
      resolveArtifact: () => ({
        connector: "fixture-source",
        version: "1",
        streams: ["A", "B"].map((name) => ({
          name,
          primaryKey: ["id"],
          coverageStrategy: "full_inventory",
          semantics: "mutable_state",
        })),
      }),
      declaredStreams: () => ["A", "B"],
      olderVersionReads: () => true,
    });
    const collect = async (
      id: string,
      at: number,
      input: {
        rows: Partial<Record<"A" | "B", string[]>>;
        outcome?: "succeeded" | "partial" | "retry_pending";
        covered?: string[];
        proven?: string[];
        full?: boolean;
        publish?: boolean;
      },
    ) => {
      now = at;
      await sync.intake.begin(id, {
        connector: "fixture-source",
        artifactDigest: "fixture",
        owner: { address: owner, leaseId: null },
        wantFull: input.full ?? true,
        observedAt: at,
      });
      const records = Object.entries(input.rows).flatMap(([stream, ids]) =>
        ids!.map((key) => ({ stream, data: { id: key } })),
      );
      if (records.length) await sync.intake.batch(id, { batch: 0, records });
      await sync.intake.end(id, {
        outcome: input.outcome ?? "succeeded",
        coveredStreams: input.covered ?? ["A", "B"],
        provenFullStreams: input.proven ?? ["A", "B"],
        lastBatch: records.length ? 0 : -1,
      });
      if (input.publish !== false) await publish();
    };
    const publish = async () => {
      const report = await sync.cycle();
      expect(report.connections.map((c) => c.error)).toEqual([null]);
    };
    const rows = async (stream: string) =>
      (
        await sync.query.listRecords({
          connectionId: connection,
          stream,
          limit: 100,
        })
      ).records
        .map((r) => r.recordKey)
        .sort();
    devices.push({
      db,
      sync,
      collect,
      publish,
      rows,
      setNow: (value: number) => {
        now = value;
      },
    });
  }
  if (seed)
    await devices[0]!.collect("base", 1000, {
      rows: { A: ["a", "b"], B: ["x", "y"] },
    });
  await devices[1]!.sync.apply();
  return { a: devices[0]!, b: devices[1]!, registry, blobs };
}

describe("r5 H per-stream replacement through real intake/apply/publish", () => {
  it("a partial run replaces proven A while unproven B merges and keeps old rows", async () => {
    const { a, b } = await world();
    await a.collect("partial", 5000, {
      rows: { A: ["a"], B: ["x"] },
      outcome: "partial",
      covered: ["A"],
      proven: ["A"],
    });
    expect(
      await a.db.query(
        "SELECT stream,replace FROM run_streams WHERE run_id='partial' ORDER BY stream",
      ),
    ).toEqual([
      { stream: "A", replace: 1 },
      { stream: "B", replace: 0 },
    ]);
    await b.sync.apply();
    for (const device of [a, b]) {
      expect(await device.rows("A")).toEqual(["a"]);
      expect(await device.rows("B")).toEqual(["x", "y"]);
    }
  });

  it.each(["own error", "own gap"])(
    "a stream with %s never replaces even while another succeeds",
    async () => {
      const { a, b } = await world();
      // The producer cannot put B in provenFullStreams after its own error/gap,
      // even when it listed B as covered before that error was known.
      await a.collect("own-error", 5000, {
        rows: { A: ["a"], B: ["x"] },
        outcome: "partial",
        covered: ["A", "B"],
        proven: ["A"],
      });
      await b.sync.apply();
      expect(await b.rows("A")).toEqual(["a"]);
      expect(await b.rows("B")).toEqual(["x", "y"]);
    },
  );

  it("an all-succeeded run keeps the same per-stream replacement behavior", async () => {
    const { a, b } = await world();
    await a.collect("success", 5000, { rows: { A: ["a"], B: ["x"] } });
    await b.sync.apply();
    expect(await b.rows("A")).toEqual(["a"]);
    expect(await b.rows("B")).toEqual(["x"]);
  });

  it("a retry from a full request stays incomplete after publication", async () => {
    const { a } = await world(false);
    await a.collect("retry", 5000, {
      rows: { A: ["a"] },
      outcome: "retry_pending",
      covered: [],
      proven: [],
    });
    expect(
      await a.db.query("SELECT complete FROM stream_state WHERE stream='A'"),
    ).toEqual([{ complete: 0 }]);
  });
});

// #560 cases 1-5, recovered from 879b2eb8 covered-replace.test.ts.
describe("#560 replacement key-set cases", () => {
  it("case 1: a covered refresh removes an omission on another device", async () => {
    const { a, b } = await world();
    await a.collect("refresh", 5000, {
      rows: { A: ["a"] },
      covered: ["A"],
      proven: ["A"],
    });
    await b.sync.apply();
    expect(await b.rows("A")).toEqual(["a"]);
  });
  it("case 2: the same unmarked refresh keeps omissions", async () => {
    const { a, b } = await world();
    await a.collect("refresh", 5000, {
      rows: { A: ["a"] },
      covered: [],
      proven: [],
    });
    await b.sync.apply();
    expect(await b.rows("A")).toEqual(["a", "b"]);
  });
  it("case 3: replacement keeps a row newer than the refresh stamp", async () => {
    const { a, b } = await world();
    await b.collect("late", 9000, {
      rows: { A: ["c"] },
      full: false,
      covered: ["A"],
      proven: [],
    });
    await a.sync.apply();
    await a.collect("refresh", 5000, {
      rows: { A: ["a"] },
      covered: ["A"],
      proven: ["A"],
    });
    await b.sync.apply();
    expect(await b.rows("A")).toEqual(["a", "c"]);
  });
  it("case 4: a merge after the refresh adds without restoring omissions", async () => {
    const { a, b } = await world();
    await a.collect("refresh", 5000, {
      rows: { A: ["a"] },
      covered: ["A"],
      proven: ["A"],
    });
    await b.sync.apply();
    await b.collect("after", 6000, {
      rows: { A: ["c"] },
      full: false,
      covered: ["A"],
      proven: [],
    });
    await a.sync.apply();
    expect(await a.rows("A")).toEqual(["a", "c"]);
  });
  it("case 5: omitted rows survive locally until the replacement CAS commits", async () => {
    const { a, b } = await world();
    await a.collect("refresh", 5000, {
      rows: { A: ["a"] },
      covered: ["A"],
      proven: ["A"],
      publish: false,
    });
    expect(await a.rows("A")).toEqual(["a", "b"]);
    expect(await b.rows("A")).toEqual(["a", "b"]);
    await a.publish();
    await b.sync.apply();
    expect(await b.rows("A")).toEqual(["a"]);
  });
});

// 14563ecc: two clock skews, merge-only control, basis match and crash/replay.
describe("#560 five basis/skew traces", () => {
  it.each([
    { queued: "mine", other: "other", q: 5000, o: 4000, proof: true },
    { queued: "z-refresh", other: "a-new", q: 5000, o: 5000, proof: true },
    { queued: "mine", other: "other", q: 5000, o: 4000, proof: false },
  ])(
    "keeps a concurrent remote row ($queued/$other, proof=$proof)",
    async (trace) => {
      const { a, b } = await world();
      await a.collect(trace.queued, trace.q, {
        rows: { A: ["a"] },
        covered: ["A"],
        proven: trace.proof ? ["A"] : [],
        publish: false,
      });
      await b.collect(trace.other, trace.o, {
        rows: { A: ["a", "c"] },
        covered: ["A"],
        proven: ["A"],
      });
      await a.publish();
      await b.sync.apply();
      for (const device of [a, b])
        expect(await device.rows("A")).toEqual(["a", "c"]);
    },
  );
  it("a matching basis permits the omission", async () => {
    const { a, b } = await world();
    await a.collect("mine", 5000, {
      rows: { A: ["a"] },
      covered: ["A"],
      proven: ["A"],
    });
    await b.sync.apply();
    expect(await b.rows("A")).toEqual(["a"]);
  });
  it("a crash after registry CAS is idempotent on retry", async () => {
    const { a, b, registry } = await world();
    await a.collect("mine", 5000, {
      rows: { A: ["a"] },
      covered: ["A"],
      proven: ["A"],
      publish: false,
    });
    let crashed = false;
    const post = registry.post.bind(registry);
    registry.post = async (request) => {
      const answer = await post(request);
      if (!crashed && request.scope.endsWith(".A")) {
        crashed = true;
        throw new Error("simulated reply loss after CAS");
      }
      return answer;
    };
    const failed = await a.sync.cycle();
    expect(crashed).toBe(true);
    expect(failed.connections[0]!.error).toBe("simulated reply loss after CAS");
    await a.publish();
    await b.sync.apply();
    expect(await b.rows("A")).toEqual(["a"]);
    const version = await registry.read(connection + ".A");
    await a.publish();
    expect(await registry.read(connection + ".A")).toEqual(version);
  });
});

it("an offline unknown basis merges; a later verified basis can replace", async () => {
  const { a, b, registry } = await world(false);
  await a.collect("old-local", 1000, {
    rows: { A: ["old"] },
    covered: ["A"],
    proven: [],
    publish: false,
  });
  const read = registry.read.bind(registry);
  registry.read = async () => {
    throw new Error("offline fixture");
  };
  try {
    await a.collect("offline", 5000, {
      rows: { A: ["a"] },
      covered: ["A"],
      proven: ["A"],
      publish: false,
    });
  } finally {
    registry.read = read;
  }
  expect(
    await a.db.query(
      "SELECT basis_generation FROM run_streams WHERE run_id='offline' AND stream='A'",
    ),
  ).toEqual([{ basis_generation: null }]);
  await a.publish();
  await b.sync.apply();
  expect(await b.rows("A")).toEqual(["a", "old"]);
  await a.collect("verified", 6000, {
    rows: { A: ["a"] },
    covered: ["A"],
    proven: ["A"],
  });
  await b.sync.apply();
  expect(await b.rows("A")).toEqual(["a"]);
});

it("a declared full-inventory empty proof replaces the old image", async () => {
  const { a, b } = await world();
  await a.collect("empty", 5000, { rows: {}, covered: ["A"], proven: ["A"] });
  expect(
    await a.db.query(
      "SELECT replace FROM run_streams WHERE run_id='empty' AND stream='A'",
    ),
  ).toEqual([{ replace: 1 }]);
  await b.sync.apply();
  expect(await b.rows("A")).toEqual([]);
});
