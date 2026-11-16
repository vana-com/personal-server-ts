import { keccak_256 } from "@noble/hashes/sha3";
import { afterEach, expect, it } from "vitest";
import {
  controlHashes,
  deriveKeyCheck,
  LOG_STREAM,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createGatewayStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createFakeGateway } from "./fake-gateway.js";

// Publish while collecting together with the stream-sync log. Admission is
// per run batch and writes `records` and `record_changes`; the log publisher
// reads `record_changes` and sends one segment and one registry commit per
// publish round. Both flags on must keep the same end states as either alone.

const OWNER = `0x${"11".repeat(20)}` as const;
const CONNECTION_ID = "pdpp.fixture~";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function world(options: {
  admit: boolean;
  coverage?: "full_inventory" | "checkpoint_window";
}) {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const gateway = createFakeGateway({
    owner: OWNER,
    isTombstone: (v) =>
      v.dataHash === hashes.tombstoneData &&
      v.metadataHash === hashes.tombstoneMetadata,
  });
  const store = new Map<string, Uint8Array>();
  const blobs = {
    governor: createMemoryStreamSyncBlobs().governor,
    put: async (key: string, bytes: Uint8Array) => {
      store.set(key, bytes.slice());
    },
    get: async (key: string) => store.get(key) ?? null,
    exists: async (key: string) => store.has(key),
  };
  let clock = 1000;

  const device = async (deviceId: string) => {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner: OWNER,
      network: "test",
      deviceId,
    });
    drivers.push(db);
    let op = 0;
    const deps: LocalSyncDeps = {
      db,
      queue: connectionQueue(),
      registry: createGatewayStreamSyncRegistry({
        gatewayUrl: "https://gateway.test",
        ownerAddress: OWNER,
        fetch: gateway.fetch,
      }),
      blobs,
      ownerAddress: OWNER,
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: async (_s, b) => b,
        encryptPart: async (_s, b) => b,
        decrypt: async (_s, b) => b,
      },
      signer: { signAddData: async () => "0x00" },
      logger: { info: () => {}, warn: () => {} },
      now: () => clock,
      newOp: () => `${deviceId}-${++op}`,
      ...(options.admit ? { publishWhileCollecting: true } : {}),
    };
    const sync = createLocalSync(deps, {
      resolveArtifact: () => ({
        connector: "fixture",
        version: "1",
        streams: [
          {
            name: "items",
            semantics: "mutable_state" as const,
            primaryKey: ["id"],
            coverageStrategy: options.coverage ?? "full_inventory",
          },
        ],
      }),
      declaredStreams: () => ["items"],
      olderVersionReads: () => true,
    });
    const begin = (id: string, observedAt?: number) => {
      clock++;
      return sync.intake.begin(id, {
        connector: "fixture",
        artifactDigest: "fixture",
        wantFull: true,
        observedAt,
        owner: { address: OWNER, leaseId: null },
      });
    };
    const batch = (
      id: string,
      n: number,
      rows: Array<string | { id: string; remove?: boolean }>,
    ) =>
      sync.intake.batch(id, {
        batch: n,
        records: rows.map((r) => {
          const row = typeof r === "string" ? { id: r } : r;
          return {
            stream: "items",
            ...(row.remove ? { op: "delete" as const } : {}),
            data: { id: row.id },
          };
        }),
      });
    const end = (id: string, lastBatch: number, proven = false) =>
      sync.intake.end(id, {
        outcome: "succeeded",
        coveredStreams: ["items"],
        lastBatch,
        ...(proven ? { provenFullStreams: ["items"] } : {}),
      });
    const cycle = async () => {
      const report = await sync.cycle();
      const failed = report.connections.find((c) => c.error !== null);
      if (failed) throw new Error(`cycle failed: ${failed.error}`);
    };
    return {
      db,
      begin,
      batch,
      end,
      cycle,
      async run(
        id: string,
        rows: Parameters<typeof batch>[2],
        options: { observedAt?: number; proven?: boolean } = {},
      ) {
        await begin(id, options.observedAt);
        await batch(id, 0, rows);
        return end(id, 0, options.proven);
      },
      async keys() {
        return (
          await sync.query.listRecords({
            connectionId: CONNECTION_ID,
            stream: "items",
            limit: 100,
          })
        ).records
          .map((r) => r.recordKey)
          .sort();
      },
      async position() {
        const [row] = await db.query<{ position: number }>(
          "SELECT position FROM log_state WHERE connection_id = ?",
          [CONNECTION_ID],
        );
        return row?.position ?? 0;
      },
      async tombstones() {
        const [row] = await db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM record_tombstones",
        );
        return row!.n;
      },
    };
  };
  return {
    a: await device("a"),
    b: await device("b"),
    // Log commits. A new connection's control row is created on its own
    // batch when a round has nothing to publish; that is not a log commit.
    commits: () =>
      gateway
        .batches()
        .filter((call) =>
          call.body.rows.some((row: { scope: string }) =>
            row.scope.endsWith(`.${LOG_STREAM}`),
          ),
        ).length,
    segmentPuts: () =>
      [...store.keys()].filter((k) => k.includes("/s-")).length,
  };
}

it("each publish round while a run collects is one segment and one registry commit", async () => {
  const w = await world({ admit: true });
  await w.a.begin("r1");
  await w.a.batch("r1", 0, ["x", "y", "z"]);
  await w.a.cycle();
  expect([w.commits(), w.segmentPuts(), await w.a.position()]).toEqual([
    1, 1, 1,
  ]);
  await w.a.batch("r1", 1, ["p"]);
  await w.a.batch("r1", 2, ["q"]);
  await w.a.cycle();
  // Two batches that arrived between rounds ride one segment, not two.
  expect([w.commits(), w.segmentPuts(), await w.a.position()]).toEqual([
    2, 2, 2,
  ]);
  await w.a.end("r1", 2);
  await w.a.cycle();
  // Run end admits no row again. Its one publish is the stream's head going
  // complete, still one segment and one commit; the rows are not sent twice.
  expect([w.commits(), w.segmentPuts(), await w.a.position()]).toEqual([
    3, 3, 3,
  ]);
  await w.a.cycle();
  expect(w.commits()).toBe(3);
  await w.b.cycle();
  expect(await w.b.keys()).toEqual(["p", "q", "x", "y", "z"]);
  expect(await w.b.keys()).toEqual(await w.a.keys());
});

it("with publish while collecting off the same run is one segment, at run end", async () => {
  const w = await world({ admit: false });
  await w.a.begin("r1");
  await w.a.batch("r1", 0, ["x", "y"]);
  await w.a.cycle();
  expect(w.commits()).toBe(0);
  await w.a.batch("r1", 1, ["p"]);
  await w.a.end("r1", 1);
  await w.a.cycle();
  expect([w.commits(), w.segmentPuts(), await w.a.position()]).toEqual([
    1, 1, 1,
  ]);
  await w.b.cycle();
  expect(await w.b.keys()).toEqual(["p", "x", "y"]);
});

it("a row an omission dropped through the log is not brought back by an older run's late batch", async () => {
  const w = await world({ admit: true });
  await w.a.run("seed", ["gone", "kept"], { observedAt: 1100 });
  await w.a.cycle();
  await w.b.cycle();
  await w.a.begin("older", 1200);
  await w.a.run("newer", ["kept"], { observedAt: 3000, proven: true });
  await w.a.cycle();
  await w.b.cycle();
  expect(await w.a.keys()).toEqual(["kept"]);
  // The log's commit applied the omission, so it remembers it.
  expect(await w.a.tombstones()).toBeGreaterThan(0);
  const result = await w.a.batch("older", 0, ["gone", "fresh"]);
  expect(result).toMatchObject({ accepted: 2, tombstoned: 1 });
  await w.a.end("older", 0);
  await w.a.cycle();
  await w.b.cycle();
  expect(await w.a.keys()).toEqual(["fresh", "kept"]);
  expect(await w.b.keys()).toEqual(["fresh", "kept"]);
});

it("a newer explicit delete published through the log beats an older run's late rows", async () => {
  const w = await world({ admit: true, coverage: "checkpoint_window" });
  await w.a.run("seed", ["gone"], { observedAt: 1100 });
  await w.a.cycle();
  await w.b.cycle();
  await w.a.begin("older", 1200);
  await w.a.begin("newer", 3000);
  await w.a.batch("newer", 0, [{ id: "gone", remove: true }]);
  await w.a.end("newer", 0);
  await w.a.cycle();
  await w.b.cycle();
  expect(await w.a.keys()).toEqual([]);
  await w.a.batch("older", 0, ["gone"]);
  await w.a.end("older", 0);
  await w.a.cycle();
  await w.b.cycle();
  expect(await w.a.keys()).toEqual([]);
  expect(await w.b.keys()).toEqual([]);
});

it("a run refused at end keeps its admitted rows and they publish through the log", async () => {
  const w = await world({ admit: true });
  await w.a.run("seed", ["old"], { observedAt: 1100 });
  await w.a.cycle();
  await w.a.begin("older", 1200);
  await w.a.batch("older", 0, ["late"]);
  await w.a.run("newer", ["old", "new"], { observedAt: 3000 });
  // The older run saw only `late`: out of order, it may not omit `old`.
  await w.a.end("older", 0, true);
  await w.a.cycle();
  await w.b.cycle();
  expect(await w.a.keys()).toEqual(["late", "new", "old"]);
  expect(await w.b.keys()).toEqual(["late", "new", "old"]);
});
