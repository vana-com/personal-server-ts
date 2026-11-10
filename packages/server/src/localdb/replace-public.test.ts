import { afterEach, expect, it, vi } from "vitest";
import {
  createLocalSync,
  openLocalDb,
  connectionQueue,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
const owner = `0x${"11".repeat(20)}` as const;
const connectionId = "pdpp.fixture~";
async function world(
  coverageStrategy:
    "full_inventory" | "checkpoint_window" | null = "full_inventory",
) {
  const registry = createMemoryStreamSyncRegistry();
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
    const sync = createLocalSync(
      {
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
        now: () => now,
        newOp: () => `${deviceId}-${++op}`,
      },
      {
        resolveArtifact: (digest) => ({
          connector: digest === "other" ? "other" : "fixture",
          version: "1",
          streams: [
            {
              name: "items",
              semantics: "mutable_state",
              primaryKey: ["id"],
              coverageStrategy: coverageStrategy ?? undefined,
            },
          ],
        }),
        declaredStreams: () => ["items"],
        olderVersionReads: () => true,
      },
    );
    return {
      db,
      sync,
      async run(
        id: string,
        rows: string[],
        options: {
          restricted?: boolean;
          proven?: boolean;
          connector?: string;
        } = {},
      ) {
        now++;
        await sync.intake.begin(id, {
          connector: options.connector ?? "fixture",
          artifactDigest: options.connector ?? "fixture",
          wantFull: true,
          owner: { address: owner, leaseId: null },
          ...(options.restricted
            ? {
                streams: [
                  { name: "items", time_range: { from: "2026-01-01" } },
                ],
              }
            : {}),
        });
        await sync.intake.batch(id, {
          batch: 0,
          records: rows.map((key) => ({ stream: "items", data: { id: key } })),
        });
        await sync.intake.end(id, {
          outcome: "succeeded",
          coveredStreams: ["items"],
          lastBatch: 0,
          ...(options.proven ? { provenFullStreams: ["items"] } : {}),
        });
      },
      async publish() {
        expect(
          (await sync.cycle()).connections.every((c) => c.error === null),
        ).toBe(true);
      },
      async keys() {
        return (
          await sync.query.listRecords({
            connectionId,
            stream: "items",
            limit: 100,
          })
        ).records
          .map((r) => r.recordKey)
          .sort();
      },
    };
  };
  return { a: await make("a"), b: await make("b"), registry };
}

it("a producer proof cannot replace rows from a server-restricted full run on either device", async () => {
  const { a, b } = await world();
  await a.run("seed", ["old"]);
  await a.publish();
  await b.sync.apply();
  await a.run("restricted", ["new"], { restricted: true, proven: true });
  await a.publish();
  await b.sync.apply();
  expect(await b.keys()).toEqual(["new", "old"]);
  expect(await a.keys()).toEqual(["new", "old"]);
});

it("a proven full empty run removes stale rows on both devices", async () => {
  const { a, b } = await world();
  await a.run("seed", ["old"]);
  await a.publish();
  await b.sync.apply();
  await a.run("empty", [], { proven: true });
  await a.publish();
  await b.sync.apply();
  expect(await b.keys()).toEqual([]);
  expect(await a.keys()).toEqual([]);
});

it("compaction expires a changes cursor even when an unrelated connection retains older events", async () => {
  const { a, b } = await world();
  await b.run("other-seed", ["elsewhere"], { connector: "other" });
  await b.publish();
  await a.sync.apply();
  await a.run("seed", ["old"]);
  await a.publish();
  expect(
    await a.sync.query.changesSince({
      connectionId,
      stream: "items",
      cursor: 0,
    }),
  ).toBe("gone");
});

it.each(["checkpoint_window", "unknown"])(
  "%s declarations cannot replace even with producer full proof",
  async (strategy) => {
    const { a, b } = await world(
      strategy === "unknown" ? null : "checkpoint_window",
    );
    await a.run("seed", ["old", "keep"]);
    await a.publish();
    await b.sync.apply();
    await a.run("window", ["keep"], { proven: true });
    await a.publish();
    await b.sync.apply();
    expect(await b.keys()).toEqual(["keep", "old"]);
    expect(await a.keys()).toEqual(["keep", "old"]);
  },
);
it("full_inventory omission becomes a changes_since tombstone on another device", async () => {
  const { a, b } = await world();
  await a.run("seed", ["old", "keep"]);
  await a.publish();
  await b.sync.apply();
  const before = await b.sync.query.changesSince({
    connectionId,
    stream: "items",
    cursor: 0,
  });
  if (before === "gone") throw new Error("fixture cursor expired");
  const cursor = before.changes.at(-1)!.seq;
  await a.run("inventory", ["keep"], { proven: true });
  await a.publish();
  await b.sync.apply();
  const after = await b.sync.query.changesSince({
    connectionId,
    stream: "items",
    cursor,
  });
  if (after === "gone") throw new Error("fixture cursor expired");
  expect(
    after.changes
      .filter((c) => c.op === "remove")
      .map((c) => ({ key: c.recordKey, record: c.record })),
  ).toEqual([{ key: "old", record: null }]);
});
