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
async function world() {
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
        resolveArtifact: () => ({
          connector: "fixture",
          version: "1",
          streams: [
            { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
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
        options: { restricted?: boolean; proven?: boolean } = {},
      ) {
        now++;
        await sync.intake.begin(id, {
          connector: "fixture",
          artifactDigest: "fixture",
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
        expect((await sync.cycle()).connections.map((c) => c.error)).toEqual([
          null,
        ]);
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
