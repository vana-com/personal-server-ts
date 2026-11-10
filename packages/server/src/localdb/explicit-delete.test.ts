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
  semantics: "mutable_state" | "append_only" = "mutable_state",
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
              semantics,
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
          remove?: boolean;
          observedAt?: number;
        } = {},
      ) {
        now++;
        await sync.intake.begin(id, {
          connector: options.connector ?? "fixture",
          artifactDigest: options.connector ?? "fixture",
          wantFull: true,
          observedAt: options.observedAt,
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
          records: rows.map((key) => ({
            stream: "items",
            ...(options.remove ? { op: "delete" as const } : {}),
            data: { id: key },
          })),
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

it("an explicit checkpoint_window delete removes the record and reaches another device as a changes_since tombstone", async () => {
  const { a, b } = await world("checkpoint_window");
  await a.run("seed", ["old"]);
  await a.publish();
  await b.sync.apply();
  const before = await b.sync.query.changesSince({
    connectionId,
    stream: "items",
    cursor: 0,
  });
  if (before === "gone") throw new Error("fixture cursor expired");
  const cursor = before.changes.at(-1)!.seq;
  await a.run("explicit-delete", ["old"], { remove: true });
  await a.publish();
  await b.sync.apply();
  expect.soft(await b.keys()).toEqual([]);
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

it("a pending explicit tombstone wins over an older head learned before publish", async () => {
  const { a, b } = await world("checkpoint_window");
  await a.run("seed", ["keep"]);
  await a.publish();
  await b.sync.apply();
  await b.sync.intake.begin("older", {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    observedAt: 1002,
  });
  await b.sync.intake.batch("older", {
    batch: 0,
    records: [{ stream: "items", data: { id: "unseen" } }],
  });
  await a.run("delete-unseen", ["unseen"], { remove: true, observedAt: 2000 });
  await b.sync.intake.end("older", {
    outcome: "succeeded",
    coveredStreams: ["items"],
    lastBatch: 0,
  });
  await b.publish();
  await a.publish();
  await b.sync.apply();
  expect(await a.keys()).toEqual(["keep"]);
  expect(await b.keys()).toEqual(["keep"]);
});

it("a staged delete leaves data intact if its run aborts", async () => {
  const { a, b } = await world("checkpoint_window");
  await a.run("seed", ["keep"]);
  await a.publish();
  await b.sync.apply();
  await a.sync.intake.begin("aborted", {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
  });
  const batch = {
    batch: 0,
    records: [
      { stream: "items", op: "delete", key: "keep", data: { id: "keep" } },
    ],
  };
  expect(await a.sync.intake.batch("aborted", batch)).toMatchObject({
    accepted: 1,
    deletesSkipped: 0,
  });
  expect(await a.sync.intake.batch("aborted", batch)).toMatchObject({
    applied: false,
    accepted: 0,
  });
  expect(await a.keys()).toEqual(["keep"]);
  await a.sync.intake.abort("aborted", "cancelled");
  await a.publish();
  await b.sync.apply();
  expect(await b.keys()).toEqual(["keep"]);
});
it("append-only streams refuse explicit deletion", async () => {
  const { a } = await world("checkpoint_window", "append_only");
  await a.run("seed", ["keep"]);
  await a.publish();
  await expect(
    a.run("invalid-delete", ["keep"], { remove: true }),
  ).rejects.toMatchObject({ code: "invalid_request" });
  expect(await a.keys()).toEqual(["keep"]);
});
it("a mismatched declared key rejects the whole delete batch", async () => {
  const { a } = await world("checkpoint_window");
  await a.run("seed", ["keep"]);
  await a.publish();
  await a.sync.intake.begin("bad-key", {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
  });
  await expect(
    a.sync.intake.batch("bad-key", {
      batch: 0,
      records: [
        { stream: "items", op: "delete", key: "other", data: { id: "keep" } },
      ],
    }),
  ).rejects.toMatchObject({ code: "invalid_request" });
  expect(await a.keys()).toEqual(["keep"]);
});

it("an append-only inventory cannot remove omissions even with producer proof", async () => {
  const { a, b } = await world("full_inventory", "append_only");
  await a.run("seed", ["keep"]);
  await a.publish();
  await b.sync.apply();
  await a.run("empty", [], { proven: true });
  await a.publish();
  await b.sync.apply();
  expect(await b.keys()).toEqual(["keep"]);
});
