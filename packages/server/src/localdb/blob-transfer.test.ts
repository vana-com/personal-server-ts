import { createHash } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import {
  createLocalSync,
  openLocalDb,
  connectionQueue,
  type LocalSyncDeps,
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
const id = "pdpp.fixture~";
async function fixture(late = false) {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
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
      now: () => 1000,
      newOp: () => `${deviceId}-${++op}`,
    };
    return {
      db,
      sync: createLocalSync(deps, {
        resolveArtifact: () => ({
          connector: "fixture",
          version: "1",
          streams: [
            { name: "media", semantics: "mutable_state", primaryKey: ["id"] },
          ],
        }),
        declaredStreams: () => ["media"],
        olderVersionReads: () => true,
      }),
    };
  };
  const a = await make("a"),
    b = await make("b");
  const bytes = new Uint8Array(140_000).fill(7);
  const hash = createHash("sha256").update(bytes).digest("hex");
  const blobId = `sha256:${hash}`;
  await a.sync.intake.begin("run", {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    observedAt: 1000,
  });
  await a.sync.intake.batch("run", {
    batch: 0,
    records: [
      {
        stream: "media",
        data: { id: "m", day: "2026-11-10", blob_ref: { blob_id: blobId } },
      },
    ],
  });
  if (!late) {
    await a.sync.blobs.put({
      runId: "run",
      sha256: hash,
      mimeType: "application/octet-stream",
      bytes,
    });
  }
  await a.sync.intake.end("run", {
    outcome: "succeeded",
    coveredStreams: ["media"],
    lastBatch: 0,
  });
  expect((await a.sync.cycle()).connections.map((c) => c.error)).toEqual([
    null,
  ]);
  if (late) {
    await a.sync.blobs.put({
      runId: "run",
      sha256: hash,
      mimeType: "application/octet-stream",
      bytes,
    });
    expect(
      (await a.sync.cycle()).connections
        .flatMap((c) => c.published)
        .map((r) => r.outcome),
    ).toEqual(["noop"]);
  }
  await b.sync.apply();
  return { a, b, blobs, bytes, hash, blobId };
}
it("publishes run blobs before their head and lazily reads them on another device", async () => {
  const f = await fixture();
  expect(
    new Uint8Array((await f.blobs.get(`${id}.media/g1-b-${f.hash}`))!),
  ).toEqual(f.bytes);
  expect(await f.b.db.query("SELECT * FROM blobs")).toEqual([]);
  expect(new Uint8Array((await f.b.sync.blobs.get(f.hash))!.bytes)).toEqual(
    f.bytes,
  );
  expect(await f.b.db.query("SELECT blob_id FROM blob_refs")).toEqual([
    { blob_id: f.hash },
  ]);
});
it("applying a delete removes the second device's blob refs and cached bytes", async () => {
  const f = await fixture();
  await f.b.sync.blobs.get(f.hash);
  await f.a.sync.deleter.requestConnectionDelete("fixture");
  expect(await f.a.sync.deleter.resumeDeletes()).toEqual([]);
  await f.b.sync.apply();
  expect(await f.b.db.query("SELECT * FROM blob_refs")).toEqual([]);
  expect(await f.b.db.query("SELECT * FROM blobs")).toEqual([]);
  expect(await f.b.sync.blobs.get(f.hash)).toBeNull();
});

it("uploads bytes arriving after an unchanged head without republishing its records", async () => {
  const f = await fixture(true);
  expect(
    new Uint8Array((await f.blobs.get(`${id}.media/g1-b-${f.hash}`))!),
  ).toEqual(f.bytes);
  expect(new Uint8Array((await f.b.sync.blobs.get(f.hash))!.bytes)).toEqual(
    f.bytes,
  );
});
