import { startPersonalServer } from "./client.js";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, expect, it, vi } from "vitest";
import { endRequest } from "@opendatalabs/personal-server-ts-core/test-utils";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  seedLegacyStore,
  type FoldLayer,
  type LegacySeedStream,
  type SeedIntake,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { createIndexedDbPsLiteRuntime } from "./browser-runtime.js";
import type { SqlDriver } from "../../core/src/localdb/driver.js";
import { createSwitchedIndexedDbPsLiteRuntime } from "./test-support/unswitched-runtime.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";

const contexts: Awaited<
  ReturnType<typeof createSwitchedIndexedDbPsLiteRuntime>
>[] = [];
const roots: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) {
    await context.syncManager?.stop();
    await context.closeStreamSync?.();
  }
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
  vi.unstubAllGlobals();
});
const declaration = {
  connector: "fixture-source",
  version: "1",
  streams: [
    { name: "items", semantics: "mutable_state" as const, primaryKey: ["id"] },
  ],
};
const manifest = JSON.stringify({
  connector_key: declaration.connector,
  version: declaration.version,
  streams: [{ name: "items", semantics: "mutable_state", primary_key: ["id"] }],
});
async function fixture() {
  vi.stubGlobal("indexedDB", new IDBFactory());
  const temporary = join(homedir(), ".tmp");
  await mkdir(temporary, { recursive: true });
  const root = await mkdtemp(join(temporary, "lite-seed-"));
  roots.push(root);
  const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const signature = await signOwnerMasterKey(owner);
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  let driver: SqlDriver;
  let crashAfter: number | null = null;
  const openDriver = vi.fn(async () => {
    driver = openBetterSqlite3(join(root, "store.sqlite"));
    const raw = driver;
    return {
      ...raw,
      async batch(statements: Parameters<SqlDriver["batch"]>[0]) {
        if (
          crashAfter !== null &&
          statements.some((s) => s.sql.startsWith("INSERT INTO records")) &&
          --crashAfter === 0
        ) {
          crashAfter = null;
          throw new Error("seed_merge_crash");
        }
        return raw.batch(statements);
      },
    };
  });
  const boot = async (switched = true) => {
    const create = switched
      ? createSwitchedIndexedDbPsLiteRuntime
      : createIndexedDbPsLiteRuntime;
    const context = await create({
      ownerAddress: owner.address,
      ownerSignature: signature,
      dbName: root,
      storageDbName: root + "-data",
      gateway: createMockPsLiteGateway(),
      auth: createBearerTokenPsLiteAuth({ ownerToken: "owner-token" }),
      active: true,
      localDb: { openDriver },
      streamSyncRegistry: registry,
      streamSyncBlobs: blobs,
      streamSyncDeclarations: () => declaration,
      streamSyncRetainedManifests: () => [manifest],
      configDefaults: {
        sync: { enabled: false },
        gateway: { url: "https://gateway.local" },
      },
    });
    contexts.push(context);
    return context;
  };
  return {
    boot,
    owner,
    openDriver,
    driver: () => driver,
    crashAfterMerges: (n: number) => {
      crashAfter = n;
    },
  };
}
const encoder = new TextEncoder();
async function* body(records: Record<string, unknown>[]) {
  yield encoder.encode(
    JSON.stringify({
      primaryKey: ["id"],
      profile: { key: "fixture-source", version: "1" },
      records: records.length,
    }) + "\n",
  );
  for (const record of records)
    yield encoder.encode(JSON.stringify(record) + "\n");
}
async function read(
  context: Awaited<ReturnType<typeof createSwitchedIndexedDbPsLiteRuntime>>,
) {
  // Seed snapshots do not invent a complete published head. Read the imported
  // rows through the runtime's database facade, as the in-process host can.
  const page = await (
    await context.getLocalSync!()
  ).query.listRecords({
    connectionId: "pdpp.fixture-source~",
    stream: "items",
  });
  return { data: { records: page.records.map((row) => JSON.parse(row.body)) } };
}

it("imports a phone snapshot through the real Lite runtime and reopens its receipt", async () => {
  const { boot } = await fixture();
  const context = await boot();
  const seed = context.runtime.streamSyncSeed;
  expect(seed).toBeDefined();
  expect(
    await seed!.put(
      "fixture-source",
      "items",
      body([{ id: "a", value: "old" }]),
    ),
  ).toEqual({ state: "staged", records: 1, invalid: 0 });
  expect(await read(context)).toMatchObject({
    data: { records: [{ id: "a", value: "old" }] },
  });
  expect(await seed!.status("fixture-source")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" } },
  });
  await context.syncManager?.stop();
  await context.closeStreamSync?.();
  contexts.splice(contexts.indexOf(context), 1);
  const reopened = await boot();
  async function* unread(): AsyncIterable<Uint8Array> {
    throw new Error("receipt replay read the body");
  }
  expect(
    await reopened.runtime.streamSyncSeed!.put(
      "fixture-source",
      "items",
      unread(),
    ),
  ).toEqual({ state: "merged" });
  expect(await read(reopened)).toMatchObject({
    data: { records: [{ id: "a", value: "old" }] },
  });
});

it("fills a late seed into a stream a real collection owns, without overwriting it", async () => {
  const f = await fixture();
  const context = await f.boot();
  const intake = context.streamSyncIntake!;
  await intake.begin("real-run", {
    connector: "fixture-source",
    artifactDigest: "fixture",
    owner: { address: f.owner.address, leaseId: null },
    observedAt: 1000,
  });
  await intake.batch("real-run", {
    batch: 0,
    records: [{ stream: "items", data: { id: "a", value: "new" } }],
  });
  await intake.end(
    "real-run",
    endRequest({ lastBatch: 0, live: ["items"], provenFullStreams: ["items"] }),
  );
  await context.runtime.streamSyncSeed!.put(
    "fixture-source",
    "items",
    body([
      { id: "a", value: "old" },
      { id: "b", value: "seed-only" },
    ]),
  );
  // The seed fills what the stream lacks: the real "a" stays, the old "b" is
  // added under the seed stamp, and the stream's own receipt says so.
  expect(
    await f
      .driver()
      .query(
        "SELECT record_key, stamp_r FROM records WHERE stream = 'items' ORDER BY record_key",
      ),
  ).toMatchObject([
    {
      record_key: expect.stringContaining("a"),
      stamp_r: expect.not.stringMatching(/^seed$/),
    },
    { record_key: expect.stringContaining("b"), stamp_r: "seed" },
  ]);
  expect(await read(context)).toMatchObject({
    data: {
      records: [
        { id: "a", value: "new" },
        { id: "b", value: "seed-only" },
      ],
    },
  });
  expect(
    await f
      .driver()
      .query("SELECT stream, state, reason, rows FROM import_ledger"),
  ).toEqual([{ stream: "items", state: "imported", reason: null, rows: 2 }]);
  expect(
    await context.runtime.streamSyncSeed!.status("fixture-source"),
  ).toEqual({ targetKnown: true, streams: { items: { state: "merged" } } });
});
it("resumes a staged phone snapshot after a merge crash without duplicate changes", async () => {
  const f = await fixture();
  const context = await f.boot();
  f.crashAfterMerges(2);
  await expect(
    context.runtime.streamSyncSeed!.put(
      "fixture-source",
      "items",
      body([{ id: "a" }, { id: "b" }]),
    ),
  ).rejects.toThrow("seed_merge_crash");
  expect(
    await f.driver().query("SELECT count(*) AS n FROM import_ledger"),
  ).toEqual([{ n: 0 }]);
  await context.syncManager?.stop();
  await context.closeStreamSync?.();
  contexts.splice(contexts.indexOf(context), 1);
  const reopened = await f.boot();
  expect(
    await reopened.runtime.streamSyncSeed!.status("fixture-source"),
  ).toEqual({ targetKnown: true, streams: { items: { state: "merged" } } });
  expect(
    await f.driver().query("SELECT count(*) AS n FROM record_changes"),
  ).toEqual([{ n: 2 }]);
  expect(await read(reopened)).toMatchObject({
    data: { records: expect.arrayContaining([{ id: "a" }, { id: "b" }]) },
  });
});
it("does not open the database or consume a seed body while Account is unknown or Off", async () => {
  const f = await fixture();
  const context = await f.boot(false);
  async function* unread(): AsyncIterable<Uint8Array> {
    throw new Error("blocked intake read the body");
  }
  await expect(
    context.runtime.streamSyncSeed!.put("fixture-source", "items", unread()),
  ).rejects.toMatchObject({ errorCode: "ACCOUNT_MODE_UNKNOWN" });
  await context.accountModeAuthority.submitEvidence({
    owner: f.owner.address,
    state: "off",
  });
  await expect(
    context.runtime.streamSyncSeed!.put("fixture-source", "items", unread()),
  ).rejects.toMatchObject({ errorCode: "STREAM_SYNC_NOT_ENABLED" });
  expect(f.openDriver).not.toHaveBeenCalled();
});
it("never recreates a deleted connection from a phone snapshot", async () => {
  const f = await fixture();
  const context = await f.boot();
  await context.runtime.streamSyncSeed!.put(
    "fixture-source",
    "items",
    body([{ id: "a" }]),
  );
  await context.localSync!.deleter.requestConnectionDelete("fixture-source");
  async function* unread(): AsyncIterable<Uint8Array> {
    throw new Error("deleted intake read the body");
  }
  await expect(
    context.runtime.streamSyncSeed!.put("fixture-source", "items", unread()),
  ).rejects.toMatchObject({ errorCode: "CONNECTION_DELETED" });
  expect(await f.driver().query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 0 },
  ]);
});

it("receipts an empty phone snapshot without inventing records", async () => {
  const f = await fixture();
  const context = await f.boot();
  const seed = context.runtime.streamSyncSeed!;
  expect(await seed.put("fixture-source", "items", body([]))).toEqual({
    state: "staged",
    records: 0,
    invalid: 0,
  });
  expect(await seed.status("fixture-source")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" } },
  });
  expect(
    await f.driver().query("SELECT rows, highest_seq FROM import_ledger"),
  ).toEqual([{ rows: 0, highest_seq: 0 }]);
  expect(await f.driver().query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 0 },
  ]);
});

it("commits one snapshot when two intake calls race on the same stream", async () => {
  const f = await fixture();
  const context = await f.boot();
  const seed = context.runtime.streamSyncSeed!;
  const result = await Promise.all([
    seed.put("fixture-source", "items", body([{ id: "first" }])),
    seed.put("fixture-source", "items", body([{ id: "second" }])),
  ]);
  expect(result).toEqual([
    { state: "staged", records: 1, invalid: 0 },
    { state: "merged" },
  ]);
  expect(await read(context)).toEqual({ data: { records: [{ id: "first" }] } });
});

it("does not re-import a seed the database has already excluded", async () => {
  const f = await fixture();
  const context = await f.boot();
  const seed = context.runtime.streamSyncSeed!;
  await seed.put("fixture-source", "items", body([{ id: "a" }]));
  // The shared publisher records this final outcome when a seed cannot enter
  // the current generation. Existing database data remains authoritative.
  await f.driver().batch([
    { sql: "UPDATE write_ctx SET origin = 'purge' WHERE id = 1" },
    { sql: "DELETE FROM records" },
    { sql: "UPDATE write_ctx SET origin = 'local' WHERE id = 1" },
    {
      sql: "UPDATE import_ledger SET state = 'excluded', reason = 'seed_skipped'",
    },
  ]);
  const before = await f
    .driver()
    .query("SELECT count(*) AS n FROM record_changes");
  expect(await seed.status("fixture-source")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" } },
  });
  expect(await read(context)).toEqual({ data: { records: [] } });
  expect(
    await f.driver().query("SELECT count(*) AS n FROM record_changes"),
  ).toEqual(before);
});

it("exposes seed intake through the public Lite handle", async () => {
  const f = await fixture();
  const context = await f.boot();
  const handle = await startPersonalServer({
    runtime: context.runtime,
    relay: false,
    localOrigin: "https://ps.local",
    gateway: createMockPsLiteGateway(),
  });
  try {
    expect(handle.streamSyncSeed).toBeDefined();
    expect(
      await handle.streamSyncSeed!.put(
        "fixture-source",
        "items",
        body([{ id: "from-phone" }]),
      ),
    ).toEqual({ state: "staged", records: 1, invalid: 0 });
    expect(await read(context)).toEqual({
      data: { records: [{ id: "from-phone" }] },
    });
    const seed = handle.streamSyncSeed!;
    await handle.stop();
    async function* unread(): AsyncIterable<Uint8Array> {
      throw new Error("stopped intake read the body");
    }
    await expect(seed.put("fixture-source", "items", unread())).rejects.toThrow(
      "unavailable",
    );
  } finally {
    await handle.stop();
  }
});

// The producer a host with a legacy store only it can read (a browser's
// IndexedDB, a phone's files) calls with that store's layers.
const layer = (rows: () => AsyncIterable<unknown>): FoldLayer => ({
  records: rows,
});
const stream = (layers: FoldLayer[], sourceId?: string): LegacySeedStream => ({
  connector: "fixture-source",
  stream: "items",
  primaryKey: ["id"],
  version: "1",
  layers,
  ...(sourceId ? { sourceId } : {}),
});
const storeOf = (...streams: LegacySeedStream[]) => ({
  async *streams() {
    yield* streams;
  },
});
async function* rowsOf(...rows: unknown[]) {
  yield* rows;
}

it("seeds a Web-only legacy store through the real runtime: newest layer wins, unfit rows are counted, a second run adds nothing", async () => {
  const f = await fixture();
  const context = await f.boot();
  const seed = context.runtime.streamSyncSeed!;
  const SOURCE = "urn:fixture";
  const tag = { $pdpp: { sourceId: SOURCE } };
  const store = storeOf(
    stream(
      [
        layer(() =>
          rowsOf(
            { id: "a", v: "new", ...tag },
            { v: "no key", ...tag },
            { id: null, ...tag },
          ),
        ),
        layer(() =>
          rowsOf(
            { id: "a", v: "old", ...tag },
            { id: "b", v: "old-b", ...tag },
            { id: "c", v: "untagged" },
          ),
        ),
      ],
      SOURCE,
    ),
  );
  const report = await seedLegacyStore(seed, store);
  expect(report).toEqual({
    rows: 2,
    quarantine: {
      bad_key_value: 1,
      missing_key_field: 1,
      superseded: 1,
      untagged: 1,
    },
    streams: [
      {
        connector: "fixture-source",
        stream: "items",
        outcome: "staged",
        rows: 2,
        quarantine: {
          bad_key_value: 1,
          missing_key_field: 1,
          superseded: 1,
          untagged: 1,
        },
        invalid: 0,
      },
    ],
  });
  expect(await read(context)).toMatchObject({
    data: {
      records: expect.arrayContaining([
        { id: "a", v: "new" },
        { id: "b", v: "old-b" },
      ]),
    },
  });
  const changes = await f.driver().query("SELECT * FROM record_changes");
  expect(changes).toHaveLength(2);
  // A second run reads nothing and changes nothing.
  const again = await seedLegacyStore(seed, {
    async *streams() {
      yield stream([
        layer(() => {
          throw new Error("receipt replay read the layers");
        }),
      ]);
    },
  });
  expect(again.streams).toEqual([
    expect.objectContaining({ outcome: "merged", rows: 0 }),
  ]);
  expect(await f.driver().query("SELECT * FROM record_changes")).toEqual(
    changes,
  );
});

it("seeds a large phone store in bounded chunks from lazily read layers", async () => {
  const f = await fixture();
  const context = await f.boot();
  const real = context.runtime.streamSyncSeed!;
  const TOTAL = 6000;
  const chunkSizes: number[] = [];
  const spy: SeedIntake = {
    status: (connector) => real.status(connector),
    async put(connector, name, body) {
      async function* measured() {
        for await (const chunk of body) {
          chunkSizes.push(chunk.byteLength);
          yield chunk;
        }
      }
      return real.put(connector, name, measured());
    },
  };
  const padding = "x".repeat(1024);
  const big = layer(async function* () {
    for (let i = 0; i < TOTAL; i++) {
      yield { id: `k${String(i).padStart(5, "0")}`, padding };
    }
  });
  const report = await seedLegacyStore(spy, storeOf(stream([big])));
  expect(report.rows).toBe(TOTAL);
  expect(chunkSizes.length).toBeGreaterThan(10);
  // A chunk is about one staging batch, never the stream: the bound plus one row.
  expect(Math.max(...chunkSizes)).toBeLessThan(256 * 1024 + 2 * 1024);
  expect(await f.driver().query("SELECT count(*) AS n FROM records")).toEqual([
    { n: TOTAL },
  ]);
});
