import { startPersonalServer } from "./client.js";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
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
      streamSyncDeclaredStreams: () => ["items"],
      streamSyncRetainedManifests: () => [manifest],
      configDefaults: {
        sync: { enabled: false },
        gateway: { url: "https://gateway.local" },
        streamSync: { write: false, read: false },
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

it("skips a late seed once a real collection owns the stream", async () => {
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
  await intake.end("real-run", {
    outcome: "succeeded",
    coveredStreams: ["items"],
    provenFullStreams: ["items"],
    lastBatch: 0,
  });
  await context.runtime.streamSyncSeed!.put(
    "fixture-source",
    "items",
    body([
      { id: "a", value: "old" },
      { id: "b", value: "seed-only" },
    ]),
  );
  // Old data is a one-time seed: the real full refresh won, so neither the
  // stale "a" nor the seed-only "b" comes back, and the skip is a final receipt.
  expect(await read(context)).toMatchObject({
    data: { records: [{ id: "a", value: "new" }] },
  });
  expect(
    await f
      .driver()
      .query("SELECT record_key FROM records WHERE stamp_r = 'seed'"),
  ).toEqual([]);
  expect(
    await f
      .driver()
      .query("SELECT stream, state, reason, rows FROM import_ledger"),
  ).toEqual([
    {
      stream: "items",
      state: "excluded",
      reason: "seed_window_closed",
      rows: 0,
    },
  ]);
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
