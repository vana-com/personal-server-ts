import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createLocalSync,
  openLocalDb,
  connectionQueue,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
  createStreamSyncKeyPorts,
  streamSyncNetwork,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";
import { createInMemoryMcpConnectionStore } from "@opendatalabs/personal-server-ts-core/mcp";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

// Evidence for the Web v2 design: save a record on the Lite runtime, reload,
// read it from an independent reader, delete it with a batch tombstone, and
// never touch the legacy data plane.
const account = privateKeyToAccount(`0x${"12".repeat(32)}`);
let signature: `0x${string}`;
beforeAll(async () => {
  signature = await signOwnerMasterKey(account);
});
type Lite = Awaited<ReturnType<typeof createPsLiteSyncManager>>;
const lites: Lite[] = [];
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const lite of lites.splice(0)) {
    await lite.syncManager.stop();
    await lite.closeStreamSync();
  }
  for (const db of drivers.splice(0)) await db.close();
  vi.unstubAllGlobals();
});
const declaration = {
  connector: "fixture",
  version: "1",
  streams: [
    {
      name: "items",
      semantics: "mutable_state" as const,
      primaryKey: ["id"],
      coverageStrategy: "full_inventory" as const,
    },
  ],
};
const connectionId = "pdpp.fixture~";
const config = ServerConfigSchema.parse({
  streamSync: { write: false, read: false },
});
const request = (observedAt: number) => ({
  connector: "fixture",
  artifactDigest: "fixture",
  owner: { address: account.address, leaseId: null },
  observedAt,
});

async function world() {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: signature,
  });
  // The legacy data plane: a gateway, remote fetch, and the legacy file storage.
  const legacy = vi.fn(() => {
    throw new Error("legacy data plane called");
  });
  vi.stubGlobal("fetch", legacy);
  const gateway = new Proxy({}, { get: () => legacy });
  const storage = new Proxy(createMemoryPsLiteStorage(), {
    get: (target, key) =>
      typeof (target as never)[key] === "function"
        ? legacy
        : (target as never)[key],
  });
  // Tripwire: any legacy data-point call fails loudly and is recorded.
  const dataPointFeed = {
    getDataPoint: vi.fn(async () => {
      throw new Error("legacy dataPointFeed.getDataPoint called");
    }),
    listDataPointsByOwner: vi.fn(async () => {
      throw new Error("legacy dataPointFeed.listDataPointsByOwner called");
    }),
  };
  const dbPath = join(mkdtempSync(join(tmpdir(), "lite-cycle-")), "lite.db");
  const open = async () => {
    const lite = await createPsLiteSyncManager({
      config,
      autoStartSync: false,
      localDb: { openDriver: async () => openBetterSqlite3(dbPath) },
      accountStorageMode: { owner: account.address, read: () => "switched" },
      streamSyncRegistry: registry,
      streamSyncBlobs: blobs,
      streamSyncDeclarations: () => declaration,
      streamSyncDeclaredStreams: () => ["items"],
      stateStore,
      storage: storage as never,
      ownerSignature: signature,
      serverAccount: identity.account,
      ownerSyncSigner: {
        address: account.address,
        signMessage: (message) => account.signMessage({ message }),
        signAddData: async () => "0x00",
        signLineageAttestation: async () => "0x00",
      },
      gateway: gateway as never,
      dataPointFeed: dataPointFeed as never,
    });
    lites.push(lite);
    return lite;
  };
  // A second, independent reader: its own database, the same registry and blobs.
  const readerDb = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: account.address,
    network: streamSyncNetwork(config.gateway),
    deviceId: "reader",
  });
  drivers.push(readerDb);
  const reader = createLocalSync(
    {
      db: readerDb,
      queue: connectionQueue(),
      ownerAddress: account.address,
      registry,
      blobs,
      keys: createStreamSyncKeyPorts(signature),
      signer: { signAddData: async () => "0x00" },
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => 2000,
      newOp: () => crypto.randomUUID(),
    },
    {
      resolveArtifact: () => declaration,
      declaredStreams: () => ["items"],
      olderVersionReads: () => true,
    },
  );
  const readerKeys = async () => {
    await reader.apply();
    return (
      await reader.query.listRecords({ connectionId, stream: "items" })
    ).records
      .map((r) => r.recordKey)
      .sort();
  };
  return { open, legacy, dataPointFeed, readerKeys };
}

describe("Lite save and delete cycle", () => {
  it("saves, survives a reload, reads from another reader, deletes by tombstone, never touches legacy", async () => {
    const { open, legacy, dataPointFeed, readerKeys } = await world();
    let lite = await open();

    // 1. Begin, one batch with one record, end, publish.
    const intake = lite.streamSyncIntake!;
    await intake.begin("run-save", request(1000));
    await intake.batch("run-save", {
      batch: 0,
      records: [{ stream: "items", data: { id: "rec-1", value: 1 } }],
    });
    const end = {
      outcome: "succeeded" as const,
      coveredStreams: ["items"],
      provenFullStreams: ["items"],
      lastBatch: 0,
    };
    const receipt = await intake.end("run-save", end);
    await lite.syncManager.trigger();

    // 2. Reload: close, reopen on the same database. The end receipt remains.
    await lite.syncManager.stop();
    await lite.closeStreamSync();
    lite = await open();
    expect(await lite.streamSyncIntake!.end("run-save", end)).toEqual(receipt);

    // 3. An independent reader sees the record from the shared registry and blobs.
    expect(await readerKeys()).toEqual(["rec-1"]);

    // 4. A new run tombstones the record's exact key; the reader no longer sees it.
    const next = lite.streamSyncIntake!;
    await next.begin("run-delete", request(2000));
    expect(
      await next.batch("run-delete", {
        batch: 0,
        records: [
          {
            stream: "items",
            op: "delete",
            key: "rec-1",
            data: { id: "rec-1" },
          },
        ],
      }),
    ).toMatchObject({ accepted: 1 });
    await next.end("run-delete", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      lastBatch: 0,
    });
    await lite.syncManager.trigger();
    expect(await readerKeys()).toEqual([]);

    // 5. The legacy data plane was never called.
    expect(legacy).not.toHaveBeenCalled();
    expect(dataPointFeed.getDataPoint).not.toHaveBeenCalled();
    expect(dataPointFeed.listDataPointsByOwner).not.toHaveBeenCalled();
  });

  it("answers the publication of a saved run over HTTP, across a reload, and 404s an unknown run", async () => {
    const { open } = await world();
    let lite = await open();
    const intake = lite.streamSyncIntake!;
    await intake.begin("run-save", request(1000));
    await intake.batch("run-save", {
      batch: 0,
      records: [{ stream: "items", data: { id: "rec-1", value: 1 } }],
    });
    await intake.end("run-save", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      provenFullStreams: ["items"],
      lastBatch: 0,
    });
    const owner = account.address;
    const other = `0x${"2".repeat(40)}` as const;
    const authority = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await authority.ready;
    await authority.submitEvidence({ owner, state: "on" });
    const otherAuthority = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await otherAuthority.ready;
    await otherAuthority.submitEvidence({ owner: other, state: "on" });
    const accessLog = createMemoryPsLiteAccessLogStore();
    const call = async (
      path: string,
      token = "owner-fixture",
      runtimeOwner: `0x${string}` = owner,
    ) =>
      createPsLiteRuntime({
        accessLogReader: accessLog,
        accessLogWriter: accessLog,
        tokenStore: createMemoryPsLiteTokenStore(),
        saveConfig: async () => {},
        stateCapabilities: { config: "memory" },
        mcpConnectionStore: createInMemoryMcpConnectionStore(),
        storage: createMemoryPsLiteStorage(),
        serverOwner: runtimeOwner,
        auth: createBearerTokenPsLiteAuth({
          ownerToken: "owner-fixture",
          builderToken: "builder-fixture",
        }),
        accountModeAuthority:
          runtimeOwner === owner ? authority : otherAuthority,
        active: true,
        localSync: lite.getLocalSync,
      }).fetch(
        new Request("https://fixture.test" + path, {
          headers: { authorization: `Bearer ${token}` },
        }),
      );
    const url = "/v1/stream-sync/runs/run-save/publication";

    // Saved but not yet published.
    expect(await (await call(url)).json()).toMatchObject({
      runId: "run-save",
      state: "pending",
      streams: [{ name: "items", state: "pending" }],
    });
    await lite.syncManager.trigger();
    const published = {
      runId: "run-save",
      state: "published",
      streams: [{ name: "items", state: "published" }],
    };
    expect(await (await call(url)).json()).toMatchObject(published);

    // The answer survives a reload on the same database.
    await lite.syncManager.stop();
    await lite.closeStreamSync();
    lite = await open();
    expect(await (await call(url)).json()).toMatchObject(published);

    const unknown = await call("/v1/stream-sync/runs/nope/publication");
    expect(unknown.status).toBe(404);
    expect((await unknown.json()).error.errorCode).toBe("RUN_NOT_FOUND");
    // The run was written under `owner`; another owner's valid token answers
    // 404 RUN_NOT_FOUND, not 403, so the run's existence is not revealed.
    const crossOwner = await call(url, "owner-fixture", other);
    expect(crossOwner.status).toBe(404);
    expect((await crossOwner.json()).error.errorCode).toBe("RUN_NOT_FOUND");
    expect((await call(url, "builder-fixture")).status).toBeGreaterThanOrEqual(
      401,
    );
    await authority.close();
    await otherAuthority.close();
  });
});
