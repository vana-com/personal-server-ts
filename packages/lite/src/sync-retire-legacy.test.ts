import "fake-indexeddb/auto";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemoryStreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createMemoryStreamSyncReadFiles } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { fakeRegistry } from "./test-support/stream-registry.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

const GATEWAY = "https://gateway.local";
const OWNER_KEY = `0x${"13".repeat(32)}` as const;
const OWNER = privateKeyToAccount(OWNER_KEY);
const SCHEMA_ID = `0x${"12".repeat(32)}`;
const SHAPE = { primaryKey: ["id"], profile: { key: null, version: "1.0.0" } };
const SWITCH = "2026-11-05T00:00:00.000Z";
/** A logical stream-sync name doubles as a legacy scope name. */
const SCOPES = ["pdpp.acme.items", "pdpp.acme.orders"];

type Config = {
  streamSync: { write: boolean; read: boolean; switchedAt?: string };
};

/** Legacy rows collected before the switch, as a device holds them. */
async function legacyStorage(collectedAt = "2026-11-01T00:00:00.000Z") {
  const storage = createMemoryPsLiteStorage();
  for (const scope of SCOPES) {
    const envelope = createDataFileEnvelope(
      scope,
      collectedAt,
      { n: 1 },
      `https://schemas.example/${scope}.json`,
      SCHEMA_ID,
    );
    const write = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      fileId: null,
      schemaId: SCHEMA_ID,
      path: write.relativePath,
      scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
  }
  return storage;
}

async function open(
  registry: ReturnType<typeof fakeRegistry>,
  streamSync: Config["streamSync"],
  storage = createMemoryPsLiteStorage(),
) {
  const config = ServerConfigSchema.parse({
    gateway: { url: GATEWAY },
    sync: { enabled: true },
    streamSync,
  });
  const ownerSignature = await OWNER.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature,
  });
  const lite = await createPsLiteSyncManager({
    config,
    storage,
    stateStore,
    ownerSignature,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: OWNER.address,
      signMessage: (message: string) => OWNER.signMessage({ message }),
      signAddData: async () => `0x${"22".repeat(65)}`,
      signLineageAttestation: vi.fn(),
    },
    gateway: {
      getServer: vi.fn().mockResolvedValue({ id: "server-1" }),
    } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({
        dataPoints: registry.feed(),
        cursor: null,
      }),
    } as never,
    autoStartSync: false,
    streamSyncFiles: () => createMemoryStreamSyncFiles(),
    streamSyncRead: { files: createMemoryStreamSyncReadFiles() },
  });
  return { lite, config, storage };
}

/** Publish a complete `acme.items` stream through the real writer. */
async function publishItems(lite: Awaited<ReturnType<typeof open>>["lite"]) {
  const writer = lite.streamSyncWriter!;
  await writer.refreshControls();
  await writer.beginRun({
    runId: "run-1",
    connector: "acme",
    userConnect: false,
    observedAt: Date.parse("2026-11-04T00:00:00Z"),
    identity: "none",
    checkpointUsed: null,
  });
  await writer.declareStream("run-1", "items", SHAPE);
  await writer.append("run-1", "items", { id: "a", v: 1 });
  await writer.finishRun("run-1", {
    checkpointCandidate: { cursor: "run-1" },
    coveredStreams: ["items"],
  });
  await writer.publishPending();
}

const scopesOf = (storage: ReturnType<typeof createMemoryPsLiteStorage>) =>
  storage
    .listScopes({})
    .scopes.map((s: { scope: string }) => s.scope)
    .sort();

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function cycle(o: Awaited<ReturnType<typeof open>>) {
  await o.lite.syncManager.trigger();
}

describe("PS Lite: retire legacy scopes after the switch (real reader and writer)", () => {
  async function switched(
    streamSync: Config["streamSync"],
    collectedAt?: string,
  ) {
    const registry = fakeRegistry(OWNER.address);
    vi.stubGlobal("fetch", registry.fetchImpl);
    const o = await open(
      registry,
      streamSync,
      await legacyStorage(collectedAt),
    );
    await publishItems(o.lite);
    return { registry, ...o };
  }

  it("writer off: nothing is retired, whatever the views say", async () => {
    const registry = fakeRegistry(OWNER.address);
    vi.stubGlobal("fetch", registry.fetchImpl);
    const o = await open(
      registry,
      { write: false, read: true, switchedAt: SWITCH },
      await legacyStorage(),
    );
    await cycle(o);
    await o.lite.syncManager.stop();
    expect(scopesOf(o.storage)).toEqual(SCOPES);
  });

  it("writer on, switch time set: the covered scope is retired, the uncovered one stays", async () => {
    const o = await switched({ write: true, read: true, switchedAt: SWITCH });
    // The real reader maps `pdpp.acme.items` to a complete head; `orders` has none.
    await cycle(o);
    expect(o.lite.streamSyncRead!.viewCoverage("pdpp.acme.items").kind).toBe(
      "covered",
    );
    expect(scopesOf(o.storage)).toEqual(["pdpp.acme.orders"]);
    await o.lite.syncManager.stop();
  });

  it("writer on but no switch time: nothing is retired", async () => {
    const o = await switched({ write: true, read: true });
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(SCOPES);
    await o.lite.syncManager.stop();
  });

  it("a legacy file collected at or after the switch keeps its scope", async () => {
    const o = await switched(
      { write: true, read: true, switchedAt: SWITCH },
      "2026-11-06T00:00:00.000Z",
    );
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(SCOPES);
    expect(o.lite.syncManager.getStatus().streamSync).toEqual({
      legacyWritesAfterSwitch: 2,
    });
    await o.lite.syncManager.stop();
  });

  it("a legacy file newer than the head keeps its scope", async () => {
    // Collected before the switch but after the head was observed (Nov 4).
    const o = await switched(
      { write: true, read: true, switchedAt: "2026-11-09T00:00:00.000Z" },
      "2026-11-05T00:00:00.000Z",
    );
    await cycle(o);
    expect(scopesOf(o.storage)).toContain("pdpp.acme.items");
    await o.lite.syncManager.stop();
  });

  it("turning the switch off mid-run stops retiring on the next cycle", async () => {
    const o = await switched({ write: true, read: true, switchedAt: SWITCH });
    o.config.streamSync.write = false;
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(SCOPES);
    o.config.streamSync.write = true;
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(["pdpp.acme.orders"]);
    await o.lite.syncManager.stop();
  });
});
