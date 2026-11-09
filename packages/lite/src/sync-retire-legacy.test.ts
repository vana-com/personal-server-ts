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
const SWITCH = "2026-11-05T00:00:00.000Z";
const HEAD_AT = Date.parse("2026-11-08T00:00:00Z");
/**
 * A scope with two read targets (the original connector and the browser
 * connector's alternate binding): both must hold a complete head to cover it.
 */
const SCOPE = "strava.activities";
const OTHER = "youtube.likes"; // no view at all
const SCOPES = [OTHER, SCOPE].sort();

const activityRow = (id: string) => ({
  id,
  activity_type: "Ride",
  start_date: "2026-09-20",
  start_date_local: "2026-09-20",
  start_time: "2026-09-20T06:30:00-07:00",
  start_time_basis: "local",
  distance_m: 32150.4,
  moving_time_s: 5400,
  elapsed_time_s: 6120,
  total_elevation_gain_m: 610,
  average_heartrate: null,
  max_heartrate: null,
  calories_kcal: null,
  gear: null,
  freshness: "live",
  exported_at: null,
});

type Config = {
  streamSync: { write: boolean; read: boolean; switchedAt?: string };
};

/** Legacy rows collected before the switch, as a device holds them. */
async function legacyStorage(
  collectedAt = "2026-11-01T00:00:00.000Z",
  ids: readonly string[] = ["a"],
) {
  const storage = createMemoryPsLiteStorage();
  const bodies: Record<string, unknown> = {
    [SCOPE]: { activities: ids.map((id) => ({ id })) },
    [OTHER]: { likedVideos: [{ videoId: "v" }] },
  };
  for (const scope of SCOPES) {
    const envelope = createDataFileEnvelope(
      scope,
      collectedAt,
      bodies[scope] as Record<string, unknown>,
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
  /** The gateway's registry row for the legacy scope, as the feed reads it. */
  legacyRow: { addedAt: string } | null = null,
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
      getDataPoint: async () => (legacyRow ?? null) as never,
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

/** Publish a complete `activities` stream of each target through the real writer. */
async function publishActivities(
  lite: Awaited<ReturnType<typeof open>>["lite"],
  ids: readonly string[] = ["a"],
) {
  const writer = lite.streamSyncWriter!;
  await writer.refreshControls();
  for (const [connector, key] of [
    ["strava", null],
    ["strava-browser", "strava-browser"],
  ] as const) {
    const runId = `run-${connector}`;
    await writer.beginRun({
      runId,
      connector,
      userConnect: false,
      observedAt: HEAD_AT,
      identity: "none",
      checkpointUsed: null,
    });
    await writer.declareStream(runId, "activities", {
      primaryKey: ["id"],
      profile: { key, version: "2.0.0" },
    });
    for (const id of ids)
      await writer.append(runId, "activities", activityRow(id));
    await writer.finishRun(runId, {
      checkpointCandidate: { cursor: runId },
      coveredStreams: ["activities"],
    });
  }
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
    opts: {
      collectedAt?: string;
      localIds?: readonly string[];
      viewIds?: readonly string[];
      legacyRow?: { addedAt: string } | null;
    } = {},
  ) {
    const registry = fakeRegistry(OWNER.address);
    vi.stubGlobal("fetch", registry.fetchImpl);
    const o = await open(
      registry,
      streamSync,
      await legacyStorage(opts.collectedAt, opts.localIds),
      opts.legacyRow ?? null,
    );
    await publishActivities(o.lite, opts.viewIds);
    return { registry, ...o };
  }
  const ON = { write: true, read: true, switchedAt: SWITCH };

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

  it("writer on, switch time set, the view holds every key: the covered scope is retired, the uncovered one stays", async () => {
    const o = await switched(ON, { viewIds: ["a", "b"] });
    await cycle(o);
    expect(o.lite.streamSyncRead!.viewCoverage(SCOPE).kind).toBe("covered");
    expect(scopesOf(o.storage)).toEqual([OTHER]);
    await o.lite.syncManager.stop();
  });

  it("a complete head that lacks a key of the local file keeps the scope (membership, not time)", async () => {
    // Head observed after the file was collected, so time alone would retire it.
    const o = await switched(ON, { localIds: ["a", "b"], viewIds: ["a"] });
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(SCOPES);
    await o.lite.syncManager.stop();
  });

  it("writer on but no switch time: nothing is retired", async () => {
    const o = await switched({ write: true, read: true });
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(SCOPES);
    await o.lite.syncManager.stop();
  });

  it("this device's own rows after the switch report 0 old-app writes and the scope still retires", async () => {
    const o = await switched(ON, { collectedAt: "2026-11-06T00:00:00.000Z" });
    await cycle(o);
    expect(o.lite.syncManager.getStatus().streamSync).toEqual({
      legacyWritesAfterSwitch: 0,
    });
    expect(scopesOf(o.storage)).toEqual([OTHER]);
    await o.lite.syncManager.stop();
  });

  it("a gateway registration after the switch (another device) keeps the scope and counts 1", async () => {
    const o = await switched(ON, {
      legacyRow: { addedAt: "2026-11-07T00:00:00.000Z" },
    });
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(SCOPES);
    expect(o.lite.syncManager.getStatus().streamSync).toEqual({
      legacyWritesAfterSwitch: 1,
    });
    await o.lite.syncManager.stop();
  });

  it("a legacy file newer than the head keeps its scope", async () => {
    const o = await switched(
      { write: true, read: true, switchedAt: "2026-11-20T00:00:00.000Z" },
      { collectedAt: "2026-11-09T00:00:00.000Z" }, // head observed Nov 8
    );
    await cycle(o);
    expect(scopesOf(o.storage)).toContain(SCOPE);
    await o.lite.syncManager.stop();
  });

  it("turning the switch off mid-run stops retiring on the next cycle", async () => {
    const o = await switched(ON);
    o.config.streamSync.write = false;
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual(SCOPES);
    o.config.streamSync.write = true;
    await cycle(o);
    expect(scopesOf(o.storage)).toEqual([OTHER]);
    await o.lite.syncManager.stop();
  });
});
