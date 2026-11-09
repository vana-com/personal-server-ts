/**
 * A connection delete on PS-Lite, through the real stream-sync writer and an
 * in-memory registry. Rows are written under a declaration; the server then
 * restarts with the connector removed from config. The delete must still
 * answer (no 503 CONNECTOR_NOT_VERIFIED) and tombstone the row.
 */
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createMemoryStreamSyncRegistry,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

const CONNECTOR = "acme";

/** Minimal exclusive Web Locks: `request` queues, `ifAvailable` answers null. */
function fakeLocks() {
  const held = new Set<string>();
  const waiting = new Map<string, Array<() => void>>();
  const request = vi.fn(
    async (
      name: string,
      options: { mode?: string; ifAvailable?: boolean },
      callback: (lock: { name: string } | null) => Promise<unknown>,
    ) => {
      while (held.has(name)) {
        if (options.ifAvailable) return callback(null);
        await new Promise<void>((resolve) => {
          waiting.set(name, [...(waiting.get(name) ?? []), resolve]);
        });
      }
      held.add(name);
      try {
        return await callback({ name });
      } finally {
        held.delete(name);
        waiting.get(name)?.shift()?.();
      }
    },
  );
  return { request, held };
}

let factory: IDBFactory;

beforeEach(() => {
  factory = new IDBFactory();
  vi.stubGlobal("indexedDB", factory);
  vi.stubGlobal("IDBKeyRange", IDBKeyRange);
  vi.stubGlobal("navigator", { locks: fakeLocks() });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * One boot of PS-Lite on the same owner and the same IndexedDB. `declared` is
 * the host's declared names for the connector; the registry is shared across
 * boots, as the gateway would be.
 */
async function boot(registry: StreamSyncRegistry, declared: string[]) {
  const owner = privateKeyToAccount(`0x${"21".repeat(32)}`);
  const ownerSignature = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature,
  });
  return createPsLiteSyncManager({
    streamSyncRegistry: registry,
    streamSyncDeclaredStreams: (connector) =>
      connector === CONNECTOR ? declared : [],
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      streamSync: { write: true },
    }),
    storage: createMemoryPsLiteStorage(),
    stateStore,
    ownerSignature,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: owner.address,
      signMessage: (message: string) => owner.signMessage({ message }),
      signAddData: vi.fn(),
      signLineageAttestation: vi.fn(),
    },
    gateway: { getServer: vi.fn().mockResolvedValue(null) } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
    autoStartSync: false,
  });
}

it("rows written under a declaration survive a restart without the connector in config: the delete answers and tombstones the row (mutant: DURABLE_NAMES_IGNORED)", async () => {
  const registry = createMemoryStreamSyncRegistry();

  const first = await boot(registry, ["items"]);
  const writer = first.streamSyncWriter!;
  await writer.refreshControls();
  await writer.beginRun({
    runId: "run-1",
    connector: CONNECTOR,
    userConnect: false,
    observedAt: Date.now(),
    identity: "none",
    checkpointUsed: null,
  });
  await writer.declareStream("run-1", "items", {
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
  });
  await writer.append("run-1", "items", { id: "a" });
  await writer.finishRun("run-1", { checkpointCandidate: { cursor: "run-1" } });
  await writer.publishPending();

  const rows = await registry.listStreamRows(CONNECTOR);
  expect(rows.length).toBeGreaterThan(0);
  expect(rows.every((row) => row.read.found)).toBe(true);
  const scope = rows[0]!.scope;
  const before = (await registry.read(scope)) as { version: number };

  // A restart with the connector removed from config: no host name, no manifest.
  await first.closeStreamSync();
  const second = await boot(registry, []);
  const delete_ = second.streamSyncWriter!;
  await expect(
    delete_.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await delete_.publishPending();

  // The delete posted a tombstone on the stream row.
  const after = (await registry.read(scope)) as { version: number };
  expect(after.version).toBeGreaterThan(before.version);
});
