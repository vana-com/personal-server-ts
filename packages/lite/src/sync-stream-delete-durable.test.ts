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
/** The local disk one PS-Lite home keeps across boots. */
function newDisk() {
  return {
    stateStore: createMemoryPsLiteStateStore(),
    storage: createMemoryPsLiteStorage(),
  };
}

async function boot(
  registry: StreamSyncRegistry,
  declared: string[],
  disk: ReturnType<typeof newDisk> = newDisk(),
) {
  const owner = privateKeyToAccount(`0x${"21".repeat(32)}`);
  const ownerSignature = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = disk.stateStore;
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
    storage: disk.storage,
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

/**
 * Writes one row under `firstDeclared`, restarts with `secondDeclared`, and
 * deletes the connector. Returns the stream row's version before and after.
 */
async function deleteAfterRestart(
  firstDeclared: string[],
  secondDeclared: string[],
) {
  const registry = createMemoryStreamSyncRegistry();

  const first = await boot(registry, firstDeclared);
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
  const second = await boot(registry, secondDeclared);
  const delete_ = second.streamSyncWriter!;
  await expect(
    delete_.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await delete_.publishPending();

  const after = (await registry.read(scope)) as { version: number };
  return { before: before.version, after: after.version };
}

it("rows written under a declaration survive a restart without the connector in config: the delete answers and tombstones the row", async () => {
  const { before, after } = await deleteAfterRestart(["items"], []);
  // The delete posted a tombstone on the stream row.
  expect(after).toBeGreaterThan(before);
});

it("pre-change rows: rows written by a boot that named no streams are deleted after a restart without the connector, with 202 and a tombstone (mutant: PRECHANGE_ROWS_REFUSED)", async () => {
  // The second boot has a new state store, so it holds no durable name: the
  // state an upgrade leaves behind: no name was ever recorded for them.
  const { before, after } = await deleteAfterRestart([], []);
  expect(after).toBeGreaterThan(before);
});

it("rows appended under a declaration and never published: after a restart without the connector, the delete answers 202 and no later publish brings them back", async () => {
  const registry = createMemoryStreamSyncRegistry();
  const disk = newDisk();

  // The run appends, then stops before finishRun and before any publish.
  const first = await boot(registry, ["items"], disk);
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
  await first.closeStreamSync();

  // A restart with the connector absent from config, on the same disk.
  const second = await boot(registry, [], disk);
  const delete_ = second.streamSyncWriter!;
  await expect(
    delete_.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await delete_.publishPending();
  await delete_.publishPending();

  const { pending, finished } = await delete_.status();
  expect(pending).toEqual([]);
  expect(
    finished
      .flatMap((run) => Object.values(run.streams))
      .filter((s) => s.state === "committed"),
  ).toEqual([]);
});

it("rows appended under a declaration, run still open when the delete lands: a later finish is refused and nothing publishes (mutant: UNFINISHED_RUN_STREAMS_IGNORED)", async () => {
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

  // The same process deletes while run-1 is still collecting.
  await expect(
    writer.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await expect(
    writer.finishRun("run-1", { checkpointCandidate: { cursor: "run-1" } }),
  ).rejects.toThrow();
  await writer.publishPending();
  await writer.publishPending();

  const { pending, finished } = await writer.status();
  expect(pending).toEqual([]);
  expect(
    finished
      .flatMap((run) => Object.values(run.streams))
      .filter((s) => s.state === "committed"),
  ).toEqual([]);
});
