import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type {
  DataFileEnvelope,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import {
  createMemoryUploadAttemptStore,
  STOP_REPAIR_WINDOW_MS,
  type UploadAttemptRecord,
  type UploadAttemptStore,
} from "../upload-attempts.js";

// Only the download side is stubbed: the upload worker is the real one.
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(async () => []),
  downloadScopes: vi.fn(async () => []),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));
vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  deriveScopeKey: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

import { createSyncManager } from "./sync-manager.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const HOUR = 3_600_000;

const row: IndexEntry = {
  id: 1,
  fileId: null,
  schemaId: null,
  path: "scope.a/2026-11-07T10:01:00Z.json",
  scope: "scope.a",
  collectedAt: "2026-11-07T10:01:00Z",
  createdAt: "2026-11-07T10:01:00Z",
  sizeBytes: 1024,
  version: 1,
  dataPointId: null,
};

/** One process: the same durable store, a lock of its own. */
function processOver(store: UploadAttemptStore, boot: number) {
  return {
    namespace: `${store.namespace}#boot-${boot}`,
    read: () => store.read(),
    write: (envelope: Parameters<UploadAttemptStore["write"]>[0]) =>
      store.write(envelope),
    preserveCorrupt: (value: unknown, stamp: string) =>
      store.preserveCorrupt(value, stamp),
  } satisfies UploadAttemptStore;
}

function buildManager(store?: UploadAttemptStore) {
  /** Each attempt's body read: settles only when the test says so. */
  const bodies: Array<{ fail(): void }> = [];
  const storage = {
    findUnsynced: vi.fn(() => [row]),
    updateDataPointId: vi.fn().mockReturnValue(true),
    updateEntryVersion: vi.fn().mockReturnValue(true),
    readEnvelope: vi.fn(
      () =>
        new Promise<DataFileEnvelope>((_resolve, reject) => {
          bodies.push({ fail: () => reject(new Error("late failure")) });
        }),
    ),
  } as unknown as DataStoragePort;
  const logger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
  const uploadDeps: UploadWorkerDeps = {
    storage,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    signer: {} as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger,
  };
  const downloadDeps = {
    storage: {},
    storageAdapter: {},
    gateway: {},
    cursor: { read: vi.fn(), write: vi.fn() },
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger,
  } as unknown as DownloadWorkerDeps;
  const manager = createSyncManager(uploadDeps, downloadDeps, {
    pollInterval: 365 * 24 * HOUR,
    ...(store ? { uploadAttemptStore: store } : {}),
  });
  return { manager, bodies, storage };
}

const recordsOf = async (store: UploadAttemptStore) =>
  ((await store.read()) as { records: UploadAttemptRecord[] } | null)
    ?.records ?? [];

describe("upload attempts across manager stop and start", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("keeps an unsettled attempt live across stop/start, so a late settle cannot clear the next attempt's marker", async () => {
    const store = createMemoryUploadAttemptStore();
    const first = buildManager(processOver(store, 1));

    // Attempt A hangs past its deadline and the grace; the cycle gives up on it.
    first.manager.start();
    await vi.advanceTimersByTimeAsync(10 * 60_000 + 5_000);
    expect(first.bodies).toHaveLength(1);
    const stopping = first.manager.stop();
    await vi.advanceTimersByTimeAsync(5_000);
    await stopping;

    // Reactivate the same manager once the failure backoff is due.
    await vi.advanceTimersByTimeAsync(24 * HOUR);
    first.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    // A is still running: no second body may start beside it.
    expect(first.storage.readEnvelope).toHaveBeenCalledTimes(1);

    // A settles late. Only then may the entry be attempted again (B).
    first.bodies[0]!.fail();
    await vi.advanceTimersByTimeAsync(0);
    void first.manager.trigger();
    await vi.advanceTimersByTimeAsync(0);
    expect(first.storage.readEnvelope).toHaveBeenCalledTimes(2);
    expect(await recordsOf(store)).toEqual([
      expect.objectContaining({ inFlight: true }),
    ]);

    // B kills the process. The next boot counts it (and tries the entry once
    // more, so the record is in flight again).
    const reboot = buildManager(processOver(store, 2));
    reboot.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(await recordsOf(store)).toEqual([
      expect.objectContaining({ interrupted: 1 }),
    ]);
  });

  it("with no store namespace, stop waits for live work, so a rebuilt manager cannot overlap it", async () => {
    const first = buildManager(); // the in-memory fallback names no store
    first.manager.start();
    await vi.advanceTimersByTimeAsync(10 * 60_000 + 5_000);
    expect(first.bodies).toHaveLength(1);

    let stopped = false;
    const stopping = first.manager.stop().then(() => {
      stopped = true;
    });
    await vi.advanceTimersByTimeAsync(24 * HOUR);
    expect(stopped).toBe(false); // the read is still live

    first.bodies[0]!.fail();
    await vi.advanceTimersByTimeAsync(0);
    await stopping;
    expect(stopped).toBe(true);
  });

  it("with a stable namespace, stop is bounded and a rebuilt manager over the same store is excluded", async () => {
    const store = createMemoryUploadAttemptStore();
    const first = buildManager(store);
    first.manager.start();
    await vi.advanceTimersByTimeAsync(10 * 60_000 + 5_000);
    const stopping = first.manager.stop();
    await vi.advanceTimersByTimeAsync(10_000);
    await stopping; // resolved although the read is still live

    const second = buildManager(store);
    second.manager.start();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(second.storage.readEnvelope).not.toHaveBeenCalled();
  });

  it("records a failed stop, resolves it, and the old manager hands the store over once storage heals", async () => {
    const inner = createMemoryUploadAttemptStore();
    let failWrites = false;
    const store: UploadAttemptStore = {
      namespace: inner.namespace,
      read: () => inner.read(),
      write: async (envelope) => {
        if (failWrites) throw new Error("disk full");
        await inner.write(envelope);
      },
      preserveCorrupt: () => inner.preserveCorrupt(),
    };
    const first = buildManager(store);
    first.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(first.bodies).toHaveLength(1);

    // The body fails while storage is down: the settlement cannot be saved.
    failWrites = true;
    first.bodies[0]!.fail();
    await vi.advanceTimersByTimeAsync(0);
    // The stop retries the refused repair for the whole window, then resolves.
    const stopping = first.manager.stop();
    await vi.advanceTimersByTimeAsync(STOP_REPAIR_WINDOW_MS + 1_000);
    await stopping; // does not reject

    const errors = first.manager.getStatus().errors.map((e) => e.message);
    expect(errors.join("\n")).toMatch(/could not be saved on stop/);

    // Storage heals; nobody calls the old manager again.
    failWrites = false;
    await vi.advanceTimersByTimeAsync(60_000);
    const second = buildManager(store);
    second.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(second.storage.readEnvelope).toHaveBeenCalledTimes(1);
    const [stored] = await recordsOf(store);
    expect(stored).toEqual(expect.objectContaining({ interrupted: 0 }));
  });
});
