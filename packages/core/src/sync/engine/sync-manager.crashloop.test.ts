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

const entry = (id: number, scope: string, sizeBytes: number): IndexEntry => ({
  id,
  fileId: null,
  schemaId: null,
  path: `${scope}/2026-11-07T10:0${id}:00Z.json`,
  scope,
  collectedAt: `2026-11-07T10:0${id}:00Z`,
  createdAt: `2026-11-07T10:0${id}:00Z`,
  sizeBytes,
  version: 1,
  dataPointId: null,
});
const heavy = entry(1, "scope.heavy", 1024);
const small = entry(2, "scope.small", 10);

/** A durable value that survives "process death", each boot with its own lock. */
function durableStore() {
  let value: unknown = null;
  let boots = 0;
  return () => {
    const boot = ++boots;
    return {
      namespace: `crash-loop#boot-${boot}`,
      read: async () => structuredClone(value),
      write: async (envelope: unknown) => {
        value = structuredClone(envelope);
      },
      preserveCorrupt: async () => undefined,
    };
  };
}

function boot(
  entries: IndexEntry[],
  uploadAttemptStore: ReturnType<ReturnType<typeof durableStore>>,
) {
  const attempted: string[] = [];
  const storage = {
    findUnsynced: vi.fn(() => entries),
    updateDataPointId: vi.fn().mockReturnValue(true),
    updateEntryVersion: vi.fn().mockReturnValue(true),
    // The body reads and never returns: the process dies inside it.
    readEnvelope: vi.fn((scope: string) => {
      attempted.push(scope);
      return new Promise<DataFileEnvelope>(() => undefined);
    }),
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
    uploadAttemptStore,
  } as never);
  return { manager, attempted };
}

describe("a crash loop", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("quarantines an entry whose upload kills the process, and still uploads a later small one", async () => {
    const next = durableStore();
    // Each boot: the manager starts, the body begins, the process dies. The
    // manager is dropped without stop and nothing settles.
    for (let boots = 1; boots <= 2; boots++) {
      const { manager, attempted } = boot([heavy], next());
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(attempted, `boot ${boots} attempts the entry`).toEqual([
        heavy.scope,
      ]);
    }

    // Third boot: two interrupted attempts quarantined the entry for good.
    const third = boot([heavy, small], next());
    third.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(third.attempted).toEqual([small.scope]);
    expect((await third.manager.getStatus()).uploads?.stopped ?? []).toEqual(
      expect.arrayContaining([expect.objectContaining({ path: heavy.path })]),
    );

    // And it stays out on a fourth boot.
    const fourth = boot([heavy], next());
    fourth.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(fourth.attempted).toEqual([]);
  });
});
