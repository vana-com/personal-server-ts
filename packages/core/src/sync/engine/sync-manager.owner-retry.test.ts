import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type {
  DataFileEnvelope,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { SyncCursor } from "../cursor.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

// Only unrelated work is faked. The real createSyncManager drives the real
// uploadAll and a real shared upload tracker.
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(async () => []),
  downloadScopes: vi.fn(),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));
vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  deriveScopeKey: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import { createSyncManager } from "./sync-manager.js";
import { uploadAll } from "../workers/upload.js";
import {
  createUploadStateTracker,
  MAX_UPLOAD_FAILURES,
} from "../upload-state.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SCHEMA_ID =
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const COLLECTED_AT = "2026-11-07T10:00:00Z";
const T0 = Date.parse("2026-11-07T12:00:00Z");
const SECOND = 1000;
const MINUTE = 60 * SECOND;
const MIB = 1024 * 1024;

function row(id: number, scope: string, sizeBytes: number): IndexEntry {
  return {
    id,
    fileId: null,
    schemaId: null,
    path: `${scope}/${COLLECTED_AT}.json`,
    scope,
    collectedAt: COLLECTED_AT,
    createdAt: COLLECTED_AT,
    sizeBytes,
    version: 1,
    dataPointId: null,
  };
}

function makeLogger(): Logger {
  return {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
  } as unknown as Logger;
}

/** Fake storage and transport. Every PUT rejects like a failed fetch. */
function makeFixture(rows: IndexEntry[]) {
  const uploadState = createUploadStateTracker();
  const readEnvelope = vi.fn(
    async (scope: string) =>
      ({
        version: "1.0",
        scope,
        collectedAt: COLLECTED_AT,
        data: { username: "testuser" },
      }) as DataFileEnvelope,
  );
  const put = vi.fn(async (): Promise<string> => {
    throw new Error("Failed to fetch");
  });
  const registerDataPoint = vi.fn();
  const uploadDeps: UploadWorkerDeps = {
    storage: {
      findUnsynced: vi.fn(() => rows),
      readEnvelope,
      updateEntryVersion: vi.fn().mockReturnValue(true),
      updateDataPointId: vi.fn().mockReturnValue(true),
    } as unknown as DataStoragePort,
    storageAdapter: {
      upload: put,
      urlForKey: vi.fn((key: string) => `https://storage.example/${key}`),
      exists: vi.fn().mockResolvedValue(true),
    } as unknown as StorageAdapter,
    gateway: {
      getSchemaForScope: vi.fn().mockResolvedValue({
        id: SCHEMA_ID,
        ownerAddress: OWNER,
        name: "s",
        definitionUrl: "https://schemas.example/s.json",
        scope: "s",
        addedAt: "2026-01-01T00:00:00Z",
      }),
      getDataPoint: vi.fn().mockResolvedValue(null),
      registerDataPoint,
    } as unknown as GatewayClient,
    signer: {
      signAddData: vi.fn().mockResolvedValue("0xadddatasignature"),
      signLineageAttestation: vi.fn().mockResolvedValue("0xlineagesignature"),
    } as unknown as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: makeLogger(),
    uploadState,
  };
  const downloadDeps: DownloadWorkerDeps = {
    storage: {} as DataStoragePort,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    cursor: {
      read: vi.fn().mockResolvedValue(null),
      write: vi.fn().mockResolvedValue(undefined),
    } as SyncCursor,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: makeLogger(),
  };
  // An idle manager: never started, so no start-up cycle and no interval.
  const manager = createSyncManager(uploadDeps, downloadDeps, {
    pollInterval: 60 * MINUTE,
  });
  const at = (offsetMs: number) => vi.setSystemTime(T0 + offsetMs);
  return {
    uploadDeps,
    uploadState,
    manager,
    put,
    readEnvelope,
    registerDataPoint,
    at,
  };
}

describe("sync manager — owner retry with real uploadAll", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Fake the clock only: no timer is used, and promises stay real.
    vi.useFakeTimers({ toFake: ["Date"] });
    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(
      new Uint8Array(32).fill(0xbb),
    );
    (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    );
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  // Failure n waits 2^(n-1) minutes: cumulative offsets of the 8 attempts.
  const BUDGET_OFFSETS_MIN = [0, 1, 3, 7, 15, 31, 63, 123];

  it("gives a stopped entry one immediate attempt on trigger(), then a fresh eight-failure budget", async () => {
    expect(MAX_UPLOAD_FAILURES).toBe(8);
    const small = row(1, "owner.small", 256);
    const f = makeFixture([small]);

    // Eight real worker attempts stop the entry.
    for (const minutes of BUDGET_OFFSETS_MIN) {
      f.at(minutes * MINUTE);
      await uploadAll(f.uploadDeps, {
        now: () => new Date(T0 + minutes * MINUTE),
      });
    }
    expect(f.put).toHaveBeenCalledTimes(8);
    expect(f.uploadState.snapshot().stopped).toEqual([
      expect.objectContaining({ path: small.path, failures: 8 }),
    ]);
    expect(f.uploadState.snapshot().retrying).toEqual([]);

    // A day of ordinary cycles gives it nothing more.
    f.at(30 * 60 * MINUTE);
    await uploadAll(f.uploadDeps);
    expect(f.put).toHaveBeenCalledTimes(8);

    // One trigger() on the idle manager: exactly one immediate attempt.
    const trigger0 = 31 * 60 * MINUTE;
    f.at(trigger0);
    await f.manager.trigger();
    expect(f.put).toHaveBeenCalledTimes(9);

    // Its failure is retrying failures=1 with a 60 s backoff, not a stop.
    expect(f.uploadState.snapshot().stopped).toEqual([]);
    expect(f.uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({
        path: small.path,
        failures: 1,
        nextAttemptAt: new Date(T0 + trigger0 + MINUTE).toISOString(),
      }),
    ]);

    // Further triggers inside the backoff change nothing.
    for (const early of [30 * SECOND, 59_999]) {
      f.at(trigger0 + early);
      await f.manager.trigger();
    }
    expect(f.put).toHaveBeenCalledTimes(9);
    expect(f.uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({
        failures: 1,
        nextAttemptAt: new Date(T0 + trigger0 + MINUTE).toISOString(),
      }),
    ]);

    // Seven more due failures stop it again at a fresh failure 8.
    const dueOffsets = BUDGET_OFFSETS_MIN.slice(1);
    for (const minutes of dueOffsets) {
      f.at(trigger0 + minutes * MINUTE);
      await f.manager.trigger();
    }
    expect(f.put).toHaveBeenCalledTimes(16);
    expect(f.uploadState.snapshot().retrying).toEqual([]);
    expect(f.uploadState.snapshot().stopped).toEqual([
      expect.objectContaining({
        path: small.path,
        failures: 8,
        stoppedAt: new Date(T0 + trigger0 + 123 * MINUTE).toISOString(),
      }),
    ]);

    // Ordinary cycles after the new stop make no further attempt.
    f.at(trigger0 + 124 * MINUTE);
    await uploadAll(f.uploadDeps);
    f.at(trigger0 + 400 * MINUTE);
    await uploadAll(f.uploadDeps);
    expect(f.put).toHaveBeenCalledTimes(16);
  });

  it("does not let repeated early triggers bypass the backoff of an entry that has not stopped", async () => {
    const waiting = row(1, "owner.waiting", 256);
    const f = makeFixture([waiting]);

    f.at(0);
    await f.manager.trigger();
    expect(f.put).toHaveBeenCalledTimes(1);
    const first = f.uploadState.snapshot().retrying;
    expect(first).toEqual([expect.objectContaining({ failures: 1 })]);

    for (const early of [SECOND, 10 * SECOND, 30 * SECOND, 59_999]) {
      f.at(early);
      await f.manager.trigger();
    }
    expect(f.put).toHaveBeenCalledTimes(1);
    expect(f.uploadState.snapshot().retrying).toEqual(first);

    // At the due time one attempt runs; the second wait is two minutes.
    f.at(MINUTE);
    await f.manager.trigger();
    expect(f.put).toHaveBeenCalledTimes(2);
    expect(f.uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({
        failures: 2,
        nextAttemptAt: new Date(T0 + MINUTE + 2 * MINUTE).toISOString(),
      }),
    ]);
  });

  it("never reads, encrypts or sends a too-large entry, however often the owner triggers", async () => {
    const huge = row(1, "owner.huge", 319 * MIB);
    const f = makeFixture([huge]);

    for (let i = 0; i < 3; i++) {
      f.at(i * MINUTE);
      await f.manager.trigger();
    }

    expect(f.uploadState.snapshot().tooLarge).toEqual([
      expect.objectContaining({ path: huge.path }),
    ]);
    expect(f.uploadState.snapshot().stopped).toEqual([]);
    expect(f.uploadState.snapshot().retrying).toEqual([]);
    expect(f.readEnvelope).not.toHaveBeenCalled();
    expect(encryptWithPassword).not.toHaveBeenCalled();
    expect(f.put).not.toHaveBeenCalled();
    expect(f.registerDataPoint).not.toHaveBeenCalled();
  });
});
