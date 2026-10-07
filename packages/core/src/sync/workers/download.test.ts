import { describe, it, expect, vi, beforeEach } from "vitest";

import type { DownloadWorkerDeps } from "./download.js";
import { downloadOne, downloadAll, downloadScopes } from "./download.js";
import { createDownloadRetryMemory } from "../retry-memory.js";
import type {
  DataFileEnvelope,
  DataPointRecord,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { SyncCursor } from "../cursor.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "../tombstone.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import { computeQuestion } from "../../derivatives/compute.js";
import { createFakeInferenceProvider } from "../../derivatives/inference.js";
import { createInMemoryQuestionStore } from "../../derivatives/store.js";

vi.mock("@opendatalabs/vana-sdk/browser", async (importOriginal) => ({
  ...(await importOriginal()),
  deriveScopeKey: vi.fn(),
  decryptWithPassword: vi.fn(),
}));

import {
  decryptWithPassword,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/browser";

const SCOPE = "instagram.profile";
const COLLECTED_AT = "2026-01-21T10:00:00Z";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const DATA_POINT_ID =
  "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const EXPECTED_VERSION = "1";
// The download worker reconstructs the version-keyed URL from the record's
// (scope, expectedVersion); the adapter maps that key back to a URL.
const STORAGE_KEY = `${SCOPE}/${EXPECTED_VERSION}`;
const STORAGE_URL = `https://storage.vana.com/v1/blobs/${OWNER}/${STORAGE_KEY}`;

function makeDataPointRecord(
  overrides?: Partial<DataPointRecord>,
): DataPointRecord {
  return {
    id: DATA_POINT_ID,
    ownerAddress: OWNER,
    scope: SCOPE,
    dataHash: "0x" + "11".repeat(32),
    metadataHash: "0x" + "22".repeat(32),
    expectedVersion: EXPECTED_VERSION,
    addedAt: "2026-01-21T10:00:00Z",
    ...overrides,
  };
}

function makeEnvelope(): DataFileEnvelope {
  return {
    version: "1.0",
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    data: { username: "testuser" },
  };
}

function makeMockDeps(): DownloadWorkerDeps {
  const mockStorage: Partial<DataStoragePort> = {
    findEntry: vi.fn().mockReturnValue(undefined),
    findByDataPointId: vi.fn().mockReturnValue(undefined),
    writeEnvelope: vi.fn().mockResolvedValue({
      path: `/tmp/data/${SCOPE}/${COLLECTED_AT}.json`,
      relativePath: `${SCOPE}/${COLLECTED_AT}.json`,
      sizeBytes: 128,
    }),
    insertEntry: vi.fn().mockImplementation((entry) => ({
      id: 1,
      createdAt: "2026-01-21T10:00:00Z",
      ...entry,
    })),
    updateDataPointId: vi.fn().mockResolvedValue(true),
  };

  const mockStorageAdapter: Partial<StorageAdapter> = {
    urlForKey: vi
      .fn()
      .mockImplementation(
        (key: string) => `https://storage.vana.com/v1/blobs/${OWNER}/${key}`,
      ),
    download: vi.fn().mockResolvedValue(new Uint8Array([0xde, 0xad])),
  };

  const mockGateway: Partial<GatewayClient> = {
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
  };

  const mockCursor: SyncCursor = {
    read: vi.fn().mockResolvedValue(null),
    write: vi.fn().mockResolvedValue(undefined),
  };

  const mockLogger: Partial<Logger> = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  };

  return {
    storage: mockStorage as DataStoragePort,
    storageAdapter: mockStorageAdapter as StorageAdapter,
    gateway: mockGateway as GatewayClient,
    cursor: mockCursor,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: mockLogger as Logger,
  };
}

describe("download worker", () => {
  const SCOPE_KEY = new Uint8Array(32).fill(0xbb);
  const SCOPE_KEY_HEX = Buffer.from(SCOPE_KEY).toString("hex");
  const RELATIVE_PATH = `${SCOPE}/${COLLECTED_AT}.json`;

  beforeEach(() => {
    vi.clearAllMocks();

    const envelope = makeEnvelope();
    const plaintextBytes = new TextEncoder().encode(JSON.stringify(envelope));

    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(SCOPE_KEY);
    (decryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      plaintextBytes,
    );
  });

  describe("downloadOne", () => {
    it("skips if dataPointId already in index (dedup)", async () => {
      const deps = makeMockDeps();
      const existingEntry: IndexEntry = {
        id: 1,
        fileId: null,
        schemaId: null,
        path: RELATIVE_PATH,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        createdAt: "2026-01-21T10:00:00Z",
        sizeBytes: 128,
        version: 1,
        dataPointId: DATA_POINT_ID,
      };
      (
        deps.storage.findByDataPointId as ReturnType<typeof vi.fn>
      ).mockReturnValue(existingEntry);

      const record = makeDataPointRecord();
      const result = await downloadOne(deps, record);

      expect(result).toBeNull();
      expect(deps.storageAdapter.download).not.toHaveBeenCalled();
    });

    it("downloads a newer version of a data point indexed at an older one", async () => {
      // DPv2 ids are per (owner, scope): every version of a scope shares
      // one id, so the id alone must not dedup a new version away.
      const deps = makeMockDeps();
      (
        deps.storage.findByDataPointId as ReturnType<typeof vi.fn>
      ).mockReturnValue({
        id: 1,
        fileId: null,
        schemaId: null,
        path: `${SCOPE}/2026-01-20T10:00:00Z.json`,
        scope: SCOPE,
        collectedAt: "2026-01-20T10:00:00Z",
        createdAt: "2026-01-20T10:00:00Z",
        sizeBytes: 128,
        version: 1,
        dataPointId: DATA_POINT_ID,
      } satisfies IndexEntry);

      const result = await downloadOne(
        deps,
        makeDataPointRecord({ expectedVersion: "3" }),
      );

      expect(deps.storageAdapter.urlForKey).toHaveBeenCalledWith(`${SCOPE}/3`);
      expect(deps.storage.insertEntry).toHaveBeenCalledWith(
        expect.objectContaining({
          collectedAt: COLLECTED_AT,
          version: 3,
          dataPointId: DATA_POINT_ID,
        }),
      );
      expect(result).not.toBeNull();
    });

    it("still skips when the indexed version is newer than the listed one", async () => {
      const deps = makeMockDeps();
      (
        deps.storage.findByDataPointId as ReturnType<typeof vi.fn>
      ).mockReturnValue({
        id: 1,
        fileId: null,
        schemaId: null,
        path: RELATIVE_PATH,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        createdAt: "2026-01-21T10:00:00Z",
        sizeBytes: 128,
        version: 4,
        dataPointId: DATA_POINT_ID,
      } satisfies IndexEntry);

      const result = await downloadOne(
        deps,
        makeDataPointRecord({ expectedVersion: "3" }),
      );

      expect(result).toBeNull();
      expect(deps.storageAdapter.download).not.toHaveBeenCalled();
    });

    it("adopts the listed version on a local copy found by collectedAt", async () => {
      // Without this the copy keeps its old version and the next cycle
      // downloads the same blob again.
      const deps = makeMockDeps();
      (deps.storage as { updateEntryVersion?: unknown }).updateEntryVersion = vi
        .fn()
        .mockResolvedValue(true);
      (deps.storage.findEntry as ReturnType<typeof vi.fn>).mockReturnValue({
        id: 2,
        fileId: null,
        schemaId: null,
        path: RELATIVE_PATH,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        createdAt: "2026-01-21T10:00:00Z",
        sizeBytes: 128,
        version: 1,
        dataPointId: DATA_POINT_ID,
      } satisfies IndexEntry);

      const result = await downloadOne(
        deps,
        makeDataPointRecord({ expectedVersion: "2" }),
      );

      expect(result).toBeNull();
      expect(deps.storage.updateEntryVersion).toHaveBeenCalledWith(
        RELATIVE_PATH,
        2,
      );
      expect(deps.storage.insertEntry).not.toHaveBeenCalled();
    });

    it("downloads, decrypts, writes, and indexes data point", async () => {
      const deps = makeMockDeps();
      const record = makeDataPointRecord();

      const result = await downloadOne(deps, record);

      // URL is reconstructed from (scope, expectedVersion), then downloaded.
      expect(deps.storageAdapter.urlForKey).toHaveBeenCalledWith(STORAGE_KEY);
      expect(deps.storageAdapter.download).toHaveBeenCalledWith(STORAGE_URL);

      // Verify decrypt was called with the scope-derived key
      expect(decryptWithPassword).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        SCOPE_KEY_HEX,
      );

      // Verify write was called with envelope
      expect(deps.storage.writeEnvelope).toHaveBeenCalledWith({
        version: "1.0",
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        data: { username: "testuser" },
      });

      // Verify index insert carries dataPointId + version
      expect(deps.storage.insertEntry).toHaveBeenCalledWith({
        fileId: null,
        schemaId: null,
        path: RELATIVE_PATH,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        sizeBytes: 128,
        version: 1,
        dataPointId: DATA_POINT_ID,
      });

      // Verify result
      expect(result).toEqual({
        dataPointId: DATA_POINT_ID,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        path: RELATIVE_PATH,
      });
    });

    it("clears the encrypted download after decryption completes", async () => {
      const deps = makeMockDeps();
      const encrypted = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      (
        deps.storageAdapter.download as ReturnType<typeof vi.fn>
      ).mockResolvedValue(encrypted);

      await downloadOne(deps, makeDataPointRecord());

      expect(encrypted).toEqual(new Uint8Array(encrypted.byteLength));
    });

    it("skips and attaches dataPointId when the same version already exists locally", async () => {
      const deps = makeMockDeps();
      const existingEntry: IndexEntry = {
        id: 1,
        fileId: null,
        schemaId: null,
        path: RELATIVE_PATH,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        createdAt: "2026-01-21T10:00:00Z",
        sizeBytes: 128,
        version: 1,
        dataPointId: null,
      };
      (deps.storage.findEntry as ReturnType<typeof vi.fn>).mockReturnValue(
        existingEntry,
      );

      const result = await downloadOne(deps, makeDataPointRecord());

      expect(result).toBeNull();
      expect(deps.storage.updateDataPointId).toHaveBeenCalledWith(
        RELATIVE_PATH,
        DATA_POINT_ID,
      );
      expect(deps.storage.writeEnvelope).not.toHaveBeenCalled();
      expect(deps.storage.insertEntry).not.toHaveBeenCalled();
    });

    it("derives the scope key straight from the record scope", async () => {
      const deps = makeMockDeps();
      const record = makeDataPointRecord();

      await downloadOne(deps, record);

      expect(deriveScopeKey).toHaveBeenCalledWith(deps.masterKey, SCOPE);
    });

    it("validates envelope against DataFileEnvelopeSchema", async () => {
      const deps = makeMockDeps();
      const record = makeDataPointRecord();

      // Return invalid envelope (missing required fields)
      const invalidPlaintext = new TextEncoder().encode(
        JSON.stringify({ invalid: true }),
      );
      (decryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
        invalidPlaintext,
      );

      await expect(downloadOne(deps, record)).rejects.toThrow();
    });

    it("throws on decrypt failure (wrong key / corrupted)", async () => {
      const deps = makeMockDeps();
      const record = makeDataPointRecord();

      (decryptWithPassword as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error("Error decrypting message: Session key decryption failed."),
      );

      await expect(downloadOne(deps, record)).rejects.toThrow(
        "Session key decryption failed",
      );
    });
  });

  describe("downloadAll", () => {
    it("polls gateway with cursor from config", async () => {
      const deps = makeMockDeps();
      const cursorValue = "opaque-cursor-1";
      (deps.cursor.read as ReturnType<typeof vi.fn>).mockResolvedValue(
        cursorValue,
      );

      await downloadAll(deps);

      expect(deps.cursor.read).toHaveBeenCalled();
      expect(deps.gateway.listDataPointsByOwner).toHaveBeenCalledWith(
        OWNER,
        cursorValue,
      );
    });

    it("advances cursor after processing", async () => {
      const deps = makeMockDeps();
      const nextCursor = "opaque-cursor-2";
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [makeDataPointRecord()],
        cursor: nextCursor,
      });

      await downloadAll(deps);

      expect(deps.cursor.write).toHaveBeenCalledWith(nextCursor);
    });

    it("does not advance cursor when nextCursor is null", async () => {
      const deps = makeMockDeps();
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [makeDataPointRecord()],
        cursor: null,
      });

      await downloadAll(deps);

      expect(deps.cursor.write).not.toHaveBeenCalled();
    });

    it("continues on individual data-point failure without advancing cursor", async () => {
      const deps = makeMockDeps();
      const dataPoints = [
        makeDataPointRecord({ id: "0x01", expectedVersion: "1" }),
        makeDataPointRecord({ id: "0x02", expectedVersion: "2" }),
        makeDataPointRecord({ id: "0x03", expectedVersion: "3" }),
      ];
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints,
        cursor: "opaque-cursor-2",
      });

      // Make the second data point fail at the storage download step.
      let callCount = 0;
      (
        deps.storageAdapter.download as ReturnType<typeof vi.fn>
      ).mockImplementation(() => {
        callCount++;
        if (callCount === 2) return Promise.reject(new Error("blob 404"));
        return Promise.resolve(new Uint8Array([0xde, 0xad]));
      });

      const results = await downloadAll(deps);

      // First and third succeed, second fails
      expect(results).toHaveLength(2);
      expect(deps.logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ dataPointId: "0x02" }),
        "Failed to download data point",
      );
      expect(deps.cursor.write).not.toHaveBeenCalled();
    });

    it("quarantines a message-embedded 404 download failure and advances the cursor", async () => {
      const deps = makeMockDeps();
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [makeDataPointRecord()],
        cursor: "opaque-cursor-2",
      });
      // The SDK's vana-storage provider carries the HTTP status only in the
      // message — no numeric status property.
      (
        deps.storageAdapter.download as ReturnType<typeof vi.fn>
      ).mockRejectedValue(
        Object.assign(
          new Error("vana-storage download failed: 404 Not Found"),
          {
            name: "StorageError",
          },
        ),
      );

      const results = await downloadAll(deps);

      expect(results).toEqual([]);
      // Deterministic → quarantined, not "failed": the cursor advances so one
      // missing blob can't wedge the whole sync listing.
      expect(deps.logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ stage: "download", scope: SCOPE }),
        "Quarantined corrupt synced data point",
      );
      expect(deps.cursor.write).toHaveBeenCalledWith("opaque-cursor-2");
    });
  });

  describe("downloadScopes", () => {
    it("downloads only the requested scope without reading or writing the cursor", async () => {
      const requestedScope = "chatgpt.conversations";
      const records = Array.from({ length: 12 }, (_, index) =>
        makeDataPointRecord({
          id: `0x${String(index + 1).padStart(64, "0")}`,
          scope: index === 7 ? requestedScope : `decoy.scope.${index}`,
        }),
      );
      const deps = makeMockDeps();
      deps.dataPointFeed = {
        listDataPointsByOwner: vi.fn().mockResolvedValue({
          dataPoints: records,
          cursor: null,
        }),
        getDataPoint: vi.fn(
          async ({ scope }) =>
            records.find((record) => record.scope === scope) ?? null,
        ),
      };
      const envelope = { ...makeEnvelope(), scope: requestedScope };
      (decryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
        new TextEncoder().encode(JSON.stringify(envelope)),
      );

      await downloadScopes(deps, [requestedScope]);

      expect(deps.dataPointFeed.getDataPoint).toHaveBeenCalledWith({
        ownerAddress: OWNER,
        scope: requestedScope,
      });
      expect(deps.dataPointFeed.listDataPointsByOwner).not.toHaveBeenCalled();
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(1);
      expect(deps.cursor.read).not.toHaveBeenCalled();
      expect(deps.cursor.write).not.toHaveBeenCalled();
    });

    it("reconciles a requested tombstone and updates deletion memory", async () => {
      const deletedAt = "2026-02-01T00:00:00.000Z";
      const record = { ...makeDataPointRecord(), deletedAt };
      const deps = makeMockDeps();
      deps.storage.listVersions = vi.fn().mockReturnValue([
        {
          id: 1,
          fileId: null,
          schemaId: null,
          path: RELATIVE_PATH,
          scope: SCOPE,
          collectedAt: COLLECTED_AT,
          createdAt: COLLECTED_AT,
          sizeBytes: 128,
          version: 1,
          dataPointId: DATA_POINT_ID,
        },
      ]);
      deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
      deps.dataPointFeed = {
        listDataPointsByOwner: vi.fn(),
        getDataPoint: vi.fn().mockResolvedValue(record),
      };
      deps.scopeDeletions = {
        markDeleted: vi.fn(),
        markLive: vi.fn(),
        noteFeedSynced: vi.fn(),
        knownDeletion: vi.fn(() => null),
        feedAgeMs: vi.fn(() => null),
        resolve: vi.fn(),
        maxStalenessMs: 0,
      };

      await downloadScopes(deps, [SCOPE]);

      expect(deps.storageAdapter.download).not.toHaveBeenCalled();
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        COLLECTED_AT,
      );
      expect(deps.scopeDeletions.markDeleted).toHaveBeenCalledWith(SCOPE, {
        deletedAt,
        version: EXPECTED_VERSION,
      });
      expect(deps.cursor.read).not.toHaveBeenCalled();
      expect(deps.cursor.write).not.toHaveBeenCalled();
    });

    it("quarantines a corrupt requested scope without throwing", async () => {
      const deps = makeMockDeps();
      deps.dataPointFeed = {
        listDataPointsByOwner: vi.fn(),
        getDataPoint: vi.fn().mockResolvedValue(makeDataPointRecord()),
      };
      deps.storageAdapter.download = vi
        .fn()
        .mockRejectedValue(
          Object.assign(
            new Error("vana-storage download failed: 404 Not Found"),
            { name: "StorageError" },
          ),
        );
      const retryMemory = createDownloadRetryMemory({ now: () => 0 });

      await expect(
        downloadScopes(deps, [SCOPE], { retryMemory }),
      ).resolves.toEqual([]);

      expect(deps.logger.warn).toHaveBeenCalledWith(
        expect.objectContaining({ stage: "download", scope: SCOPE }),
        "Quarantined corrupt synced data point",
      );
    });
  });

  describe("downloadAll — cross-cycle retry memory", () => {
    const STORAGE_404 = () =>
      Object.assign(new Error("vana-storage download failed: 404 Not Found"), {
        name: "StorageError",
      });
    const STORAGE_503 = () =>
      Object.assign(
        new Error("vana-storage download failed: 503 Service Unavailable"),
        { name: "StorageError" },
      );

    it("never re-attempts a 404 blob in later cycles", async () => {
      const deps = makeMockDeps();
      const memory = createDownloadRetryMemory({ now: () => 0 });
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [makeDataPointRecord()],
        cursor: null,
      });
      (
        deps.storageAdapter.download as ReturnType<typeof vi.fn>
      ).mockRejectedValue(STORAGE_404());

      await downloadAll(deps, { retryMemory: memory });
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(1);

      // The single-page listing has no nextCursor, so the same record is
      // re-listed every cycle — the memory must gate the re-download.
      await downloadAll(deps, { retryMemory: memory });
      await downloadAll(deps, { retryMemory: memory });
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(1);
    });

    it("backs off transient failures and blocks the cursor while waiting", async () => {
      const deps = makeMockDeps();
      let nowMs = 0;
      const memory = createDownloadRetryMemory({
        now: () => nowMs,
        backoffBaseMs: 30_000,
      });
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [makeDataPointRecord()],
        cursor: "opaque-cursor-2",
      });
      (
        deps.storageAdapter.download as ReturnType<typeof vi.fn>
      ).mockRejectedValue(STORAGE_503());

      await downloadAll(deps, { retryMemory: memory });
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(1);

      // Within the backoff window: no re-attempt, and the cursor must stay
      // blocked so the record is still listed when the backoff expires.
      nowMs = 1_000;
      await downloadAll(deps, { retryMemory: memory });
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(1);
      expect(deps.cursor.write).not.toHaveBeenCalled();

      // Past the backoff window: retried.
      nowMs = 30_000;
      await downloadAll(deps, { retryMemory: memory });
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(2);
    });

    it("gives up on transient failures after the cap and unblocks the cursor", async () => {
      const deps = makeMockDeps();
      let nowMs = 0;
      const memory = createDownloadRetryMemory({
        now: () => nowMs,
        backoffBaseMs: 0,
        maxTransientAttempts: 2,
      });
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [makeDataPointRecord()],
        cursor: "opaque-cursor-2",
      });
      (
        deps.storageAdapter.download as ReturnType<typeof vi.fn>
      ).mockRejectedValue(STORAGE_503());

      await downloadAll(deps, { retryMemory: memory }); // attempt 1
      nowMs = 1;
      await downloadAll(deps, { retryMemory: memory }); // attempt 2 (cap)
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(2);
      expect(deps.cursor.write).not.toHaveBeenCalled();

      // Cap reached → give up: no further attempts, and the cursor advances
      // so the exhausted record can't wedge the rest of the listing.
      nowMs = 2;
      await downloadAll(deps, { retryMemory: memory });
      expect(deps.storageAdapter.download).toHaveBeenCalledTimes(2);
      expect(deps.cursor.write).toHaveBeenCalledWith("opaque-cursor-2");
    });

    it("clears the failure history when a retry succeeds", async () => {
      const deps = makeMockDeps();
      let nowMs = 0;
      const memory = createDownloadRetryMemory({
        now: () => nowMs,
        backoffBaseMs: 0,
        maxTransientAttempts: 2,
      });
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [makeDataPointRecord()],
        cursor: null,
      });
      const download = deps.storageAdapter.download as ReturnType<typeof vi.fn>;

      download.mockRejectedValueOnce(STORAGE_503()); // cycle 1: fail (1 attempt)
      await downloadAll(deps, { retryMemory: memory });
      nowMs = 1;
      await downloadAll(deps, { retryMemory: memory }); // cycle 2: succeeds
      expect(download).toHaveBeenCalledTimes(2);

      // History cleared by the success: two fresh failures fit under the cap.
      download.mockRejectedValue(STORAGE_503());
      nowMs = 2;
      await downloadAll(deps, { retryMemory: memory }); // fresh attempt 1
      nowMs = 3;
      await downloadAll(deps, { retryMemory: memory }); // fresh attempt 2
      expect(download).toHaveBeenCalledTimes(4);
    });

    it("full reconcile refreshes exhausted transient budgets but not 404s", async () => {
      const deps = makeMockDeps();
      let nowMs = 0;
      const memory = createDownloadRetryMemory({
        now: () => nowMs,
        backoffBaseMs: 0,
        maxTransientAttempts: 1,
      });
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [
          makeDataPointRecord({ id: "0xaa", expectedVersion: "1" }),
          makeDataPointRecord({ id: "0xbb", expectedVersion: "1" }),
        ],
        cursor: null,
      });
      const download = deps.storageAdapter.download as ReturnType<typeof vi.fn>;
      // 0xaa fails transiently, 0xbb 404s.
      download
        .mockRejectedValueOnce(STORAGE_503())
        .mockRejectedValueOnce(STORAGE_404());

      await downloadAll(deps, { retryMemory: memory });
      expect(download).toHaveBeenCalledTimes(2);

      // Both exhausted/dead — a plain cycle attempts neither.
      nowMs = 1;
      await downloadAll(deps, { retryMemory: memory });
      expect(download).toHaveBeenCalledTimes(2);

      // An explicit reconcile exists to re-fetch: the transient record gets
      // a fresh budget; the 404 stays dead.
      download.mockResolvedValue(new Uint8Array([0xde, 0xad]));
      nowMs = 2;
      await downloadAll(deps, { fullReconcile: true, retryMemory: memory });
      expect(download).toHaveBeenCalledTimes(3);
      expect(download).toHaveBeenLastCalledWith(
        expect.stringContaining(`${SCOPE}/1`),
      );
    });
  });

  describe("deletion reconciliation (durable delete)", () => {
    const DELETED_AT = "2026-02-01T00:00:00.000Z";

    function syncedEntry(overrides?: Partial<IndexEntry>): IndexEntry {
      return {
        id: 1,
        fileId: null,
        schemaId: null,
        path: RELATIVE_PATH,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        createdAt: "2026-01-21T10:00:00Z",
        sizeBytes: 128,
        version: 1,
        dataPointId: DATA_POINT_ID,
        ...overrides,
      };
    }

    function withLocalVersions(
      deps: DownloadWorkerDeps,
      entries: IndexEntry[],
    ) {
      deps.storage.listVersions = vi.fn().mockReturnValue(entries);
      deps.storage.deleteVersion = vi.fn(async () => true);
      return deps;
    }

    // Resurrection reproduction. Before this change the worker ignored the
    // gateway's deletion marker: the point was still listed, the local index
    // no longer had it (the owner deleted the scope), so the worker
    // downloaded and re-indexed it -- the deleted scope came back on the next
    // cycle. Now a tombstoned row is never downloaded.
    it("does not resurrect a scope the gateway reports as deleted (includeDeleted feed)", async () => {
      const deps = withLocalVersions(makeMockDeps(), []);
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [
          {
            ...makeDataPointRecord({ expectedVersion: "2" }),
            deletedAt: DELETED_AT,
          },
        ],
        cursor: null,
      });

      const results = await downloadAll(deps);

      expect(results).toEqual([]);
      expect(deps.storageAdapter.download).not.toHaveBeenCalled();
      expect(deps.storage.writeEnvelope).not.toHaveBeenCalled();
      expect(deps.storage.insertEntry).not.toHaveBeenCalled();
    });

    it("removes the local synced copy and stale unsynced versions, keeps a re-ingest newer than the deletion", async () => {
      const synced = syncedEntry();
      // Ingested without knowledge of the tombstone; its clock-ahead
      // createdAt and higher local version do not save it.
      const staleUnsynced = syncedEntry({
        id: 2,
        collectedAt: "2026-01-25T00:00:00Z",
        createdAt: "2099-01-25T00:00:00Z",
        version: 2,
        dataPointId: null,
      });
      // Ingested on top of the tombstone (version 1): a deliberate re-add.
      const reIngest = syncedEntry({
        id: 3,
        collectedAt: "2026-03-01T00:00:00Z",
        createdAt: "2026-03-01T00:00:00Z",
        version: 3,
        dataPointId: null,
        afterTombstoneVersion: 1,
      });
      const deps = withLocalVersions(makeMockDeps(), [
        synced,
        staleUnsynced,
        reIngest,
      ]);
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [{ ...makeDataPointRecord(), deletedAt: DELETED_AT }],
        cursor: "next",
      });

      await downloadAll(deps);

      expect(deps.storage.deleteVersion).toHaveBeenCalledTimes(2);
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        synced.collectedAt,
      );
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        staleUnsynced.collectedAt,
      );
      expect(deps.storage.deleteVersion).not.toHaveBeenCalledWith(
        SCOPE,
        reIngest.collectedAt,
      );
      expect(deps.cursor.write).toHaveBeenCalledWith("next");
    });

    it("queues the exact key of a dropped unsynced entry above the tombstone version for cleanup", async () => {
      // This replica may have uploaded version 9 before registering it (or
      // crashed in between); the deleting replica only enumerates registry
      // versions up to the tombstone, so this key is ours to clean up.
      const deps = withLocalVersions(makeMockDeps(), [
        syncedEntry({ id: 1, version: 1 }),
        syncedEntry({ id: 2, version: 9, dataPointId: null }),
      ]);
      const pendingBlobDeletions = {
        list: vi.fn(async () => []),
        add: vi.fn(async () => undefined),
        remove: vi.fn(async () => undefined),
      };
      deps.pendingBlobDeletions = pendingBlobDeletions;
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [
          {
            ...makeDataPointRecord({ expectedVersion: "2" }),
            deletedAt: DELETED_AT,
          },
        ],
        cursor: null,
      });

      await downloadAll(deps);

      expect(deps.storage.deleteVersion).toHaveBeenCalledTimes(2);
      expect(pendingBlobDeletions.add).toHaveBeenCalledWith([
        { scope: SCOPE, version: "9" },
      ]);
    });

    it("feeds the read-side deletion memory from every listed row and marks a complete pass", async () => {
      const deps = withLocalVersions(makeMockDeps(), []);
      // The live row is already indexed, so no download is attempted for it.
      deps.storage.findByDataPointId = vi
        .fn()
        .mockImplementation((id: string) =>
          id === "0xother" ? syncedEntry({ dataPointId: id }) : undefined,
        );
      const scopeDeletions = {
        markDeleted: vi.fn(),
        markLive: vi.fn(),
        noteFeedSynced: vi.fn(),
        knownDeletion: vi.fn(() => null),
        feedAgeMs: vi.fn(() => null),
        resolve: vi.fn(),
        maxStalenessMs: 0,
      };
      deps.scopeDeletions = scopeDeletions;
      const listing = deps.gateway.listDataPointsByOwner as ReturnType<
        typeof vi.fn
      >;
      listing.mockResolvedValueOnce({
        dataPoints: [
          { ...makeDataPointRecord(), deletedAt: DELETED_AT },
          makeDataPointRecord({ id: "0xother", scope: "other.scope" }),
        ],
        cursor: "more-pages",
      });

      await downloadAll(deps);

      expect(scopeDeletions.markDeleted).toHaveBeenCalledWith(SCOPE, {
        deletedAt: DELETED_AT,
        version: "1",
      });
      expect(scopeDeletions.markLive).toHaveBeenCalledWith("other.scope");
      // More pages remain: the memory is not complete yet.
      expect(scopeDeletions.noteFeedSynced).not.toHaveBeenCalled();

      listing.mockResolvedValueOnce({ dataPoints: [], cursor: null });
      await downloadAll(deps);
      expect(scopeDeletions.noteFeedSynced).toHaveBeenCalledTimes(1);
      // This listing started from no cursor: it covered the whole registry.
      expect(scopeDeletions.noteFeedSynced).toHaveBeenCalledWith(undefined, {
        full: true,
      });

      // An incremental pass (from a stored cursor) is not a full listing.
      (deps.cursor.read as ReturnType<typeof vi.fn>).mockResolvedValueOnce(
        "cursor-7",
      );
      listing.mockResolvedValueOnce({ dataPoints: [], cursor: null });
      await downloadAll(deps);
      expect(scopeDeletions.noteFeedSynced).toHaveBeenLastCalledWith(
        undefined,
        { full: false },
      );
    });

    it("uses the dedicated feed with includeDeleted=true when one is wired", async () => {
      const deps = withLocalVersions(makeMockDeps(), [syncedEntry()]);
      deps.dataPointFeed = {
        listDataPointsByOwner: vi.fn(async () => ({
          dataPoints: [{ ...makeDataPointRecord(), deletedAt: DELETED_AT }],
          cursor: null,
        })),
        getDataPoint: vi.fn(),
      };

      await downloadAll(deps);

      expect(deps.dataPointFeed.listDataPointsByOwner).toHaveBeenCalledWith(
        OWNER,
        null,
        { includeDeleted: true },
      );
      expect(deps.gateway.listDataPointsByOwner).not.toHaveBeenCalled();
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        COLLECTED_AT,
      );
    });

    it("recognises a tombstone row by its hash pair even without deletedAt", async () => {
      const deps = withLocalVersions(makeMockDeps(), [syncedEntry()]);
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [
          makeDataPointRecord({
            dataHash: TOMBSTONE_DATA_HASH,
            metadataHash: TOMBSTONE_METADATA_HASH,
            addedAt: DELETED_AT,
            expectedVersion: "2",
          }),
        ],
        cursor: null,
      });

      await downloadAll(deps);

      expect(deps.storageAdapter.download).not.toHaveBeenCalled();
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        COLLECTED_AT,
      );
    });

    it("holds the cursor when the local reconcile fails so the tombstone is retried", async () => {
      const deps = withLocalVersions(makeMockDeps(), [syncedEntry()]);
      (
        deps.storage.deleteVersion as ReturnType<typeof vi.fn>
      ).mockRejectedValue(new Error("disk error"));
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPoints: [{ ...makeDataPointRecord(), deletedAt: DELETED_AT }],
        cursor: "next",
      });

      await downloadAll(deps);

      expect(deps.cursor.write).not.toHaveBeenCalled();
      expect(deps.logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ scope: SCOPE, error: "disk error" }),
        "Failed to reconcile deleted data point locally",
      );
    });
  });

  describe("replica catch-up feeds derivatives the latest version", () => {
    // Regression: a replica that first downloaded version 1 of a scope
    // skipped every later version (same per-scope data point id), so a
    // question it computed answered from the oldest version.
    const REPOS = "github.repositories";
    const VERSIONS = [
      { version: "1", collectedAt: "2026-10-06T18:02:27Z" },
      { version: "2", collectedAt: "2026-10-06T18:04:01Z" },
      { version: "3", collectedAt: "2026-10-06T18:09:43Z" },
    ];

    it("downloads versions 2 and 3 after version 1 and computes from version 3", async () => {
      const storage = createMemoryDataStorage();
      const deps = makeMockDeps();
      deps.storage = storage;
      const listed: DataPointRecord[] = [];
      (
        deps.gateway.listDataPointsByOwner as ReturnType<typeof vi.fn>
      ).mockImplementation(async () => ({ dataPoints: listed, cursor: null }));

      for (const { version, collectedAt } of VERSIONS) {
        const envelope: DataFileEnvelope = {
          version: "1.0",
          scope: REPOS,
          collectedAt,
          data: { repositories: [{ name: `repo-v${version}` }] },
        };
        (decryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
          new TextEncoder().encode(JSON.stringify(envelope)),
        );
        // The feed lists the data point once, at its latest version.
        listed.splice(
          0,
          listed.length,
          makeDataPointRecord({ scope: REPOS, expectedVersion: version }),
        );
        await downloadAll(deps);
      }

      expect(
        storage.entries
          .filter((entry) => entry.scope === REPOS)
          .map((entry) => [entry.version, entry.collectedAt]),
      ).toEqual(VERSIONS.map((v) => [Number(v.version), v.collectedAt]));

      const provider = createFakeInferenceProvider();
      const outcome = await computeQuestion("q-langs", {
        storage,
        store: createInMemoryQuestionStore({
          initial: [
            {
              questionId: "q-langs",
              derivedScope: "hermesqa.languages",
              sourceScopes: [REPOS],
              question: "Which languages appear most across my repos?",
              model: null,
              answerShape: null,
              recompute: "on-change",
              registeredBy: { kind: "owner" },
              status: "pending",
              error: null,
              errorCode: null,
              createdAt: "2026-10-06T22:00:00.000Z",
              updatedAt: "2026-10-06T22:00:00.000Z",
              lastComputedAt: null,
              derivedVersion: null,
              derivedCollectedAt: null,
            },
          ],
        }),
        provider,
        serverOwner: OWNER,
        now: () => new Date("2026-10-07T00:22:47.000Z"),
        retryDelaysMs: [0, 0],
      });
      expect(outcome.status).toBe("ready");

      const derived = storage.findEntry({ scope: "hermesqa.languages" });
      const answer = await storage.readEnvelope(
        "hermesqa.languages",
        derived!.collectedAt,
      );
      expect((answer.data as { sources: unknown }).sources).toEqual([
        { scope: REPOS, version: 3, collectedAt: "2026-10-06T18:09:43Z" },
      ]);
      expect(JSON.stringify(provider.calls[0]!.messages)).toContain("repo-v3");
    });
  });
});
