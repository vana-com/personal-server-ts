import { describe, it, expect, vi, beforeEach } from "vitest";

import type { DownloadWorkerDeps } from "./download.js";
import { downloadOne, downloadAll } from "./download.js";
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
});
