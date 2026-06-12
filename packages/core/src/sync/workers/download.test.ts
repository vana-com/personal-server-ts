import { describe, it, expect, vi, beforeEach } from "vitest";

import type { DownloadWorkerDeps } from "./download.js";
import { downloadOne, downloadAll } from "./download.js";
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
  });
});
