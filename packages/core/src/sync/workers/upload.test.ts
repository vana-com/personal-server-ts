import { describe, it, expect, vi, beforeEach } from "vitest";

import { keccak256 } from "viem";

import type { UploadWorkerDeps } from "./upload.js";
import { uploadOne, uploadAll, computeDataPointId } from "./upload.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type {
  DataFileEnvelope,
  GatewayClient,
  Schema,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  deriveScopeKey: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";

const SCOPE = "instagram.profile";
const COLLECTED_AT = "2026-01-21T10:00:00Z";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const SCHEMA_ID =
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const VERSION = 1;
const DATA_POINT_ID =
  "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
// Blobs are version-keyed `{scope}/{version}`, not collectedAt-keyed.
const STORAGE_URL = `https://storage.vana.com/v1/blobs/${OWNER}/${SCOPE}/${VERSION}`;

function makeEntry(overrides?: Partial<IndexEntry>): IndexEntry {
  return {
    id: 1,
    fileId: null,
    schemaId: null,
    path: `${SCOPE}/${COLLECTED_AT}.json`,
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    createdAt: "2026-01-21T10:00:00Z",
    sizeBytes: 256,
    version: 1,
    dataPointId: null,
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

function makeSchema(): Schema {
  return {
    id: SCHEMA_ID,
    ownerAddress: OWNER,
    name: "instagram-profile",
    definitionUrl: "https://schemas.vana.com/instagram/profile.json",
    scope: SCOPE,
    addedAt: "2026-01-01T00:00:00Z",
  };
}

function makeMockDeps(): UploadWorkerDeps {
  const mockStorage: Partial<DataStoragePort> = {
    findUnsynced: vi.fn().mockReturnValue([]),
    updateDataPointId: vi.fn().mockReturnValue(true),
    updateEntryVersion: vi.fn().mockReturnValue(true),
    readEnvelope: vi.fn().mockResolvedValue(makeEnvelope()),
  };

  const mockStorageAdapter: Partial<StorageAdapter> = {
    upload: vi.fn().mockResolvedValue(STORAGE_URL),
  };

  const mockGateway: Partial<GatewayClient> = {
    getSchemaForScope: vi.fn().mockResolvedValue(makeSchema()),
    getDataPoint: vi.fn().mockResolvedValue(null),
    registerDataPoint: vi
      .fn()
      .mockResolvedValue({ dataPointId: DATA_POINT_ID, expectedVersion: "1" }),
  };

  const mockSigner: Partial<ServerSigner> = {
    signAddData: vi
      .fn()
      .mockResolvedValue("0xadddatasignature" as `0x${string}`),
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
    signer: mockSigner as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: mockLogger as Logger,
  };
}

describe("upload worker", () => {
  const SCOPE_KEY = new Uint8Array(32).fill(0xbb);
  const SCOPE_KEY_HEX = Buffer.from(SCOPE_KEY).toString("hex");
  const ENCRYPTED_BYTES = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

  beforeEach(() => {
    vi.clearAllMocks();

    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(SCOPE_KEY);
    (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      ENCRYPTED_BYTES,
    );
  });

  describe("uploadOne", () => {
    it("calls encryptWithPassword with correct scope key hex", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry();

      await uploadOne(deps, entry);

      expect(deriveScopeKey).toHaveBeenCalledWith(deps.masterKey, SCOPE);
      expect(encryptWithPassword).toHaveBeenCalledWith(
        expect.any(Uint8Array),
        SCOPE_KEY_HEX,
      );

      // Verify the plaintext passed to encrypt is the JSON of the envelope
      const plaintextArg = (encryptWithPassword as ReturnType<typeof vi.fn>)
        .mock.calls[0][0] as Uint8Array;
      const decoded = new TextDecoder().decode(plaintextArg);
      expect(JSON.parse(decoded)).toEqual(makeEnvelope());
    });

    it("calls storage adapter upload with encrypted binary", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry();

      await uploadOne(deps, entry);

      expect(deps.storageAdapter.upload).toHaveBeenCalledWith(
        `${SCOPE}/${VERSION}`,
        ENCRYPTED_BYTES,
      );
    });

    it("never consults a schema (DPv2 is scope-addressed, no schema concept)", async () => {
      const deps = makeMockDeps();

      await uploadOne(deps, makeEntry());

      // Upload neither looks up nor commits a schema — the gateway records none.
      expect(deps.gateway.getSchemaForScope).not.toHaveBeenCalled();
      expect(deps.gateway.registerDataPoint).toHaveBeenCalledOnce();
    });

    it("stamps the gateway dataPointId on the index entry", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry();

      const result = await uploadOne(deps, entry);

      expect(deps.storage.updateDataPointId).toHaveBeenCalledWith(
        entry.path,
        DATA_POINT_ID,
      );
      expect(result).toEqual({
        path: entry.path,
        url: STORAGE_URL,
        dataPointId: DATA_POINT_ID,
      });
    });

    it("registers DPv2 data point with expectedVersion + signed AddData", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry({ version: 3 });

      await uploadOne(deps, entry);

      expect(deps.signer.signAddData).toHaveBeenCalledWith(
        expect.objectContaining({
          ownerAddress: OWNER,
          scope: SCOPE,
          expectedVersion: 3n,
        }),
      );
      // dataHash and metadataHash are deterministic keccak256s; assert
      // shape (32-byte hex) rather than exact bytes so we don't pin the
      // commitment recipe inside the test.
      const addDataCall = (deps.signer.signAddData as ReturnType<typeof vi.fn>)
        .mock.calls[0][0];
      expect(addDataCall.dataHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(addDataCall.metadataHash).toMatch(/^0x[0-9a-fA-F]{64}$/);

      expect(deps.gateway.registerDataPoint).toHaveBeenCalledWith(
        expect.objectContaining({
          ownerAddress: OWNER,
          scope: SCOPE,
          expectedVersion: "3",
          signature: "0xadddatasignature",
        }),
      );
    });

    it("skips data-point registration when entry already has a dataPointId", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry({ dataPointId: DATA_POINT_ID });

      const result = await uploadOne(deps, entry);

      expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
      expect(deps.signer.signAddData).not.toHaveBeenCalled();
      expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
      expect(result.dataPointId).toBe(DATA_POINT_ID);
    });

    it("throws if registerDataPoint returns no dataPointId", async () => {
      const deps = makeMockDeps();
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockResolvedValue({});

      await expect(uploadOne(deps, makeEntry())).rejects.toThrow(
        /registerDataPoint did not return a dataPointId/,
      );
    });
  });

  describe("uploadAll", () => {
    it("processes all unsynced entries", async () => {
      const deps = makeMockDeps();
      const entries = [
        makeEntry({ id: 1, path: "a/1.json" }),
        makeEntry({ id: 2, path: "b/2.json", scope: "chatgpt.conversations" }),
        makeEntry({ id: 3, path: "c/3.json" }),
      ];
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue(
        entries,
      );

      const results = await uploadAll(deps);

      expect(deps.storage.findUnsynced).toHaveBeenCalledWith({
        limit: 50,
      });
      expect(results).toHaveLength(3);
      expect(deps.storageAdapter.upload).toHaveBeenCalledTimes(3);
    });

    it("continues on individual entry failure (logs error)", async () => {
      const deps = makeMockDeps();
      const onError = vi.fn();
      const entries = [
        makeEntry({ id: 1, path: "a/1.json" }),
        makeEntry({ id: 2, path: "b/2.json" }),
        makeEntry({ id: 3, path: "c/3.json" }),
      ];
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue(
        entries,
      );

      // Make the second entry fail at the storage upload step.
      let callCount = 0;
      (
        deps.storageAdapter.upload as ReturnType<typeof vi.fn>
      ).mockImplementation(() => {
        callCount++;
        if (callCount === 2) return Promise.reject(new Error("storage 500"));
        return Promise.resolve(STORAGE_URL);
      });

      const results = await uploadAll(deps, { onError });

      expect(results).toHaveLength(2);
      expect(onError).toHaveBeenCalledWith(
        entries[1],
        expect.objectContaining({ message: "storage 500" }),
      );
      expect(deps.logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ path: "b/2.json" }),
        "Failed to upload entry",
      );
    });
  });

  describe("uploadOne — stale-version conflicts (BUI-540)", () => {
    const STALE_409 = new Error(
      "Gateway error: 409 Stale expectedVersion 1: must be strictly greater than the stored value 1",
    );
    // The dataHash the worker computes for makeEnvelope()'s plaintext.
    const ENVELOPE_DATA_HASH = keccak256(
      new TextEncoder().encode(JSON.stringify(makeEnvelope())),
    );
    const REGISTRY_ID = computeDataPointId(OWNER, SCOPE);

    function makeRecord(overrides?: {
      dataHash?: string;
      expectedVersion?: string;
    }) {
      return {
        id: REGISTRY_ID,
        ownerAddress: OWNER,
        scope: SCOPE,
        dataHash: overrides?.dataHash ?? ENVELOPE_DATA_HASH,
        metadataHash: "0x" + "00".repeat(32),
        expectedVersion: overrides?.expectedVersion ?? "1",
        addedAt: "2026-06-12T00:00:00Z",
      };
    }

    it("adopts the registered data point when its content matches", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry();
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockRejectedValueOnce(STALE_409);
      (deps.gateway.getDataPoint as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeRecord(),
      );

      const result = await uploadOne(deps, entry);

      expect(deps.gateway.getDataPoint).toHaveBeenCalledWith(REGISTRY_ID);
      expect(result.dataPointId).toBe(REGISTRY_ID);
      expect(deps.storage.updateDataPointId).toHaveBeenCalledWith(
        entry.path,
        REGISTRY_ID,
      );
      // No second registration, no extra blob; the local version already
      // matches the registry's, so no version rewrite either.
      expect(deps.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
      expect(deps.storage.updateEntryVersion).not.toHaveBeenCalled();
      expect(deps.storageAdapter.upload).toHaveBeenCalledTimes(1);
    });

    it("aligns the local version with the adopted registry version", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry(); // local version 1
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockRejectedValueOnce(STALE_409);
      // Same content, but the registry sequence has moved on to 7 (e.g. a
      // replica re-registered identical bytes at a higher version).
      (deps.gateway.getDataPoint as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeRecord({ expectedVersion: "7" }),
      );

      const result = await uploadOne(deps, entry);

      expect(result.dataPointId).toBe(REGISTRY_ID);
      // Downstream consumers (x402 RecordDataAccess) sign from the local
      // row's version — it must follow the adopted registry version.
      expect(deps.storage.updateEntryVersion).toHaveBeenCalledWith(
        entry.path,
        7,
      );
      expect(deps.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
    });

    it("rebases onto the registry's version + 1 when content differs", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry();
      (deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(STALE_409)
        .mockResolvedValueOnce({ dataPointId: DATA_POINT_ID });
      (deps.gateway.getDataPoint as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeRecord({ dataHash: "0x" + "ff".repeat(32), expectedVersion: "7" }),
      );

      const result = await uploadOne(deps, entry);

      // Re-signed and re-registered one past the registry's live version.
      expect(deps.signer.signAddData).toHaveBeenLastCalledWith(
        expect.objectContaining({ expectedVersion: 8n }),
      );
      expect(deps.gateway.registerDataPoint).toHaveBeenLastCalledWith(
        expect.objectContaining({ expectedVersion: "8" }),
      );
      // The rebased version gets its own blob and the index row follows.
      expect(deps.storageAdapter.upload).toHaveBeenCalledWith(
        `${SCOPE}/8`,
        expect.any(Uint8Array),
      );
      expect(deps.storage.updateEntryVersion).toHaveBeenCalledWith(
        entry.path,
        8,
      );
      expect(result.dataPointId).toBe(DATA_POINT_ID);
      expect(deps.storage.updateDataPointId).toHaveBeenCalledWith(
        entry.path,
        DATA_POINT_ID,
      );
    });

    it("rethrows non-409 gateway errors without a registry lookup", async () => {
      const deps = makeMockDeps();
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockRejectedValue(
        new Error("Gateway error: 500 Internal Server Error"),
      );

      await expect(uploadOne(deps, makeEntry())).rejects.toThrow(
        "Gateway error: 500",
      );
      expect(deps.gateway.getDataPoint).not.toHaveBeenCalled();
      expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
    });

    it("rethrows the conflict when the registry row is missing", async () => {
      const deps = makeMockDeps();
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockRejectedValue(STALE_409);
      (deps.gateway.getDataPoint as ReturnType<typeof vi.fn>).mockResolvedValue(
        null,
      );

      await expect(uploadOne(deps, makeEntry())).rejects.toThrow(
        "Gateway error: 409",
      );
      expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
    });

    it("surfaces a raced rebase so the next cycle re-reads the registry", async () => {
      const deps = makeMockDeps();
      // Another replica wins the race to version 8 between our read and write.
      (deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(STALE_409)
        .mockRejectedValueOnce(
          new Error(
            "Gateway error: 409 Stale expectedVersion 8: must be strictly greater than the stored value 8",
          ),
        );
      (deps.gateway.getDataPoint as ReturnType<typeof vi.fn>).mockResolvedValue(
        makeRecord({ dataHash: "0x" + "ff".repeat(32), expectedVersion: "7" }),
      );

      await expect(uploadOne(deps, makeEntry())).rejects.toThrow(
        "Gateway error: 409",
      );
      expect(deps.storage.updateEntryVersion).not.toHaveBeenCalled();
      expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
    });
  });
});
