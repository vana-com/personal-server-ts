import { describe, it, expect, vi, beforeEach } from "vitest";

import type { UploadWorkerDeps } from "./upload.js";
import { uploadOne, uploadAll } from "./upload.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type {
  DataFileEnvelope,
  GatewayClient,
  Schema,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "pino";
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
const FILE_ID = "file-001";
const STORAGE_URL = `https://storage.vana.com/v1/blobs/${OWNER}/${SCOPE}/${COLLECTED_AT}`;

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
    updateFileId: vi.fn().mockReturnValue(true),
    readEnvelope: vi.fn().mockResolvedValue(makeEnvelope()),
  };

  const mockStorageAdapter: Partial<StorageAdapter> = {
    upload: vi.fn().mockResolvedValue(STORAGE_URL),
  };

  const mockGateway: Partial<GatewayClient> = {
    getSchemaForScope: vi.fn().mockResolvedValue(makeSchema()),
    registerFile: vi.fn().mockResolvedValue({ fileId: FILE_ID }),
  };

  const mockSigner: Partial<ServerSigner> = {
    signFileRegistration: vi
      .fn()
      .mockResolvedValue("0xmocksignature" as `0x${string}`),
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
        `${SCOPE}/${COLLECTED_AT}`,
        ENCRYPTED_BYTES,
      );
    });

    it("calls gateway registerFile with correct schemaId and signature", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry();

      await uploadOne(deps, entry);

      expect(deps.signer.signFileRegistration).toHaveBeenCalledWith({
        ownerAddress: OWNER,
        url: STORAGE_URL,
        schemaId: SCHEMA_ID,
      });

      expect(deps.gateway.registerFile).toHaveBeenCalledWith({
        ownerAddress: OWNER,
        url: STORAGE_URL,
        schemaId: SCHEMA_ID,
        signature: "0xmocksignature",
      });
    });

    it("uses indexed schemaId without a schema lookup", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry({ schemaId: SCHEMA_ID });

      await uploadOne(deps, entry);

      expect(deps.gateway.getSchemaForScope).not.toHaveBeenCalled();
      expect(deps.gateway.registerFile).toHaveBeenCalledWith(
        expect.objectContaining({ schemaId: SCHEMA_ID }),
      );
    });

    it("updates index with returned fileId", async () => {
      const deps = makeMockDeps();
      const entry = makeEntry();

      const result = await uploadOne(deps, entry);

      expect(deps.storage.updateFileId).toHaveBeenCalledWith(
        entry.path,
        FILE_ID,
      );
      expect(result).toEqual({
        path: entry.path,
        fileId: FILE_ID,
        url: STORAGE_URL,
      });
    });

    it("throws if schema lookup returns null", async () => {
      const deps = makeMockDeps();
      (
        deps.gateway.getSchemaForScope as ReturnType<typeof vi.fn>
      ).mockResolvedValue(null);
      const entry = makeEntry();

      await expect(uploadOne(deps, entry)).rejects.toThrow(
        `No schema found for scope: ${SCOPE}`,
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

      // Make the second entry fail at schema lookup
      let callCount = 0;
      (
        deps.gateway.getSchemaForScope as ReturnType<typeof vi.fn>
      ).mockImplementation(() => {
        callCount++;
        if (callCount === 2) return Promise.resolve(null);
        return Promise.resolve(makeSchema());
      });

      const results = await uploadAll(deps, { onError });

      expect(results).toHaveLength(2);
      expect(onError).toHaveBeenCalledWith(
        entries[1],
        expect.objectContaining({
          message: `No schema found for scope: ${SCOPE}`,
        }),
      );
      expect(deps.logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ path: "b/2.json" }),
        "Failed to upload entry",
      );
    });
  });
});
