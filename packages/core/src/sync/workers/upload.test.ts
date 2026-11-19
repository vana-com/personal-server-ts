import { describe, it, expect, vi, beforeEach } from "vitest";

import { keccak256 } from "viem";

import type { UploadWorkerDeps } from "./upload.js";
import { uploadOne, uploadAll, computeDataPointId } from "./upload.js";
import {
  createUploadStateTracker,
  type UploadStateTracker,
} from "../upload-state.js";
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
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "../tombstone.js";

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

/** Wire `listVersions` to return the given versions of their scope. */
function withVersions(deps: UploadWorkerDeps, versions: IndexEntry[]): void {
  deps.storage.listVersions = vi.fn((scope: string) =>
    versions.filter((entry) => entry.scope === scope),
  );
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
    urlForKey: vi.fn(
      (key: string) => `https://storage.vana.com/v1/blobs/${OWNER}/${key}`,
    ),
    exists: vi.fn().mockResolvedValue(true),
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
    signLineageAttestation: vi
      .fn()
      .mockResolvedValue("0xlineagesignature" as `0x${string}`),
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

  describe("orphaned entry (missing local payload)", () => {
    it("drops the index row and does not head-block when the payload file is gone", async () => {
      const deps = makeMockDeps();
      const dropUnsyncedEntry = vi.fn().mockReturnValue(true);
      const enoent = Object.assign(
        new Error("ENOENT: no such file or directory, open '/x/spotify.json'"),
        { code: "ENOENT" },
      );
      (deps.storage as unknown as Record<string, unknown>).dropUnsyncedEntry =
        dropUnsyncedEntry;
      deps.storage.readEnvelope = vi.fn().mockRejectedValue(enoent);
      const entry = makeEntry({ path: "spotify/savedTracks/x.json" });

      await expect(uploadOne(deps, entry)).rejects.toMatchObject({
        name: "OrphanedEntryError",
      });
      expect(dropUnsyncedEntry).toHaveBeenCalledWith(
        "spotify/savedTracks/x.json",
      );
    });

    it("surfaces the original error when the orphan drop reports no row removed", async () => {
      const deps = makeMockDeps();
      const enoent = Object.assign(new Error("ENOENT: no such file"), {
        code: "ENOENT",
      });
      (deps.storage as unknown as Record<string, unknown>).dropUnsyncedEntry =
        vi.fn().mockReturnValue(false);
      deps.storage.readEnvelope = vi.fn().mockRejectedValue(enoent);
      const entry = makeEntry();

      // Not an OrphanedEntryError — nothing was dropped, so the real ENOENT
      // must surface rather than being silently swallowed.
      await expect(uploadOne(deps, entry)).rejects.toThrow(/ENOENT/);
    });

    it("uploadAll swallows the orphan drop instead of surfacing a sync error", async () => {
      const deps = makeMockDeps();
      const onError = vi.fn();
      const enoent = Object.assign(new Error("ENOENT: no such file"), {
        code: "ENOENT",
      });
      (deps.storage as unknown as Record<string, unknown>).dropUnsyncedEntry =
        vi.fn().mockReturnValue(true);
      deps.storage.readEnvelope = vi.fn().mockRejectedValue(enoent);
      deps.storage.findUnsynced = vi
        .fn()
        .mockReturnValue([makeEntry({ path: "spotify/savedTracks/x.json" })]);

      const results = await uploadAll(deps, { onError });

      expect(results).toEqual([]);
      expect(onError).not.toHaveBeenCalled();
    });

    it("a non-ENOENT read failure still surfaces as a real error", async () => {
      const deps = makeMockDeps();
      const onError = vi.fn();
      deps.storage.readEnvelope = vi
        .fn()
        .mockRejectedValue(new Error("disk exploded"));
      deps.storage.findUnsynced = vi.fn().mockReturnValue([makeEntry()]);

      await uploadAll(deps, { onError });

      expect(onError).toHaveBeenCalledTimes(1);
    });

    it("does NOT drop on a non-ENOENT error whose message merely mentions a missing file", async () => {
      const deps = makeMockDeps();
      const dropUnsyncedEntry = vi.fn().mockReturnValue(true);
      (deps.storage as unknown as Record<string, unknown>).dropUnsyncedEntry =
        dropUnsyncedEntry;
      // No `code: "ENOENT"` — a validation/adapter error that happens to say
      // "no such file" must not be treated as a missing payload.
      deps.storage.readEnvelope = vi
        .fn()
        .mockRejectedValue(new Error("gateway rejected: no such file id"));
      const entry = makeEntry();

      await expect(uploadOne(deps, entry)).rejects.toThrow(/no such file id/);
      expect(dropUnsyncedEntry).not.toHaveBeenCalled();
    });
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

      expect(results).toHaveLength(3);
      expect(deps.storageAdapter.upload).toHaveBeenCalledTimes(3);
    });

    it("publishes only the newest unsynced snapshot of a memory scope and erases the older ones", async () => {
      const deps = makeMockDeps();
      deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
      const older = makeEntry({
        id: 11,
        path: "memory.claude/1.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:00.000Z",
        version: 1,
      });
      const newer = makeEntry({
        id: 12,
        path: "memory.claude/2.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:05.000Z",
        version: 2,
      });
      const other = makeEntry({ id: 3, path: "a/1.json" });
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
        older,
        other,
        newer,
      ]);
      withVersions(deps, [older, newer]);

      const results = await uploadAll(deps);

      expect(results.map((r) => r.path).sort()).toEqual([
        "a/1.json",
        "memory.claude/2.json",
      ]);
      expect(deps.storageAdapter.upload).toHaveBeenCalledTimes(2);
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        "memory.claude",
        older.collectedAt,
        { id: older.id, path: older.path },
      );
    });

    it("waits for a quiet period before publishing a memory scope, but not longer than the max wait", async () => {
      const deps = makeMockDeps();
      deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
      const now = new Date("2026-10-27T10:05:00.000Z");
      const fresh = makeEntry({
        id: 21,
        path: "memory.claude/fresh.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:04:30.000Z", // 30 s old: still active
      });
      const stale = makeEntry({
        id: 31,
        path: "memory.hermes/old.json",
        scope: "memory.hermes",
        collectedAt: "2026-10-27T09:50:00.000Z", // oldest unsynced 15 min ago
      });
      const staleNewest = makeEntry({
        id: 32,
        path: "memory.hermes/new.json",
        scope: "memory.hermes",
        collectedAt: "2026-10-27T10:04:50.000Z", // newest is fresh, max wait hit
      });
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
        stale,
        fresh,
        staleNewest,
      ]);
      withVersions(deps, [stale, fresh, staleNewest]);

      const results = await uploadAll(deps, { now: () => now });

      expect(results.map((r) => r.path)).toEqual(["memory.hermes/new.json"]);
      expect(deps.storage.deleteVersion).toHaveBeenCalledTimes(1);
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        "memory.hermes",
        stale.collectedAt,
        { id: stale.id, path: stale.path },
      );
    });

    it("orders memory snapshots by time, not by string, for sub-second stamps", async () => {
      const deps = makeMockDeps();
      deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
      const older = makeEntry({
        id: 41,
        path: "memory.claude/a.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:00Z",
      });
      const newer = makeEntry({
        id: 42,
        path: "memory.claude/b.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:00.500Z",
      });
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
        older,
        newer,
      ]);
      withVersions(deps, [older, newer]);

      const results = await uploadAll(deps);

      expect(results.map((r) => r.path)).toEqual(["memory.claude/b.json"]);
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        "memory.claude",
        older.collectedAt,
        { id: older.id, path: older.path },
      );
    });

    it("publishes the scope's latest local version even when it is beyond the batch page", async () => {
      const deps = makeMockDeps();
      deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
      const inPage = makeEntry({
        id: 51,
        path: "memory.claude/old.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:00.000Z",
      });
      const head = makeEntry({
        id: 59,
        path: "memory.claude/head.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:09.000Z",
      });
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
        inPage,
      ]);
      deps.storage.findEntry = vi.fn().mockReturnValue(head);
      withVersions(deps, [inPage, head]);

      const results = await uploadAll(deps);

      expect(results.map((r) => r.path)).toEqual(["memory.claude/head.json"]);
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        "memory.claude",
        inPage.collectedAt,
        { id: inPage.id, path: inPage.path },
      );
    });

    it("erases, and never publishes, unsynced snapshots older than an already-published latest version", async () => {
      const deps = makeMockDeps();
      deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
      const unsynced = makeEntry({
        id: 61,
        path: "memory.claude/local.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:00.000Z",
      });
      const leftover = makeEntry({
        id: 62,
        path: "memory.claude/leftover.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:05.000Z",
      });
      const publishedHead = makeEntry({
        id: 69,
        path: "memory.claude/remote.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:09.000Z",
        dataPointId: DATA_POINT_ID,
      });
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
        unsynced,
      ]);
      deps.storage.findEntry = vi.fn().mockReturnValue(publishedHead);
      // `leftover` is beyond this batch page but still erased.
      withVersions(deps, [unsynced, leftover, publishedHead]);

      const results = await uploadAll(deps);

      expect(results).toEqual([]);
      expect(deps.storageAdapter.upload).not.toHaveBeenCalled();
      expect(deps.storage.deleteVersion).toHaveBeenCalledTimes(2);
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        "memory.claude",
        leftover.collectedAt,
        { id: leftover.id, path: leftover.path },
      );
    });

    it("keeps older memory snapshots when the newest one fails to publish", async () => {
      const deps = makeMockDeps();
      deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
      const older = makeEntry({
        id: 11,
        path: "memory.claude/1.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:00.000Z",
      });
      const newer = makeEntry({
        id: 12,
        path: "memory.claude/2.json",
        scope: "memory.claude",
        collectedAt: "2026-10-27T10:00:05.000Z",
      });
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
        older,
        newer,
      ]);
      (
        deps.storageAdapter.upload as ReturnType<typeof vi.fn>
      ).mockRejectedValue(new Error("storage 500"));

      const results = await uploadAll(deps, { onError: vi.fn() });

      expect(results).toHaveLength(0);
      expect(deps.storageAdapter.upload).toHaveBeenCalledTimes(1);
      expect(deps.storage.deleteVersion).not.toHaveBeenCalled();
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

    it.each(["1", "7"])(
      "requires fencing before healing matching registered version %s whose bytes are missing",
      async (version) => {
        const deps = makeMockDeps();
        (
          deps.storageAdapter.exists as ReturnType<typeof vi.fn>
        ).mockResolvedValue(false);
        (
          deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
        ).mockRejectedValueOnce(STALE_409);
        (
          deps.gateway.getDataPoint as ReturnType<typeof vi.fn>
        ).mockResolvedValue(makeRecord({ expectedVersion: version }));
        await expect(uploadOne(deps, makeEntry())).rejects.toMatchObject({
          code: "NEEDS_FENCED_PUBLICATION",
          retryable: true,
        });
        expect(deps.storage.updateEntryVersion).not.toHaveBeenCalled();
        expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
        expect(deps.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
      },
    );

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

    it("rethrows the conflict when the registry row is missing and the error carries no version hint", async () => {
      const deps = makeMockDeps();
      // A 409 with no parseable next-valid version and no registry row leaves
      // us nothing to rebase onto — surface it rather than guess.
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockRejectedValue(new Error("Gateway error: 409 Conflict"));
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

  describe("uploadOne — registry behind local (BUI-715)", () => {
    // New-format gateway 409 when the local version overshoots the registry
    // (e.g. after a moksha/DataRegistry reset dropped currentVersion below the
    // local index, or duplicate re-snapshots pushed the local counter ahead).
    const gap409 = (expected: number, effectiveMax: number) =>
      new Error(
        `Gateway error: 409 Gap in version sequence: expectedVersion ${expected} ` +
          `would skip past the effective max (${effectiveMax}; gateway stored=${effectiveMax}, ` +
          `on-chain currentVersion=${effectiveMax}). Versions must be POSTed in order — ` +
          `next valid version is ${effectiveMax + 1}.`,
      );
    const REGISTRY_ID = computeDataPointId(OWNER, SCOPE);
    const CHANGED_DATA_HASH = "0x" + "ff".repeat(32);

    it("recovers a full registry wipe (no record) by rebasing to the error's next-valid version", async () => {
      const deps = makeMockDeps();
      // Local index is at version 4; the registry was wiped to 0 and has no
      // row at all, so getDataPoint returns null. Pre-fix this rethrew and
      // head-blocked the whole scope forever.
      const entry = makeEntry({ version: 4 });
      (deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(gap409(4, 0))
        .mockResolvedValueOnce({ dataPointId: DATA_POINT_ID });
      (deps.gateway.getDataPoint as ReturnType<typeof vi.fn>).mockResolvedValue(
        null,
      );

      const result = await uploadOne(deps, entry);

      // Rebased down to the gateway's stated next-valid version (0 + 1 = 1).
      expect(deps.signer.signAddData).toHaveBeenLastCalledWith(
        expect.objectContaining({ expectedVersion: 1n }),
      );
      expect(deps.gateway.registerDataPoint).toHaveBeenLastCalledWith(
        expect.objectContaining({ expectedVersion: "1" }),
      );
      expect(deps.storageAdapter.upload).toHaveBeenCalledWith(
        `${SCOPE}/1`,
        expect.any(Uint8Array),
      );
      expect(deps.storage.updateEntryVersion).toHaveBeenCalledWith(
        entry.path,
        1,
      );
      expect(result.dataPointId).toBe(DATA_POINT_ID);
    });

    it("rebases to the gateway's next-valid version when the registry is behind local (record present, content changed)", async () => {
      const deps = makeMockDeps();
      // Local version 4, gateway currentVersion 1, content differs from the
      // registered v1. record-based next (1+1=2) and error-based next
      // (effectiveMax 1 → 2) agree: rebase to 2.
      const entry = makeEntry({ version: 4 });
      (deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(gap409(4, 1))
        .mockResolvedValueOnce({ dataPointId: DATA_POINT_ID });
      (deps.gateway.getDataPoint as ReturnType<typeof vi.fn>).mockResolvedValue(
        {
          id: REGISTRY_ID,
          ownerAddress: OWNER,
          scope: SCOPE,
          dataHash: CHANGED_DATA_HASH,
          metadataHash: "0x" + "00".repeat(32),
          expectedVersion: "1",
          addedAt: "2026-07-12T00:00:00Z",
        },
      );

      await uploadOne(deps, entry);

      expect(deps.gateway.registerDataPoint).toHaveBeenLastCalledWith(
        expect.objectContaining({ expectedVersion: "2" }),
      );
      expect(deps.storageAdapter.upload).toHaveBeenCalledWith(
        `${SCOPE}/2`,
        expect.any(Uint8Array),
      );
      expect(deps.storage.updateEntryVersion).toHaveBeenCalledWith(
        entry.path,
        2,
      );
    });
  });

  describe("deletion guard (durable delete)", () => {
    const DELETED_AT = "2026-02-01T00:00:00.000Z";

    function withFeed(
      deps: UploadWorkerDeps,
      remote: {
        deletedAt: string | null;
        expectedVersion: string;
        dataHash?: string;
      } | null,
    ) {
      deps.dataPointFeed = {
        getDataPoint: vi.fn(async () =>
          remote
            ? {
                id: DATA_POINT_ID,
                ownerAddress: OWNER,
                scope: SCOPE,
                dataHash: remote.dataHash ?? "0x" + "33".repeat(32),
                metadataHash: "0x" + "44".repeat(32),
                expectedVersion: remote.expectedVersion,
                addedAt: "2026-01-01T00:00:00.000Z",
                deletedAt: remote.deletedAt,
              }
            : null,
        ),
        listDataPointsByOwner: vi.fn(),
      };
      deps.storage.deleteVersion = vi.fn(async () => true);
      return deps;
    }

    it("drops an unsynced entry whose scope the gateway has tombstoned instead of uploading it", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: DELETED_AT,
        expectedVersion: "4",
      });
      const entry = makeEntry({ createdAt: "2026-01-21T10:00:00Z" });
      (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
        entry,
      ]);
      const onError = vi.fn();

      const results = await uploadAll(deps, { onError });

      expect(results).toEqual([]);
      expect(onError).not.toHaveBeenCalled();
      expect(deps.storageAdapter.upload).not.toHaveBeenCalled();
      expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        COLLECTED_AT,
      );
    });

    it("publishes an ingest-acknowledged re-add strictly after the observed tombstone without a fence", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: DELETED_AT,
        expectedVersion: "4",
      });
      const entry = makeEntry({ afterTombstoneVersion: 4 });

      await uploadOne(deps, entry);

      expect(deps.storage.deleteVersion).not.toHaveBeenCalled();
      expect(deps.storageAdapter.upload).toHaveBeenCalledWith(
        `${SCOPE}/5`,
        expect.any(Uint8Array),
      );
      expect(deps.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
      expect(deps.gateway.registerDataPoint).toHaveBeenCalledWith(
        expect.objectContaining({ expectedVersion: "5" }),
      );
      expect(deps.storage.updateEntryVersion).toHaveBeenCalledWith(
        entry.path,
        5,
      );
    });

    it("still requires fencing for a re-add whose marker is not the observed tombstone", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: DELETED_AT,
        expectedVersion: "4",
      });
      await expect(
        uploadOne(deps, makeEntry({ afterTombstoneVersion: 7 })),
      ).rejects.toMatchObject({
        code: "NEEDS_FENCED_PUBLICATION",
        reason: "tombstone was not acknowledged by this publication",
      });
      expect(deps.storageAdapter.upload).not.toHaveBeenCalled();
      expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
    });

    it("drops a pre-deletion entry even when this replica's clock is ahead of the gateway", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: DELETED_AT,
        expectedVersion: "4",
      });
      // Wall clocks are not consulted: a future createdAt and a local version
      // past the tombstone do not make this a re-add; only the marker does.
      const entry = makeEntry({
        createdAt: "2099-01-01T00:00:00.000Z",
        version: 9,
        afterTombstoneVersion: null,
      });

      await expect(uploadOne(deps, entry)).rejects.toMatchObject({
        name: "DeletedScopeEntryError",
      });
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        COLLECTED_AT,
      );
      expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
    });

    it("drops a re-add that was made on top of an older tombstone than the current one", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: DELETED_AT,
        expectedVersion: "6",
      });
      const entry = makeEntry({ afterTombstoneVersion: 4 });

      await expect(uploadOne(deps, entry)).rejects.toMatchObject({
        name: "DeletedScopeEntryError",
      });
      expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
    });

    it("recognises a tombstone row by its hash pair even without deletedAt", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: null,
        expectedVersion: "4",
        dataHash: TOMBSTONE_DATA_HASH,
      });
      (
        deps.dataPointFeed!.getDataPoint as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        id: DATA_POINT_ID,
        ownerAddress: OWNER,
        scope: SCOPE,
        dataHash: TOMBSTONE_DATA_HASH,
        metadataHash: TOMBSTONE_METADATA_HASH,
        expectedVersion: "4",
        addedAt: DELETED_AT,
        deletedAt: null,
      });
      const entry = makeEntry({ createdAt: "2026-01-21T10:00:00Z" });

      await expect(uploadOne(deps, entry)).rejects.toMatchObject({
        name: "DeletedScopeEntryError",
      });
      expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
    });

    it("drops the entry when a 409 reveals a tombstone that landed after the guard ran", async () => {
      // Step 1b saw a live row below this entry's version; another replica
      // deleted the scope before this worker registered. The 409 path must apply the same rule
      // instead of rebasing past the tombstone (which would resurrect it).
      const deps = withFeed(makeMockDeps(), {
        deletedAt: null,
        expectedVersion: "1",
      });
      const tombstoned = {
        id: DATA_POINT_ID,
        ownerAddress: OWNER,
        scope: SCOPE,
        dataHash: "0x" + "33".repeat(32),
        metadataHash: "0x" + "44".repeat(32),
        expectedVersion: "3",
        addedAt: DELETED_AT,
        deletedAt: DELETED_AT,
      };
      const feed = deps.dataPointFeed!.getDataPoint as ReturnType<typeof vi.fn>;
      const live = await feed({ ownerAddress: OWNER, scope: SCOPE });
      feed.mockReset();
      feed.mockResolvedValueOnce(live).mockResolvedValueOnce(tombstoned);
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockRejectedValueOnce(
        new Error(
          "Gateway error: 409 Stale expectedVersion 2: must be strictly greater than the stored value 3",
        ),
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
      deps.storageAdapter.delete = vi.fn(async () => true);
      const entry = makeEntry({
        createdAt: "2026-01-21T10:00:00Z",
        version: 2,
      });

      await expect(uploadOne(deps, entry)).rejects.toMatchObject({
        name: "DeletedScopeEntryError",
      });

      expect(deps.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
      expect(deps.storageAdapter.upload).toHaveBeenCalledTimes(1);
      // Cleanup belongs to the fenced deletion pipeline: a registry refusal
      // cannot prove that another replica did not commit these same bytes.
      expect(deps.storageAdapter.delete).not.toHaveBeenCalled();
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        COLLECTED_AT,
      );
      expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
      expect(scopeDeletions.markLive).not.toHaveBeenCalled();
    });

    it("does not enqueue an unfenced reclaim after a registry refusal", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: null,
        expectedVersion: "1",
      });
      const feed = deps.dataPointFeed!.getDataPoint as ReturnType<typeof vi.fn>;
      const live = await feed({ ownerAddress: OWNER, scope: SCOPE });
      feed.mockReset();
      feed.mockResolvedValueOnce(live).mockResolvedValueOnce({
        id: DATA_POINT_ID,
        ownerAddress: OWNER,
        scope: SCOPE,
        dataHash: "0x" + "33".repeat(32),
        metadataHash: "0x" + "44".repeat(32),
        expectedVersion: "3",
        addedAt: DELETED_AT,
        deletedAt: DELETED_AT,
      });
      (
        deps.gateway.registerDataPoint as ReturnType<typeof vi.fn>
      ).mockRejectedValueOnce(
        new Error(
          "Gateway error: 409 Stale expectedVersion 2: must be strictly greater than the stored value 3",
        ),
      );
      deps.storageAdapter.delete = vi.fn(async () => {
        throw new Error("storage 503");
      });
      const pendingBlobDeletions = {
        list: vi.fn(async () => []),
        add: vi.fn(async () => undefined),
        remove: vi.fn(async () => undefined),
      };
      deps.pendingBlobDeletions = pendingBlobDeletions;

      await expect(
        uploadOne(deps, makeEntry({ version: 2 })),
      ).rejects.toMatchObject({
        name: "DeletedScopeEntryError",
      });

      expect(pendingBlobDeletions.add).not.toHaveBeenCalled();
      expect(deps.storageAdapter.delete).not.toHaveBeenCalled();
      expect(deps.storage.deleteVersion).toHaveBeenCalledWith(
        SCOPE,
        COLLECTED_AT,
      );
    });

    it("marks the scope live in the read-side memory once it is registered", async () => {
      const deps = withFeed(makeMockDeps(), null);
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

      await uploadOne(deps, makeEntry());

      expect(scopeDeletions.markLive).toHaveBeenCalledWith(SCOPE);
    });

    it("uploads normally when the gateway has a live row or no row", async () => {
      const live = withFeed(makeMockDeps(), {
        deletedAt: null,
        expectedVersion: "1",
      });
      await uploadOne(live, makeEntry({ version: 2 }));
      expect(live.gateway.registerDataPoint).toHaveBeenCalledWith(
        expect.objectContaining({ expectedVersion: "2" }),
      );

      const none = withFeed(makeMockDeps(), null);
      await uploadOne(none, makeEntry());
      expect(none.gateway.registerDataPoint).toHaveBeenCalledTimes(1);
    });

    it("does not consult the feed for entries that are already synced", async () => {
      const deps = withFeed(makeMockDeps(), {
        deletedAt: DELETED_AT,
        expectedVersion: "4",
      });

      await uploadOne(deps, makeEntry({ dataPointId: DATA_POINT_ID }));

      expect(deps.dataPointFeed!.getDataPoint).not.toHaveBeenCalled();
    });
  });
});

describe("uploadOne — derivative registration (lineage)", () => {
  const SOURCE_ID =
    "0xabababababababababababababababababababababababababababababababab";

  function derivativeEnvelope(): DataFileEnvelope {
    return {
      version: "1.0",
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      data: {
        summary: "x",
        lineage: [SOURCE_ID],
        $lineage: { sources: [SOURCE_ID], writtenAt: COLLECTED_AT },
      },
    };
  }

  it("registers an envelope carrying $lineage through the lineage gateway with its sources", async () => {
    const deps = makeMockDeps();
    (deps.storage.readEnvelope as ReturnType<typeof vi.fn>).mockResolvedValue(
      derivativeEnvelope(),
    );
    const registerDataPoint = vi
      .fn()
      .mockResolvedValue({ dataPointId: DATA_POINT_ID, expectedVersion: "1" });
    deps.lineageGateway = { registerDataPoint };

    const result = await uploadOne(deps, makeEntry());

    expect(result.dataPointId).toBe(DATA_POINT_ID);
    expect(registerDataPoint).toHaveBeenCalledWith(
      expect.objectContaining({
        ownerAddress: OWNER,
        scope: SCOPE,
        expectedVersion: "1",
        signature: "0xadddatasignature",
        lineage: [SOURCE_ID],
        lineageSignature: "0xlineagesignature",
      }),
    );
    // The attestation binds the lineage to this exact registration.
    expect(deps.signer.signLineageAttestation).toHaveBeenCalledWith({
      ownerAddress: OWNER,
      scope: SCOPE,
      expectedVersion: 1n,
      dataHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
      sources: [SOURCE_ID],
    });
    expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
  });

  it("fails closed on a malformed stored $lineage instead of registering the record as a root", async () => {
    const deps = makeMockDeps();
    const env = derivativeEnvelope() as { data: Record<string, unknown> };
    (deps.storage.readEnvelope as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...env,
      data: { ...env.data, $lineage: "invalid" },
    });
    await expect(uploadOne(deps, makeEntry())).rejects.toThrow(
      /Stored \$lineage is malformed/,
    );
    expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
    expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
  });

  it("fails (and leaves the entry unsynced) instead of registering a derivative as a root when no lineage gateway is wired", async () => {
    const deps = makeMockDeps();
    (deps.storage.readEnvelope as ReturnType<typeof vi.fn>).mockResolvedValue(
      derivativeEnvelope(),
    );
    await expect(uploadOne(deps, makeEntry())).rejects.toThrow(
      /lineage registration needs a gateway URL/,
    );
    expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
    expect(deps.storage.updateDataPointId).not.toHaveBeenCalled();
  });

  it("registers an explicit empty $lineage as an attested root statement", async () => {
    const deps = makeMockDeps();
    (deps.storage.readEnvelope as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...derivativeEnvelope(),
      data: {
        note: "x",
        lineage: [],
        $lineage: { sources: [], writtenAt: COLLECTED_AT },
      },
    });
    const registerDataPoint = vi
      .fn()
      .mockResolvedValue({ dataPointId: DATA_POINT_ID, expectedVersion: "1" });
    deps.lineageGateway = { registerDataPoint };
    await uploadOne(deps, makeEntry());
    expect(registerDataPoint).toHaveBeenCalledWith(
      expect.objectContaining({
        lineage: [],
        lineageSignature: "0xlineagesignature",
      }),
    );
    expect(deps.signer.signLineageAttestation).toHaveBeenCalledWith(
      expect.objectContaining({ sources: [] }),
    );
    expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
  });

  it("keeps using the SDK client for root records", async () => {
    const deps = makeMockDeps();
    deps.lineageGateway = { registerDataPoint: vi.fn() };
    await uploadOne(deps, makeEntry());
    expect(deps.gateway.registerDataPoint).toHaveBeenCalled();
    expect(deps.lineageGateway.registerDataPoint).not.toHaveBeenCalled();
  });
});

describe("uploadAll — upload size cap and bounded retry", () => {
  const SCOPE_KEY = new Uint8Array(32).fill(0xbb);
  const MIB = 1024 * 1024;
  const T0 = Date.parse("2026-11-07T12:00:00Z");
  const MINUTE = 60_000;

  beforeEach(() => {
    vi.clearAllMocks();
    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(SCOPE_KEY);
    (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    );
  });

  function setup(entries: IndexEntry[]) {
    const deps = makeMockDeps();
    const uploadState = createUploadStateTracker();
    deps.uploadState = uploadState;
    (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue(
      entries,
    );
    return { deps, uploadState };
  }
  const cycle = (deps: UploadWorkerDeps, offsetMs: number) =>
    uploadAll(deps, { now: () => new Date(T0 + offsetMs) });

  it("never reads, encrypts or sends a 337 MiB entry and reports it too large", async () => {
    const huge = makeEntry({ sizeBytes: 337 * MIB });
    const { deps, uploadState } = setup([huge]);

    const results = await cycle(deps, 0);

    expect(results).toEqual([]);
    expect(deps.storage.readEnvelope).not.toHaveBeenCalled();
    expect(encryptWithPassword).not.toHaveBeenCalled();
    expect(deps.storageAdapter.upload).not.toHaveBeenCalled();
    expect(deps.gateway.registerDataPoint).not.toHaveBeenCalled();
    expect(uploadState.snapshot().tooLarge).toEqual([
      expect.objectContaining({
        scope: huge.scope,
        path: huge.path,
        sizeBytes: 337 * MIB,
      }),
    ]);
  });

  it("treats an entry whose encrypted body would pass the cap as too large, and one safely under it as uploadable", async () => {
    const nearCap = makeEntry({
      id: 1,
      path: "a/1.json",
      sizeBytes: 94_000_000,
    });
    const safe = makeEntry({ id: 2, path: "b/2.json", sizeBytes: 80_000_000 });
    const { deps, uploadState } = setup([nearCap, safe]);

    const results = await cycle(deps, 0);

    expect(results.map((r) => r.path)).toEqual(["b/2.json"]);
    expect(uploadState.snapshot().tooLarge.map((e) => e.path)).toEqual([
      "a/1.json",
    ]);
  });

  it("logs a too-large entry once across several cycles", async () => {
    const { deps } = setup([makeEntry({ sizeBytes: 337 * MIB })]);

    for (let i = 0; i < 5; i++) await cycle(deps, i * 4 * MINUTE);

    const tooLargeLogs = [
      ...(deps.logger.warn as ReturnType<typeof vi.fn>).mock.calls,
      ...(deps.logger.info as ReturnType<typeof vi.fn>).mock.calls,
      ...(deps.logger.error as ReturnType<typeof vi.fn>).mock.calls,
    ].filter(([, message]) => /too large/i.test(String(message)));
    expect(tooLargeLogs).toHaveLength(1);
    expect(deps.storage.readEnvelope).not.toHaveBeenCalled();
  });

  it("does not erase older snapshots when the coalesced head is too large", async () => {
    const deps = makeMockDeps();
    deps.uploadState = createUploadStateTracker();
    deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
    const older = makeEntry({
      id: 11,
      path: "memory.claude/1.json",
      scope: "memory.claude",
      collectedAt: "2026-10-27T10:00:00.000Z",
      version: 1,
    });
    const head = makeEntry({
      id: 12,
      path: "memory.claude/2.json",
      scope: "memory.claude",
      collectedAt: "2026-10-27T10:00:05.000Z",
      version: 2,
      sizeBytes: 337 * MIB,
    });
    (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
      older,
      head,
    ]);
    withVersions(deps, [older, head]);

    await cycle(deps, 0);

    expect(deps.storage.deleteVersion).not.toHaveBeenCalled();
    expect(deps.storage.readEnvelope).not.toHaveBeenCalled();
    expect(deps.uploadState?.snapshot().tooLarge).toHaveLength(1);
  });

  it("backs off a failing entry and stops after the failure cap", async () => {
    const entry = makeEntry();
    const { deps, uploadState } = setup([entry]);
    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("Failed to fetch"),
    );
    const upload = deps.storageAdapter.upload as ReturnType<typeof vi.fn>;

    await cycle(deps, 0);
    expect(upload).toHaveBeenCalledTimes(1);
    expect(uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({ path: entry.path, failures: 1 }),
    ]);

    // Inside the 1 minute backoff: no attempt.
    await cycle(deps, 30_000);
    expect(upload).toHaveBeenCalledTimes(1);

    // After failure n the wait is 2^(n-1) minutes, capped at 60.
    let last = 0;
    for (const waitMinutes of [1, 2, 4, 8, 16, 32, 60]) {
      const due = last + waitMinutes * MINUTE;
      const before = upload.mock.calls.length;
      await cycle(deps, due - 1_000);
      expect(upload.mock.calls.length).toBe(before);
      await cycle(deps, due);
      expect(upload.mock.calls.length).toBe(before + 1);
      last = due;
    }
    const now = last;

    expect(upload).toHaveBeenCalledTimes(8);
    expect(uploadState.snapshot().retrying).toEqual([]);
    expect(uploadState.snapshot().stopped).toEqual([
      expect.objectContaining({
        path: entry.path,
        failures: 8,
        lastError: "Failed to fetch",
      }),
    ]);

    // Stopped: a day of cycles makes no further attempt.
    for (let i = 1; i <= 20; i++) await cycle(deps, now + i * 60 * MINUTE);
    expect(upload).toHaveBeenCalledTimes(8);
  });

  it("clears the state after a later successful upload", async () => {
    const entry = makeEntry();
    const { deps, uploadState } = setup([entry]);
    const upload = deps.storageAdapter.upload as ReturnType<typeof vi.fn>;
    upload.mockRejectedValueOnce(new Error("boom"));

    await cycle(deps, 0);
    expect(uploadState.snapshot().retrying).toHaveLength(1);

    await cycle(deps, 2 * MINUTE);
    expect(uploadState.snapshot()).toEqual({
      tooLarge: [],
      unsizable: [],
      retrying: [],
      stopped: [],
    });
  });

  it("clears a stopped scope when new data arrives for it", async () => {
    const stale = makeEntry({ id: 1, path: "s/1.json", version: 1 });
    const { deps, uploadState } = setup([stale]);
    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );
    for (let i = 0; i < 8; i++) await cycle(deps, i * 61 * MINUTE);
    expect(uploadState.snapshot().stopped).toHaveLength(1);

    const fresh = makeEntry({
      id: 2,
      path: "s/2.json",
      version: 2,
      collectedAt: "2026-01-22T10:00:00Z",
    });
    (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue([
      stale,
      fresh,
    ]);
    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockResolvedValue(
      STORAGE_URL,
    );

    const results = await cycle(deps, 10 * 61 * MINUTE);

    expect(results.map((r) => r.path)).toEqual(["s/2.json"]);
    expect(uploadState.snapshot().stopped).toEqual([]);
  });
});

describe("uploadAll — terminal entries, failure clock and removals", () => {
  const SCOPE_KEY = new Uint8Array(32).fill(0xbb);
  const MIB = 1024 * 1024;
  const T0 = Date.parse("2026-11-07T12:00:00Z");
  const MINUTE = 60_000;
  const oversized = (n: number, overrides?: Partial<IndexEntry>) =>
    makeEntry({
      id: n,
      path: `big/${n}.json`,
      scope: `big.${n}`,
      sizeBytes: 337 * MIB,
      ...overrides,
    });
  const healthy = (n: number, overrides?: Partial<IndexEntry>) =>
    makeEntry({
      id: n,
      path: `ok/${n}.json`,
      scope: `ok.${n}`,
      sizeBytes: 1024,
      ...overrides,
    });

  beforeEach(() => {
    vi.clearAllMocks();
    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(SCOPE_KEY);
    (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    );
  });

  /** A live index that honours `limit` the way the real hosts do. */
  function setup(initial: IndexEntry[]) {
    const deps = makeMockDeps();
    const uploadState = createUploadStateTracker();
    deps.uploadState = uploadState;
    const index = { rows: [...initial] };
    deps.storage.findUnsynced = vi.fn((options?: { limit?: number }) => {
      const unsynced = index.rows.filter((row) => row.dataPointId === null);
      return options?.limit === undefined
        ? unsynced
        : unsynced.slice(0, options.limit);
    });
    deps.storage.updateDataPointId = vi.fn(
      (path: string, id: string | null) => {
        const row = index.rows.find((r) => r.path === path);
        if (row) row.dataPointId = id;
        return true;
      },
    );
    return { deps, uploadState, index };
  }

  it("reaches a healthy entry behind a page full of oversized ones", async () => {
    const { deps } = setup([oversized(1), healthy(2)]);
    const uploaded: string[] = [];
    for (let i = 0; i < 5; i++) {
      const results = await uploadAll(deps, {
        batchSize: 1,
        now: () => new Date(T0 + i * 60 * MINUTE),
      });
      uploaded.push(...results.map((r) => r.path));
    }
    expect(uploaded).toEqual(["ok/2.json"]);
    expect(deps.storage.readEnvelope).toHaveBeenCalledTimes(1);
  });

  it("keeps terminal entries instead of deleting them to make room", async () => {
    const { deps, index } = setup([oversized(1), oversized(2), healthy(3)]);
    deps.storage.deleteVersion = vi.fn().mockResolvedValue(true);
    await uploadAll(deps, { batchSize: 2, now: () => new Date(T0) });
    expect(deps.storage.deleteVersion).not.toHaveBeenCalled();
    expect(index.rows.map((r) => r.path)).toContain("big/1.json");
  });

  it("lets a fresh entry release a stopped scope even when terminal entries fill the page", async () => {
    const stale = makeEntry({
      id: 3,
      path: "s/1.json",
      scope: "s",
      version: 1,
    });
    const fresh = makeEntry({
      id: 4,
      path: "s/2.json",
      scope: "s",
      version: 2,
      collectedAt: "2026-01-22T10:00:00Z",
      sizeBytes: 1024,
    });
    const { deps, uploadState } = setup([
      oversized(1),
      oversized(2),
      stale,
      fresh,
    ]);
    for (let i = 0; i < 8; i++)
      uploadState.recordFailure(
        { scope: "s", path: stale.path },
        "boom",
        T0 + i,
      );
    expect(uploadState.snapshot().stopped).toHaveLength(1);

    const results = await uploadAll(deps, {
      batchSize: 2,
      now: () => new Date(T0 + 10 * 60 * MINUTE),
    });

    expect(results.map((r) => r.path)).toEqual(["s/2.json"]);
    expect(uploadState.snapshot().stopped).toEqual([]);
  });

  it("starts the backoff at the failure time when the upload itself takes minutes", async () => {
    const entry = healthy(1);
    const { deps, uploadState } = setup([entry]);
    let clock = T0;
    const upload = deps.storageAdapter.upload as ReturnType<typeof vi.fn>;
    upload.mockImplementation(async () => {
      clock += 120_000;
      throw new Error("Failed to fetch");
    });

    await uploadAll(deps, { now: () => new Date(clock) });
    expect(upload).toHaveBeenCalledTimes(1);
    expect(uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({
        path: entry.path,
        nextAttemptAt: new Date(T0 + 120_000 + MINUTE).toISOString(),
      }),
    ]);

    await uploadAll(deps, { now: () => new Date(clock) });
    expect(upload).toHaveBeenCalledTimes(1);
  });

  it("forgets rows removed elsewhere while the backlog stays a full page, and keeps later-page backoff", async () => {
    const failing = healthy(100);
    const bigs = Array.from({ length: 10 }, (_, i) => oversized(i + 1));
    const { deps, uploadState, index } = setup([failing, ...bigs]);
    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );

    for (let i = 0; i < 6; i++) {
      // Another path (a download tombstone) removes the oldest oversized row.
      index.rows.splice(1, 1);
      await uploadAll(deps, {
        batchSize: 3,
        now: () => new Date(T0 + i * 1000),
      });
      const live = new Set(index.rows.map((r) => r.path));
      const tracked = [
        ...uploadState.snapshot().tooLarge,
        ...uploadState.snapshot().retrying,
        ...uploadState.snapshot().stopped,
      ].map((e) => e.path);
      expect(tracked.filter((p) => !live.has(p))).toEqual([]);
    }
    await uploadAll(deps, { batchSize: 3, now: () => new Date(T0 + 7000) });
    const final = uploadState.snapshot();
    expect(final.retrying).toEqual([
      expect.objectContaining({ path: failing.path, failures: 1 }),
    ]);
    expect(
      final.tooLarge.every((e) => index.rows.some((r) => r.path === e.path)),
    ).toBe(true);
  });

  it.each([
    ["undefined", undefined],
    ["NaN", Number.NaN],
    ["zero", 0],
    ["negative", -5],
    ["infinite", Number.POSITIVE_INFINITY],
  ])(
    "never reads the body of an entry whose size is %s",
    async (_name, size) => {
      const entry = healthy(1, { sizeBytes: size as unknown as number });
      const { deps, uploadState } = setup([entry]);

      for (let i = 0; i < 3; i++)
        await uploadAll(deps, { now: () => new Date(T0 + i * MINUTE) });

      expect(deps.storage.readEnvelope).not.toHaveBeenCalled();
      expect(deps.storageAdapter.upload).not.toHaveBeenCalled();
      expect(uploadState.snapshot().unsizable).toEqual([
        expect.objectContaining({ scope: entry.scope, path: entry.path }),
      ]);
      expect(uploadState.snapshot().tooLarge).toEqual([]);
      const logs = (deps.logger.warn as ReturnType<typeof vi.fn>).mock.calls
        .map(([, message]) => String(message))
        .filter((message) => /size/i.test(message));
      expect(logs).toHaveLength(1);
    },
  );
});

describe("uploadAll — planning cost over a large backlog", () => {
  const T0 = Date.parse("2026-11-07T12:00:00Z");

  /** Elements read through the array iterator (spread, for-of) while `fn` runs. */
  async function countIteratedElements(fn: () => Promise<void>) {
    const proto = Array.prototype as unknown as Record<symbol, unknown>;
    const original = proto[Symbol.iterator] as () => IterableIterator<unknown>;
    let count = 0;
    proto[Symbol.iterator] = function (this: unknown[]) {
      count += this.length;
      return original.call(this);
    };
    try {
      await fn();
    } finally {
      proto[Symbol.iterator] = original;
    }
    return count;
  }

  it("plans one coalesced scope in a single pass, without copying its growing version list", async () => {
    const N = 2000;
    const deps = makeMockDeps();
    const rows = Array.from({ length: N }, (_, i) =>
      makeEntry({
        id: i + 1,
        path: `memory.claude/${i}.json`,
        scope: "memory.claude",
        collectedAt: new Date(T0 + i * 10).toISOString(),
        sizeBytes: 1024,
      }),
    );
    (deps.storage.findUnsynced as ReturnType<typeof vi.fn>).mockReturnValue(
      rows,
    );

    // The newest snapshot is inside the quiet window, so nothing uploads: the
    // whole cost measured here is selection and planning.
    const iterated = await countIteratedElements(async () => {
      await uploadAll(deps, { now: () => new Date(T0 + N * 10 + 1000) });
    });

    expect(deps.storageAdapter.upload).not.toHaveBeenCalled();
    // One pass is a few passes over N rows; the quadratic accumulator reads
    // about N^2 / 2 (2,000,000 here).
    expect(iterated).toBeLessThan(20 * N);
  });
});

describe("uploadAll — terminal state follows the row, not the path", () => {
  const SCOPE_KEY = new Uint8Array(32).fill(0xbb);
  const MIB = 1024 * 1024;
  const T0 = Date.parse("2026-11-07T12:00:00Z");
  const MINUTE = 60_000;

  beforeEach(() => {
    vi.clearAllMocks();
    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(SCOPE_KEY);
    (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    );
  });

  function setup(initial: IndexEntry) {
    const deps = makeMockDeps();
    const uploadState = createUploadStateTracker();
    deps.uploadState = uploadState;
    const index = { row: initial };
    deps.storage.findUnsynced = vi.fn(() =>
      index.row.dataPointId === null ? [index.row] : [],
    );
    deps.storage.updateDataPointId = vi.fn(
      (_path: string, id: string | null) => {
        index.row = { ...index.row, dataPointId: id };
        return true;
      },
    );
    const cycle = (n: number) =>
      uploadAll(deps, { now: () => new Date(T0 + n * 61 * MINUTE) });
    return { deps, uploadState, index, cycle };
  }

  it("uploads a small row written at the path of a held too-large row", async () => {
    const big = makeEntry({ id: 1, path: "s/1.json", sizeBytes: 337 * MIB });
    const { deps, uploadState, index, cycle } = setup(big);
    await cycle(0);
    expect(uploadState.snapshot().tooLarge).toHaveLength(1);

    // Same scope and collectedAt, so the same path; a fresh id and a 1 KiB body.
    index.row = { ...big, id: 2, sizeBytes: 1024 };
    const results = await cycle(1);

    expect(results.map((r) => r.path)).toEqual(["s/1.json"]);
    expect(deps.storage.readEnvelope).toHaveBeenCalledTimes(1);
    expect(uploadState.snapshot().tooLarge).toEqual([]);
  });

  it("uploads a row whose missing size was repaired in place", async () => {
    const bad = makeEntry({ id: 1, path: "s/1.json", sizeBytes: 0 });
    const { uploadState, index, cycle } = setup(bad);
    await cycle(0);
    expect(uploadState.snapshot().unsizable).toHaveLength(1);

    index.row = { ...bad, sizeBytes: 1024 };
    const results = await cycle(1);

    expect(results.map((r) => r.path)).toEqual(["s/1.json"]);
    expect(uploadState.snapshot().unsizable).toEqual([]);
  });

  it("uploads a valid row written at the path of an unsizable one", async () => {
    const bad = makeEntry({ id: 1, path: "s/1.json", sizeBytes: Number.NaN });
    const { uploadState, index, cycle } = setup(bad);
    await cycle(0);
    expect(uploadState.snapshot().unsizable).toHaveLength(1);

    index.row = { ...bad, id: 2, sizeBytes: 1024 };
    const results = await cycle(1);

    expect(results.map((r) => r.path)).toEqual(["s/1.json"]);
  });

  it("retries a stopped path at once when a new row replaces it", async () => {
    const row = makeEntry({ id: 1, path: "s/1.json", sizeBytes: 1024 });
    const { deps, uploadState, index, cycle } = setup(row);
    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );
    for (let i = 0; i < 8; i++) await cycle(i);
    expect(uploadState.snapshot().stopped).toHaveLength(1);

    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockResolvedValue(
      `https://storage.vana.com/v1/blobs/${OWNER}/s/1`,
    );
    index.row = { ...row, id: 2 };
    const results = await cycle(8);

    expect(results.map((r) => r.path)).toEqual(["s/1.json"]);
  });

  it("keeps an unchanged held row held and an unchanged backoff in force", async () => {
    const big = makeEntry({ id: 1, path: "s/1.json", sizeBytes: 337 * MIB });
    const { deps, uploadState, cycle } = setup(big);
    for (let i = 0; i < 4; i++) await cycle(i);
    expect(uploadState.snapshot().tooLarge).toHaveLength(1);
    expect(deps.storage.readEnvelope).not.toHaveBeenCalled();

    const failing = makeEntry({ id: 2, path: "s/2.json", sizeBytes: 1024 });
    const second = setup(failing);
    (
      second.deps.storageAdapter.upload as ReturnType<typeof vi.fn>
    ).mockRejectedValue(new Error("boom"));
    await uploadAll(second.deps, { now: () => new Date(T0) });
    await uploadAll(second.deps, { now: () => new Date(T0 + 1000) });
    expect(second.deps.storageAdapter.upload).toHaveBeenCalledTimes(1);
    expect(second.uploadState.snapshot().retrying).toHaveLength(1);
  });
});

describe("uploadAll — paged scan of a large backlog", () => {
  const SCOPE_KEY = new Uint8Array(32).fill(0xbb);
  const MIB = 1024 * 1024;
  const T0 = Date.parse("2026-11-07T12:00:00Z");
  const MINUTE = 60_000;

  beforeEach(() => {
    vi.clearAllMocks();
    (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(SCOPE_KEY);
    (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
      new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    );
  });

  const row = (id: number, overrides?: Partial<IndexEntry>) =>
    makeEntry({
      id,
      path: `p/${id}.json`,
      scope: `p.${id}`,
      sizeBytes: 1024,
      ...overrides,
    });

  /** A host with the keyset page method: rows after `afterId`, id order. */
  function setup(rows: IndexEntry[]) {
    const deps = makeMockDeps();
    const uploadState = createUploadStateTracker();
    deps.uploadState = uploadState;
    const pageLimits: number[] = [];
    deps.storage.findUnsynced = vi.fn(() => {
      throw new Error("a paged host is never asked for the whole set");
    });
    deps.storage.findUnsyncedPage = vi.fn(
      ({ afterId, limit }: { afterId: number; limit: number }) => {
        pageLimits.push(limit);
        return rows
          .filter((r) => r.dataPointId === null && r.id > afterId)
          .sort((a, b) => a.id - b.id)
          .slice(0, limit);
      },
    );
    deps.storage.maxUnsyncedId = vi.fn(() =>
      rows
        .filter((r) => r.dataPointId === null)
        .reduce((max, r) => Math.max(max, r.id), 0),
    );
    deps.storage.updateDataPointId = vi.fn(
      (path: string, id: string | null) => {
        const found = rows.find((r) => r.path === path);
        if (found) found.dataPointId = id;
        return true;
      },
    );
    return { deps, uploadState, rows, pageLimits };
  }

  it("reads at most the scan budget per cycle and still reaches rows behind a terminal prefix", async () => {
    const rows = [
      ...Array.from({ length: 25 }, (_, i) =>
        row(i + 1, { sizeBytes: 337 * MIB }),
      ),
      row(26),
    ];
    const { deps, pageLimits } = setup(rows);
    const uploaded: string[] = [];
    for (let i = 0; i < 6; i++) {
      const results = await uploadAll(deps, {
        batchSize: 2,
        scanBudget: 10,
        now: () => new Date(T0 + i * 60 * MINUTE),
      });
      uploaded.push(...results.map((r) => r.path));
    }
    expect(uploaded).toEqual(["p/26.json"]);
    expect(Math.max(...pageLimits)).toBeLessThanOrEqual(10);
  });

  it("does not forget backoff of rows outside the window it scanned", async () => {
    const rows = Array.from({ length: 30 }, (_, i) => row(i + 1));
    const { deps, uploadState } = setup(rows);
    // A row far beyond the first window has a failure on record.
    uploadState.recordFailure(
      {
        scope: "p.30",
        path: "p/30.json",
        identity: { id: 30, sizeBytes: 1024 },
      },
      "boom",
      T0,
    );
    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );

    await uploadAll(deps, {
      batchSize: 1,
      scanBudget: 10,
      now: () => new Date(T0 + 1000),
    });

    expect(uploadState.snapshot().retrying.map((e) => e.path)).toContain(
      "p/30.json",
    );
  });

  it("forgets a row that vanished from the range it scanned", async () => {
    const rows = Array.from({ length: 5 }, (_, i) => row(i + 1));
    const { deps, uploadState } = setup(rows);
    uploadState.recordFailure(
      {
        scope: "p.9",
        path: "p/9.json",
        identity: { id: 3.5, sizeBytes: 1024 },
      },
      "boom",
      T0,
    );
    (deps.storageAdapter.upload as ReturnType<typeof vi.fn>).mockRejectedValue(
      new Error("boom"),
    );

    await uploadAll(deps, {
      batchSize: 50,
      scanBudget: 10,
      now: () => new Date(T0 + 1000),
    });

    expect(uploadState.snapshot().retrying.map((e) => e.path)).not.toContain(
      "p/9.json",
    );
  });
  describe("tracked state above a new sweep's maximum", () => {
    const track = (uploadState: UploadStateTracker, id: number) =>
      uploadState.recordFailure(
        {
          scope: `p.${id}`,
          path: `p/${id}.json`,
          identity: { id, sizeBytes: 1024 },
        },
        "boom",
        T0,
      );

    it("prunes the state of a deleted tracked maximum while lower rows remain", async () => {
      const { deps, uploadState } = setup([row(1), row(2), row(3)]);
      track(uploadState, 10);
      await uploadAll(deps, { now: () => new Date(T0 + 1000) });
      expect(uploadState.has("p/10.json")).toBe(false);
    });

    it("prunes the state of the last deleted row", async () => {
      const { deps, uploadState } = setup([]);
      track(uploadState, 10);
      await uploadAll(deps, { now: () => new Date(T0 + 1000) });
      expect(uploadState.has("p/10.json")).toBe(false);
    });

    it("keeps live backoff above an older active fence", async () => {
      const { deps, uploadState } = setup([row(1), row(2), row(3), row(10)]);
      track(uploadState, 10);
      uploadState.setScanFence(3);
      uploadState.setScanCursor(1);
      await uploadAll(deps, {
        batchSize: 1,
        now: () => new Date(T0 + 1000),
      });
      expect(uploadState.has("p/10.json")).toBe(true);
    });

    it("does not bring the moving-tail starvation back on a host with a page method but no maximum", async () => {
      const { rows } = await runWithArrivals({
        initial: 100,
        arrivals: 50,
        cycles: 30,
        failScope: "p.1",
        failTimes: 1,
        withoutMax: true,
      });
      expect(rows.find((r) => r.id === 1)?.dataPointId).not.toBeNull();
    });
  });

  /** Rows arrive at the tail every cycle while the scan keeps working. */
  async function runWithArrivals(options: {
    initial: number;
    arrivals: number;
    batchSize?: number;
    scanBudget?: number;
    cycles: number;
    failScope: string;
    failTimes: number;
    withoutMax?: boolean;
    onCycle?: (cycle: number, rows: IndexEntry[]) => void;
  }) {
    const rows = Array.from({ length: options.initial }, (_, i) => row(i + 1));
    const ctx = setup(rows);
    if (options.withoutMax) {
      // A host with the page method but no maximum is scanned whole.
      ctx.deps.storage.maxUnsyncedId = undefined;
      ctx.deps.storage.findUnsynced = vi.fn(() =>
        rows.filter((r) => r.dataPointId === null),
      );
    }
    let failuresLeft = options.failTimes;
    (ctx.deps.storage.readEnvelope as ReturnType<typeof vi.fn>)
      .mockReset()
      .mockImplementation(async (scope: string) => {
        if (scope === options.failScope && failuresLeft > 0) {
          failuresLeft -= 1;
          throw new Error("transient");
        }
        return makeEnvelope();
      });
    let nextId = options.initial + 1;
    for (let cycle = 0; cycle < options.cycles; cycle++) {
      if (cycle > 0) {
        for (let i = 0; i < options.arrivals; i++) rows.push(row(nextId++));
      }
      options.onCycle?.(cycle, rows);
      await uploadAll(ctx.deps, {
        batchSize: options.batchSize,
        scanBudget: options.scanBudget,
        now: () => new Date(T0 + cycle * MINUTE),
      });
    }
    return ctx;
  }

  it("retries an earlier failed row while arrivals keep extending the tail (default sizes)", async () => {
    const { rows } = await runWithArrivals({
      initial: 100,
      arrivals: 50,
      cycles: 30,
      failScope: "p.1",
      failTimes: 1,
    });
    expect(rows.find((r) => r.id === 1)?.dataPointId).not.toBeNull();
  });

  it("retries an earlier failed row while arrivals keep extending the tail (small sizes)", async () => {
    const { rows } = await runWithArrivals({
      initial: 6,
      arrivals: 2,
      batchSize: 2,
      scanBudget: 5,
      cycles: 30,
      failScope: "p.1",
      failTimes: 1,
    });
    expect(rows.find((r) => r.id === 1)?.dataPointId).not.toBeNull();
  });

  it("prunes a tracked row deleted behind the cursor while arrivals continue", async () => {
    const ctx = await runWithArrivals({
      initial: 100,
      arrivals: 50,
      cycles: 40,
      failScope: "p.5",
      failTimes: Number.POSITIVE_INFINITY,
      onCycle: (cycle, rows) => {
        if (cycle !== 5) return;
        const at = rows.findIndex((r) => r.id === 5);
        if (at >= 0) rows.splice(at, 1);
      },
    });
    expect(
      ctx.uploadState.snapshot().retrying.map((e) => e.path),
    ).not.toContain("p/5.json");
  });
});
