import { keccak256, stringToHex } from "viem";
import {
  createLegacyDownloadHold,
  retainCanonicalInputs,
} from "./legacy-publication-fence.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { uploadAll, uploadOne } from "../../../core/src/sync/workers/upload.js";
import { downloadAll } from "../../../core/src/sync/workers/download.js";
import {
  withLegacyStorageFence,
  withLegacySignerFence,
  withLegacyGatewayFence,
} from "./legacy-publication-issuance.js";
import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../../../core/src/storage/adapters/interface.js";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import pino from "pino";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";
import {
  deriveScopeKey,
  decryptWithPassword,
  encryptWithPassword,
  createDataFileEnvelope,
} from "@opendatalabs/vana-sdk/node";
import {
  createLegacyPublicationPolicy,
  type LegacyRestorationAdapter,
} from "./legacy-publication-policy.js";
import type { LegacyCanonicalCoveragePort } from "./legacy-publication-canonical.js";

const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});
function fixture(maxRestorationBytes?: number, owner = "0xowner") {
  const root = mkdtempSync(join(tmpdir(), "legacy-rollback-"));
  cleanups.push(() => rmSync(root, { recursive: true, force: true }));
  const db = initializeDatabase(join(root, "index.db"));
  cleanups.push(() => db.open && db.close());
  const index = createIndexManager(db);
  const hierarchyOptions = { dataDir: join(root, "data") };
  const storage = createNodeDataStorage({
    indexManager: index,
    hierarchyOptions,
  });
  // Seed a qualified stopped cohort; qualification itself is tested separately.
  db.prepare(
    "INSERT INTO legacy_publication_policy VALUES (?, ?, ?, 'stopped', 2, 1, NULL)",
  ).run(owner, "generation-1", "spotify.profile");
  let revision = "current-1";
  const adapter: LegacyRestorationAdapter = {
    prepare: async (context) => ({
      ...context,
      contractVersion: 1,
      canonicalRevision: revision,
      canonicalIdentity: {
        declaration: "decl",
        artifact: "artifact",
        binding: "binding",
        projection: "projection",
        servingGeneration: "generation-1",
      },
      completeCurrentProjection: true,
      blobsHydrated: true,
      historyRecoveryQualified: true,
      envelope: {
        ...createDataFileEnvelope("spotify.profile", "2026-10-01T00:00:00Z", {
          full: "current canonical projection",
          unchangedStream: [1, 2],
          revision,
        }),
        producer: "pdpp-projector",
      },
    }),
    assertCurrent: (projection) => projection.canonicalRevision === revision,
    confirmRemote: async (commit) => ({
      owner,
      serverGeneration: "generation-1",
      scope: "spotify.profile",
      epoch: commit.epoch,
      canonicalRevision: commit.projection.canonicalRevision,
      operation: commit.receipt.operation,
      bodySha256: commit.receipt.bodySha256,
      headGeneration: commit.headGeneration,
      remoteRevision: "registered-final",
      visible: true,
      historyRecoveryQualified: true,
    }),
    commitReopen: vi.fn(() => true),
  };
  const makePolicy = () =>
    createLegacyPublicationPolicy(db, {
      owner,
      serverGeneration: "generation-1",
      enabled: () => false,
      storage: { indexManager: index, hierarchyOptions },
      restoration: adapter,
      now: () => Date.parse("2026-09-01T00:00:00Z"),
      maxRestorationBytes,
    });
  return {
    db,
    index,
    storage,
    adapter,
    makePolicy,
    setRevision: (value: string) => {
      revision = value;
    },
    root,
  };
}

describe("durable canonical rollback", () => {
  it("restores the complete current head once, monotonically, before reopening; retains history", async () => {
    const { db, index, storage, makePolicy, adapter, root } = fixture();
    // Historical files predate the gate; seed through a separate mirroring fixture.
    db.prepare("UPDATE legacy_publication_policy SET state='mirroring'").run();
    const prior = await storage.commitVersion!({
      kind: "append",
      envelope: createDataFileEnvelope(
        "spotify.profile",
        "2026-10-24T00:00:00Z",
        { old: true },
      ),
      metadata: {},
    });
    expect(prior.kind).toBe("stored");
    // Stop requires the queue to drain, so a stopped cohort's history is synced.
    index.updateDataPointId(
      index.findLatestByScope("spotify.profile")!.path,
      "prior-remote",
    );
    db.prepare(
      "INSERT INTO legacy_publication_retained_versions SELECT id FROM data_files",
    ).run();
    const old = index.findLatestByScope("spotify.profile")!;
    const bytes = readFileSync(join(root, "data", old.path));
    db.prepare("UPDATE legacy_publication_policy SET state='stopped'").run();
    const policy = makePolicy();
    const mirrored = await policy.rollback("spotify.profile", {
      expectedEpoch: 2,
    });
    expect(mirrored).toMatchObject({ state: "mirroring", epoch: 4 });
    expect(index.countByScope("spotify.profile")).toBe(2);
    const restored = index.findLatestByScope("spotify.profile")!;
    expect(Date.parse(restored.collectedAt)).toBeGreaterThan(
      Date.parse(old.collectedAt),
    );
    expect(restored.producer).toBe("pdpp-projector");
    expect(
      (await storage.readEnvelope("spotify.profile", restored.collectedAt))
        ?.data,
    ).toMatchObject({
      full: "current canonical projection",
      unchangedStream: [1, 2],
    });
    expect(readFileSync(join(root, "data", old.path))).toEqual(bytes);
    expect(adapter.commitReopen).toHaveBeenCalledOnce();
    expect(
      db
        .prepare("SELECT COUNT(*) n FROM legacy_publication_restorations")
        .get(),
    ).toEqual({ n: 1 });
  });

  it("reconciles uncertain remote delivery with the same operation and no duplicate after restart", async () => {
    const { db, root, index, adapter, makePolicy } = fixture();
    const confirm = adapter.confirmRemote;
    adapter.confirmRemote = vi
      .fn()
      .mockRejectedValueOnce(new Error("timeout after accepted POST"))
      .mockImplementation(confirm);
    const policy = makePolicy();
    await expect(
      policy.rollback("spotify.profile", { expectedEpoch: 2 }),
    ).rejects.toThrow("timeout");
    expect(policy.read("spotify.profile").state).toBe("restoring");
    expect(index.countByScope("spotify.profile")).toBe(1);
    const first = index.findLatestByScope("spotify.profile");
    db.close();
    const reopened = initializeDatabase(join(root, "index.db"));
    cleanups.push(() => reopened.close());
    const newIndex = createIndexManager(reopened);
    const restarted = createLegacyPublicationPolicy(reopened, {
      owner: "0xowner",
      serverGeneration: "generation-1",
      enabled: () => false,
      restoration: adapter,
      storage: {
        indexManager: newIndex,
        hierarchyOptions: { dataDir: join(root, "data") },
      },
    });
    expect(restarted.read("spotify.profile")).toMatchObject({
      state: "restoring",
      epoch: 3,
    });
    await restarted.rollback("spotify.profile", { expectedEpoch: 3 });
    expect(newIndex.countByScope("spotify.profile")).toBe(1);
    expect(newIndex.findLatestByScope("spotify.profile")).toEqual(first);
    const calls = vi.mocked(adapter.confirmRemote).mock.calls;
    expect(calls[0][0].receipt).toEqual(calls[1][0].receipt);
  });

  it.each(["offline", "missing blob", "oversized projection"])(
    "keeps restoring and never reopens for %s",
    async (reason) => {
      const { adapter, makePolicy, index } = fixture();
      adapter.prepare = async () => {
        throw new Error(reason);
      };
      const policy = makePolicy();
      await expect(
        policy.rollback("spotify.profile", { expectedEpoch: 2 }),
      ).rejects.toThrow(reason);
      expect(policy.read("spotify.profile").state).toBe("restoring");
      expect(index.countByScope("spotify.profile")).toBe(0);
      expect(adapter.commitReopen).not.toHaveBeenCalled();
    },
  );

  it("does not reopen after canonical data changes while remote confirmation is pending", async () => {
    const { adapter, makePolicy, setRevision, index } = fixture();
    const confirm = adapter.confirmRemote;
    adapter.confirmRemote = async (commit) => {
      setRevision("current-2");
      return confirm(commit);
    };
    const policy = makePolicy();
    await expect(
      policy.rollback("spotify.profile", { expectedEpoch: 2 }),
    ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_BLOCKED" });
    expect(policy.read("spotify.profile").state).toBe("restoring");
    expect(adapter.commitReopen).not.toHaveBeenCalled();
    adapter.confirmRemote = confirm;
    await makePolicy().rollback("spotify.profile", { expectedEpoch: 3 });
    expect(index.countByScope("spotify.profile")).toBe(2);
    expect(
      (
        (await adapter.prepare({
          owner: "0xowner",
          serverGeneration: "generation-1",
          scope: "spotify.profile",
          epoch: 3,
        })) as any
      ).canonicalRevision,
    ).toBe("current-2");
  });
});

it("retains a committed restored head before an uncertain remote acknowledgement", async () => {
  const { db, root, index, storage, adapter, makePolicy } = fixture();
  adapter.confirmRemote = async () => {
    throw new Error("remote acknowledgement lost");
  };
  const policy = makePolicy();
  await expect(
    policy.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toThrow("remote acknowledgement lost");
  const head = index.findLatestByScope("spotify.profile")!;
  const bytes = readFileSync(join(root, "data", head.path));
  expect(policy.read("spotify.profile").state).toBe("restoring");
  expect(index.countByScope("spotify.profile")).toBe(1);
  await expect(storage.deleteScope("spotify.profile")).rejects.toMatchObject({
    errorCode: "legacy_history_retained",
  });
  expect(() => index.deleteByScope("spotify.profile")).toThrow(
    "legacy_history_retained",
  );
  expect(readFileSync(join(root, "data", head.path))).toEqual(bytes);
  expect(
    db
      .prepare("SELECT COUNT(*) n FROM legacy_publication_retained_versions")
      .get(),
  ).toEqual({ n: 1 });
});

it("keeps the independent index repair fence and refuses to reopen rollback", async () => {
  const { index, makePolicy, adapter } = fixture();
  index.closeScopeForWrites("spotify.profile");
  const policy = makePolicy();
  await expect(
    policy.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toMatchObject({ errorCode: "SCOPE_CLOSED_FOR_WRITES" });
  expect(policy.read("spotify.profile").state).toBe("restoring");
  expect(adapter.commitReopen).not.toHaveBeenCalled();
});

it("reopening failure rolls back its durable effects and keeps local issuance fenced", async () => {
  const { db, root, index, adapter, makePolicy } = fixture();
  db.exec("CREATE TABLE reopen_outbox(value TEXT)");
  adapter.commitReopen = () => {
    db.prepare("INSERT INTO reopen_outbox VALUES ('reopen')").run();
    return false;
  };
  const policy = makePolicy();
  await expect(
    policy.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_BLOCKED" });
  expect(policy.read("spotify.profile").state).toBe("restoring");
  expect(db.prepare("SELECT * FROM reopen_outbox").all()).toEqual([]);
  expect(index.countByScope("spotify.profile")).toBe(1);
  await expect(
    createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
    }).writeEnvelope(
      createDataFileEnvelope("spotify.profile", "2026-10-30T00:00:00Z", {
        unauthorized: true,
      }),
    ),
  ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
});

it("refuses a projection exceeding the real restoration byte limit before publishing", async () => {
  const { makePolicy, index, adapter } = fixture(16);
  const policy = makePolicy();
  await expect(
    policy.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_TOO_LARGE" });
  expect(policy.read("spotify.profile").state).toBe("restoring");
  expect(index.countByScope("spotify.profile")).toBe(0);
  expect(adapter.commitReopen).not.toHaveBeenCalled();
});

it("recovers a prepared restoration after publication failed before index commit", async () => {
  const { db, root, adapter, makePolicy } = fixture();
  db.exec(
    "CREATE TRIGGER inject_restore_failure BEFORE INSERT ON data_files BEGIN SELECT RAISE(ABORT, 'injected crash boundary'); END",
  );
  const policy = makePolicy();
  await expect(
    policy.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toThrow("injected crash boundary");
  expect(db.prepare("SELECT state FROM owner_import_operations").get()).toEqual(
    { state: "prepared" },
  );
  expect(policy.read("spotify.profile")).toMatchObject({
    state: "restoring",
    epoch: 3,
  });
  db.close();
  const reopened = initializeDatabase(join(root, "index.db"));
  cleanups.push(() => reopened.close());
  reopened.exec("DROP TRIGGER inject_restore_failure");
  const newIndex = createIndexManager(reopened);
  const hierarchyOptions = { dataDir: join(root, "data") };
  createNodeDataStorage({ indexManager: newIndex, hierarchyOptions });
  expect(newIndex.countByScope("spotify.profile")).toBe(1);
  const head = newIndex.findLatestByScope("spotify.profile");
  const restarted = createLegacyPublicationPolicy(reopened, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => false,
    restoration: adapter,
    storage: { indexManager: newIndex, hierarchyOptions },
  });
  await expect(
    restarted.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_POLICY_EPOCH_MISMATCH" });
  await restarted.rollback("spotify.profile", { expectedEpoch: 3 });
  expect(newIndex.countByScope("spotify.profile")).toBe(1);
  expect(newIndex.findLatestByScope("spotify.profile")).toEqual(head);
});

it("reads stopped after closing the database; old clients and identity changes cannot bypass it", async () => {
  const { db, root } = fixture();
  db.close();
  const reopened = initializeDatabase(join(root, "index.db"));
  cleanups.push(() => reopened.close());
  const policy = createLegacyPublicationPolicy(reopened, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => false,
  });
  expect(policy.read("spotify.profile")).toMatchObject({
    state: "stopped",
    epoch: 2,
  });
  await expect(
    policy.stop("spotify.profile", { expectedEpoch: 0, ownerOptIn: true }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_POLICY_EPOCH_MISMATCH" });
  expect(() =>
    reopened
      .prepare(
        "INSERT INTO data_files(scope, path, collected_at) VALUES ('spotify.profile', 'old-client.json', '2026-10-24T00:00:00Z')",
      )
      .run(),
  ).toThrow("legacy_scope_retired");
  for (const identity of [
    { owner: "0xother", serverGeneration: "generation-1" },
    { owner: "0xowner", serverGeneration: "generation-2" },
  ]) {
    const changed = createLegacyPublicationPolicy(reopened, {
      ...identity,
      enabled: () => false,
    });
    expect(changed.read("spotify.profile")).toMatchObject({
      state: "stopped",
      identityMismatch: true,
    });
    await expect(
      changed.rollback("spotify.profile", { expectedEpoch: 2 }),
    ).rejects.toMatchObject({ errorCode: "LEGACY_POLICY_IDENTITY_MISMATCH" });
  }
});

it("publishes the restored head through the real upload worker and all three fences only", async () => {
  const { db, storage, index, adapter, makePolicy } = fixture();
  const masterKey = new Uint8Array(32).fill(7);
  const blobs = new Map<string, Uint8Array>();
  const rawStorage: StorageAdapter = {
    upload: vi.fn(async (key, bytes) => {
      if (blobs.has(key)) throw new StoredBlobConflictError(key);
      blobs.set(key, bytes.slice());
      return key;
    }),
    download: async (key) => blobs.get(key)!.slice(),
    urlForKey: (key) => key,
    exists: async (key) => blobs.has(key),
    delete: async () => false,
  };
  const rawSigner = {
    signAddData: vi.fn(async () => "0xsigned"),
  } as unknown as ServerSigner;
  const rawGateway = {
    getDataPoint: async () => null,
    registerDataPoint: vi.fn(async () => ({ dataPointId: "restored-remote" })),
  } as unknown as GatewayClient;
  const signer = withLegacySignerFence(db, rawSigner);
  const gateway = withLegacyGatewayFence(db, rawGateway);
  const remoteStorage = withLegacyStorageFence(
    db,
    "0xowner",
    rawStorage,
    masterKey,
    storage,
  );
  const confirm = adapter.confirmRemote;
  adapter.confirmRemote = async (commit) => {
    expect(makePolicy().read("spotify.profile").state).toBe("restoring");
    const entry = index.findLatestByScope("spotify.profile")!;
    const deps = {
      storage,
      storageAdapter: remoteStorage,
      gateway,
      signer,
      masterKey,
      serverOwner: "0xowner",
      logger: pino({ level: "silent" }),
    };
    // Fail after the real upload/sign to exercise ciphertext conflict recovery.
    vi.mocked(rawGateway.registerDataPoint).mockRejectedValueOnce(
      new Error("registry offline"),
    );
    await expect(uploadOne(deps, entry)).rejects.toThrow("registry offline");
    await uploadOne(deps, entry);
    expect(index.findLatestByScope(entry.scope)?.dataPointId).toBe(
      "restored-remote",
    );
    const message = vi.mocked(rawSigner.signAddData).mock.calls.at(-1)![0];
    const currentEnvelope = await storage.readEnvelope(
      entry.scope,
      entry.collectedAt,
    );
    const password = Buffer.from(
      deriveScopeKey(masterKey, entry.scope),
    ).toString("hex");
    for (const clear of [
      JSON.stringify({ ...currentEnvelope, data: { unauthorized: true } }),
      JSON.stringify(currentEnvelope, null, 2),
    ]) {
      const forged = await encryptWithPassword(
        new TextEncoder().encode(clear),
        password,
      );
      await expect(
        remoteStorage.upload(`${entry.scope}/${entry.version}`, forged),
      ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
    }

    expect(
      await createLegacyDownloadHold(
        db,
        remoteStorage,
        storage,
        masterKey,
      )({
        id: "restored-remote",
        ownerAddress: "0xowner",
        scope: entry.scope,
        expectedVersion: String(message.expectedVersion),
        dataHash: message.dataHash,
        metadataHash: message.metadataHash,
        addedAt: "2026-10-24T00:00:00Z",
        deletedAt: null,
      } as any),
    ).toBe(true);
    expect(db.prepare("SELECT * FROM legacy_publication_holds").all()).toEqual(
      [],
    );
    for (const changed of [
      { expectedVersion: message.expectedVersion + 1n },
      { dataHash: `0x${"0".repeat(64)}` },
      { metadataHash: `0x${"0".repeat(64)}` },
      { ownerAddress: "0xforeign" },
    ]) {
      await expect(
        signer.signAddData({ ...message, ...changed } as typeof message),
      ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
      await expect(
        gateway.registerDataPoint({
          ...message,
          expectedVersion: String(message.expectedVersion),
          signature: "0xsig",
          ...changed,
        } as any),
      ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
    }
    await expect(
      remoteStorage.upload(
        `${entry.scope}/${entry.version + 1}`,
        blobs.values().next().value!,
      ),
    ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
    db.prepare(
      "INSERT INTO legacy_publication_policy VALUES ('0xowner','generation-1','spotify.playlists','stopped',2,1,NULL)",
    ).run();
    await expect(
      signer.signAddData({ ...message, scope: "spotify.playlists" }),
    ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
    await expect(
      remoteStorage.upload(
        `spotify.playlists/${entry.version}`,
        blobs.values().next().value!,
      ),
    ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
    db.prepare(
      "UPDATE legacy_publication_restore_authorization SET operation='stale'",
    ).run();
    await expect(signer.signAddData(message)).rejects.toMatchObject({
      errorCode: "legacy_scope_retired",
    });
    db.prepare(
      "UPDATE legacy_publication_restore_authorization SET operation=?",
    ).run(commit.receipt.operation);
    expect(() =>
      db
        .prepare("UPDATE data_files SET generation='different-head' WHERE id=?")
        .run(entry.id),
    ).toThrow("legacy_history_retained");
    return confirm(commit);
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 2 }),
  ).resolves.toMatchObject({ state: "mirroring" });
  expect(rawSigner.signAddData).toHaveBeenCalledTimes(2);
  expect(rawGateway.registerDataPoint).toHaveBeenCalledTimes(2);
  expect(index.countByScope("spotify.profile")).toBe(1);
});

it("retains all legacy and canonical history after rollback, blocks owner deletion with 409, and protects REPLACE", async () => {
  const { db, storage, adapter, makePolicy } = fixture();
  const records = createSqliteRecordStore(db);
  records.registerConnection({
    instance: "conn",
    sourceId: "https://example.test/spotify",
    method: "test",
    label: "test",
  });
  records.ingestBatch(
    [
      {
        instance: "conn",
        stream: "profile",
        key: "owner",
        data: { id: "owner" },
        emitted_at: "2026-10-01T00:00:00Z",
      },
    ],
    () => "upsert",
    () => ["id"],
    { method: "test", generation: 1 },
  );
  retainCanonicalInputs(db, [
    { instance: "conn", stream: "profile", generation: 1 },
  ]);
  await makePolicy().rollback("spotify.profile", { expectedEpoch: 2 });
  expect(adapter.commitReopen).toHaveBeenCalledOnce();
  await expect(storage.deleteScope("spotify.profile")).rejects.toMatchObject({
    code: 409,
    errorCode: "legacy_history_retained",
  });
  expect(() => records.deleteConnection("conn")).toThrow(
    expect.objectContaining({
      code: 409,
      errorCode: "canonical_history_retained",
    }),
  );
  expect(() =>
    records.resetInstanceBinding({
      instance: "conn",
      expectedMethod: "test",
      expectedGeneration: 1,
      nextMethod: "test",
    }),
  ).toThrow(
    expect.objectContaining({
      code: 409,
      errorCode: "canonical_history_retained",
    }),
  );
  expect(() =>
    db.exec("INSERT OR REPLACE INTO data_files SELECT * FROM data_files"),
  ).toThrow("legacy_history_retained");
  expect(() =>
    db.exec(
      "INSERT OR REPLACE INTO pdpp_record_changes SELECT * FROM pdpp_record_changes",
    ),
  ).toThrow("canonical_history_retained");
  expect(records.getRecord("conn", "profile", "owner")?.data).toEqual({
    id: "owner",
  });
  expect(
    db.prepare("SELECT COUNT(*) n FROM pdpp_record_changes").get(),
  ).toEqual({ n: 1 });
});

it("reconciles an accepted restore through download after its registration response is lost", async () => {
  const { db, storage, index, adapter, makePolicy } = fixture();
  const masterKey = new Uint8Array(32).fill(7);
  const blobs = new Map<string, Uint8Array>();
  const rawStorage: StorageAdapter = {
    upload: async (key, bytes) => {
      if (blobs.has(key)) throw new StoredBlobConflictError(key);
      blobs.set(key, bytes.slice());
      return key;
    },
    download: async (key) => blobs.get(key)!.slice(),
    urlForKey: (key) => key,
    exists: async (key) => blobs.has(key),
    delete: async () => false,
  };
  let accepted: any;
  const register = vi.fn(async (request: any) => {
    accepted = {
      ...request,
      id: "restored-remote",
      addedAt: "2026-10-24T00:00:00Z",
      deletedAt: null,
    };
    throw new Error("timeout after accept");
  });
  const gateway = withLegacyGatewayFence(db, {
    getDataPoint: async () => accepted ?? null,
    registerDataPoint: register,
  } as unknown as GatewayClient);
  const remote = withLegacyStorageFence(
    db,
    "0xowner",
    rawStorage,
    masterKey,
    storage,
  );
  const deps = {
    storage,
    storageAdapter: remote,
    gateway,
    masterKey,
    serverOwner: "0xowner",
    signer: withLegacySignerFence(db, {
      signAddData: async () => "0xsigned",
    } as unknown as ServerSigner),
    dataPointFeed: {
      getDataPoint: async () => accepted ?? null,
      listDataPointsByOwner: async () => ({
        dataPoints: [accepted],
        cursor: "observed",
      }),
    },
    logger: pino({ level: "silent" }),
  };
  const cursor = { read: async () => null, write: vi.fn(async () => {}) };
  const confirm = adapter.confirmRemote;
  adapter.confirmRemote = async (commit) => {
    const head = index.findLatestByScope("spotify.profile")!;
    await expect(uploadOne(deps, head)).rejects.toThrow("timeout after accept");
    expect(index.findLatestByScope(head.scope)?.dataPointId).toBeNull();
    await downloadAll({
      ...deps,
      cursor,
      holdRemoteChange: createLegacyDownloadHold(
        db,
        remote,
        storage,
        masterKey,
      ),
    });
    expect(cursor.write).toHaveBeenCalledWith("observed");
    expect(makePolicy().read(head.scope).blockers).toEqual([]);
    await uploadOne(deps, index.findLatestByScope(head.scope)!);
    expect(index.findLatestByScope(head.scope)?.dataPointId).toBe(
      "restored-remote",
    );
    return confirm(commit);
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 2 }),
  ).resolves.toMatchObject({ state: "mirroring" });
  expect(register).toHaveBeenCalledOnce();
  expect(index.countByScope("spotify.profile")).toBe(1);
});

it("keeps superseded restores readable but never publishes them after reopening, including captured queue entries", async () => {
  const { db, storage, index, adapter, makePolicy, setRevision, root } =
    fixture();
  const masterKey = new Uint8Array(32).fill(7);
  const blobs = new Map<string, Uint8Array>();
  const rawStorage: StorageAdapter = {
    upload: vi.fn(async (key, bytes) => {
      if (blobs.has(key)) throw new StoredBlobConflictError(key);
      blobs.set(key, bytes.slice());
      return key;
    }),
    download: async (key) => blobs.get(key)!.slice(),
    urlForKey: (key) => key,
    exists: async (key) => blobs.has(key),
    delete: async () => false,
  };
  const chain: any[] = [];
  const rawGateway = {
    getDataPoint: async () => chain.at(-1) ?? null,
    registerDataPoint: vi.fn(async (req: any) => {
      const next = chain.length + 1;
      if (Number(req.expectedVersion) !== next)
        throw new Error(`Gateway error: 409 next valid version is ${next}`);
      chain.push({ id: "dp", ...req, addedAt: new Date().toISOString() });
      return { dataPointId: "dp" };
    }),
  } as unknown as GatewayClient;
  const deps = {
    dataPointFeed: {
      getDataPoint: async () => chain.at(-1) ?? null,
      listDataPointsByOwner: async () => ({ dataPoints: chain, cursor: null }),
    },
    storage,
    storageAdapter: withLegacyStorageFence(
      db,
      "0xowner",
      rawStorage,
      masterKey,
      storage,
    ),
    gateway: withLegacyGatewayFence(db, rawGateway),
    signer: withLegacySignerFence(db, {
      signAddData: async () => "0xsig",
    } as unknown as ServerSigner),
    masterKey,
    serverOwner: "0xowner",
    logger: pino({ level: "silent" }),
  };
  const confirm = adapter.confirmRemote;
  adapter.confirmRemote = async () => {
    throw new Error("failed before upload");
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toThrow("failed before upload");
  const stale = index.findUnsynced()[0];
  const bytes = readFileSync(join(root, "data", stale.path));
  setRevision("current-2");
  adapter.confirmRemote = async (commit) => {
    await uploadAll(deps);
    expect(chain).toHaveLength(1);
    return confirm(commit);
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
  ).resolves.toMatchObject({ state: "mirroring" });
  expect(index.findUnsynced()).toEqual([]);
  expect(index.isHistoryOnly(stale.scope, stale.path)).toBe(true);
  await expect(uploadOne(deps, stale)).rejects.toMatchObject({
    code: "HISTORY_ONLY_VERSION",
  });
  await uploadAll(deps);
  expect(chain).toHaveLength(1);
  const latest = chain.at(-1);
  const password = Buffer.from(deriveScopeKey(masterKey, stale.scope)).toString(
    "hex",
  );
  const latestBody = JSON.parse(
    new TextDecoder().decode(
      await decryptWithPassword(
        blobs.get(`${stale.scope}/${latest.expectedVersion}`)!,
        password,
      ),
    ),
  );
  expect(latestBody.data.revision).toBe("current-2");
  expect(readFileSync(join(root, "data", stale.path))).toEqual(bytes);
  expect(
    (await storage.readEnvelope(stale.scope, stale.collectedAt)).data,
  ).toMatchObject({ revision: "current-1" });
  expect(index.countByScope(stale.scope)).toBe(2);
  expect(
    db
      .prepare("SELECT state FROM owner_import_operations ORDER BY rowid")
      .all(),
  ).toEqual([{ state: "accepted" }, { state: "accepted" }]);
  // A captured entry may already hold ciphertext; signing and registration
  // refuse its exact upload commitment after reopening too.
  const superseded = db
    .prepare(
      "SELECT data_hash FROM legacy_publication_restore_versions WHERE state='superseded'",
    )
    .get() as { data_hash: string };
  expect(superseded.data_hash).toBe(
    keccak256(
      stringToHex(
        JSON.stringify(
          await storage.readEnvelope(stale.scope, stale.collectedAt),
        ),
      ),
    ),
  );
  const forged = {
    ownerAddress: "0xowner",
    scope: stale.scope,
    dataHash: superseded.data_hash,
    metadataHash: `0x${"5".repeat(64)}`,
  };
  await expect(
    deps.signer.signAddData({ ...forged, expectedVersion: 2n } as any),
  ).rejects.toMatchObject({ code: "HISTORY_ONLY_VERSION" });
  await expect(
    deps.gateway.registerDataPoint({
      ...forged,
      expectedVersion: "2",
      signature: "0xsig",
    } as any),
  ).rejects.toMatchObject({ code: "HISTORY_ONLY_VERSION" });
  expect(chain).toHaveLength(1);
});

it("refuses every local deletion or drop while fenced, including unretained rows", async () => {
  const { db, root, index, storage } = fixture();
  // Rows that are not in the retained set must still survive any fenced state.
  db.prepare("UPDATE legacy_publication_policy SET state='mirroring'").run();
  for (const collectedAt of ["2026-10-02T00:00:00Z", "2026-10-03T00:00:00Z"])
    await storage.commitVersion!({
      kind: "append",
      envelope: createDataFileEnvelope("spotify.profile", collectedAt, {
        collectedAt,
      }),
      metadata: {},
    });
  const [synced, unsynced] = index.findUnsynced();
  index.updateDataPointId(synced.path, "remote-1");
  index.updateFileId(synced.path, "file-1");
  for (const state of ["quiescing", "stopped", "restoring"]) {
    db.prepare("UPDATE legacy_publication_policy SET state=?").run(state);
    for (const attempt of [
      () => storage.deleteScope("spotify.profile"),
      () => storage.deleteVersion("spotify.profile", synced.collectedAt),
      () => storage.deleteByFileId("file-1"),
      () => storage.dropUnsyncedEntry!(unsynced.path),
    ])
      await expect(attempt()).rejects.toMatchObject({
        code: 409,
        errorCode: "legacy_history_retained",
      });
  }
  expect(index.countByScope("spotify.profile")).toBe(2);
  for (const entry of [synced, unsynced])
    expect(readFileSync(join(root, "data", entry.path))).toBeTruthy();
});

it("after reopening, an unretained new row with a missing file self-heals while retained rows stay protected", async () => {
  const { db, root, index, storage, makePolicy } = fixture();
  await makePolicy().rollback("spotify.profile", { expectedEpoch: 2 });
  const restored = index.findLatestByScope("spotify.profile")!;
  await storage.commitVersion!({
    kind: "append",
    envelope: createDataFileEnvelope(
      "spotify.profile",
      "2026-12-01T00:00:00Z",
      {
        after: "reopen",
      },
    ),
    metadata: {},
  });
  const fresh = index.findLatestByScope("spotify.profile")!;
  expect(fresh.id).not.toBe(restored.id);
  rmSync(join(root, "data", fresh.path));
  const deps = {
    storage,
    logger: pino({ level: "silent" }),
  } as unknown as Parameters<typeof uploadOne>[0];
  await expect(uploadOne(deps, fresh)).rejects.toThrow(
    "Orphaned index entry dropped",
  );
  expect(index.findByPath(fresh.path)).toBeUndefined();
  rmSync(join(root, "data", restored.path));
  await expect(storage.dropUnsyncedEntry!(restored.path)).rejects.toMatchObject(
    { code: 409, errorCode: "legacy_history_retained" },
  );
  expect(index.findByPath(restored.path)).toBeDefined();
  expect(
    db
      .prepare("SELECT COUNT(*) n FROM legacy_publication_retained_versions")
      .get(),
  ).toEqual({ n: 1 });
});

it("repins a superseded restore's refused version on a host without a data-point feed, then registers the current head once", async () => {
  // A real address: without a feed the head lookup derives the data-point id.
  const owner = "0x1111111111111111111111111111111111111111";
  const { db, storage, index, adapter, makePolicy, setRevision } = fixture(
    undefined,
    owner,
  );
  const masterKey = new Uint8Array(32).fill(7);
  const blobs = new Map<string, Uint8Array>();
  const rawStorage: StorageAdapter = {
    upload: async (key, bytes) => {
      if (blobs.has(key)) throw new StoredBlobConflictError(key);
      blobs.set(key, bytes.slice());
      return key;
    },
    download: async (key) => blobs.get(key)!.slice(),
    urlForKey: (key) => key,
    exists: async (key) => blobs.has(key),
    delete: async () => false,
  };
  const chain: any[] = [];
  const register = vi.fn(async (req: any) => {
    const next = chain.length + 1;
    if (Number(req.expectedVersion) !== next)
      throw new Error(`Gateway error: 409 next valid version is ${next}`);
    chain.push({ id: "dp", ...req, addedAt: "2026-10-24T00:00:00Z" });
    return { dataPointId: "dp" };
  });
  // No dataPointFeed: publication starts from the local version.
  const deps = {
    storage,
    storageAdapter: withLegacyStorageFence(
      db,
      owner,
      rawStorage,
      masterKey,
      storage,
    ),
    gateway: withLegacyGatewayFence(db, {
      getDataPoint: async () => chain.at(-1) ?? null,
      registerDataPoint: register,
    } as unknown as GatewayClient),
    signer: withLegacySignerFence(db, {
      signAddData: async () => "0xsig",
    } as unknown as ServerSigner),
    masterKey,
    serverOwner: owner,
    logger: pino({ level: "silent" }),
  };
  const confirm = adapter.confirmRemote;
  adapter.confirmRemote = async () => {
    throw new Error("failed before upload");
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toThrow("failed before upload");
  setRevision("current-2");
  const errors: string[] = [];
  adapter.confirmRemote = async (commit) => {
    await uploadAll(deps, {
      onError: (_entry, error) => errors.push(error.message),
    });
    expect(errors).toEqual([]);
    expect(chain.map((c) => c.expectedVersion)).toEqual(["1"]);
    return confirm(commit);
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
  ).resolves.toMatchObject({ state: "mirroring" });
  await uploadAll(deps);
  expect(chain).toHaveLength(1);
  const password = Buffer.from(
    deriveScopeKey(masterKey, "spotify.profile"),
  ).toString("hex");
  const latest = JSON.parse(
    new TextDecoder().decode(
      await decryptWithPassword(blobs.get("spotify.profile/1")!, password),
    ),
  );
  expect(latest.data.revision).toBe("current-2");
  // The pin moved only because the gateway proved version 2 was unregistered.
  expect(register.mock.calls.map(([req]) => req.expectedVersion)).toEqual([
    "2",
    "1",
  ]);
  expect(index.findUnsynced()).toEqual([]);
});

it("a superseded restore that can never publish does not block a later shutdown's drain check", async () => {
  const { db, adapter, makePolicy, setRevision, index } = fixture();
  const confirm = adapter.confirmRemote;
  adapter.confirmRemote = async () => {
    throw new Error("failed before upload");
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toThrow("failed before upload");
  setRevision("current-2");
  adapter.confirmRemote = confirm;
  await makePolicy().rollback("spotify.profile", { expectedEpoch: 3 });
  // The confirmed head is synced; only the superseded history-only row is not.
  const head = index.findLatestByScope("spotify.profile")!;
  index.updateDataPointId(head.path, "restored-remote");
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: {
      freezeAndQualify: async () => ({ incomplete: true }),
      assertCurrent: () => false,
    },
  });
  await expect(
    policy.stop("spotify.profile", { ownerOptIn: true, expectedEpoch: 4 }),
  ).rejects.toMatchObject({
    errorCode: "LEGACY_SHUTDOWN_BLOCKED",
    message: "Incomplete or non-terminal shutdown evidence",
  });
  expect(policy.read("spotify.profile")).toMatchObject({
    state: "quiescing",
    epoch: 5,
  });
});

it("never treats a foreign head at the pinned restore version as our own, and keeps its hold", async () => {
  const { db, storage, index, adapter, makePolicy } = fixture();
  const masterKey = new Uint8Array(32).fill(7);
  const blobs = new Map<string, Uint8Array>();
  const rawStorage: StorageAdapter = {
    upload: async (key, bytes) => {
      blobs.set(key, bytes.slice());
      return key;
    },
    download: async (key) => blobs.get(key)!.slice(),
    urlForKey: (key) => key,
    exists: async (key) => blobs.has(key),
    delete: async () => false,
  };
  let accepted: any;
  const gateway = withLegacyGatewayFence(db, {
    getDataPoint: async () => null,
    registerDataPoint: async (request: any) => {
      accepted = {
        ...request,
        id: "restored-remote",
        addedAt: "2026-10-24T00:00:00Z",
        deletedAt: null,
      };
      throw new Error("timeout after accept");
    },
  } as unknown as GatewayClient);
  const remote = withLegacyStorageFence(
    db,
    "0xowner",
    rawStorage,
    masterKey,
    storage,
  );
  // Bootstrap wiring: the hold reads raw remote bytes.
  const hold = createLegacyDownloadHold(db, rawStorage, storage, masterKey);
  const deps = {
    storage,
    storageAdapter: remote,
    gateway,
    masterKey,
    serverOwner: "0xowner",
    signer: withLegacySignerFence(db, {
      signAddData: async () => "0xsigned",
    } as unknown as ServerSigner),
    logger: pino({ level: "silent" }),
  };
  adapter.confirmRemote = async () => {
    await expect(
      uploadOne(deps, index.findLatestByScope("spotify.profile")!),
    ).rejects.toThrow("timeout after accept");
    const password = Buffer.from(
      deriveScopeKey(masterKey, "spotify.profile"),
    ).toString("hex");
    const foreign = await encryptWithPassword(
      new TextEncoder().encode('{"foreign":true}'),
      password,
    );
    // A different writer occupies the same version with other commitments.
    for (const changed of [
      { dataHash: `0x${"3".repeat(64)}` },
      { metadataHash: `0x${"4".repeat(64)}` },
      { ownerAddress: "0xforeign" },
    ]) {
      blobs.set(`spotify.profile/${accepted.expectedVersion}`, foreign);
      expect(await hold({ ...accepted, ...changed })).toBe(true);
    }
    expect(makePolicy().read("spotify.profile").blockers).toHaveLength(3);
    throw new Error("remote head is foreign");
  };
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toThrow("remote head is foreign");
  await expect(
    makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_BLOCKED" });
  expect(makePolicy().read("spotify.profile")).toMatchObject({
    state: "restoring",
  });
  expect(makePolicy().read("spotify.profile").blockers).toHaveLength(3);
});

describe("a lost restore acknowledgement followed by a supersede", () => {
  // Gateway contract: one data point per (owner, scope), sequential versions,
  // and a feed that lists the scope head. The first accepted registration can
  // lose its response.
  function race(options: { keepAck?: boolean } = {}) {
    const world = fixture();
    const { db, storage, adapter } = world;
    const masterKey = new Uint8Array(32).fill(7);
    const blobs = new Map<string, Uint8Array>();
    let failNextBlobUpload = false;
    const rawStorage: StorageAdapter = {
      upload: async (key, bytes) => {
        if (failNextBlobUpload) {
          failNextBlobUpload = false;
          throw new Error("storage 503");
        }
        if (blobs.has(key)) throw new StoredBlobConflictError(key);
        blobs.set(key, bytes.slice());
        return key;
      },
      download: async (key) => {
        const bytes = blobs.get(key);
        if (!bytes) throw new Error("404");
        return bytes.slice();
      },
      urlForKey: (key) => key,
      exists: async (key) => blobs.has(key),
      delete: async () => false,
    };
    let head: any = null;
    let loseAck = !options.keepAck;
    const registrations: any[] = [];
    const rawGateway = {
      getDataPoint: async () => head,
      registerDataPoint: vi.fn(async (req: any) => {
        const next = head ? Number(head.expectedVersion) + 1 : 1;
        if (Number(req.expectedVersion) !== next)
          throw new Error(`Gateway error: 409 next valid version is ${next}`);
        head = {
          id: "dp-spotify",
          ownerAddress: req.ownerAddress,
          scope: req.scope,
          dataHash: req.dataHash,
          metadataHash: req.metadataHash,
          expectedVersion: String(req.expectedVersion),
          addedAt: "2026-10-24T00:00:00Z",
          deletedAt: null,
        };
        registrations.push(head);
        if (loseAck) {
          loseAck = false;
          throw new Error("timeout after accept");
        }
        return { dataPointId: "dp-spotify" };
      }),
    } as unknown as GatewayClient;
    let listed: () => any[] = () => (head ? [head] : []);
    const deps = {
      storage,
      storageAdapter: withLegacyStorageFence(
        db,
        "0xowner",
        rawStorage,
        masterKey,
        storage,
      ),
      gateway: withLegacyGatewayFence(db, rawGateway),
      signer: withLegacySignerFence(db, {
        signAddData: async () => "0xsig",
      } as unknown as ServerSigner),
      masterKey,
      serverOwner: "0xowner",
      logger: pino({ level: "silent" }),
      dataPointFeed: {
        getDataPoint: async () => head,
        listDataPointsByOwner: async () => ({
          dataPoints: listed(),
          cursor: null,
        }),
      },
    };
    const cursor = { read: async () => null, write: vi.fn(async () => {}) };
    // Bootstrap wiring: the hold reads raw remote bytes.
    const hold = createLegacyDownloadHold(db, rawStorage, storage, masterKey);
    const download = () =>
      downloadAll({ ...deps, cursor, holdRemoteChange: hold });
    const confirm = adapter.confirmRemote;
    const restoreRows = () =>
      db
        .prepare(
          "SELECT version_id, operation, data_hash, state FROM legacy_publication_restore_versions ORDER BY version_id",
        )
        .all() as {
        version_id: number;
        operation: string;
        data_hash: string;
        state: string;
      }[];
    // Attempt 1 commits op1; remote confirmation is not yet available. The
    // upload worker registers op1; the gateway accepts but the response is lost.
    async function publishOp1() {
      adapter.confirmRemote = async () => {
        throw new Error("not yet visible");
      };
      await expect(
        world.makePolicy().rollback("spotify.profile", { expectedEpoch: 2 }),
      ).rejects.toThrow("not yet visible");
      const op1 = world.index.findLatestByScope("spotify.profile")!;
      if (options.keepAck) await uploadOne(deps, op1);
      else {
        await expect(uploadOne(deps, op1)).rejects.toThrow(
          "timeout after accept",
        );
        expect(
          world.index.findLatestByScope("spotify.profile")!.dataPointId,
        ).toBeNull();
      }
      expect(head).toMatchObject({ expectedVersion: "1" });
      // A listing before any supersede recognizes the current restore.
      await download();
      expect(world.makePolicy().read("spotify.profile").blockers).toEqual([]);
      // Canonical ingest continued while restoring.
      world.setRevision("current-2");
      return op1;
    }
    return {
      ...world,
      deps,
      blobs,
      hold,
      download,
      confirm,
      publishOp1,
      restoreRows,
      registrations,
      masterKey,
      head: () => head,
      failNextBlobUpload: () => {
        failNextBlobUpload = true;
      },
      list: (records: () => any[]) => {
        listed = records;
      },
    };
  }

  async function expectOwnHistoryRetainedAfterReopen(
    world: ReturnType<typeof race>,
    op1: { path: string; scope: string; collectedAt: string },
  ) {
    const { db, index, storage, deps, blobs, masterKey, restoreRows } = world;
    const [superseded, confirmed] = restoreRows();
    expect([superseded.state, confirmed.state]).toEqual([
      "superseded",
      "confirmed",
    ]);
    // Exactly one registration per operation; the remote head is op2 at v2.
    expect(
      world.registrations.map((r) => [r.expectedVersion, r.dataHash]),
    ).toEqual([
      ["1", superseded.data_hash],
      ["2", confirmed.data_hash],
    ]);
    expect(world.head()).toMatchObject({
      expectedVersion: "2",
      dataHash: confirmed.data_hash,
    });
    const password = Buffer.from(
      deriveScopeKey(masterKey, "spotify.profile"),
    ).toString("hex");
    const remoteBody = async (version: string) =>
      JSON.parse(
        new TextDecoder().decode(
          await decryptWithPassword(
            blobs.get(`spotify.profile/${version}`)!,
            password,
          ),
        ),
      ).data.revision;
    expect(await remoteBody("1")).toBe("current-1");
    expect(await remoteBody("2")).toBe("current-2");
    // All local history stays readable and retained.
    expect(index.countByScope("spotify.profile")).toBe(2);
    expect(
      (await storage.readEnvelope(op1.scope, op1.collectedAt)).data,
    ).toMatchObject({ revision: "current-1" });
    expect(
      db
        .prepare("SELECT COUNT(*) n FROM legacy_publication_retained_versions")
        .get(),
    ).toEqual({ n: 2 });
    expect(
      db.prepare("SELECT COUNT(*) n FROM legacy_publication_holds").get(),
    ).toEqual({ n: 0 });
    // The superseded op1 stays ineligible at the queue, blob, signer and
    // registration boundaries after reopening.
    expect(index.findUnsynced()).toEqual([]);
    expect(index.isHistoryOnly(op1.scope, op1.path)).toBe(true);
    const op1Row = index.findByPath(op1.path)!;
    // An acknowledged op1 is already synced; only an unacknowledged one could publish.
    if (op1Row.dataPointId === null)
      await expect(uploadOne(deps, op1Row)).rejects.toMatchObject({
        code: "HISTORY_ONLY_VERSION",
      });
    const forged = {
      ownerAddress: "0xowner",
      scope: op1.scope,
      dataHash: superseded.data_hash,
      metadataHash: `0x${"5".repeat(64)}`,
    };
    await expect(
      deps.signer.signAddData({ ...forged, expectedVersion: 3n } as any),
    ).rejects.toMatchObject({ code: "HISTORY_ONLY_VERSION" });
    await expect(
      deps.gateway.registerDataPoint({
        ...forged,
        expectedVersion: "3",
        signature: "0xsig",
      } as any),
    ).rejects.toMatchObject({ code: "HISTORY_ONLY_VERSION" });
    await uploadAll(deps);
    expect(world.registrations).toHaveLength(2);
  }

  it("CONTROL-ACK: an acknowledged op1 listed after the supersede is retained history", async () => {
    const world = race({ keepAck: true });
    const op1 = await world.publishOp1();
    world.adapter.confirmRemote = async (commit) => {
      await world.download();
      await uploadAll(world.deps);
      return world.confirm(commit);
    };
    await expect(
      world.makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
    ).resolves.toMatchObject({ state: "mirroring", blockers: [] });
    await expectOwnHistoryRetainedAfterReopen(world, op1);
  });

  it("recognizes our unacknowledged superseded op1 when a download lists it before op2 uploads", async () => {
    const world = race();
    const op1 = await world.publishOp1();
    world.adapter.confirmRemote = async (commit) => {
      // hydrateScopes, startup hydration or a concurrent cycle's download.
      await world.download();
      expect(world.makePolicy().read("spotify.profile").blockers).toEqual([]);
      await uploadAll(world.deps);
      return world.confirm(commit);
    };
    await expect(
      world.makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
    ).resolves.toMatchObject({ state: "mirroring", blockers: [] });
    await expectOwnHistoryRetainedAfterReopen(world, op1);
  });

  it("recognizes our unacknowledged superseded op1 when op2's blob upload fails transiently before the download", async () => {
    const world = race();
    const op1 = await world.publishOp1();
    world.adapter.confirmRemote = async (commit) => {
      // Sync-manager order: upload, then download, even after a failed upload.
      world.failNextBlobUpload();
      await uploadAll(world.deps);
      expect(world.registrations).toHaveLength(1);
      await world.download();
      expect(world.makePolicy().read("spotify.profile").blockers).toEqual([]);
      await uploadAll(world.deps);
      return world.confirm(commit);
    };
    await expect(
      world.makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
    ).resolves.toMatchObject({ state: "mirroring", blockers: [] });
    await expectOwnHistoryRetainedAfterReopen(world, op1);
  });

  it("recognized op1 history neither confirms the stale head nor reopens without op2's own confirmation", async () => {
    const world = race();
    await world.publishOp1();
    world.adapter.confirmRemote = async (commit) => {
      await world.download();
      // op2 has not registered; a confirmation of op1's stale head is refused.
      const [op1] = world.restoreRows();
      const stale = (await world.confirm(commit)) as Record<string, unknown>;
      return { ...stale, operation: op1.operation };
    };
    await expect(
      world.makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
    ).rejects.toMatchObject({
      errorCode: "LEGACY_RESTORE_BLOCKED",
      message: "Remote confirmation does not identify this restored operation",
    });
    expect(world.makePolicy().read("spotify.profile")).toMatchObject({
      state: "restoring",
      blockers: [],
    });
    expect(world.registrations).toHaveLength(1);
    world.adapter.confirmRemote = async (commit) => {
      await uploadAll(world.deps);
      return world.confirm(commit);
    };
    await expect(
      world.makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
    ).resolves.toMatchObject({ state: "mirroring" });
    expect(world.registrations.map((r) => r.expectedVersion)).toEqual([
      "1",
      "2",
    ]);
  });

  it("still holds foreign heads at op1's version, and recognizing op1 keeps every existing hold", async () => {
    const world = race();
    await world.publishOp1();
    world.adapter.confirmRemote = async () => {
      const op1Head = world.head();
      const password = Buffer.from(
        deriveScopeKey(world.masterKey, "spotify.profile"),
      ).toString("hex");
      const ownBlob = world.blobs.get("spotify.profile/1")!;
      for (const changed of [
        { dataHash: `0x${"3".repeat(64)}` },
        { metadataHash: `0x${"4".repeat(64)}` },
        { ownerAddress: "0xforeign" },
      ])
        expect(await world.hold({ ...op1Head, ...changed })).toBe(true);
      // Our exact commitments over foreign ciphertext are not our history.
      world.blobs.set(
        "spotify.profile/1",
        await encryptWithPassword(
          new TextEncoder().encode('{"foreign":true}'),
          password,
        ),
      );
      expect(await world.hold(op1Head)).toBe(true);
      world.blobs.set("spotify.profile/1", ownBlob);
      expect(world.makePolicy().read("spotify.profile").blockers).toHaveLength(
        4,
      );
      // The exact own superseded op1 is recognized without adding or clearing holds.
      await world.download();
      expect(world.makePolicy().read("spotify.profile").blockers).toHaveLength(
        4,
      );
      throw new Error("remote head is foreign");
    };
    await expect(
      world.makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
    ).rejects.toThrow("remote head is foreign");
    await expect(
      world.makePolicy().rollback("spotify.profile", { expectedEpoch: 3 }),
    ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_BLOCKED" });
    expect(world.makePolicy().read("spotify.profile")).toMatchObject({
      state: "restoring",
    });
    expect(world.makePolicy().read("spotify.profile").blockers).toHaveLength(4);
  });
});

/** Lifecycle tests stub the native port; legacy-publication-canonical.test.ts covers the real reader. */
function canonicalStub(): LegacyCanonicalCoveragePort {
  const coverage = (scope: string, servingGeneration: string) => ({
    scope,
    identity: {
      declaration: "decl",
      artifact: "artifact",
      projection: "projection",
      binding: "binding",
      servingGeneration,
    },
    inputs: [{ instance: "conn", stream: "profile", generation: 1 }],
    receipts: [],
    additionsTrackedSince: "2026-10-01T00:00:00.000Z",
    inputDigest: "inputs-1",
  });
  return {
    assess: (scope, generation) => ({
      ok: true,
      coverage: coverage(scope, generation),
    }),
    qualify: async (scope, generation) => ({
      ok: true,
      coverage: {
        ...coverage(scope, generation),
        projectionRevision: "projection-1",
        watermark: "committed-1",
      },
    }),
    isCurrent: () => true,
  };
}
