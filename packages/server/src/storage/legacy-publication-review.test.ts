import { keccak256, stringToHex } from "viem";
import { createLegacyDownloadHold } from "./legacy-publication-fence.js";
import { downloadAll } from "../../../core/src/sync/workers/download.js";
import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/node";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { StorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import pino from "pino";
import { afterEach, expect, it, vi } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import {
  createNodeDataStorage,
  reindexLegacyDataFiles,
} from "./node-data-storage.js";
import { createLegacyPublicationPolicy } from "./legacy-publication-policy.js";

const cleanup: (() => void)[] = [];
afterEach(() => {
  for (const fn of cleanup.splice(0).reverse()) fn();
});
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "gate-review-"));
  cleanup.push(() => rmSync(root, { recursive: true, force: true }));
  const db = initializeDatabase(join(root, "index.db"));
  cleanup.push(() => db.open && db.close());
  const index = createIndexManager(db);
  const hierarchyOptions = { dataDir: join(root, "data") };
  mkdirSync(hierarchyOptions.dataDir);
  const storage = createNodeDataStorage({
    indexManager: index,
    hierarchyOptions,
  });
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "gen",
    enabled: () => true,
  });
  const stop = () =>
    db
      .prepare(
        "INSERT INTO legacy_publication_policy VALUES ('0xowner', 'gen', 'spotify.profile', 'stopped', 2, 1, NULL)",
      )
      .run();
  return { root, db, index, hierarchyOptions, storage, policy, stop };
}

it("holds fenced recovery orphans durably, preserves bytes and recovers unrelated scopes", async () => {
  const f = fixture();
  f.stop();
  const paths = ["spotify.profile", "spotify.playlists"].map((scope) => {
    const env = createDataFileEnvelope(scope, "2026-10-01T00:00:00Z", {
      scope,
    });
    const path = buildDataFilePath(
      f.hierarchyOptions.dataDir,
      scope,
      env.collectedAt,
    );
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(env));
    return path;
  });
  const bytes = readFileSync(paths[0]);
  await expect(
    reindexLegacyDataFiles({
      indexManager: f.index,
      hierarchyOptions: f.hierarchyOptions,
    }),
  ).resolves.toBe(1);
  expect(f.index.countByScope("spotify.profile")).toBe(0);
  expect(readFileSync(paths[0])).toEqual(bytes);
  const held = f.db
    .prepare(
      "SELECT kind, payload FROM legacy_publication_holds WHERE scope='spotify.profile'",
    )
    .get();
  expect(held).toEqual({ kind: "recovery-orphan", payload: bytes });
  expect(f.policy.read("spotify.profile")).toMatchObject({
    blockers: [{ kind: "recovery-orphan" }],
  });
  await reindexLegacyDataFiles({
    indexManager: f.index,
    hierarchyOptions: f.hierarchyOptions,
  });
  expect(
    f.db.prepare("SELECT COUNT(*) n FROM legacy_publication_holds").get(),
  ).toEqual({ n: 1 });
  f.db.close();
  const restarted = initializeDatabase(join(f.root, "index.db"));
  cleanup.push(() => restarted.close());
  const policy = createLegacyPublicationPolicy(restarted, {
    owner: "0xowner",
    serverGeneration: "gen",
    enabled: () => true,
  });
  expect(policy.read("spotify.profile").blockers).toHaveLength(1);
  await expect(
    policy.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_BLOCKED" });
  expect(readFileSync(paths[0])).toEqual(bytes);
});

it("verifies lazy NULL generation fill while retaining immutable identity and permits only matching file repair", async () => {
  const f = fixture();
  const env = createDataFileEnvelope(
    "spotify.profile",
    "2026-10-01T00:00:00Z",
    { old: true },
  );
  await f.storage.commitVersion!({
    kind: "append",
    envelope: env,
    metadata: {},
  });
  f.db.prepare("UPDATE data_files SET generation=NULL").run();
  const entry = f.index.findLatestByScope(env.scope)!;
  f.index.updateDataPointId(entry.path, "retained-remote");
  f.db
    .prepare(
      "INSERT INTO legacy_publication_retained_versions SELECT id FROM data_files",
    )
    .run();
  f.stop();
  const versionPath = join(f.hierarchyOptions.dataDir, entry.path);
  const originalBytes = readFileSync(versionPath);
  rmSync(versionPath);
  await expect(f.storage.backfillGeneration!(entry)).resolves.toBeUndefined();
  writeFileSync(versionPath, originalBytes);
  // Raw callers cannot invent a retained generation.
  expect(() => f.index.swapGeneration(entry.id, null, "invented")).toThrow(
    "legacy_history_retained",
  );
  const generation = await f.storage.backfillGeneration!(entry);
  expect(generation).toMatch(/^[a-f0-9]{64}$/);
  expect(() =>
    f.index.swapGeneration(entry.id, generation!, "different"),
  ).toThrow("legacy_history_retained");
  const persisted = await f.storage.readEnvelope(
    entry.scope,
    entry.collectedAt,
  );
  rmSync(join(f.hierarchyOptions.dataDir, entry.path));
  await expect(
    f.storage.writeEnvelope({ ...persisted, data: { wrong: true } }),
  ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
  await expect(f.storage.writeEnvelope(persisted)).resolves.toMatchObject({
    relativePath: entry.path,
  });
  expect(f.index.countByScope(entry.scope)).toBe(1);
  rmSync(join(f.hierarchyOptions.dataDir, entry.path));
  const replica = {
    kind: "replica" as const,
    envelope: persisted,
    metadata: {
      schemaId: null,
      dataPointId: "retained-remote",
      version: entry.version,
    },
  };
  await expect(
    f.storage.commitVersion!({
      ...replica,
      metadata: { ...replica.metadata, version: entry.version + 1 },
    }),
  ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
  await expect(f.storage.commitVersion!(replica)).resolves.toMatchObject({
    kind: "stored",
    entry: { id: entry.id, generation },
  });
  expect(f.index.countByScope(entry.scope)).toBe(1);
});

it("keeps never-enrolled schema compatible and detached stop fails with unavailable", async () => {
  const f = fixture();
  expect(f.db.pragma("user_version", { simple: true })).toBe(16);
  const { stop } = f.policy;
  await expect(
    stop("spotify.profile", { ownerOptIn: true, expectedEpoch: 0 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_UNAVAILABLE" });
  expect(f.db.pragma("user_version", { simple: true })).toBe(16);
});

it("holds fenced live heads and tombstones durably without stalling unrelated download pages", async () => {
  const f = fixture();
  await f.storage.commitVersion!({
    kind: "append",
    envelope: createDataFileEnvelope(
      "spotify.profile",
      "2026-10-01T00:00:00Z",
      { retained: true },
    ),
    metadata: {},
  });
  f.db
    .prepare(
      "INSERT INTO legacy_publication_retained_versions SELECT id FROM data_files",
    )
    .run();
  f.stop();
  const original = f.index.findLatestByScope("spotify.profile")!;
  const bytes = readFileSync(join(f.hierarchyOptions.dataDir, original.path));
  const masterKey = new Uint8Array(32).fill(8);
  const encrypted = new Map<string, Uint8Array>();
  for (const scope of ["spotify.profile", "spotify.playlists"]) {
    encrypted.set(
      `${scope}/2`,
      await encryptWithPassword(
        new TextEncoder().encode(
          JSON.stringify(
            createDataFileEnvelope(scope, "2026-10-02T00:00:00Z", { scope }),
          ),
        ),
        Buffer.from(deriveScopeKey(masterKey, scope)).toString("hex"),
      ),
    );
  }
  const records = ["spotify.profile", "spotify.playlists"].map((scope, i) => ({
    id: `dp-${i}`,
    scope,
    expectedVersion: "2",
    dataHash: `0x${"1".repeat(64)}`,
    metadataHash: `0x${"2".repeat(64)}`,
    addedAt: "2026-10-02T00:00:00Z",
  }));
  const remote: StorageAdapter = {
    urlForKey: (key) => key,
    download: async (key) => encrypted.get(key)!.slice(),
    upload: async (key) => key,
    exists: async () => true,
    delete: async () => false,
  };
  // An unchanged registry head whose bytes are already retained is skipped,
  // rather than inventing a foreign-head blocker on every normal sync pass.
  const knownEnvelope = await f.storage.readEnvelope(
    original.scope,
    original.collectedAt,
  );
  const clear = new TextEncoder().encode(JSON.stringify(knownEnvelope));
  const knownCipher = await encryptWithPassword(
    clear,
    Buffer.from(deriveScopeKey(masterKey, original.scope)).toString("hex"),
  );
  encrypted.set(`${original.scope}/1`, knownCipher);
  f.index.updateDataPointId(original.path, "known");
  const hold = createLegacyDownloadHold(f.db, remote, f.storage, masterKey);
  expect(
    await hold({
      ...records[0],
      id: "known",
      expectedVersion: "1",
      deletedAt: null,
      dataHash: keccak256(clear),
      metadataHash: keccak256(
        stringToHex(
          JSON.stringify({
            scope: original.scope,
            collectedAt: original.collectedAt,
            sizeBytes: knownCipher.byteLength,
          }),
        ),
      ),
    } as any),
  ).toBe(true);
  expect(
    f.db.prepare("SELECT COUNT(*) n FROM legacy_publication_holds").get(),
  ).toEqual({ n: 0 });
  const cursor = {
    read: vi.fn(async () => null),
    write: vi.fn(async () => {}),
  };
  const listing = vi.fn(async () => ({
    dataPoints: records,
    cursor: "next-page",
  }));
  const deps = {
    holdRemoteChange: hold,
    storage: f.storage,
    storageAdapter: remote,
    gateway: {} as GatewayClient,
    masterKey,
    serverOwner: "0xowner",
    cursor,
    dataPointFeed: {
      listDataPointsByOwner: listing,
      getDataPoint: async () => null,
    },
    logger: pino({ level: "silent" }),
  };
  const results = await downloadAll(deps);
  expect(results.map((r) => r.scope)).toEqual(["spotify.playlists"]);
  expect(cursor.write).toHaveBeenCalledWith("next-page");
  const held = f.db
    .prepare(
      "SELECT kind, payload FROM legacy_publication_holds WHERE scope='spotify.profile'",
    )
    .get();
  expect(held).toEqual({
    kind: "remote-head",
    payload: Buffer.from(encrypted.get("spotify.profile/2")!),
  });
  // A tombstone is a separate held instruction, not an erasure or canonical claim.
  listing.mockResolvedValueOnce({
    dataPoints: [
      {
        ...records[0],
        deletedAt: "2026-10-03T00:00:00Z",
        expectedVersion: "3",
      },
    ],
    cursor: "after-delete",
  } as any);
  await downloadAll(deps);
  expect(cursor.write).toHaveBeenCalledWith("after-delete");
  expect(readFileSync(join(f.hierarchyOptions.dataDir, original.path))).toEqual(
    bytes,
  );
  expect(
    f.db
      .prepare("SELECT kind FROM legacy_publication_holds ORDER BY kind")
      .all(),
  ).toEqual([{ kind: "remote-head" }, { kind: "remote-tombstone" }]);
  expect(f.index.countByScope("spotify.profile")).toBe(1);
  cursor.write.mockClear();
  remote.download = async () => {
    throw new Error("hold storage offline");
  };
  await downloadAll(deps);
  expect(cursor.write).not.toHaveBeenCalled();
  expect(readFileSync(join(f.hierarchyOptions.dataDir, original.path))).toEqual(
    bytes,
  );
});

it("boot keeps fenced prepared-import journals and their bytes without crashing or accepting them", () => {
  const f = fixture();
  f.stop();
  const envelope = createDataFileEnvelope(
    "spotify.profile",
    "2026-10-01T00:00:00Z",
    { pending: true },
  );
  const bytes = Buffer.from(JSON.stringify(envelope));
  f.db
    .prepare(
      "INSERT INTO owner_import_operations VALUES ('owner-import','0xowner','spotify.profile','pending','digest','prepared',?,'pending.json',?,'{}',NULL)",
    )
    .run(envelope.collectedAt, bytes);
  expect(() =>
    createNodeDataStorage({
      indexManager: f.index,
      hierarchyOptions: f.hierarchyOptions,
    }),
  ).not.toThrow();
  expect(f.index.countByScope("spotify.profile")).toBe(0);
  expect(
    f.db
      .prepare("SELECT state, envelope_bytes FROM owner_import_operations")
      .get(),
  ).toEqual({ state: "prepared", envelope_bytes: bytes });
  expect(
    f.db.prepare("SELECT kind, payload FROM legacy_publication_holds").get(),
  ).toEqual({ kind: "prepared-import", payload: bytes });
});

it("records a permanently missing fenced foreign blob as a durable blocker and advances; transient or unpersisted holds stay retryable", async () => {
  const f = fixture();
  f.stop();
  const record = {
    id: "foreign",
    ownerAddress: "0xowner",
    scope: "spotify.profile",
    expectedVersion: "9",
    dataHash: `0x${"1".repeat(64)}`,
    metadataHash: `0x${"2".repeat(64)}`,
    addedAt: "2026-10-02T00:00:00Z",
    deletedAt: null,
  };
  let failure: Error = Object.assign(
    new Error("Storage download failed: 503 Service Unavailable"),
    { status: 503 },
  );
  const remote: StorageAdapter = {
    urlForKey: (key) => key,
    download: async () => {
      throw failure;
    },
    upload: async (key) => key,
    exists: async () => false,
    delete: async () => false,
  };
  const masterKey = new Uint8Array(32).fill(1);
  const cursor = {
    read: vi.fn(async () => "c0"),
    write: vi.fn(async () => {}),
  };
  const deps = {
    holdRemoteChange: createLegacyDownloadHold(
      f.db,
      remote,
      f.storage,
      masterKey,
    ),
    storage: f.storage,
    storageAdapter: remote,
    gateway: {} as GatewayClient,
    masterKey,
    serverOwner: "0xowner",
    cursor,
    dataPointFeed: {
      listDataPointsByOwner: async () => ({
        dataPoints: [record],
        cursor: "c1",
      }),
      getDataPoint: async () => null,
    },
    logger: pino({ level: "silent" }),
  };
  const blockers = () => f.policy.read("spotify.profile").blockers;
  // Unknown or transient availability is not evidence the blob is gone.
  await downloadAll(deps as any);
  expect(cursor.write).not.toHaveBeenCalled();
  expect(blockers()).toEqual([]);
  // A deterministic 404 holds the record metadata with no bytes.
  failure = Object.assign(new Error("Storage download failed: 404 Not Found"), {
    status: 404,
  });
  f.db.exec(
    "CREATE TRIGGER fail_hold BEFORE INSERT ON legacy_publication_holds BEGIN SELECT RAISE(ABORT, 'disk full'); END",
  );
  await downloadAll(deps as any);
  expect(cursor.write).not.toHaveBeenCalled();
  f.db.exec("DROP TRIGGER fail_hold");
  await downloadAll(deps as any);
  expect(cursor.write).toHaveBeenCalledWith("c1");
  expect(blockers()).toEqual([
    { id: expect.any(String), kind: "remote-head-missing-blob" },
  ]);
  const held = f.db
    .prepare("SELECT identity_json, payload FROM legacy_publication_holds")
    .get() as { identity_json: string; payload: Buffer };
  expect(JSON.parse(held.identity_json)).toMatchObject({
    record,
    failure: { stage: "download", disposition: "deterministic" },
  });
  expect(held.payload.byteLength).toBe(0);
  // The blocker is durable: stop and rollback both refuse until recovery.
  await expect(
    f.policy.rollback("spotify.profile", { expectedEpoch: 2 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_BLOCKED" });
});
