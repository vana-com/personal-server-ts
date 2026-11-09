import { describe, it, expect, vi, beforeEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type {
  DataPointFeedPort,
  DataStoragePort,
  DeleteDataPort,
} from "../../ports/index.js";
import type { Logger } from "../../logger/index.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import type { RetireLegacyOption } from "../workers/retire-legacy.js";
import { entityKeySets } from "../../storage/legacy-entity-key-sets.js";
import { LEGACY_SCOPE_ENTITY_KEYS } from "../../storage/legacy-scope-entity-keys.js";

vi.mock("../workers/upload.js", () => ({ uploadAll: vi.fn(async () => []) }));
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(),
  downloadScopes: vi.fn(),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));

import { downloadAll } from "../workers/download.js";
import { createSyncManager } from "./sync-manager.js";

const BEFORE = "2026-11-01T00:00:00.000Z";
const SWITCH = "2026-11-05T00:00:00.000Z";
const SECRET = "youtube.history";

const logger = () =>
  ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }) as unknown as Logger;

function allLogged(...loggers: Logger[]): string {
  return JSON.stringify(
    loggers.flatMap((l) =>
      (["info", "warn", "error", "debug"] as const).flatMap(
        (level) => (l[level] as ReturnType<typeof vi.fn>).mock.calls,
      ),
    ),
  );
}

/** A legacy body holding one item, keyed as the reviewed table says. */
function keyedBody(scope: string, ids: readonly string[] = ["a"]) {
  const [path, fields] = Object.entries(LEGACY_SCOPE_ENTITY_KEYS[scope]!).find(
    ([p]) => /^\$\.\w+$/.test(p),
  )!;
  return {
    [path.slice(2)]: ids.map((id) =>
      Object.fromEntries(fields.map((f) => [f, id])),
    ),
  };
}

function rig(scopeNames = [SECRET, "github.events"], addedAt = BEFORE) {
  const scopes = new Set(scopeNames);
  const storage = {
    findUnsynced: () => [],
    listScopes: () => ({
      total: scopes.size,
      scopes: [...scopes].map((scope) => ({
        scope,
        latestCollectedAt: BEFORE,
        versionCount: 1,
      })),
    }),
    listVersions: (scope: string) =>
      scopes.has(scope)
        ? [
            {
              id: 1,
              fileId: null,
              schemaId: null,
              path: `${scope}/x.json`,
              scope,
              collectedAt: BEFORE,
              createdAt: BEFORE,
              sizeBytes: 1,
              version: 1,
              dataPointId: "0xdp",
            },
          ]
        : [],
    readEnvelope: async (scope: string) => ({ data: keyedBody(scope) }),
    markAfterTombstone: () => true,
    deleteScope: async (scope: string) => (scopes.delete(scope) ? 1 : 0),
    deleteVersion: async (scope: string) => scopes.delete(scope),
  } as unknown as DataStoragePort;
  const tombstone = vi.fn(async () => ({
    status: "tombstoned" as const,
    dataPointId: "0xsecret-id",
    version: "2",
    deletedAt: "2026-11-02T00:00:00.000Z",
  }));
  let blobFailure: string | null = null;
  const deleteData: DeleteDataPort = {
    tombstone,
    deleteBlobVersions: async (_s, versions) =>
      blobFailure
        ? {
            deleted: [],
            missing: [],
            failed: versions.map((version) => ({
              version,
              error: blobFailure!,
            })),
          }
        : { deleted: versions, missing: [], failed: [] },
  };
  const feed: DataPointFeedPort = {
    getDataPoint: async () => ({ addedAt }) as never,
    listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
  };
  const upload = {
    storage,
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger: logger(),
    dataPointFeed: feed,
  } as unknown as UploadWorkerDeps;
  const download = {
    storage,
    cursor: { read: async () => null, write: async () => {} },
    logger: logger(),
  } as unknown as DownloadWorkerDeps;
  return {
    scopes,
    tombstone,
    deleteData,
    upload,
    download,
    failBlobsWith: (message: string | null) => (blobFailure = message),
  };
}

/** A download pass that reports itself complete (or not), as the real one does. */
function downloadReports(complete: boolean) {
  vi.mocked(downloadAll).mockImplementation(async (deps) => {
    deps.onCycleOutcome?.({ complete });
    return [];
  });
}

const on =
  (
    covers: (scope: string) => boolean = () => true,
  ): (() => RetireLegacyOption) =>
  () => ({
    switchedAt: SWITCH,
    viewKeys: async (scope) => entityKeySets(scope, keyedBody(scope)),
    coverage: (scope) =>
      covers(scope)
        ? { kind: "covered", throughMs: Date.parse(SWITCH) }
        : { kind: "skip", reason: "incomplete" },
  });

describe("sync manager: retire legacy scopes after the switch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    downloadReports(true);
  });

  it("switch off: a cycle deletes nothing", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: () => null,
    });
    await manager.trigger();
    expect(r.tombstone).not.toHaveBeenCalled();
    expect(r.scopes.size).toBe(2);
  });

  it("no retireLegacy option at all: nothing is deleted", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
    });
    await manager.trigger();
    expect(r.scopes.size).toBe(2);
  });

  it("switch on: a cycle deletes the covered scopes and keeps the others", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on((s) => s === SECRET),
    });
    await manager.trigger();
    expect([...r.scopes]).toEqual(["github.events"]);
    expect(r.tombstone).toHaveBeenCalledTimes(1);
  });

  it("switch on but no remote delete port: nothing is deleted locally", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      retireLegacy: on(),
    });
    await manager.trigger();
    expect(r.scopes.size).toBe(2);
  });

  it("a download pass that reports a failure deletes nothing", async () => {
    downloadReports(false);
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on(),
    });
    await manager.trigger();
    expect(r.tombstone).not.toHaveBeenCalled();
    expect(r.scopes.size).toBe(2);
  });

  it("a download pass that throws deletes nothing", async () => {
    vi.mocked(downloadAll).mockRejectedValue(new Error("gateway down"));
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on(),
    });
    await manager.trigger();
    expect(r.tombstone).not.toHaveBeenCalled();
    expect(r.scopes.size).toBe(2);
  });

  it("a download pass that never reports its outcome deletes nothing", async () => {
    vi.mocked(downloadAll).mockResolvedValue([]);
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on(),
    });
    await manager.trigger();
    expect(r.tombstone).not.toHaveBeenCalled();
  });

  it("a failed pass after a good one does not reuse the earlier success", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on((s) => s === "github.events"),
    });
    await manager.trigger(); // good: retires github.events
    downloadReports(false);
    await manager.trigger(); // failed: must not retire the other one
    expect([...r.scopes]).toEqual([SECRET]);
  });

  it("the switch is read each cycle: turning it off stops retiring without a rebuild", async () => {
    const r = rig(["github.events", "youtube.likes", "strava.activities"]);
    let switched: RetireLegacyOption | null = null;
    const option = on();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: () => switched,
    });
    await manager.trigger();
    expect(r.scopes.size).toBe(3);
    switched = option();
    await manager.trigger();
    expect(r.scopes.size).toBe(0);
    r.scopes.add("shop.orders");
    switched = null;
    await manager.trigger();
    expect([...r.scopes]).toEqual(["shop.orders"]);
  });

  it("reports another device's legacy registrations after the switch in the sync status, and keeps those scopes", async () => {
    // Every scope's registry row is dated after the switch.
    const r = rig([SECRET, "github.events"], "2026-11-06T00:00:00.000Z");
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on(),
    });
    expect(manager.getStatus().streamSync).toEqual({
      legacyWritesAfterSwitch: 0,
    });
    await manager.trigger();
    expect(manager.getStatus().streamSync).toEqual({
      legacyWritesAfterSwitch: 2,
    });
    expect(r.scopes.size).toBe(2);
    expect(r.tombstone).not.toHaveBeenCalled();
  });

  it("this device's own rows after the switch report 0 and the scopes still retire", async () => {
    const r = rig();
    // Local rows dated after the switch (this device's current app).
    r.upload.storage.listVersions = ((scope: string) => [
      {
        id: 1,
        fileId: null,
        schemaId: null,
        path: `${scope}/x.json`,
        scope,
        collectedAt: "2026-11-06T00:00:00.000Z",
        createdAt: "2026-11-06T00:00:00.000Z",
        sizeBytes: 1,
        version: 1,
        dataPointId: "0xdp",
      },
    ]) as never;
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: () => ({
        ...on()(),
        coverage: () => ({
          kind: "covered",
          throughMs: Date.parse("2026-11-07T00:00:00.000Z"),
        }),
      }),
    });
    await manager.trigger();
    expect(manager.getStatus().streamSync).toEqual({
      legacyWritesAfterSwitch: 0,
    });
    expect(r.tombstone).toHaveBeenCalledTimes(2);
  });

  it("a good cycle then a thrown download: the second cycle deletes nothing (the outcome resets each cycle)", async () => {
    const r = rig();
    let covered = false;
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on(() => covered),
    });
    await manager.trigger(); // good pass, nothing covered yet
    expect(r.tombstone).not.toHaveBeenCalled();
    covered = true;
    vi.mocked(downloadAll).mockRejectedValue(new Error("gateway down"));
    await manager.trigger(); // the pass threw: the earlier success must not carry
    expect(r.tombstone).not.toHaveBeenCalled();
    expect(r.scopes.size).toBe(2);
  });

  it("the registry wiring: a head registered after the switch keeps the scope (not read as 'never seen')", async () => {
    const r = rig([SECRET], "2026-11-09T00:00:00.000Z");
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on(),
    });
    await manager.trigger();
    expect(r.tombstone).not.toHaveBeenCalled();
    expect([...r.scopes]).toEqual([SECRET]);
  });

  it("no registry to read keeps every scope (it is not 'the gateway never saw it')", async () => {
    const r = rig();
    (r.upload as { dataPointFeed?: unknown }).dataPointFeed = undefined;
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: on(),
    });
    await manager.trigger();
    expect(r.tombstone).not.toHaveBeenCalled();
  });

  it("turning the switch off mid-pass stops the next delete (read through the manager)", async () => {
    const r = rig([SECRET, "github.events", "youtube.likes"]);
    let option: RetireLegacyOption | null = on()();
    r.tombstone.mockImplementation(async () => {
      option = null; // the account switches off during the first delete
      return {
        status: "tombstoned" as const,
        dataPointId: "0xsecret-id",
        version: "2",
        deletedAt: "2026-11-02T00:00:00.000Z",
      };
    });
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      retireLegacy: () => option,
    });
    await manager.trigger();
    expect(r.tombstone).toHaveBeenCalledTimes(1);
    expect(r.scopes.size).toBe(2);
  });

  it("no log on the retire path carries a scope name, id, key or message text", async () => {
    const r = rig([SECRET]);
    // The first pass: the storage delete fails, leaving a retry marker; the
    // gateway then fails once in the next pass's retry.
    r.failBlobsWith("secret-message youtube.history");
    const pending = createMemoryPendingBlobDeletionStore();
    const manager = createSyncManager(r.upload, r.download, {
      deleteData: r.deleteData,
      pendingBlobDeletions: pending,
      retireLegacy: on(),
    });
    await manager.trigger();
    await manager.trigger(); // retries the marker
    r.tombstone.mockRejectedValueOnce(new Error("secret-message " + SECRET));
    r.scopes.add("amazon.orders");
    await manager.trigger();
    const logged = allLogged(r.upload.logger, r.download.logger);
    for (const forbidden of [
      "youtube",
      "github",
      "strava",
      "shop",
      "amazon",
      "secret",
      "0xsecret-id",
      "0xAbCd",
    ]) {
      expect(logged).not.toContain(forbidden);
    }
    expect(logged).toContain("Scope deletion finished");
  });
});
