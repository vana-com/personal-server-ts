import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "@opendatalabs/personal-server-ts-core/api";
import {
  createScopeDeletionTracker,
  deleteScope,
} from "@opendatalabs/personal-server-ts-core/sync";
import { createIndexManager } from "./index-manager.js";
import { initializeDatabase } from "./index-schema.js";
import { createNodeDataStorage } from "./node-data-storage.js";

const owner = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const scope = "notes.items";
const logger = { debug() {}, info() {}, warn() {}, error() {} } as never;
const DELETED_AT = "2026-10-02T00:00:00Z";

function openServer(root: string) {
  const index = createIndexManager(initializeDatabase(join(root, "index.db")));
  const storage = createNodeDataStorage({
    indexManager: index,
    hierarchyOptions: { dataDir: join(root, "data") },
  });
  return { index, storage };
}

/** A direct owner-import commit, as the import route makes it, marker included. */
function importCommit(value: string, afterTombstoneVersion: number | null) {
  return {
    kind: "append" as const,
    envelope: createDataFileEnvelope(scope, "2026-10-01T00:00:00Z", { value }),
    metadata: { afterTombstoneVersion },
    import: {
      authority: "local",
      owner,
      operation: value.repeat(64),
      bodySha256: value.repeat(64),
    },
  };
}

/** The owner's HTTP PUT import, the same request a connector sends. */
function putImport(value: string) {
  return new Request(
    `https://ps.example/${scope}/imports/${value.repeat(64)}`,
    {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value }),
    },
  );
}

function routeDeps(
  storage: ReturnType<typeof openServer>["storage"],
  scopeDeletions: ReturnType<typeof createScopeDeletionTracker>,
): PersonalServerDataApiDeps {
  return {
    storage,
    serverOwner: owner,
    scopeDeletions,
    auth: {
      authorizeOwner: async () => undefined,
      authorizeBuilderRead: async () => undefined,
      authorizeBuilderList: async () => undefined,
    },
    accessLogWriter: { write: async () => undefined },
    now: () => new Date("2026-10-02T01:00:00Z"),
  };
}

function gatewayTombstone() {
  return {
    tombstone: async () => ({
      status: "tombstoned" as const,
      dataPointId: "0xdp",
      version: "4",
      deletedAt: DELETED_AT,
    }),
  };
}

/** An ordinary (non-import) local write: the stamp is the row's collection time. */
function storedCommit(
  value: string,
  collectedAt: string,
  afterTombstoneVersion: number | null = null,
) {
  return {
    kind: "append" as const,
    envelope: createDataFileEnvelope(scope, collectedAt, { value }),
    metadata: { afterTombstoneVersion },
  };
}

/**
 * Passes every storage call straight through, except that the first erase
 * pauses right after it returns, so a test can act between two erases.
 */
function pauseAfterFirstErase(storage: Storage) {
  let erasures = 0;
  let reach!: (collectedAt: string) => void;
  const reached = new Promise<string>((resolve) => {
    reach = resolve;
  });
  let open!: () => void;
  const gate = new Promise<void>((resolve) => {
    open = resolve;
  });
  const port = new Proxy(storage, {
    get(target, prop, receiver) {
      if (prop !== "deleteVersion") return Reflect.get(target, prop, receiver);
      return async (scope: string, collectedAt: string, fence?: unknown) => {
        const removed = await target.deleteVersion(
          scope,
          collectedAt,
          fence as never,
        );
        erasures += 1;
        if (erasures === 1) {
          reach(collectedAt);
          await gate;
        }
        return removed;
      };
    },
  });
  return { port, reached, release: () => open() };
}

describe("a stamp freed after capture is not erased for a later owner re-add", () => {
  it("erases only the captured versions when an owner re-add takes a freed stamp mid-deletion", async () => {
    const root = await mkdtemp(join(tmpdir(), "psd-readd-fence-"));
    const { index, storage } = openServer(root);
    try {
      const tracker = createScopeDeletionTracker();
      await storage.commitVersion!(
        storedCommit("a", "2026-08-01T00:00:00.000Z"),
      );
      await storage.commitVersion!(
        storedCommit("old", "2026-08-02T00:00:00.000Z"),
      );
      const covered = storage.listVersions(scope, { limit: 10 });
      const paused = pauseAfterFirstErase(storage);

      const deletion = deleteScope(
        {
          storage: paused.port,
          serverOwner: owner,
          scopeDeletions: tracker,
          logger,
          deleteData: {
            ...gatewayTombstone(),
            deleteBlobVersions: async (_scope, versions) => ({
              deleted: versions,
              missing: [],
              failed: [],
            }),
          },
        },
        scope,
      );
      const firstErased = await paused.reached;
      const stamp = covered
        .map((entry) => entry.collectedAt)
        .find((collectedAt) => collectedAt !== firstErased)!;

      // A concurrent deleter frees the later covered stamp.
      expect(await storage.deleteVersion(scope, stamp)).toBe(true);
      // The owner's real HTTP import takes that same collection stamp.
      const readd = await handlePersonalServerDataRequest(putImport("c"), {
        ...routeDeps(storage, tracker),
        now: () => new Date(stamp),
      });
      expect(readd.status).toBe(201);
      // A null-marker write that arrives after the snapshot.
      await storage.commitVersion!(
        storedCommit("plain", "2026-10-02T00:40:00.000Z"),
      );
      paused.release();
      const result = await deletion;

      expect(result.steps.local).toMatchObject({
        status: "ok",
        deletedCount: 1,
      });
      const survivors = storage.listVersions(scope, { limit: 10 });
      expect(survivors.map((entry) => entry.collectedAt).sort()).toEqual(
        [stamp, "2026-10-02T00:40:00Z"].sort(),
      );
      expect(JSON.stringify(await storage.readEnvelope(scope, stamp))).toMatch(
        /"value":"c"/,
      );
      // The owner's operation was not retired: its replay still succeeds.
      const replay = await handlePersonalServerDataRequest(
        putImport("c"),
        routeDeps(storage, createScopeDeletionTracker()),
      );
      expect(replay.status).toBe(200);
      expect(await replay.text()).not.toContain("IMPORT_DELETED");
    } finally {
      index.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("scope deletion while the remote blob delete is in flight", () => {
  it("erases the covered version and keeps an owner re-add accepted during the remote delete, across restart", async () => {
    const root = await mkdtemp(join(tmpdir(), "psd-readd-fence-"));
    let server = openServer(root);
    try {
      const { storage } = server;
      const tracker = createScopeDeletionTracker();
      await storage.commitVersion!(importCommit("a", null));
      // A first-seen sidecar derived from the row about to be erased.
      await storage.writeFirstSeenLedger!(scope, { stale: true });
      const covered = storage.listVersions(scope, { limit: 10 })[0];

      let inFlight: Response | undefined;
      const result = await deleteScope(
        {
          storage,
          serverOwner: owner,
          scopeDeletions: tracker,
          logger,
          deleteData: {
            ...gatewayTombstone(),
            deleteBlobVersions: async (_scope, versions) => {
              // Owner re-add lands while the remote blob delete is in flight.
              inFlight = await handlePersonalServerDataRequest(
                putImport("b"),
                routeDeps(storage, tracker),
              );
              return { deleted: versions, missing: [], failed: [] };
            },
          },
        },
        scope,
      );

      expect(inFlight?.status).toBe(201);
      expect(result.steps.gateway.status).toBe("ok");
      expect(result.steps.storage.status).toBe("ok");
      expect(result.steps.local.status).toBe("ok");

      const survivors = storage.listVersions(scope, { limit: 10 });
      expect(await storage.readFirstSeenLedger!(scope)).toBeNull();
      expect(survivors).toHaveLength(1);
      expect(survivors[0].afterTombstoneVersion).toBe(4);
      expect(existsSync(join(root, "data", covered.path))).toBe(false);
      expect(existsSync(join(root, "data", survivors[0].path))).toBe(true);
      expect(
        (
          await handlePersonalServerDataRequest(
            putImport("b"),
            routeDeps(storage, tracker),
          )
        ).status,
      ).toBe(200);

      // Restart: a fresh process opens the same index and data directory.
      server.index.close();
      server = openServer(root);
      const afterRestart = server.storage.listVersions(scope, { limit: 10 });
      expect(afterRestart.map((entry) => entry.path)).toEqual(
        survivors.map((entry) => entry.path),
      );
      expect(
        JSON.stringify(
          await server.storage.readEnvelope(scope, afterRestart[0].collectedAt),
        ),
      ).toMatch(/"value":"b"/);
      const replayAfterRestart = await handlePersonalServerDataRequest(
        putImport("b"),
        routeDeps(server.storage, createScopeDeletionTracker()),
      );
      expect(replayAfterRestart.status).toBe(200);
      expect(await replayAfterRestart.text()).not.toContain("IMPORT_DELETED");
    } finally {
      server.index.close();
      await rm(root, { recursive: true, force: true });
    }
  });

  it("erases only the covered versions captured before the remote delete and keeps every arrival after the snapshot", async () => {
    const root = await mkdtemp(join(tmpdir(), "psd-readd-fence-"));
    const { index, storage } = openServer(root);
    try {
      const tracker = createScopeDeletionTracker();
      await storage.commitVersion!(importCommit("a", null));
      await storage.commitVersion!(importCommit("f", 3));
      const covered = storage.listVersions(scope, { limit: 10 });

      let readdStatus: number | undefined;
      const result = await deleteScope(
        {
          storage,
          serverOwner: owner,
          scopeDeletions: tracker,
          logger,
          deleteData: {
            ...gatewayTombstone(),
            deleteBlobVersions: async (_scope, versions) => {
              readdStatus = (
                await handlePersonalServerDataRequest(
                  putImport("b"),
                  routeDeps(storage, tracker),
                )
              ).status;
              await storage.commitVersion!(importCommit("c", null));
              await storage.commitVersion!(importCommit("d", 5));
              await storage.commitVersion!(importCommit("e", 3));
              return { deleted: versions, missing: [], failed: [] };
            },
          },
        },
        scope,
      );

      expect(readdStatus).toBe(201);
      expect(result.steps.storage.status).toBe("ok");
      expect(result.steps.local).toMatchObject({
        status: "ok",
        deletedCount: covered.length,
      });
      const survivors = storage.listVersions(scope, { limit: 10 });
      expect(survivors.map((entry) => entry.afterTombstoneVersion)).toEqual(
        expect.arrayContaining([4, null, 5, 3]),
      );
      expect(survivors).toHaveLength(4);
      for (const entry of covered) {
        expect(existsSync(join(root, "data", entry.path))).toBe(false);
      }
    } finally {
      index.close();
      await rm(root, { recursive: true, force: true });
    }
  });
});
