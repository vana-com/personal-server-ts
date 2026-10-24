import { describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createScopeDeletionTracker,
  deleteScope,
} from "@opendatalabs/personal-server-ts-core/sync";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import { createPersistentPsLiteStorage } from "./storage.js";
import type { PsLiteDataFileStore } from "./storage.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteDataFileStore,
  createMemoryPsLitePersistence,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";

const SCOPE = "instagram.profile";
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const logger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as never;

type LiteStorage = ReturnType<typeof createMemoryPsLiteStorage>;

/** One local version written the way ingest writes it: envelope blob, then index row. */
async function writeVersion(
  storage: LiteStorage,
  value: string,
  collectedAt: string,
  afterTombstoneVersion: number | null,
) {
  const envelope = createDataFileEnvelope(SCOPE, collectedAt, { value });
  const write = await storage.writeEnvelope(envelope);
  return storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: write.relativePath,
    scope: SCOPE,
    collectedAt,
    sizeBytes: write.sizeBytes,
    afterTombstoneVersion,
  });
}

/**
 * Passes every storage call straight through, except that the first erase
 * pauses right after it returns, so a test can act between two erases.
 */
function pauseAfterFirstErase(storage: LiteStorage) {
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

function gatewayTombstone() {
  return {
    tombstone: async () => ({
      status: "tombstoned" as const,
      dataPointId: "0xdp",
      version: "4",
      deletedAt: "2026-10-02T00:00:00.000Z",
    }),
    deleteBlobVersions: async (_scope: string, versions: string[]) => ({
      deleted: versions,
      missing: [],
      failed: [],
    }),
  };
}

/**
 * A public owner POST that lands while a covered blob delete is paused. This
 * covers one runtime only: the scope lock is process-local, so writes from
 * another tab or runtime are not covered here.
 */
describe("persistent Lite owner POST during a covered delete", () => {
  const ORIGIN = "https://ps.local";
  const OWNER_TOKEN = "owner-test-token";
  const OLD_STAMP = "2026-08-01T00:00:00.000Z";
  const NOW = "2026-10-23T12:00:00.000Z";

  /** A persistent runtime whose covered blob delete waits until released. */
  async function fixture() {
    const persistence = createMemoryPsLitePersistence();
    const backingFiles = createMemoryPsLiteDataFileStore("custom");
    let coveredPath = "";
    let paused = false;
    let notifyDeleteStarted!: () => void;
    const deleteStarted = new Promise<void>((resolve) => {
      notifyDeleteStarted = resolve;
    });
    let releaseFileDelete!: () => void;
    const fileDeleteGate = new Promise<void>((resolve) => {
      releaseFileDelete = resolve;
    });
    const files: PsLiteDataFileStore = {
      ...backingFiles,
      async deleteEnvelope(path) {
        if (path === coveredPath && !paused) {
          paused = true;
          notifyDeleteStarted();
          await fileDeleteGate;
        }
        await backingFiles.deleteEnvelope(path);
      },
    };
    const createStorage = () =>
      createPersistentPsLiteStorage({ kind: "custom" }, persistence, files);
    const storage = await createStorage();
    const write = await storage.writeEnvelope(
      createDataFileEnvelope(SCOPE, OLD_STAMP, { value: "covered-old-entry" }),
    );
    coveredPath = write.relativePath;
    await storage.insertEntry({
      fileId: null,
      schemaId: null,
      path: write.relativePath,
      scope: SCOPE,
      collectedAt: OLD_STAMP,
      sizeBytes: write.sizeBytes,
      version: 1,
      afterTombstoneVersion: null,
    });

    const scopeDeletions = createScopeDeletionTracker();
    const accessLog = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage,
      auth: createBearerTokenPsLiteAuth({
        ownerToken: OWNER_TOKEN,
        builderToken: "builder-test-token",
      }),
      active: true,
      now: () => new Date(NOW),
      serverOrigin: ORIGIN,
      serverOwner: OWNER,
      scopeDeletions,
      accessLogReader: accessLog,
      accessLogWriter: accessLog,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
    });
    const deletion = deleteScope(
      {
        storage,
        serverOwner: OWNER,
        scopeDeletions,
        logger,
        deleteData: {
          tombstone: async () => ({
            status: "tombstoned" as const,
            dataPointId: "0xdp",
            version: "4",
            deletedAt: NOW,
          }),
          deleteBlobVersions: async (_scope: string, versions: string[]) => ({
            deleted: versions,
            missing: [],
            failed: [],
          }),
        },
      },
      SCOPE,
    );
    await deleteStarted;
    return { storage, createStorage, runtime, releaseFileDelete, deletion };
  }

  /** Polls fresh reloads of the persisted storage until the POST's row is on disk. */
  async function waitForPersistedVersion(
    createStorage: () => ReturnType<typeof createPersistentPsLiteStorage>,
    collectedAt: string,
  ) {
    const deadline = Date.now() + 2_000;
    while (Date.now() < deadline) {
      const reloaded = await createStorage();
      const entry = reloaded.findEntry({ scope: SCOPE, at: collectedAt });
      if (entry) return { reloaded, entry };
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(
      `Timed out waiting for persisted Lite entry at ${collectedAt}`,
    );
  }

  it("commits an owner POST that lands during the awaited delete and returns 201 after the scope lock releases", async () => {
    const state = await fixture();
    let responseSettled = false;
    const responsePromise = state.runtime
      .fetch(
        new Request(`${ORIGIN}/v1/data/${SCOPE}`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${OWNER_TOKEN}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ value: "owner-readd" }),
        }),
      )
      .then(
        (response) => {
          responseSettled = true;
          return { response };
        },
        (error: unknown) => {
          responseSettled = true;
          return { error };
        },
      );
    try {
      const persisted = await waitForPersistedVersion(state.createStorage, NOW);
      expect(responseSettled).toBe(false);
      expect(persisted.entry).toMatchObject({ afterTombstoneVersion: 4 });
      expect((await persisted.reloaded.readEnvelope(SCOPE, NOW)).data).toEqual({
        value: "owner-readd",
      });
    } finally {
      state.releaseFileDelete();
    }

    const outcome = await responsePromise;
    if ("error" in outcome) throw outcome.error;
    const response = outcome.response;
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      scope: string;
      collectedAt: string;
      status: string;
    };
    expect(body.scope).toBe(SCOPE);
    expect(body.status).toBe("stored");
    expect(Date.parse(body.collectedAt)).toBeGreaterThan(Date.parse(OLD_STAMP));
    expect(
      state.storage.findEntry({ scope: SCOPE, at: body.collectedAt }),
    ).toMatchObject({ afterTombstoneVersion: 4 });
    expect(
      (await state.storage.readEnvelope(SCOPE, body.collectedAt)).data,
    ).toEqual({ value: "owner-readd" });

    const deletion = await state.deletion;
    expect(deletion.steps.local).toMatchObject({
      status: "ok",
      deletedCount: 1,
    });
    expect(
      state.storage.findEntry({ scope: SCOPE, at: OLD_STAMP }),
    ).toBeUndefined();
    await expect(state.storage.readEnvelope(SCOPE, OLD_STAMP)).rejects.toThrow(
      "Envelope not found",
    );

    const reloaded = await state.createStorage();
    expect(
      reloaded.findEntry({ scope: SCOPE, at: body.collectedAt }),
    ).toMatchObject({ afterTombstoneVersion: 4 });
    expect((await reloaded.readEnvelope(SCOPE, body.collectedAt)).data).toEqual(
      {
        value: "owner-readd",
      },
    );
    expect(reloaded.findEntry({ scope: SCOPE, at: OLD_STAMP })).toBeUndefined();
  }, 15_000);
});

describe("lite gateway deletion keeps arrivals made during the remote delete", () => {
  it("erases the fenced version, keeps a re-add and a null-marker arrival, and drops the derived sidecar", async () => {
    const storage = createMemoryPsLiteStorage();
    const covered = await writeVersion(
      storage,
      "a",
      "2026-08-01T00:00:00.000Z",
      null,
    );
    await storage.writeFirstSeenLedger!(SCOPE, { stale: true });

    const arrivals: string[] = [];
    const result = await deleteScope(
      {
        storage,
        serverOwner: OWNER,
        logger,
        deleteData: {
          ...gatewayTombstone(),
          deleteBlobVersions: async (_scope, versions) => {
            const readd = await writeVersion(
              storage,
              "b",
              "2026-10-02T00:30:00.000Z",
              4,
            );
            const plain = await writeVersion(
              storage,
              "c",
              "2026-10-02T00:31:00.000Z",
              null,
            );
            arrivals.push(readd.path, plain.path);
            return { deleted: versions, missing: [], failed: [] };
          },
        },
      },
      SCOPE,
    );

    expect(result.steps.local).toMatchObject({ status: "ok", deletedCount: 1 });
    const survivors = storage.listVersions(SCOPE, { limit: 10 });
    expect(survivors.map((entry) => entry.path).sort()).toEqual(
      [...arrivals].sort(),
    );
    expect(survivors.map((entry) => entry.afterTombstoneVersion)).toEqual(
      expect.arrayContaining([4, null]),
    );
    expect(survivors.map((entry) => entry.path)).not.toContain(covered.path);
    const readd = survivors.find((entry) => entry.afterTombstoneVersion === 4)!;
    expect(
      JSON.stringify(await storage.readEnvelope(SCOPE, readd.collectedAt)),
    ).toMatch(/"value":"b"/);
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  it("does not erase a replacement that takes a freed stamp after the covered version was captured", async () => {
    const files = new Map<string, unknown>();
    const dataFileStore: PsLiteDataFileStore = {
      kind: "custom",
      readEnvelope: async (path: string) => (files.get(path) ?? null) as never,
      async writeEnvelope(path: string, envelope: unknown) {
        files.set(path, envelope);
        return new TextEncoder().encode(JSON.stringify(envelope)).byteLength;
      },
      async deleteEnvelope(path: string) {
        files.delete(path);
      },
    } as never;
    const storage = (await createPersistentPsLiteStorage(
      { kind: "custom" } as never,
      createMemoryPsLitePersistence(),
      dataFileStore,
    )) as unknown as LiteStorage;

    const first = await writeVersion(
      storage,
      "a",
      "2026-08-01T00:00:00.000Z",
      null,
    );
    const later = await writeVersion(
      storage,
      "old",
      "2026-08-02T00:00:00.000Z",
      null,
    );
    const paused = pauseAfterFirstErase(storage);

    const deletion = deleteScope(
      {
        storage: paused.port,
        serverOwner: OWNER,
        logger,
        deleteData: gatewayTombstone(),
      },
      SCOPE,
    );
    const firstErased = await paused.reached;
    const stamp =
      firstErased === first.collectedAt ? later.collectedAt : first.collectedAt;

    // A concurrent deleter frees the later covered stamp, then an owner write takes it.
    await storage.deleteVersion(SCOPE, stamp);
    const replacement = await writeVersion(storage, "new", stamp, 4);
    // A null-marker write that arrives after the snapshot.
    const plain = await writeVersion(
      storage,
      "plain",
      "2026-10-02T00:40:00.000Z",
      null,
    );
    paused.release();
    const result = await deletion;

    expect(result.steps.local).toMatchObject({ status: "ok", deletedCount: 1 });
    const survivors = storage.listVersions(SCOPE, { limit: 10 });
    expect(survivors.map((entry) => entry.path).sort()).toEqual(
      [replacement.path, plain.path].sort(),
    );
    expect(JSON.stringify(await storage.readEnvelope(SCOPE, stamp))).toMatch(
      /"value":"new"/,
    );
  });
});
