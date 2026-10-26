import { describe, expect, it, vi } from "vitest";
import type {
  DataBlockManifest,
  DataScopeBlock,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteDataFileStore,
  createMemoryPsLitePersistence,
} from "./test-support/memory.js";
import {
  createPersistentPsLiteStorage,
  type PsLiteDataFileStore,
} from "./storage.js";
import { previewEnvelopeValue } from "./storage-utils.js";
import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";

describe("createPersistentPsLiteStorage", () => {
  it("bounds in-memory previews by traversal work for container-heavy envelopes", () => {
    const envelope = createDataFileEnvelope(
      "chatgpt.conversations",
      "2026-05-08T00:00:00.000Z",
      { items: Array.from({ length: 50_000 }, () => ({})) },
    );

    const preview = previewEnvelopeValue(envelope, 100_000);

    expect(preview.truncated).toBe(true);
    expect(preview.text.length).toBeLessThanOrEqual(100_000);
  });

  it("leaves custom file stores without bounded previews on the core fallback path", async () => {
    const persistence = createMemoryPsLitePersistence();
    const files = new Map<string, ReturnType<typeof createDataFileEnvelope>>();
    const readEnvelope = vi.fn(async (path: string) => files.get(path) ?? null);
    const dataFileStore: PsLiteDataFileStore = {
      kind: "custom",
      readEnvelope,
      async writeEnvelope(path, envelope) {
        files.set(path, envelope);
        return new TextEncoder().encode(JSON.stringify(envelope)).byteLength;
      },
      async deleteEnvelope(path) {
        files.delete(path);
      },
    };
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      dataFileStore,
    );
    const envelope = createDataFileEnvelope(
      "notes.profile",
      "2026-05-08T00:00:00.000Z",
      { text: "x".repeat(10_000) },
    );

    const write = await storage.writeEnvelope(envelope);
    expect(write.sizeBytes).toBeGreaterThan(1_000);
    await storage.insertEntry({
      fileId: "file-1",
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    expect(storage.readEnvelopePreview).toBeUndefined();
    expect(readEnvelope).not.toHaveBeenCalled();
    expect(storage.capabilities).toMatchObject({
      metadata: "custom",
      files: "custom",
    });
  });

  it("keeps the browser IndexedDB fallback capability unchanged", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createMemoryPsLitePersistence(),
    );

    expect(storage.capabilities).toEqual({
      metadata: "indexeddb",
      files: "indexeddb",
      opfsAvailable: false,
    });
  });

  it("persists envelopes and index entries across storage reloads", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "test_user" },
    );

    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: "file-1",
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.findEntry({ scope: "instagram.profile" })).toMatchObject({
      fileId: "file-1",
      scope: "instagram.profile",
      collectedAt: "2026-05-08T00:00:00.000Z",
    });
    await expect(
      reloaded.readEnvelope("instagram.profile", "2026-05-08T00:00:00.000Z"),
    ).resolves.toMatchObject({
      data: { username: "test_user" },
    });
  });

  it("persists scope deletion", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "test_user" },
    );

    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: null,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
    await storage.deleteScope("instagram.profile");

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.countVersions("instagram.profile")).toBe(0);
    expect(reloaded.findEntry({ scope: "instagram.profile" })).toBeUndefined();
  });

  it("deletes a single version by fileId (entry + blob) and no-ops on unknown id", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    // Two versions of the same scope; only one is deleted.
    const keep = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "keep" },
    );
    const drop = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-09T00:00:00.000Z",
      { username: "drop" },
    );
    for (const [index, envelope] of [keep, drop].entries()) {
      const write = await storage.writeEnvelope(envelope);
      await storage.insertEntry({
        fileId: `file-${index + 1}`,
        path: write.relativePath,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
        sizeBytes: write.sizeBytes,
      });
    }

    expect(await storage.deleteByFileId("file-2")).toBe(true);
    // Unknown fileId is a no-op.
    expect(await storage.deleteByFileId("file-unknown")).toBe(false);

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    expect(reloaded.countVersions("instagram.profile")).toBe(1);
    expect(
      reloaded.findEntry({ scope: "instagram.profile", fileId: "file-2" }),
    ).toBeUndefined();
    // The other version (and its blob) survive.
    expect(
      reloaded.findEntry({ scope: "instagram.profile", fileId: "file-1" }),
    ).toBeDefined();
    await expect(
      reloaded.readEnvelope("instagram.profile", "2026-05-08T00:00:00.000Z"),
    ).resolves.toBeDefined();
  });

  it("summarizes persisted scopes with latest collection time and version count", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelopes = [
      createDataFileEnvelope("instagram.profile", "2026-05-08T00:00:00.000Z", {
        username: "first",
      }),
      createDataFileEnvelope("instagram.profile", "2026-05-09T00:00:00.000Z", {
        username: "second",
      }),
      createDataFileEnvelope("spotify.profile", "2026-05-07T00:00:00.000Z", {
        username: "music",
      }),
    ];

    for (const [index, envelope] of envelopes.entries()) {
      const write = await storage.writeEnvelope(envelope);
      await storage.insertEntry({
        fileId: `file-${index + 1}`,
        path: write.relativePath,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
        sizeBytes: write.sizeBytes,
      });
    }

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.listScopes({ scopePrefix: "instagram." })).toEqual({
      scopes: [
        {
          scope: "instagram.profile",
          latestCollectedAt: "2026-05-09T00:00:00.000Z",
          versionCount: 2,
        },
      ],
      total: 1,
    });
  });

  it("stores envelope JSON in the file store and metadata in persistence", async () => {
    const persistence = createMemoryPsLitePersistence();
    const fileStore = createMemoryPsLiteDataFileStore("opfs");
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
      fileStore,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "opfs_user" },
    );

    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: "file-1",
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    await expect(
      fileStore.readEnvelope(
        "data/instagram.profile/2026-05-08T00:00:00.000Z.json",
      ),
    ).resolves.toMatchObject({ data: { username: "opfs_user" } });
    await expect(persistence.read()).resolves.toMatchObject({
      envelopes: [],
      entries: [{ path: write.relativePath }],
    });
    expect(storage.capabilities).toMatchObject({
      metadata: "indexeddb",
      files: "opfs",
    });
  });

  it("persists sync index updates", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "unsynced_user" },
    );
    const write = await storage.writeEnvelope(envelope);
    await storage.insertEntry({
      fileId: null,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });

    expect(storage.findUnsynced()).toHaveLength(1);
    expect(
      await storage.updateDataPointId(write.relativePath, "0xdp-synced-1"),
    ).toBe(true);

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.findUnsynced()).toEqual([]);
    expect(reloaded.findByDataPointId("0xdp-synced-1")).toMatchObject({
      scope: "instagram.profile",
      dataPointId: "0xdp-synced-1",
    });
  });

  it("serializes overlapping index persistence so data-point id updates win", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const envelope = createDataFileEnvelope(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      { username: "race_user" },
    );
    const write = await storage.writeEnvelope(envelope);

    const inserted = storage.insertEntry({
      fileId: null,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
    const updated = storage.updateDataPointId(
      write.relativePath,
      "0xdp-synced-1",
    );
    await inserted;
    await updated;

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );

    expect(reloaded.findByDataPointId("0xdp-synced-1")).toMatchObject({
      scope: "instagram.profile",
      dataPointId: "0xdp-synced-1",
    });
    expect(reloaded.findUnsynced()).toEqual([]);
  });

  describe("a delete queued behind an overlapping row update", () => {
    const scope = "instagram.profile";
    const collectedAt = "2026-05-08T00:00:00.000Z";

    async function writeIndexed(
      storage: Awaited<ReturnType<typeof createPersistentPsLiteStorage>>,
      value: string,
    ) {
      const envelope = createDataFileEnvelope(scope, collectedAt, {
        username: value,
      });
      const write = await storage.writeEnvelope(envelope);
      const entry = await storage.insertEntry({
        fileId: null,
        path: write.relativePath,
        scope,
        collectedAt,
        sizeBytes: write.sizeBytes,
      });
      return { entry, path: write.relativePath };
    }

    it.each([
      [
        "updateFileId",
        (
          storage: Awaited<ReturnType<typeof createPersistentPsLiteStorage>>,
          path: string,
        ) => storage.updateFileId(path, "synced-id"),
      ],
      [
        "updateDataPointId",
        (
          storage: Awaited<ReturnType<typeof createPersistentPsLiteStorage>>,
          path: string,
        ) => storage.updateDataPointId(path, "0xdp-synced-1"),
      ],
      [
        "updateEntryVersion",
        (
          storage: Awaited<ReturnType<typeof createPersistentPsLiteStorage>>,
          path: string,
        ) => storage.updateEntryVersion(path, 7),
      ],
    ])(
      "erases the row and its blob when %s is queued first",
      async (_name, update) => {
        const persistence = createMemoryPsLitePersistence();
        const storage = await createPersistentPsLiteStorage(
          { kind: "indexeddb" },
          persistence,
        );
        const { path } = await writeIndexed(storage, "race");

        const updated = update(storage, path);
        const erased = storage.deleteVersion(scope, collectedAt);
        await updated;
        await expect(erased).resolves.toBe(true);

        expect(storage.countVersions(scope)).toBe(0);
        const reloaded = await createPersistentPsLiteStorage(
          { kind: "indexeddb" },
          persistence,
        );
        expect(reloaded.countVersions(scope)).toBe(0);
        await expect(reloaded.readEnvelope(scope, collectedAt)).rejects.toThrow(
          "Envelope not found",
        );
      },
    );

    it("erases by a fileId that a queued update sets just before the delete", async () => {
      const persistence = createMemoryPsLitePersistence();
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      const { path } = await writeIndexed(storage, "fresh");

      const updated = storage.updateFileId(path, "queued-file-id");
      const erased = storage.deleteByFileId("queued-file-id");
      await updated;
      await expect(erased).resolves.toBe(true);

      const reloaded = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      expect(reloaded.countVersions(scope)).toBe(0);
      await expect(reloaded.readEnvelope(scope, collectedAt)).rejects.toThrow(
        "Envelope not found",
      );
    });

    it("keeps a same-path replacement, with its blob, written while an erase of the old version is queued", async () => {
      const persistence = createMemoryPsLitePersistence();
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      const old = await writeIndexed(storage, "old");

      const erased = storage.deleteVersion(scope, collectedAt, {
        id: old.entry.id,
        path: old.path,
      });
      const replacement = await writeIndexed(storage, "new");
      // The old row was still the decided one when the erase was queued.
      await expect(erased).resolves.toBe(true);

      const reloaded = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      expect(reloaded.countVersions(scope)).toBe(1);
      expect(reloaded.findEntry({ scope, at: collectedAt })?.id).toBe(
        replacement.entry.id,
      );
      const envelope = await reloaded.readEnvelope(scope, collectedAt);
      expect(JSON.stringify(envelope)).toContain("new");
      expect(JSON.stringify(envelope)).not.toContain("old");
    });
  });

  describe("an erase in flight on one path", () => {
    const scope = "instagram.profile";
    const X = "2026-05-08T00:00:00.000Z";
    const Y = "2026-05-09T00:00:00.000Z";

    /** A custom file store whose blob delete of `path` waits until released. */
    function gatedFiles(path: () => string | undefined) {
      const backing = createMemoryPsLiteDataFileStore("custom");
      let notifyStarted!: () => void;
      const started = new Promise<void>((resolve) => {
        notifyStarted = resolve;
      });
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let paused = false;
      const files: PsLiteDataFileStore = {
        ...backing,
        async deleteEnvelope(target) {
          if (target === path() && !paused) {
            paused = true;
            notifyStarted();
            await gate;
          }
          await backing.deleteEnvelope(target);
        },
      };
      return { files, started, release };
    }

    async function writeRow(
      storage: Awaited<ReturnType<typeof createPersistentPsLiteStorage>>,
      collectedAt: string,
      value: string,
    ) {
      const envelope = createDataFileEnvelope(scope, collectedAt, {
        username: value,
      });
      const write = await storage.writeEnvelope(envelope);
      await storage.insertEntry({
        fileId: null,
        path: write.relativePath,
        scope,
        collectedAt,
        sizeBytes: write.sizeBytes,
      });
      return write.relativePath;
    }

    /** Resolves "landed" if `work` settles within 500 ms, else "blocked". */
    async function landsWithin(work: Promise<unknown>) {
      return Promise.race([
        work.then(() => "landed" as const),
        new Promise<"blocked">((resolve) =>
          setTimeout(() => resolve("blocked"), 500),
        ),
      ]);
    }

    it("does not delay a write to path Y while the erase of path X waits on its blob delete", async () => {
      const persistence = createMemoryPsLitePersistence();
      const xPath = `data/${scope}/${X}.json`;
      const gate = gatedFiles(() => xPath);
      const storage = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        gate.files,
      );
      await writeRow(storage, X, "x");

      const erase = storage.deleteVersion(scope, X);
      await gate.started;
      const write = writeRow(storage, Y, "y");
      await expect(landsWithin(write)).resolves.toBe("landed");

      gate.release();
      await expect(erase).resolves.toBe(true);
      const reloaded = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        gate.files,
      );
      expect(reloaded.findEntry({ scope, at: X })).toBeUndefined();
      expect(reloaded.findEntry({ scope, at: Y })).toBeDefined();
      await expect(reloaded.readEnvelope(scope, Y)).resolves.toBeDefined();
    });

    it("lands a write to path X issued during X's erase after it, and it survives with its blob", async () => {
      const persistence = createMemoryPsLitePersistence();
      const xPath = `data/${scope}/${X}.json`;
      const gate = gatedFiles(() => xPath);
      const storage = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        gate.files,
      );
      await writeRow(storage, X, "old");

      const erase = storage.deleteVersion(scope, X);
      await gate.started;
      const replacement = writeRow(storage, X, "new");
      await expect(landsWithin(replacement)).resolves.toBe("blocked");

      gate.release();
      await expect(erase).resolves.toBe(true);
      await replacement;
      const reloaded = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        gate.files,
      );
      expect(reloaded.countVersions(scope)).toBe(1);
      const envelope = await reloaded.readEnvelope(scope, X);
      expect(JSON.stringify(envelope)).toContain("new");
      expect(JSON.stringify(envelope)).not.toContain("old");
    });
  });

  describe("same-path races under the per-path lock", () => {
    const scope = "instagram.profile";
    const X = "2026-05-08T00:00:00.000Z";
    const X_PATH = `data/${scope}/${X}.json`;

    /** A one-shot deferred step: `pass` parks until `open`. */
    function deferredStep() {
      let markEntered!: () => void;
      const entered = new Promise<void>((resolve) => {
        markEntered = resolve;
      });
      let openIt!: () => void;
      const opened = new Promise<void>((resolve) => {
        openIt = resolve;
      });
      return {
        entered,
        pass: async () => {
          markEntered();
          await opened;
        },
        open: () => openIt(),
      };
    }

    /**
     * A custom file store that can park the nth blob delete of X, park the
     * streamed rename of X, and fail every block-tree delete.
     */
    function scriptedFiles(options: {
      pauseDelete?: Map<number, ReturnType<typeof deferredStep>>;
      pauseRename?: ReturnType<typeof deferredStep>;
      failTreeDelete?: boolean;
    }): PsLiteDataFileStore {
      const backing = createMemoryPsLiteDataFileStore("custom");
      let deletes = 0;
      return {
        ...backing,
        async deleteEnvelope(target) {
          if (target === X_PATH) {
            deletes += 1;
            await options.pauseDelete?.get(deletes)?.pass();
          }
          await backing.deleteEnvelope(target);
        },
        async deleteBlockTree() {
          if (options.failTreeDelete) {
            throw new Error("block tree delete failed");
          }
        },
        async openEnvelopeWriter(target) {
          let text = "";
          return {
            write: async (piece) => {
              text += piece;
            },
            abort: async () => {
              text = "";
            },
            commit: async () => {
              await options.pauseRename?.pass();
              return backing.writeEnvelope(
                target,
                JSON.parse(text) as Parameters<
                  PsLiteDataFileStore["writeEnvelope"]
                >[1],
              );
            },
          };
        },
      };
    }

    async function writeRowAt(
      storage: Awaited<ReturnType<typeof createPersistentPsLiteStorage>>,
      value: string,
    ) {
      const envelope = createDataFileEnvelope(scope, X, { username: value });
      const write = await storage.writeEnvelope(envelope);
      return storage.insertEntry({
        fileId: null,
        path: write.relativePath,
        scope,
        collectedAt: X,
        sizeBytes: write.sizeBytes,
      });
    }

    const pause = (ms: number) =>
      new Promise((resolve) => setTimeout(resolve, ms));

    it("a fenced erase that waits behind a streamed commit does not delete the commit's blob", async () => {
      const persistence = createMemoryPsLitePersistence();
      const rename = deferredStep();
      const files = scriptedFiles({ pauseRename: rename });
      const storage = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        files,
      );
      const oldRow = await writeRowAt(storage, "old");

      // Hold the scope lock, as a concurrent scope operation would, so an
      // erase that gets past the path lock would wait here.
      const holdScope = deferredStep();
      const hold = withScopeLock(scope, () => holdScope.pass());

      const writer = await storage.openVersionWriter!(scope, X);
      await writer.write(
        JSON.stringify(createDataFileEnvelope(scope, X, { username: "new" })),
      );
      const committed = writer.commit({ fileId: null });
      await rename.entered;

      const erase = storage.deleteVersion(scope, X, {
        id: oldRow.id,
        path: X_PATH,
      });
      await pause(50);
      rename.open();
      await committed;
      holdScope.open();
      await hold;

      // The old row was replaced by the commit before the erase ran.
      await expect(erase).resolves.toBe(false);
      const reloaded = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        files,
      );
      expect(reloaded.countVersions(scope)).toBe(1);
      expect(reloaded.findEntry({ scope, at: X })?.id).not.toBe(oldRow.id);
      const envelope = await reloaded.readEnvelope(scope, X);
      expect(JSON.stringify(envelope)).toContain("new");
    });

    it("a write issued after two erases of X waits for both, so neither removes its blob", async () => {
      const persistence = createMemoryPsLitePersistence();
      const first = deferredStep();
      const second = deferredStep();
      const files = scriptedFiles({
        pauseDelete: new Map([
          [1, first],
          [2, second],
        ]),
      });
      const storage = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        files,
      );
      const oldRow = await writeRowAt(storage, "old");

      const firstErase = storage.deleteVersion(scope, X, {
        id: oldRow.id,
        path: X_PATH,
      });
      await first.entered;
      const write = writeRowAt(storage, "new");
      const secondErase = storage.deleteVersion(scope, X, {
        id: oldRow.id,
        path: X_PATH,
      });
      first.open();
      await write;
      // Only now may the second erase reach its blob delete.
      second.open();

      await expect(firstErase).resolves.toBe(true);
      await expect(secondErase).resolves.toBe(false);
      const reloaded = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        files,
      );
      expect(reloaded.countVersions(scope)).toBe(1);
      const envelope = await reloaded.readEnvelope(scope, X);
      expect(JSON.stringify(envelope)).toContain("new");
    });

    it("a writer waits for an erase whose blob delete failed, and the late part does not remove its blob", async () => {
      const persistence = createMemoryPsLitePersistence();
      const envelopeDelete = deferredStep();
      const files = scriptedFiles({
        pauseDelete: new Map([[1, envelopeDelete]]),
        failTreeDelete: true,
      });
      const storage = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        files,
      );
      const oldRow = await writeRowAt(storage, "old");

      const erase = storage
        .deleteVersion(scope, X, { id: oldRow.id, path: X_PATH })
        .then(
          (value) => ({ value }),
          (error: unknown) => ({ error }),
        );
      await envelopeDelete.entered;
      const write = writeRowAt(storage, "new");

      // The erase is still waiting on its envelope delete, so the writer waits.
      const landedEarly = await Promise.race([
        write.then(() => true),
        pause(200).then(() => false),
      ]);
      expect(landedEarly).toBe(false);

      envelopeDelete.open();
      const outcome = await erase;
      expect(outcome).toMatchObject({
        error: new Error("block tree delete failed"),
      });
      await write;

      const reloaded = await createPersistentPsLiteStorage(
        { kind: "custom" },
        persistence,
        files,
      );
      expect(reloaded.countVersions(scope)).toBe(1);
      const envelope = await reloaded.readEnvelope(scope, X);
      expect(JSON.stringify(envelope)).toContain("new");
    });
  });

  it("persists IndexedDB fallback block sidecars across storage reloads", async () => {
    const persistence = createMemoryPsLitePersistence();
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const { manifest, blocks } = blockFixture(
      "instagram.profile",
      "2026-05-08T00:00:00.000Z",
      2,
    );

    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    await expect(
      reloaded.readScopeBlocks?.(
        "instagram.profile",
        "2026-05-08T00:00:00.000Z",
        { maxBytes: 1_000 },
      ),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      blocks: [{ value: { index: 0 } }, { value: { index: 1 } }],
    });
  });

  it("writes persistent block sidecars sequentially before publishing the manifest", async () => {
    const writes: string[] = [];
    let activePayloadWrites = 0;
    const payloads = new Map<string, DataScopeBlock>();
    const manifests = new Map<string, DataBlockManifest>();
    const dataFileStore: PsLiteDataFileStore = {
      kind: "opfs",
      async readEnvelope() {
        return null;
      },
      async writeEnvelope() {
        return 0;
      },
      async deleteEnvelope() {},
      async readBlockManifest(path) {
        return manifests.get(path) ?? null;
      },
      async writeBlockManifest(path, manifest) {
        writes.push(`manifest:${path}`);
        manifests.set(path, manifest);
      },
      async readBlockPayload(path) {
        return payloads.get(path) ?? null;
      },
      async writeBlockPayload(path, block) {
        activePayloadWrites += 1;
        try {
          expect(activePayloadWrites).toBe(1);
          writes.push(`payload:${path}`);
          await Promise.resolve();
          payloads.set(path, block);
        } finally {
          activePayloadWrites -= 1;
        }
      },
      async deleteBlockTree(pathPrefix) {
        for (const key of [...payloads.keys()]) {
          if (key.startsWith(pathPrefix)) payloads.delete(key);
        }
      },
    };
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      dataFileStore,
    );
    const { manifest, blocks } = blockFixture(
      "chatgpt.conversations",
      "2026-05-08T00:00:00.000Z",
      3,
    );

    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    expect(writes).toHaveLength(4);
    expect(
      writes.slice(0, 3).every((write) => write.startsWith("payload:")),
    ).toBe(true);
    expect(writes[3]).toMatch(/^manifest:/);
    await expect(
      storage.hasScopeBlocks?.(manifest.scope, manifest.collectedAt),
    ).resolves.toBe(true);
  });

  it("falls back to IndexedDB block sidecars when the primary file store cannot write them", async () => {
    const persistence = createMemoryPsLitePersistence();
    const primaryWriteAttempts: string[] = [];
    const dataFileStore: PsLiteDataFileStore = {
      kind: "opfs",
      async readEnvelope() {
        return null;
      },
      async writeEnvelope() {
        return 0;
      },
      async deleteEnvelope() {},
      async readBlockManifest() {
        return null;
      },
      async writeBlockManifest() {
        primaryWriteAttempts.push("manifest");
        throw new DOMException("locked", "NoModificationAllowedError");
      },
      async readBlockPayload() {
        return null;
      },
      async writeBlockPayload() {
        primaryWriteAttempts.push("payload");
        throw new DOMException("locked", "NoModificationAllowedError");
      },
      async deleteBlockTree() {},
    };
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      dataFileStore,
    );
    const { manifest, blocks } = blockFixture(
      "linkedin.skills",
      "2026-03-06T20:26:21Z",
      2,
    );

    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    expect(primaryWriteAttempts).toEqual(["payload"]);
    await expect(
      storage.hasScopeBlocks?.(manifest.scope, manifest.collectedAt),
    ).resolves.toBe(true);
    await expect(
      storage.readScopeBlocks?.(manifest.scope, manifest.collectedAt, {
        maxBytes: 1_000,
      }),
    ).resolves.toMatchObject({
      scope: "linkedin.skills",
      blocks: [{ value: { index: 0 } }, { value: { index: 1 } }],
    });

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      dataFileStore,
    );
    await expect(
      reloaded.hasScopeBlocks?.(manifest.scope, manifest.collectedAt),
    ).resolves.toBe(true);
  });

  it("pages block sidecar reads by cursor until all blocks are reachable", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createMemoryPsLitePersistence(),
    );
    const { manifest, blocks } = blockFixture(
      "chatgpt.conversations",
      "2026-05-08T00:00:00.000Z",
      3,
    );
    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    const seen: unknown[] = [];
    let cursor: string | undefined;
    do {
      const page = await storage.readScopeBlocks!(
        manifest.scope,
        manifest.collectedAt,
        { cursor, maxBytes: 16 },
      );
      seen.push(...page.blocks.map((block) => block.value));
      cursor = page.nextCursor;
    } while (cursor);

    expect(seen).toEqual([{ index: 0 }, { index: 1 }, { index: 2 }]);
  });

  it("reads only the named blocks and exposes the manifest as a table of contents", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createMemoryPsLitePersistence(),
    );
    const { manifest, blocks } = blockFixture(
      "chatgpt.conversations",
      "2026-05-08T00:00:00.000Z",
      3,
    );
    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );

    const page = await storage.readScopeBlocks!(
      manifest.scope,
      manifest.collectedAt,
      { maxBytes: 16 * 1024, blockIds: ["block-2", "block-0"] },
    );

    expect(page.blocks.map((block) => block.value)).toEqual([
      { index: 2 },
      { index: 0 },
    ]);
    expect(page.nextCursor).toBeUndefined();

    await expect(
      storage.readBlockManifest?.(manifest.scope, manifest.collectedAt),
    ).resolves.toMatchObject({ blocks: manifest.blocks });
  });

  it("returns no manifest for a scope that was never indexed", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createMemoryPsLitePersistence(),
    );

    await expect(
      storage.readBlockManifest?.(
        "chatgpt.conversations",
        "2026-05-08T00:00:00.000Z",
      ),
    ).resolves.toBeNull();
  });

  it("pages through a single oversized persistent block", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createMemoryPsLitePersistence(),
    );
    const scope = "chatgpt.conversations";
    const collectedAt = "2026-05-08T00:00:00.000Z";
    const value = "0123456789".repeat(600);
    const sizeBytes = new TextEncoder().encode(value).byteLength;
    await storage.writeBlockManifest?.(
      scope,
      collectedAt,
      {
        version: 1,
        scope,
        collectedAt,
        contentKind: "text",
        blocks: [
          {
            id: "block-000001",
            path: "$.data",
            mediaType: "text/plain",
            sizeBytes,
          },
        ],
        warnings: [],
      },
      [
        {
          id: "block-000001",
          path: "$.data",
          mediaType: "text/plain",
          value,
          sizeBytes,
        },
      ],
    );

    const firstPage = await storage.readScopeBlocks!(scope, collectedAt, {
      maxBytes: 1024,
    });
    expect(firstPage.blocks[0]?.value).toBe(value.slice(0, 1024));
    expect(firstPage.blocks[0]?.truncated).toBe(true);
    expect(firstPage.nextCursor).toBeTruthy();

    const secondPage = await storage.readScopeBlocks!(scope, collectedAt, {
      cursor: firstPage.nextCursor,
      maxBytes: 1024,
    });
    expect(secondPage.blocks[0]?.value).toBe(value.slice(1024, 2048));
    expect(secondPage.blocks[0]?.truncated).toBe(true);
    expect(secondPage.nextCursor).toBeTruthy();
  });

  it("serves missing block manifests from the raw local envelope", async () => {
    const files = new Map<string, ReturnType<typeof createDataFileEnvelope>>();
    const readEnvelope = vi.fn(async (path: string) => files.get(path) ?? null);
    const dataFileStore: PsLiteDataFileStore = {
      kind: "opfs",
      readEnvelope,
      async writeEnvelope(path, envelope) {
        files.set(path, envelope);
        return new TextEncoder().encode(JSON.stringify(envelope)).byteLength;
      },
      async deleteEnvelope(path) {
        files.delete(path);
      },
      async readBlockManifest() {
        return null;
      },
      async readBlockPayload() {
        throw new Error("payload should not be read without a manifest");
      },
    };
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      dataFileStore,
    );
    const envelope = createDataFileEnvelope(
      "notes.profile",
      "2026-05-08T00:00:00.000Z",
      { bio: "cached envelope can be read without a manifest" },
    );
    await storage.writeEnvelope(envelope);

    await expect(
      storage.canReadScopeBlocks?.("notes.profile", "2026-05-08T00:00:00.000Z"),
    ).resolves.toBe(true);
    await expect(
      storage.readScopeBlocks?.("notes.profile", "2026-05-08T00:00:00.000Z", {
        maxBytes: 1_000,
      }),
    ).resolves.toMatchObject({
      scope: "notes.profile",
      contentKind: "vana-envelope",
      blocks: expect.arrayContaining([
        expect.objectContaining({
          path: "$.data",
        }),
      ]),
    });
    await expect(
      storage.hasScopeBlocks?.("notes.profile", "2026-05-08T00:00:00.000Z"),
    ).resolves.toBe(true);
    expect(readEnvelope).toHaveBeenCalled();
  });

  it("supports block sidecars in memory storage", async () => {
    const storage = createMemoryPsLiteStorage();
    const { manifest, blocks } = blockFixture(
      "spotify.profile",
      "2026-05-08T00:00:00.000Z",
      1,
    );

    await storage.writeBlockManifest?.(
      manifest.scope,
      manifest.collectedAt,
      manifest,
      blocks,
    );
    await expect(
      storage.hasScopeBlocks?.(manifest.scope, manifest.collectedAt),
    ).resolves.toBe(true);

    await expect(
      storage.readScopeBlocks?.(manifest.scope, manifest.collectedAt, {
        maxBytes: 1_000,
      }),
    ).resolves.toMatchObject({
      contentKind: "json",
      blocks: [{ value: { index: 0 } }],
    });
  });

  it("pages through a single oversized memory block", async () => {
    const storage = createMemoryPsLiteStorage();
    const scope = "chatgpt.conversations";
    const collectedAt = "2026-05-08T00:00:00.000Z";
    const value = "abcdefghij".repeat(600);
    const sizeBytes = new TextEncoder().encode(value).byteLength;
    await storage.writeBlockManifest?.(
      scope,
      collectedAt,
      {
        version: 1,
        scope,
        collectedAt,
        contentKind: "text",
        blocks: [
          {
            id: "block-000001",
            path: "$.data",
            mediaType: "text/plain",
            sizeBytes,
          },
        ],
        warnings: [],
      },
      [
        {
          id: "block-000001",
          path: "$.data",
          mediaType: "text/plain",
          value,
          sizeBytes,
        },
      ],
    );

    const firstPage = await storage.readScopeBlocks!(scope, collectedAt, {
      maxBytes: 1024,
    });
    expect(firstPage.blocks[0]?.value).toBe(value.slice(0, 1024));
    expect(firstPage.blocks[0]?.truncated).toBe(true);
    expect(firstPage.nextCursor).toBeTruthy();

    const secondPage = await storage.readScopeBlocks!(scope, collectedAt, {
      cursor: firstPage.nextCursor,
      maxBytes: 1024,
    });
    expect(secondPage.blocks[0]?.value).toBe(value.slice(1024, 2048));
    expect(secondPage.blocks[0]?.truncated).toBe(true);
    expect(secondPage.nextCursor).toBeTruthy();
  });
});

function blockFixture(
  scope: string,
  collectedAt: string,
  count: number,
): { manifest: DataBlockManifest; blocks: DataScopeBlock[] } {
  const blocks = Array.from({ length: count }, (_, index) => {
    const value = { index };
    return {
      id: `block-${index}`,
      path: `$.items[${index}]`,
      mediaType: "application/json",
      value,
      sizeBytes: new TextEncoder().encode(JSON.stringify(value)).byteLength,
    };
  });
  return {
    manifest: {
      version: 1,
      scope,
      collectedAt,
      contentKind: "json",
      blocks: blocks.map(({ id, path, mediaType, sizeBytes }) => ({
        id,
        path,
        mediaType,
        sizeBytes,
      })),
      warnings: [],
    },
    blocks,
  };
}
