import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  binding,
  identity,
  registration,
  mutableVectors,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  createLiteCanonicalStore,
  type LiteOperationDraft,
} from "../../../lite/src/canonical-store.js";
import type {
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
} from "../../../lite/src/canonical-persistence.js";
import {
  collectStagedBlob,
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
  storagePage,
  writeCrashPoint,
  type CanonicalCrashPoint,
} from "../../../lite/src/test-support/canonical-persistence.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { sha256 } from "viem";

const context: MergeContext = {
  owner: identity.owner,
  declarations: [
    {
      sourceId: identity.sourceId,
      binding,
      validateData: (data) => typeof data.id === "string",
    },
  ],
};
const envelope = (ops: ReplicaOperation[]) => ({
  format: "vana-pdpp-replica",
  version: 1,
  owner: identity.owner,
  batchId: "batch",
  operations: ops,
});
const draft = (op: ReplicaOperation): LiteOperationDraft => {
  const { revision: _, ...value } = op;
  return value;
};
const cleanup: (() => void)[] = [];
afterEach(() => {
  for (const close of cleanup.splice(0)) close();
});

/** Real disk SQLite implementation of the port. No Dart/native-file claims. */
function sqlitePort() {
  const directory = mkdtempSync(join(tmpdir(), "lite-canonical-"));
  const path = join(directory, "native.sqlite");
  let db: Database.Database;
  let failure: CanonicalCrashPoint | undefined;
  let queue = Promise.resolve();
  const hit = (point: CanonicalCrashPoint | undefined) => {
    if (point && failure === point) {
      failure = undefined;
      throw new Error(`interrupted:${point}`);
    }
  };
  const open = () => {
    db = new Database(path);
    db.pragma("journal_mode=WAL");
    db.pragma("synchronous=FULL");
    db.exec(
      "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, descriptor TEXT NOT NULL, bytes BLOB NOT NULL); CREATE TABLE IF NOT EXISTS staging (id TEXT PRIMARY KEY, descriptor TEXT NOT NULL, bytes BLOB NOT NULL)",
    );
  };
  open();
  const port: LiteCanonicalPersistence = {
    transaction<T>(
      run: (tx: LiteCanonicalTransaction) => Promise<T>,
    ): Promise<T> {
      const work = queue.then(async () => {
        db.exec("BEGIN IMMEDIATE");
        let committed = false;
        try {
          const tx: LiteCanonicalTransaction = {
            async get(key) {
              return (
                db.prepare("SELECT value FROM kv WHERE key=?").get(key) as
                  { value: string } | undefined
              )?.value;
            },
            async put(key, value) {
              if (Buffer.byteLength(value) > 256 * 1024)
                throw new Error("native value exceeds 256 KiB");
              db.prepare(
                "INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
              ).run(key, value);
              hit(writeCrashPoint(key));
            },
            async delete(key) {
              db.prepare("DELETE FROM kv WHERE key=?").run(key);
            },
            async scan(prefix, after) {
              const entries = db
                .prepare(
                  "SELECT key,value FROM kv WHERE substr(key,1,length(?))=? AND key>? ORDER BY key LIMIT 101",
                )
                .all(prefix, prefix, after ?? "") as {
                key: string;
                value: string;
              }[];
              const page = storagePage(entries, after);
              if (entries.length === 101 && !page.after)
                page.after = page.entries.at(-1)!.key;
              return page;
            },
            async attachBlob(id, expected) {
              const staged = db
                .prepare("SELECT * FROM staging WHERE id=?")
                .get(id) as { descriptor: string; bytes: Buffer } | undefined;
              if (!staged || staged.descriptor !== canonicalJson(expected))
                throw new Error("unknown staged blob");
              const old = db
                .prepare("SELECT descriptor FROM blobs WHERE id=?")
                .get(expected.blobId) as { descriptor: string } | undefined;
              if (old && old.descriptor !== staged.descriptor)
                throw new Error("blob metadata conflict");
              db.prepare("INSERT OR IGNORE INTO blobs VALUES (?,?,?)").run(
                expected.blobId,
                staged.descriptor,
                staged.bytes,
              );
              hit("blob");
            },
            async blob(id) {
              const row = db
                .prepare("SELECT descriptor FROM blobs WHERE id=?")
                .get(id) as { descriptor: string } | undefined;
              return row ? JSON.parse(row.descriptor) : undefined;
            },
          };
          const result = await run(tx);
          hit("before-commit");
          db.exec("COMMIT");
          committed = true;
          hit("after-commit");
          return result;
        } catch (error) {
          if (!committed) db.exec("ROLLBACK");
          throw error;
        }
      });
      queue = work.then(
        () => undefined,
        () => undefined,
      );
      return work;
    },
    async stageBlob(descriptor, chunks) {
      const value = await collectStagedBlob(descriptor, chunks);
      const id = globalThis.crypto.randomUUID();
      db.prepare("INSERT INTO staging VALUES (?,?,?)").run(
        id,
        canonicalJson(value.descriptor),
        value.bytes,
      );
      return id;
    },
    async *readBlob(id) {
      const row = db.prepare("SELECT bytes FROM blobs WHERE id=?").get(id) as
        { bytes: Buffer } | undefined;
      if (!row) throw new Error("missing committed blob");
      for (let i = 0; i < row.bytes.length; i += 128 * 1024)
        yield new Uint8Array(row.bytes.subarray(i, i + 128 * 1024));
    },
  };
  cleanup.push(() => {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    port,
    crashAt(point: CanonicalCrashPoint) {
      failure = point;
    },
    reopen() {
      db.close();
      open();
    },
  };
}
function memoryPort() {
  const disk = fakeCanonicalDisk();
  let current = createFakeCanonicalPersistence(disk);
  return {
    get port() {
      return current.port;
    },
    crashAt(point: CanonicalCrashPoint) {
      current.crashAt(point);
    },
    reopen() {
      current = createFakeCanonicalPersistence(disk);
    },
  };
}
async function liteDevice(
  factory = memoryPort,
  mapped = true,
  entries = context,
) {
  const adapter = factory();
  let known = entries;
  const make = () =>
    createLiteCanonicalStore({
      persistence: adapter.port,
      enabled: true,
      context: () => known,
      authenticateReplica: (credential) =>
        credential === "replica" ? identity.owner : undefined,
    });
  let store = make();
  if (mapped)
    await store.provisionConnection(identity.connectionId, {
      sourceId: identity.sourceId,
      methodId: identity.methodId,
    });
  return {
    get store() {
      return store;
    },
    adapter,
    declare(next: MergeContext) {
      known = next;
    },
    async retry() {
      await store.retry({ credential: "replica" });
    },
    reopen() {
      adapter.reopen();
      store = make();
    },
    send(ops: ReplicaOperation[], id = globalThis.crypto.randomUUID()) {
      return store.import({
        id,
        envelope: envelope(ops),
        credential: "replica",
      });
    },
    async sendBlob(
      ops: ReplicaOperation[],
      bytes: Uint8Array,
      descriptor: Extract<ReplicaOperation, { kind: "blob-claim" }>["blob"],
    ) {
      const stagingId = await store.stageBlob(
        descriptor,
        (async function* () {
          yield bytes;
        })(),
      );
      await store.import({
        id: "blob-batch",
        envelope: envelope(ops),
        credential: "replica",
        blobs: [{ stagingId, descriptor }],
      });
    },
    async bytes(id: string) {
      return Buffer.concat(
        (await Array.fromAsync(store.readBlob(id))).map((bytes) =>
          Buffer.from(bytes),
        ),
      );
    },
    read() {
      return store.readRecord(
        identity.connectionId,
        binding.stream,
        "same-key",
      );
    },
  };
}
function nodeDevice(entries = context) {
  let known = entries;
  const directory = mkdtempSync(join(tmpdir(), "node-canonical-"));
  const path = join(directory, "records.sqlite");
  let db = new Database(path);
  let store = createSqliteRecordStore(db);
  store.registerConnection({
    instance: identity.connectionId,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "fixture",
  });
  store.replication.beginBaseline({
    owner: entries.owner,
    declarations: entries.declarations,
  });
  const receiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner: context.owner,
      authenticate: (credential) =>
        credential === "replica" ? context.owner : undefined,
      declarations: () => known.declarations,
    });
  cleanup.push(() => {
    store.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    declare(next: MergeContext) {
      known = next;
    },
    async retry() {
      receiver().retry({ credential: "replica" });
    },
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    async send(ops: ReplicaOperation[]) {
      receiver().import({ credential: "replica", envelope: envelope(ops) });
    },
    async sendBlob(
      ops: ReplicaOperation[],
      bytes: Uint8Array,
      descriptor: Extract<ReplicaOperation, { kind: "blob-claim" }>["blob"],
    ) {
      receiver().import({
        credential: "replica",
        envelope: envelope(ops),
        blobs: [{ blobId: descriptor.blobId, bytes }],
      });
    },
    async bytes(id: string) {
      return Buffer.from(store.getBlobBytes(id)!);
    },
    async read() {
      const row = db
        .prepare(
          "SELECT * FROM pdpp_records WHERE instance=? AND stream=? AND record_key=?",
        )
        .get(identity.connectionId, binding.stream, "same-key") as
        | {
            data: string | null;
            version: number;
            emitted_at: string;
            deleted_at: string | null;
          }
        | undefined;
      if (!row) return undefined;
      const base = {
        instance: identity.connectionId,
        stream: binding.stream,
        recordKey: "same-key",
        version: row.version,
        emittedAt: row.emitted_at,
      };
      return row.data === null
        ? { ...base, deleted: true, deletedAt: row.deleted_at }
        : { ...base, deleted: false, data: JSON.parse(row.data) };
    },
    reopen() {
      store.close();
      db = new Database(path);
      store = createSqliteRecordStore(db);
    },
  };
}

const factories = {
  "Node canonical SQLite": nodeDevice,
  "Lite fake": (entries = context) => liteDevice(memoryPort, true, entries),
  "Lite SQLite port": (entries = context) =>
    liteDevice(sqlitePort, true, entries),
};
for (const [name, factory] of Object.entries(factories))
  describe(name, () => {
    it("quarantines append-only conflicts after replay in either order", async () => {
      const declaration = { ...binding, semantics: "append_only" as const };
      const entries = {
        ...context,
        declarations: [{ ...context.declarations[0], binding: declaration }],
      };
      const first = { ...upsert("one", 2), declaration };
      const second = { ...upsert("two", 3), declaration };
      const device = await factory(entries);
      await device.send([registration, second]);
      expect(await device.read()).toMatchObject({ data: { text: "two" } });
      await device.send([first]);
      device.reopen();
      await device.send([second, first]);
      expect(await device.read()).toMatchObject({ deleted: true });
    });
    it("persists identical received blob bytes across restart and duplicate delivery", async () => {
      const device = await factory();
      const bytes = new Uint8Array([0, 255, 13, 10, 0, 128]);
      const hash = `sha256:${sha256(bytes).slice(2)}`;
      const descriptor = {
        blobId: hash,
        sha256: hash,
        sizeBytes: bytes.length,
        mimeType: "application/octet-stream",
      };
      const ops: ReplicaOperation[] = [
        registration,
        {
          ...identity,
          kind: "blob-claim",
          blob: descriptor,
          revision: { counter: 2, writerId: "device-a", operationId: "claim" },
        },
        {
          ...upsert("blob", 3),
          data: { id: "same-key", blob_ref: { blob_id: hash } },
          blobs: [descriptor],
        },
      ];
      await device.sendBlob(ops, bytes, descriptor);
      device.reopen();
      expect(await device.bytes(hash)).toEqual(Buffer.from(bytes));
      await device.sendBlob(ops, bytes, descriptor);
      expect(await device.read()).toMatchObject({ version: 1, deleted: false });
      const conflicting = { ...descriptor, mimeType: "text/plain" };
      await expect(
        device.send([
          {
            ...identity,
            kind: "blob-claim",
            blob: conflicting,
            revision: {
              counter: 5,
              writerId: "device-a",
              operationId: "mime-conflict",
            },
          },
          {
            ...upsert("conflicting-blob", 6),
            data: { id: "same-key", blob_ref: { blob_id: hash } },
            blobs: [conflicting],
          },
        ]),
      ).rejects.toThrow("metadata conflict");
      expect(await device.read()).toMatchObject({ version: 1, deleted: false });
    });
    it("applies shared mutable vectors in reverse order, survives restart and replay", async () => {
      const device = await factory();
      await device.send([registration]);
      for (const op of [...mutableVectors].reverse()) await device.send([op]);
      await device.send([registration]);
      expect(await device.read()).toMatchObject({
        data: { text: "resurrect" },
        version: 1,
        deleted: false,
      });
      device.reopen();
      await device.send([registration, ...mutableVectors]);
      expect(await device.read()).toMatchObject({
        data: { text: "resurrect" },
        version: 1,
      });
    });
    it("keeps deletion and reset dominant after restart", async () => {
      const device = await factory();
      await device.send([registration, upsert("put", 2)]);
      await device.send([
        {
          ...identity,
          kind: "connection-reset",
          previousGeneration: 1,
          generation: 2,
          revision: { counter: 3, writerId: "device-a", operationId: "reset" },
        },
      ]);
      device.reopen();
      await device.send([upsert("old", 100)]);
      expect(await device.read()).toMatchObject({ deleted: true });
      await device.send([{ ...upsert("new", 101), generation: 2 }]);
      expect(await device.read()).toMatchObject({
        deleted: false,
        data: { text: "new" },
      });
      await device.send([
        {
          ...identity,
          generation: 2,
          kind: "connection-delete",
          revision: {
            counter: 102,
            writerId: "device-a",
            operationId: "remove",
          },
        },
      ]);
      device.reopen();
      await device.send([{ ...upsert("late", 200), generation: 2 }]);
      expect(await device.read()).toMatchObject({ deleted: true });
    });
    it("withdraws an equivocated operation across retained keys", async () => {
      const device = await factory();
      const original = upsert("collision", 2);
      await device.send([registration, original]);
      await device.send([
        {
          ...original,
          recordKey: "other",
          data: { id: "other", text: "changed" },
        },
      ]);
      device.reopen();
      expect(await device.read()).toMatchObject({ deleted: true });
    });
    it("refuses a foreign owner's envelope without a canonical row", async () => {
      const device = await factory();
      await expect(
        device.send([{ ...upsert("foreign", 2), owner: "other" }]),
      ).rejects.toThrow();
      expect(await device.read()).toBeUndefined();
    });
  });
for (const [name, factory] of Object.entries({
  memory: memoryPort,
  sqlite: sqlitePort,
}))
  describe(`Lite ${name} crash oracle`, () => {
    for (const point of [
      "record",
      "journal",
      "outbox",
      "before-commit",
    ] as const)
      it(`rolls back a local batch interrupted at ${point}`, async () => {
        const device = await liteDevice(factory);
        await device.send([registration]);
        device.adapter.crashAt(point);
        await expect(
          device.store.commitLocal("local", [
            draft(upsert("one", 2)),
            {
              ...draft(upsert("two", 3)),
              recordKey: "other",
              data: { id: "other" },
            },
          ]),
        ).rejects.toThrow(`interrupted:${point}`);
        device.reopen();
        expect(await device.read()).toBeUndefined();
        expect((await device.store.readPage("journal")).entries).toHaveLength(
          0,
        );
        expect((await device.store.readPage("outbox")).entries).toHaveLength(0);
        await device.store.commitLocal("local", [draft(upsert("one", 2))]);
        device.reopen();
        expect(await device.read()).toMatchObject({ data: { text: "one" } });
      });
    it("adopts a committed local write after its acknowledgment is lost", async () => {
      const device = await liteDevice(factory);
      const ops = [draft(registration), draft(upsert("one", 2))];
      device.adapter.crashAt("after-commit");
      await expect(device.store.commitLocal("local", ops)).rejects.toThrow(
        "interrupted:after-commit",
      );
      device.reopen();
      const first = await device.store.commitLocal("local", ops);
      const second = await device.store.commitLocal("local", ops);
      expect(first).toEqual(second);
      expect((await device.store.readPage("journal")).entries).toHaveLength(2);
      expect((await device.store.readPage("outbox")).entries).toHaveLength(2);
      expect(await device.read()).toMatchObject({ version: 1 });
      await expect(
        device.store.commitLocal("local", [draft(upsert("changed", 3))]),
      ).rejects.toThrow("different content");
    });
    it("rolls back import receipt and row together, then replays without echo", async () => {
      const device = await liteDevice(factory);
      const ops = [registration, upsert("one", 2)];
      device.adapter.crashAt("import");
      await expect(device.send(ops, "import")).rejects.toThrow(
        "interrupted:import",
      );
      device.reopen();
      expect(await device.read()).toBeUndefined();
      await device.send(ops, "import");
      device.reopen();
      await device.send(ops, "import");
      expect(await device.read()).toMatchObject({ version: 1 });
      expect((await device.store.readPage("outbox")).entries).toHaveLength(0);
      expect((await device.store.readPage("journal")).entries).toHaveLength(0);
    });
    it("keeps each intermediate local mutation's original value", async () => {
      const device = await liteDevice(factory);
      await device.store.commitLocal("local", [
        draft(registration),
        draft(upsert("one", 2)),
        draft(upsert("two", 3)),
      ]);
      const mutations = (await device.store.readPage("mutations")).entries.map(
        (entry) => JSON.parse(entry.value),
      );
      expect(mutations.map((mutation) => mutation.value.data.text)).toEqual([
        "one",
        "two",
      ]);
      expect(mutations.map((mutation) => mutation.value.version)).toEqual([
        1, 2,
      ]);
    });
    it("does not journal or publish equal-content local retries", async () => {
      const device = await liteDevice(factory);
      await device.store.commitLocal("first", [
        draft(registration),
        draft(upsert("one", 2)),
      ]);
      const result = await device.store.commitLocal("again", [
        draft(upsert("different-id", 3, "one")),
      ]);
      expect(result.operationCount).toBe(0);
      expect((await device.store.readPage("outbox")).entries).toHaveLength(2);
      expect(await device.read()).toMatchObject({ version: 1 });
    });
    for (const point of ["blob", "record", "import", "after-commit"] as const)
      it(`atomically attaches staged bytes and imports at ${point}`, async () => {
        const device = await liteDevice(factory);
        const bytes = new TextEncoder().encode("blob bytes");
        const hash = `sha256:${sha256(bytes).slice(2)}`;
        const descriptor = {
          blobId: hash,
          sha256: hash,
          sizeBytes: bytes.length,
          mimeType: "application/octet-stream",
        };
        const ops: ReplicaOperation[] = [
          registration,
          {
            ...identity,
            kind: "blob-claim",
            blob: descriptor,
            revision: {
              counter: 2,
              writerId: "device-a",
              operationId: "claim",
            },
          },
          {
            ...upsert("blob", 3),
            data: {
              id: "same-key",
              blob_ref: {
                blob_id: hash,
                size_bytes: bytes.length,
                mime_type: descriptor.mimeType,
              },
            },
            blobs: [descriptor],
          },
        ];
        const stagingId = await device.store.stageBlob(
          descriptor,
          (async function* () {
            yield bytes;
          })(),
        );
        device.adapter.crashAt(point);
        await expect(
          device.store.import({
            id: "blob-import",
            envelope: envelope(ops),
            credential: "replica",
            blobs: [{ stagingId, descriptor }],
          }),
        ).rejects.toThrow(`interrupted:${point}`);
        device.reopen();
        if (point !== "after-commit") {
          expect(await device.read()).toBeUndefined();
          await expect(
            Array.fromAsync(device.store.readBlob(hash)),
          ).rejects.toThrow("missing committed blob");
        }
        const retryStage = await device.store.stageBlob(
          descriptor,
          (async function* () {
            yield bytes;
          })(),
        );
        await device.store.import({
          id: "blob-import",
          envelope: envelope(ops),
          credential: "replica",
          blobs: [{ stagingId: retryStage, descriptor }],
        });
        device.reopen();
        expect(await device.read()).toMatchObject({
          version: 1,
          data: { blob_ref: { blob_id: hash } },
        });
        expect(
          Buffer.concat(
            (await Array.fromAsync(device.store.readBlob(hash))).map((part) =>
              Buffer.from(part),
            ),
          ),
        ).toEqual(Buffer.from(bytes));
      });
  });
it("stays disabled unless explicitly enabled", async () => {
  const store = createLiteCanonicalStore({
    persistence: createFakeCanonicalPersistence().port,
    context: () => context,
    authenticateReplica: () => identity.owner,
  });
  await expect(
    store.commitLocal("disabled", [draft(registration)]),
  ).rejects.toThrow("disabled");
});

for (const [name, factory] of Object.entries({
  memory: memoryPort,
  sqlite: sqlitePort,
}))
  describe(`Lite ${name} review regressions`, () => {
    it("refuses provisioning against already-retained source/method evidence", async () => {
      const device = await liteDevice(factory, false);
      await device.send([registration, upsert("early", 2)]);
      await expect(
        device.store.provisionConnection(identity.connectionId, {
          sourceId: "other",
          methodId: identity.methodId,
        }),
      ).rejects.toThrow("retained connection");
      expect(await device.read()).toBeUndefined();
      await device.store.provisionConnection(identity.connectionId, {
        sourceId: identity.sourceId,
        methodId: identity.methodId,
      });
      expect(await device.read()).toMatchObject({ data: { text: "early" } });
    });
    it("blocks cross-key mixed-method evidence retained before provisioning", async () => {
      const device = await liteDevice(factory, false);
      await device.send([
        registration,
        upsert("one", 2),
        {
          ...upsert("other", 3),
          methodId: "other",
          recordKey: "other",
          data: { id: "other" },
        },
      ]);
      await expect(
        device.store.provisionConnection(identity.connectionId, {
          sourceId: identity.sourceId,
          methodId: identity.methodId,
        }),
      ).rejects.toThrow("retained connection");
      expect(await device.read()).toBeUndefined();
    });
    it("rejects a local write after a replicated connection deletion without emitting evidence", async () => {
      const device = await liteDevice(factory);
      await device.send([
        registration,
        upsert("one", 2),
        {
          ...identity,
          kind: "connection-delete",
          revision: { counter: 3, writerId: "device-a", operationId: "remove" },
        },
      ]);
      await expect(
        device.store.commitLocal("invalid", [draft(upsert("late", 4))]),
      ).rejects.toThrow("violates replica contract");
      expect((await device.store.readPage("outbox")).entries).toHaveLength(0);
    });
    it("orders the outbox by commit sequence even when request ids sort backwards", async () => {
      const device = await liteDevice(factory);
      await device.store.commitLocal("z", [
        draft(registration),
        draft(upsert("one", 2)),
      ]);
      const first = await device.store.readOutboxPage();
      expect(first.entries.map((e) => e.sequence)).toEqual([1, 2]);
      await device.store.commitLocal("a", [draft(upsert("two", 3))]);
      const next = await device.store.readOutboxPage(first.nextAfterSequence);
      expect(next.entries.map((e) => e.batchId)).toEqual(["a"]);
      expect(next.entries[0].operation).toMatchObject({
        data: { text: "two" },
      });
      await device.store.acknowledgeOutbox(0, 2);
      device.reopen();
      expect(
        (await device.store.readOutboxPage()).entries.map((e) => e.sequence),
      ).toEqual([3]);
      await device.store.acknowledgeOutbox(0, 2);
      await expect(device.store.acknowledgeOutbox(0, 3)).rejects.toThrow(
        "conflict",
      );
      expect((await device.store.readPage("journal")).entries).toHaveLength(3);
    });
    it("retries the same imported batch after its missing blob bytes arrive", async () => {
      const device = await liteDevice(factory);
      const bytes = new TextEncoder().encode("late bytes");
      const hash = `sha256:${sha256(bytes).slice(2)}`;
      const descriptor = {
        blobId: hash,
        sha256: hash,
        sizeBytes: bytes.length,
        mimeType: "text/plain",
      };
      const ops: ReplicaOperation[] = [
        registration,
        {
          ...identity,
          kind: "blob-claim",
          blob: descriptor,
          revision: { counter: 2, writerId: "device-a", operationId: "claim" },
        },
        {
          ...upsert("blob", 3),
          data: { id: "same-key", blob_ref: { blob_id: hash } },
          blobs: [descriptor],
        },
      ];
      await device.send(ops, "late-blob");
      expect(await device.read()).toBeUndefined();
      device.reopen();
      const stagingId = await device.store.stageBlob(
        descriptor,
        (async function* () {
          yield bytes;
        })(),
      );
      await device.store.import({
        id: "late-blob",
        envelope: envelope(ops),
        credential: "replica",
        blobs: [{ stagingId, descriptor }],
      });
      expect(await device.read()).toMatchObject({
        version: 1,
        data: { blob_ref: { blob_id: hash } },
      });
    });
  });
for (const [name, factory] of Object.entries(factories))
  it(`${name}: preserves current rows while a reset predecessor is missing`, async () => {
    const device = await factory();
    await device.send([registration, upsert("current", 2)]);
    const before = await device.read();
    await device.send([
      {
        ...identity,
        kind: "connection-reset",
        generation: 3,
        previousGeneration: 2,
        revision: { counter: 3, writerId: "device-a", operationId: "reset3" },
      },
    ]);
    device.reopen();
    expect(await device.read()).toEqual(before);
    await device.send([
      {
        ...identity,
        kind: "connection-reset",
        generation: 2,
        previousGeneration: 1,
        revision: { counter: 4, writerId: "device-a", operationId: "reset2" },
      },
    ]);
    expect(await device.read()).toMatchObject({ deleted: true });
  });
it("streams more than 4 MiB of retained variants for one key without discarding losers", async () => {
  const device = await liteDevice();
  await device.send([registration]);
  for (let i = 0; i < 70; i++)
    await device.send([
      upsert(`large-${i}`, i + 2, `${i}:${"x".repeat(64 * 1024)}`),
    ]);
  device.reopen();
  expect(await device.read()).toMatchObject({
    data: { text: `69:${"x".repeat(64 * 1024)}` },
  });
  const retained = await device.adapter.port.transaction(async (tx) => {
    let after: string | undefined;
    let count = 0;
    do {
      const page = await tx.scan("entries/", after);
      count += page.entries.length;
      after = page.after;
    } while (after !== undefined);
    return count;
  });
  expect(retained).toBe(71);
}, 30000);

for (const [name, factory] of Object.entries({
  memory: memoryPort,
  sqlite: sqlitePort,
}))
  it(`Node SQLite and Lite ${name} exchange their actual local journals after restart`, async () => {
    const desktop = nodeDevice();
    const phone = await liteDevice(factory);
    desktop.store.ingestBatch(
      [
        {
          instance: identity.connectionId,
          stream: binding.stream,
          key: "same-key",
          data: { id: "same-key", text: "from desktop" },
          emitted_at: "2026-10-20T00:00:00Z",
        },
      ],
      () => binding.semantics,
      () => binding.primaryKey,
      { method: identity.methodId, generation: 1 },
    );
    const outbound = [
      ...desktop.store.replication.readBaselinePage({ limit: 1000 }).operations,
      ...desktop.store.replication.readTailPage({ limit: 1000 }).operations,
    ];
    await phone.send(outbound);
    phone.reopen();
    expect(await phone.read()).toMatchObject({
      data: { text: "from desktop" },
    });
    await phone.store.commitLocal("from-phone", [
      draft(upsert("phone", 1, "from phone")),
    ]);
    phone.reopen();
    const returning = (await phone.store.readOutboxPage()).entries.map(
      (entry) => entry.operation,
    );
    expect(returning).toHaveLength(1);
    expect(returning[0].revision.counter).toBeGreaterThan(
      Math.max(...outbound.map((op) => op.revision.counter)),
    );
    await desktop.send(returning);
    desktop.reopen();
    expect(await desktop.read()).toMatchObject({
      data: { text: "from phone" },
    });
    await desktop.send(returning);
    expect(await desktop.read()).toMatchObject({ version: 2 });
  });

for (const [name, factory] of Object.entries(factories))
  it(`${name}: preserves an existing tombstone's deletion metadata through lifecycle cleanup`, async () => {
    const device = await factory();
    await device.send([
      registration,
      upsert("one", 2),
      { ...mutableVectors[2], deletedAt: "2026-10-21T00:00:00Z" },
    ]);
    const tombstone = await device.read();
    await device.send([
      {
        ...identity,
        kind: "connection-reset",
        generation: 2,
        previousGeneration: 1,
        revision: { counter: 8, writerId: "device-a", operationId: "reset" },
      },
    ]);
    device.reopen();
    expect(await device.read()).toEqual(tombstone);
    await device.send([
      {
        ...identity,
        generation: 2,
        kind: "connection-delete",
        revision: {
          counter: 9,
          writerId: "device-a",
          operationId: "delete-connection",
        },
      },
    ]);
    expect(await device.read()).toEqual(tombstone);
  });

for (const [name, factory] of Object.entries(factories))
  describe(`${name} final lifecycle parity`, () => {
    it("withdraws live rows for a retained invalid reset", async () => {
      const device = await factory();
      await device.send([registration, upsert("one", 2)]);
      await device.send([
        {
          ...identity,
          kind: "connection-reset",
          generation: 1,
          previousGeneration: 1,
          revision: {
            counter: 4,
            writerId: "device-a",
            operationId: "invalid",
          },
        },
      ]);
      device.reopen();
      expect(await device.read()).toMatchObject({ deleted: true, version: 2 });
    });
    for (const together of [false, true])
      it(`withdraws then recreates equal content in the next generation (${together ? "one batch" : "reordered batches"})`, async () => {
        const device = await factory();
        await device.send([registration, upsert("one", 2)]);
        const reset: ReplicaOperation = {
          ...identity,
          kind: "connection-reset",
          generation: 2,
          previousGeneration: 1,
          revision: { counter: 4, writerId: "device-a", operationId: "reset" },
        };
        const record = { ...upsert("equal", 5, "one"), generation: 2 };
        if (together) await device.send([reset, record]);
        else {
          await device.send([record]);
          device.reopen();
          await device.send([reset]);
        }
        device.reopen();
        expect(await device.read()).toMatchObject({
          version: 3,
          deleted: false,
          data: { text: "one" },
        });
        await device.send([reset, record]);
        expect(await device.read()).toMatchObject({ version: 3 });
      });
    it("retries retained work when its trusted declaration becomes available", async () => {
      const device = await factory({ ...context, declarations: [] });
      await device.send([registration, upsert("waiting", 2)]);
      expect(await device.read()).toBeUndefined();
      device.declare(context);
      await device.retry();
      device.reopen();
      expect(await device.read()).toMatchObject({
        version: 1,
        data: { text: "waiting" },
      });
      await device.retry();
      expect(await device.read()).toMatchObject({ version: 1 });
    });
  });

it("pages canonical connection rows without mixing accounts, streams or tombstones", async () => {
  const { store } = await liteDevice(sqlitePort);
  await store.commitLocal("write", [
    draft(registration),
    draft(upsert("one", 2)),
  ]);
  const page = await store.readConnectionPage(identity.connectionId);
  expect(page.rows).toHaveLength(1);
  expect(page.rows[0]).toMatchObject({
    instance: identity.connectionId,
    stream: binding.stream,
    recordKey: "same-key",
  });
  expect((await store.readConnectionPage("other")).rows).toEqual([]);
  await expect(
    store.readConnectionPage(identity.connectionId, "rows/foreign"),
  ).rejects.toThrow("cursor");
});
