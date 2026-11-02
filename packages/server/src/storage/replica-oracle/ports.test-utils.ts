/**
 * Uniform drivers for the replica ports the oracle judges (design §1–§2):
 * the Node canonical SQLite store with its receiver, and the Lite canonical
 * store over the fake crash disk or a real disk SQLite adapter. The SQLite
 * adapter is Lite-port evidence on SQLite, not Dart or native-file
 * durability evidence.
 *
 * Drivers translate commands into each port's own public API and read state
 * back through each port's reader surfaces. They make no visibility decision.
 */
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256 } from "viem";
import {
  canonicalJson,
  replicaOperationSchema,
  type DeclarationBinding,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  createLiteCanonicalStore,
  type LiteOperationDraft,
} from "../../../../lite/src/canonical-store.js";
import type {
  LiteBlobDescriptor,
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
} from "../../../../lite/src/canonical-persistence.js";
import {
  collectStagedBlob,
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
  storagePage,
  writeCrashPoint,
  type CanonicalCrashPoint,
} from "../../../../lite/src/test-support/canonical-persistence.js";
import { createReplicaRecordStore } from "../pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "../pdpp-replication-receiver.js";
import { rowId } from "./reference.test-utils.js";

export const OWNER = "owner-a";
export const SOURCE = "https://example.test/source";
export const METHOD = "export";
export const CREDENTIAL = "replica";

export type BlobDescriptor = LiteBlobDescriptor;
export interface BlobPayload {
  descriptor: BlobDescriptor;
  bytes: Uint8Array;
}
export function blobPayload(
  bytes: Uint8Array,
  mimeType = "application/octet-stream",
): BlobPayload {
  const hash = `sha256:${sha256(bytes).slice(2)}`;
  return {
    descriptor: {
      blobId: hash,
      sha256: hash,
      mimeType,
      sizeBytes: bytes.length,
    },
    bytes,
  };
}
export const envelope = (batchId: string, operations: ReplicaOperation[]) => ({
  format: "vana-pdpp-replica" as const,
  version: 1 as const,
  owner: OWNER,
  batchId,
  operations,
});
export function contextOf(
  declarations: readonly DeclarationBinding[],
): MergeContext {
  return {
    owner: OWNER,
    declarations: declarations.map((binding) => ({
      sourceId: SOURCE,
      binding,
      validateData: (data: Record<string, unknown>) =>
        typeof data.id === "string",
    })),
  };
}

/** A canonical row as the port stores it. Versions and times are port facts. */
export interface StoredRow {
  deleted: boolean;
  data?: Record<string, unknown>;
  version: number;
  emittedAt: string;
  deletedAt?: string | null;
}
export interface ReaderView {
  /** Live rows from point reads. */
  point: Record<string, Record<string, unknown>>;
  /** Live rows from full list pagination. */
  list: Record<string, Record<string, unknown>>;
  /** Rows marked pending. */
  pending: string[];
  /** Hex bytes of each blob a live row references; null when unreadable. */
  blobs: Record<string, string | null>;
}
export interface PortSnapshot {
  stored: Record<string, StoredRow>;
  grant: ReaderView;
  owner: ReaderView;
}
export interface Universe {
  connections: readonly string[];
  streams: readonly { stream: string }[];
  keys: readonly string[];
}
export interface LocalWrite {
  requestId: string;
  connection: string;
  generation: number;
  binding: DeclarationBinding;
  key: string;
  data: Record<string, unknown>;
  emittedAt: string;
}

export interface ReplicaPortDriver {
  readonly name: string;
  readonly durable: boolean;
  provision(connection: string): Promise<boolean>;
  declare(declarations: readonly DeclarationBinding[]): Promise<void>;
  /** Resolves to the port's own receipt. */
  importBatch(
    id: string,
    ops: ReplicaOperation[],
    blobs: BlobPayload[],
  ): Promise<unknown>;
  retry(): Promise<void>;
  local(write: LocalWrite): Promise<unknown>;
  quarantineConnection(connection: string): Promise<void>;
  stage(
    id: string,
    ops: ReplicaOperation[],
    blobs: BlobPayload[],
  ): Promise<void>;
  promote(id: string): Promise<unknown>;
  dropPending(id: string): Promise<void>;
  reopen(): Promise<void>;
  /** The port's own local journal, in commit order. */
  localOperations(): Promise<ReplicaOperation[]>;
  snapshot(universe: Universe): Promise<PortSnapshot>;
  close(): void;
}

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const blobIdOf = (data: Record<string, unknown> | undefined) => {
  const id = (data?.blob_ref as { blob_id?: unknown } | undefined)?.blob_id;
  return typeof id === "string" ? id : undefined;
};
function draftOf(op: ReplicaOperation): LiteOperationDraft {
  const { revision: _revision, ...draft } = op;
  return draft as LiteOperationDraft;
}
async function* frames(bytes: Uint8Array) {
  for (let i = 0; i < bytes.length; i += 128 * 1024)
    yield bytes.subarray(i, i + 128 * 1024);
  if (!bytes.length) yield bytes;
}
const isPending = (row: unknown) =>
  (row as { visibility?: unknown } | undefined)?.visibility === "pending";

// ---------------------------------------------------------------- Node

export interface NodeDriverOptions {
  /** Keep the database on disk so `reopen` closes and reopens it. */
  durable?: boolean;
  declarations: readonly DeclarationBinding[];
  provisioned: readonly string[];
}
export function nodeDriver(options: NodeDriverOptions) {
  const directory = options.durable
    ? mkdtempSync(join(tmpdir(), "replica-oracle-node-"))
    : undefined;
  const path = directory ? join(directory, "records.sqlite") : ":memory:";
  let context = contextOf(options.declarations);
  let db = new Database(path);
  let store = createReplicaRecordStore(db);
  for (const connection of options.provisioned)
    store.registerConnection({
      instance: connection,
      sourceId: SOURCE,
      method: METHOD,
      label: connection,
    });
  store.replication.beginBaseline({
    owner: context.owner,
    declarations: [...context.declarations],
  });
  const makeReceiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner: OWNER,
      authenticate: (credential) =>
        credential === CREDENTIAL ? OWNER : undefined,
      declarations: () => context.declarations,
      enabled: true,
    });
  let receiver = makeReceiver();
  const reader = (kind: "owner" | "grant") =>
    receiver.readStore({ reader: kind });
  const driver: ReplicaPortDriver & {
    readonly db: Database.Database;
    readonly store: typeof store;
    readonly receiver: typeof receiver;
    readonly path: string;
  } = {
    name: "node",
    durable: options.durable === true,
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    get receiver() {
      return receiver;
    },
    path,
    async provision(connection) {
      try {
        store.registerConnection({
          instance: connection,
          sourceId: SOURCE,
          method: METHOD,
          label: connection,
        });
      } catch {
        return false;
      }
      receiver.retry({ credential: CREDENTIAL });
      return true;
    },
    async declare(declarations) {
      context = contextOf(declarations);
      receiver.reconcileDeclarations({ credential: CREDENTIAL });
    },
    async importBatch(_id, ops, blobs) {
      return receiver.import({
        credential: CREDENTIAL,
        envelope: envelope(_id, ops),
        blobs: blobs.map((b) => ({
          blobId: b.descriptor.blobId,
          bytes: b.bytes,
        })),
      });
    },
    async retry() {
      receiver.retry({ credential: CREDENTIAL });
    },
    async local(write) {
      const result = store.ingestBatch(
        [
          {
            instance: write.connection,
            stream: write.binding.stream,
            key: write.key,
            data: write.data,
            emitted_at: write.emittedAt,
          },
        ],
        () => write.binding.semantics,
        () => write.binding.primaryKey,
        { method: METHOD, generation: write.generation },
        (_stream, _instance, data) =>
          typeof data.id === "string" ? null : "invalid_record_data",
        () => write.binding,
      );
      const rejected = (
        result as { results?: { outcome: string; reason?: string }[] }
      ).results?.find((r) => r.outcome === "rejected");
      if (rejected) throw new Error(`rejected:${rejected.reason ?? ""}`);
      return result;
    },
    async quarantineConnection(connection) {
      receiver.quarantineImported({
        credential: CREDENTIAL,
        envelope: envelope(`quarantine-${connection}`, [
          {
            owner: OWNER,
            sourceId: SOURCE,
            connectionId: connection,
            methodId: METHOD,
            generation: 1,
            kind: "connection-register",
            revision: {
              counter: 1,
              writerId: "oracle-host",
              operationId: `q-${connection}`,
            },
          },
        ]),
      });
    },
    async stage(id, ops, blobs) {
      receiver.stage({
        credential: CREDENTIAL,
        id,
        envelope: envelope(id, ops),
        blobs: blobs.map((b) => ({
          blobId: b.descriptor.blobId,
          bytes: b.bytes,
        })),
      });
    },
    async promote(id) {
      return receiver.promote({ credential: CREDENTIAL, id });
    },
    async dropPending(id) {
      receiver.quarantine({ credential: CREDENTIAL, id, reason: "oracle" });
    },
    async reopen() {
      if (!directory) throw new Error("memory Node store cannot reopen");
      store.close();
      db = new Database(path);
      store = createReplicaRecordStore(db);
      receiver = makeReceiver();
    },
    async localOperations() {
      return (
        db
          .prepare(
            "SELECT operation_json FROM pdpp_replica_operations ORDER BY sequence",
          )
          .all() as { operation_json: string }[]
      ).map((row) =>
        replicaOperationSchema.parse(JSON.parse(row.operation_json)),
      );
    },
    async snapshot(universe) {
      const stored: Record<string, StoredRow> = {};
      for (const row of db
        .prepare(
          "SELECT instance,stream,record_key,data,version,emitted_at,deleted_at FROM pdpp_records",
        )
        .all() as {
        instance: string;
        stream: string;
        record_key: string;
        data: string | null;
        version: number;
        emitted_at: string;
        deleted_at: string | null;
      }[])
        stored[rowId(row.instance, row.stream, row.record_key)] =
          row.data === null
            ? {
                deleted: true,
                version: row.version,
                emittedAt: row.emitted_at,
                deletedAt: row.deleted_at,
              }
            : {
                deleted: false,
                data: JSON.parse(row.data),
                version: row.version,
                emittedAt: row.emitted_at,
              };
      const view = (kind: "owner" | "grant"): ReaderView => {
        const read = reader(kind);
        const out: ReaderView = { point: {}, list: {}, pending: [], blobs: {} };
        for (const connection of universe.connections)
          for (const { stream } of universe.streams) {
            for (const key of universe.keys) {
              const row = read.getRecord(connection, stream, key) as
                | { data?: Record<string, unknown>; deleted?: boolean }
                | undefined;
              if (row && !row.deleted && row.data) {
                out.point[rowId(connection, stream, key)] = row.data;
                if (isPending(row))
                  out.pending.push(rowId(connection, stream, key));
              }
            }
            let cursor: string | undefined;
            do {
              const page = read.listRecords(stream, {
                instanceIds: [connection],
                limit: 1000,
                order: "asc",
                cursor,
              });
              for (const row of page.data as {
                instance?: string;
                recordKey: string;
                data?: Record<string, unknown>;
                deleted?: boolean;
              }[])
                if (!row.deleted && row.data)
                  out.list[rowId(connection, stream, row.recordKey)] = row.data;
              cursor = page.nextCursor;
            } while (cursor);
          }
        for (const data of Object.values(out.point)) {
          const id = blobIdOf(data);
          if (!id) continue;
          const bytes = read.getBlobBytes(id);
          out.blobs[id] = bytes ? hex(bytes) : null;
        }
        out.pending.sort();
        return out;
      };
      return { stored, grant: view("grant"), owner: view("owner") };
    },
    close() {
      try {
        store.close();
      } catch {
        /* already closed */
      }
      if (directory) rmSync(directory, { recursive: true, force: true });
    },
  };
  return driver;
}
export type NodeDriver = ReturnType<typeof nodeDriver>;

// ---------------------------------------------------------------- Lite

export interface LitePersistenceHandle {
  port: LiteCanonicalPersistence;
  /** Arm one crash; `reopen` disarms a crash the operation never reached. */
  crashAt(point: CanonicalCrashPoint): void;
  reopen(): void;
  /** Every committed row and blob id, for "nothing durable changed" assertions. */
  dump(): Record<string, unknown>;
  close(): void;
}
/** Fake crash disk: rows survive `reopen`, staged bytes do not. */
export function liteMemoryPersistence(): LitePersistenceHandle {
  const disk = fakeCanonicalDisk();
  let current = createFakeCanonicalPersistence(disk);
  return {
    get port() {
      return current.port;
    },
    crashAt: (point) => current.crashAt(point),
    reopen() {
      current = createFakeCanonicalPersistence(disk);
    },
    dump: () => ({
      rows: Object.fromEntries(
        [...disk.rows].sort(([a], [b]) => (a < b ? -1 : 1)),
      ),
      blobs: [...disk.blobs.keys()].sort(),
    }),
    close() {},
  };
}
/** Real disk SQLite implementation of the Lite persistence port. */
export function liteSqlitePersistence(): LitePersistenceHandle {
  const directory = mkdtempSync(join(tmpdir(), "replica-oracle-lite-"));
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
  return {
    port,
    crashAt(point) {
      failure = point;
    },
    reopen() {
      failure = undefined;
      db.close();
      open();
    },
    dump() {
      const { kv, blobs } = sqliteDump(db);
      return { kv, blobs };
    },
    close() {
      try {
        db.close();
      } catch {
        /* already closed */
      }
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

export interface LiteDriverOptions {
  persistence: LitePersistenceHandle;
  name: string;
  declarations: readonly DeclarationBinding[];
  provisioned: readonly string[];
}
export async function liteDriver(options: LiteDriverOptions) {
  const persistence = options.persistence;
  let context = contextOf(options.declarations);
  let ids = 0;
  // Deterministic local ids keep a seed reproducible. "lite-" sorts before
  // every remote "w-" writer, so equal-counter ties break the same way as the
  // Node installation's hex writer id.
  const newId = () => `lite-${(ids++).toString().padStart(6, "0")}`;
  const make = () =>
    createLiteCanonicalStore({
      persistence: persistence.port,
      enabled: true,
      context: () => context,
      authenticateReplica: (credential) =>
        credential === CREDENTIAL ? OWNER : undefined,
      newId,
    });
  let store = make();
  const fingerprints = new Map<string, string>();
  async function stageBlobs(blobs: BlobPayload[]) {
    const staged: { stagingId: string; descriptor: BlobDescriptor }[] = [];
    for (const blob of blobs)
      staged.push({
        stagingId: await store.stageBlob(blob.descriptor, frames(blob.bytes)),
        descriptor: blob.descriptor,
      });
    return staged;
  }
  const driver: ReplicaPortDriver & {
    readonly store: typeof store;
    readonly persistence: LitePersistenceHandle;
    /** Ids minted so far. Crash tests rewind it past ids a rollback discarded. */
    idCount: number;
  } = {
    name: options.name,
    durable: true,
    get store() {
      return store;
    },
    get idCount() {
      return ids;
    },
    set idCount(value) {
      ids = value;
    },
    persistence,
    async provision(connection) {
      try {
        await store.provisionConnection(connection, {
          sourceId: SOURCE,
          methodId: METHOD,
        });
      } catch {
        return false;
      }
      // Node's registerConnection journals a local registration; the Lite
      // host registers the provisioned connection through its local batch.
      // Lite refuses that registration when retained evidence already
      // suppresses or holds the connection; the reference then reads the
      // port's journal without it.
      await store
        .commitLocal(`register-${connection}`, [
          {
            owner: OWNER,
            sourceId: SOURCE,
            connectionId: connection,
            methodId: METHOD,
            generation: 1,
            kind: "connection-register",
          },
        ])
        .catch(() => undefined);
      return true;
    },
    async declare(declarations) {
      context = contextOf(declarations);
      await driver.retry();
    },
    async importBatch(id, ops, blobs) {
      return store.import({
        id,
        envelope: envelope(id, ops),
        credential: CREDENTIAL,
        blobs: await stageBlobs(blobs),
      });
    },
    async retry() {
      let after: string | undefined;
      do {
        after = (await store.retry({ credential: CREDENTIAL, after })).after;
      } while (after !== undefined);
    },
    async local(write) {
      return store.commitLocal(write.requestId, [
        {
          owner: OWNER,
          sourceId: SOURCE,
          connectionId: write.connection,
          methodId: METHOD,
          generation: write.generation,
          kind: "upsert",
          declaration: write.binding,
          recordKey: write.key,
          emittedAt: write.emittedAt,
          data: write.data as never,
          blobs: [],
        },
      ]);
    },
    async quarantineConnection(connection) {
      await store.quarantineConnection({
        credential: CREDENTIAL,
        connectionId: connection,
        reason: "oracle",
      });
    },
    async stage(id, ops, blobs) {
      const result = await store.stagePending({
        id,
        envelope: envelope(id, ops),
        credential: CREDENTIAL,
        blobs: await stageBlobs(blobs),
      });
      fingerprints.set(id, result.fingerprint);
    },
    async promote(id) {
      return store.promotePending({
        id,
        credential: CREDENTIAL,
        fingerprint: fingerprints.get(id)!,
      });
    },
    async dropPending(id) {
      await store.quarantinePending({
        id,
        credential: CREDENTIAL,
        reason: "oracle",
      });
    },
    async reopen() {
      persistence.reopen();
      store = make();
    },
    async localOperations() {
      const ops: ReplicaOperation[] = [];
      let after = 0;
      for (;;) {
        const page = await store.readLogPage(after);
        ops.push(...page.entries.map((entry) => entry.operation));
        after = page.nextAfterSequence;
        if (!page.hasMore) return ops;
      }
    },
    async snapshot(universe) {
      const stored: Record<string, StoredRow> = {};
      for (const connection of universe.connections)
        for (const { stream } of universe.streams)
          for (const key of universe.keys) {
            const row = await store.readRecord(connection, stream, key, {
              reader: "grant",
            });
            if (row)
              stored[rowId(connection, stream, key)] = row.deleted
                ? {
                    deleted: true,
                    version: row.version,
                    emittedAt: row.emittedAt,
                    deletedAt: row.deletedAt,
                  }
                : {
                    deleted: false,
                    data: row.data,
                    version: row.version,
                    emittedAt: row.emittedAt,
                  };
          }
      const view = async (reader: "owner" | "grant"): Promise<ReaderView> => {
        const out: ReaderView = { point: {}, list: {}, pending: [], blobs: {} };
        for (const connection of universe.connections) {
          for (const { stream } of universe.streams)
            for (const key of universe.keys) {
              const row = await store.readRecord(connection, stream, key, {
                reader,
              });
              if (row && !row.deleted) {
                out.point[rowId(connection, stream, key)] = row.data;
                if (isPending(row))
                  out.pending.push(rowId(connection, stream, key));
              }
            }
          let after: string | undefined;
          do {
            const page = await store.readConnectionPage(connection, after, {
              reader,
            });
            for (const row of page.rows)
              if (!row.deleted)
                out.list[rowId(connection, row.stream, row.recordKey)] =
                  row.data;
            after = page.after;
          } while (after !== undefined);
        }
        for (const data of Object.values(out.point)) {
          const id = blobIdOf(data);
          if (!id) continue;
          try {
            const parts: Uint8Array[] = [];
            for await (const part of store.readBlob(id, { reader }))
              parts.push(part);
            out.blobs[id] = hex(Buffer.concat(parts));
          } catch {
            out.blobs[id] = null;
          }
        }
        out.pending.sort();
        return out;
      };
      return { stored, grant: await view("grant"), owner: await view("owner") };
    },
    close() {
      persistence.close();
    },
  };
  for (const connection of options.provisioned)
    await driver.provision(connection);
  return driver;
}
export type LiteDriver = Awaited<ReturnType<typeof liteDriver>>;
export { draftOf };

/** Every row of every table, for "nothing durable changed" assertions. */
export function sqliteDump(db: Database.Database): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    )
    .all() as { name: string }[];
  for (const { name } of tables)
    out[name] = (db.prepare(`SELECT * FROM "${name}"`).all() as unknown[])
      .map((row) =>
        JSON.stringify(row, (_key, value: unknown) =>
          Buffer.isBuffer(value) ? value.toString("hex") : value,
        ),
      )
      .sort();
  return out;
}
