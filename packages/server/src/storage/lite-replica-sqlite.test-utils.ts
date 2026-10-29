/**
 * A PS-Lite replication persistence over one SQLite file, standing in for
 * the phone's native store in tests: canonical key-value rows, blobs,
 * replica bytes and the engine's relational tables share one database, so
 * one transaction covers all of them, as on the phone (host contract §4.3).
 *
 * The transaction is asynchronous like the native bridge: every call
 * answers with a promise, and transactions run one at a time. Staged bytes
 * live in memory until a transaction attaches them, so a reopen drops them,
 * as the native side discards interrupted stages.
 */
import Database from "better-sqlite3";
import { sha256 } from "viem";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type {
  LiteBlobDescriptor,
  LiteReplicaPersistence,
  LiteReplicaSql,
  LiteReplicaTransaction,
} from "@opendatalabs/personal-server-ts-lite";
import { nodeReplicaSql } from "./pdpp-replica-sql.js";

const FRAME_BYTES = 128 * 1024;
const VALUE_BYTES = 256 * 1024;
const SCHEMA = `
CREATE TABLE IF NOT EXISTS lite_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lite_blobs (blob_id TEXT PRIMARY KEY, descriptor_json TEXT NOT NULL, bytes BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS lite_bytes (id TEXT PRIMARY KEY, bytes BLOB NOT NULL);`;

const hex = (bytes: Uint8Array) => sha256(bytes).slice(2);

async function collect(chunks: AsyncIterable<Uint8Array>) {
  const parts: Buffer[] = [];
  for await (const part of chunks) {
    if (part.length > FRAME_BYTES)
      throw new Error("native frame exceeds 128 KiB");
    parts.push(Buffer.from(part));
  }
  return Buffer.concat(parts);
}

function* frames(bytes: Uint8Array) {
  if (bytes.length === 0) yield new Uint8Array(0);
  for (let i = 0; i < bytes.length; i += FRAME_BYTES)
    yield new Uint8Array(bytes.subarray(i, i + FRAME_BYTES));
}

export interface SqliteLiteReplicaPersistence {
  port: LiteReplicaPersistence;
  db: Database.Database;
  /** Statements run inside transactions, for tests that count bridge calls. */
  statements(): number;
  /** The next transaction throws after its callback, before it commits. */
  failNextCommit(): void;
  close(): void;
}

export function createSqliteLiteReplicaPersistence(
  path = ":memory:",
): SqliteLiteReplicaPersistence {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.exec(SCHEMA);
  const staged = new Map<string, Buffer>();
  const stagedBlobs = new Map<
    string,
    { descriptor: LiteBlobDescriptor; bytes: Buffer }
  >();
  const sync = nodeReplicaSql(db);
  let statements = 0;
  let queue = Promise.resolve();
  let failBeforeCommit = false;
  let closed = false;

  const port: LiteReplicaPersistence & { discardBytes(id: string): void } = {
    transaction<T>(run: (tx: LiteReplicaTransaction) => Promise<T>) {
      const work = queue.then(async () => {
        if (closed) throw new Error("native store closed");
        let open = true;
        const live = () => {
          if (!open) throw new Error("transaction escaped its callback");
          statements++;
        };
        const sql: LiteReplicaSql = {
          get: async (text, params) =>
            (live(), sync.get(text, params)) as never,
          all: async (text, params) =>
            (live(), sync.all(text, params)) as never,
          run: async (text, params) =>
            (live(), sync.run(text, params)) as never,
          exec: async (text) => (live(), sync.exec(text)) as never,
        };
        const attached: string[] = [];
        const tx: LiteReplicaTransaction = {
          async get(key) {
            live();
            const row = db
              .prepare("SELECT value FROM lite_kv WHERE key=?")
              .get(key) as { value: string } | undefined;
            return row?.value;
          },
          async put(key, value) {
            live();
            if (Buffer.byteLength(value) > VALUE_BYTES)
              throw new Error("native value exceeds 256 KiB");
            db.prepare(
              "INSERT INTO lite_kv (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ).run(key, value);
          },
          async delete(key) {
            live();
            db.prepare("DELETE FROM lite_kv WHERE key=?").run(key);
          },
          async scan(prefix, after) {
            live();
            const rows = db
              .prepare(
                "SELECT key,value FROM lite_kv WHERE substr(key,1,?)=? AND key>? ORDER BY key LIMIT 101",
              )
              .all(prefix.length, prefix, after ?? "") as {
              key: string;
              value: string;
            }[];
            const entries: { key: string; value: string }[] = [];
            let size = 0;
            for (const row of rows) {
              const bytes = Buffer.byteLength(row.value);
              if (entries.length === 100 || size + bytes > 512 * 1024) break;
              entries.push(row);
              size += bytes;
            }
            return {
              entries,
              ...(entries.length < rows.length
                ? { after: entries.at(-1)!.key }
                : {}),
            };
          },
          async attachBlob(id, expected) {
            live();
            const value = stagedBlobs.get(id);
            if (
              !value ||
              canonicalJson(value.descriptor) !== canonicalJson(expected)
            )
              throw new Error("unknown staged blob");
            db.prepare(
              "INSERT OR IGNORE INTO lite_blobs (blob_id,descriptor_json,bytes) VALUES (?,?,?)",
            ).run(expected.blobId, canonicalJson(expected), value.bytes);
          },
          async blob(id) {
            live();
            const row = db
              .prepare("SELECT descriptor_json FROM lite_blobs WHERE blob_id=?")
              .get(id) as { descriptor_json: string } | undefined;
            return row
              ? (JSON.parse(row.descriptor_json) as LiteBlobDescriptor)
              : undefined;
          },
          async attachBytes(stagingId, expected) {
            live();
            const held = db
              .prepare("SELECT bytes FROM lite_bytes WHERE id=?")
              .get(stagingId) as { bytes: Buffer } | undefined;
            const value = staged.get(stagingId) ?? held?.bytes;
            if (!value) throw new Error("unknown staged bytes");
            if (
              value.length !== expected.length ||
              hex(value) !== expected.sha256
            )
              throw new Error("staged bytes do not match");
            db.prepare(
              "INSERT OR IGNORE INTO lite_bytes (id,bytes) VALUES (?,?)",
            ).run(stagingId, value);
            attached.push(stagingId);
          },
          async releaseBytes(id) {
            live();
            db.prepare("DELETE FROM lite_bytes WHERE id=?").run(id);
          },
          async publishBlob(bytesId, expected) {
            live();
            const held = db
              .prepare("SELECT bytes FROM lite_bytes WHERE id=?")
              .get(bytesId) as { bytes: Buffer } | undefined;
            if (!held) throw new Error("unknown attached bytes");
            if (
              held.bytes.length !== expected.sizeBytes ||
              `sha256:${hex(held.bytes)}` !== expected.sha256
            )
              throw new Error("attached bytes do not match blob");
            db.prepare(
              "INSERT OR IGNORE INTO lite_blobs (blob_id,descriptor_json,bytes) VALUES (?,?,?)",
            ).run(expected.blobId, canonicalJson(expected), held.bytes);
          },
          sql,
        };
        db.exec("BEGIN IMMEDIATE");
        try {
          const result = await run(tx);
          if (failBeforeCommit) {
            failBeforeCommit = false;
            throw new Error("interrupted:before-commit");
          }
          db.exec("COMMIT");
          for (const id of attached) staged.delete(id);
          return result;
        } catch (error) {
          if (db.inTransaction) db.exec("ROLLBACK");
          throw error;
        } finally {
          open = false;
        }
      });
      queue = work.then(
        () => undefined,
        () => undefined,
      );
      return work;
    },
    async stageBlob(descriptor, chunks) {
      const bytes = await collect(chunks);
      if (
        bytes.length !== descriptor.sizeBytes ||
        `sha256:${hex(bytes)}` !== descriptor.sha256
      )
        throw new Error("invalid staged blob");
      const id = globalThis.crypto.randomUUID();
      stagedBlobs.set(id, { descriptor: structuredClone(descriptor), bytes });
      return id as never;
    },
    async *readBlob(blobId) {
      const row = db
        .prepare("SELECT bytes FROM lite_blobs WHERE blob_id=?")
        .get(blobId) as { bytes: Buffer } | undefined;
      if (!row) throw new Error("missing committed blob");
      yield* frames(row.bytes);
    },
    async stageBytes(chunks) {
      const bytes = await collect(chunks);
      const id = globalThis.crypto.randomUUID();
      staged.set(id, bytes);
      return id;
    },
    /** Drop an unattached stage, as a cancelled transfer does. */
    discardBytes(id) {
      staged.delete(id);
    },
    async *readBytes(id) {
      const row = db
        .prepare("SELECT bytes FROM lite_bytes WHERE id=?")
        .get(id) as { bytes: Buffer } | undefined;
      if (!row) throw new Error("missing attached bytes");
      yield* frames(row.bytes);
    },
  };
  return {
    port,
    db,
    statements: () => statements,
    failNextCommit() {
      failBeforeCommit = true;
    },
    close() {
      closed = true;
      if (db.open) {
        if (db.inTransaction) db.exec("ROLLBACK");
        db.close();
      }
    },
  };
}
