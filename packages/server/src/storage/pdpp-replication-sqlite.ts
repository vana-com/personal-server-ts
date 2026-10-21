import {
  BINARY_CHUNKS_MIGRATION,
  binaryLength,
  readBinaryChunks,
  verifyBinary,
  copyBinary,
} from "./pdpp-binary-chunks.js";
import type { Database } from "better-sqlite3";
import { createHash, randomUUID } from "node:crypto";
import {
  canonicalJson,
  declarationBindingSchema,
  replicaOperationSchema,
  type DeclarationBinding,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  computeRecordKeyFromData,
  type StreamSemantics,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { liveSnapshotDigest } from "./pdpp-stream-completion.js";

/** Inert until beginBaseline commits. Never wired into production bootstrap. */
export const REPLICATION_MIGRATION =
  BINARY_CHUNKS_MIGRATION +
  `
CREATE TABLE IF NOT EXISTS pdpp_replica_settings (id INTEGER PRIMARY KEY CHECK(id = 1), config_json TEXT NOT NULL, watermark INTEGER NOT NULL, checkpoint INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS pdpp_replica_clock (id INTEGER PRIMARY KEY CHECK(id = 1), counter INTEGER NOT NULL);
INSERT OR IGNORE INTO pdpp_replica_clock VALUES (1, 0);
CREATE TABLE IF NOT EXISTS pdpp_replica_operations (sequence INTEGER PRIMARY KEY, operation_json TEXT NOT NULL, digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_replica_baseline (sequence INTEGER PRIMARY KEY REFERENCES pdpp_replica_operations(sequence));
CREATE TABLE IF NOT EXISTS pdpp_replica_blob_bytes (blob_id TEXT PRIMARY KEY, bytes BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS pdpp_replica_no_update BEFORE UPDATE ON pdpp_replica_operations BEGIN SELECT RAISE(ABORT, 'replica journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_replica_no_delete BEFORE DELETE ON pdpp_replica_operations BEGIN SELECT RAISE(ABORT, 'replica journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_replica_no_replace BEFORE INSERT ON pdpp_replica_operations WHEN EXISTS (SELECT 1 FROM pdpp_replica_operations WHERE sequence = NEW.sequence) BEGIN SELECT RAISE(ABORT, 'replica journal is append-only'); END;
`;
export interface BaselineConfiguration {
  owner: string;
  /** Trusted retained bindings, not supplied by connector ingest. Missing entries fail closed. */
  declarations: { sourceId: string; binding: DeclarationBinding }[];
}
export interface ReplicaPageOptions {
  afterSequence?: number;
  limit: number;
}
export interface ReplicaPage {
  operations: ReplicaOperation[];
  nextAfterSequence: number;
  hasMore: boolean;
}
export interface ReplicationExport {
  beginBaseline(config: BaselineConfiguration): { watermark: number };
  readBaselinePage(options: ReplicaPageOptions): ReplicaPage;
  readTailPage(options: ReplicaPageOptions): ReplicaPage;
  getBaselineCheckpoint(): number;
  /** CAS acknowledgment after the page is durable at its consumer; retry is idempotent. */
  acknowledgeBaselinePage(expected: number, next: number): void;
  readPinnedBlobBytes(blobId: string): Uint8Array | undefined;
  readPinnedBlobChunks(blobId: string): Iterable<Uint8Array>;
}
type Binding = {
  instance: string;
  source_id: string | null;
  method: string | null;
  generation: number;
  deleted_at: string | null;
};
type Row = {
  record_key: string;
  data: string | null;
  emitted_at: string;
  deleted: number;
  deleted_at: string | null;
  blob_id: string | null;
};
type WithoutRevision<T> = T extends ReplicaOperation
  ? Omit<T, "revision">
  : never;

export function replicaOperationDigest(operation: ReplicaOperation): string {
  return `sha256:${createHash("sha256").update(canonicalJson(operation)).digest("hex")}`;
}

/** Owns original revisions, pinned values/bytes and exporter progress on the canonical DB. */
export function createReplicationJournal(db: Database, writerId: string) {
  const settings = () =>
    db.prepare("SELECT * FROM pdpp_replica_settings WHERE id = 1").get() as
      | { config_json: string; watermark: number; checkpoint: number }
      | undefined;
  const config = (): BaselineConfiguration | undefined => {
    const row = settings();
    return row ? JSON.parse(row.config_json) : undefined;
  };
  function base(instance: string, generation?: number) {
    const cfg = config();
    if (!cfg) throw new Error("replication baseline required");
    const binding = db
      .prepare("SELECT * FROM pdpp_instance_binding WHERE instance = ?")
      .get(instance) as Binding | undefined;
    if (!binding?.source_id || !binding.method)
      throw new Error(`unbound replication connection: ${instance}`);
    return {
      owner: cfg.owner,
      sourceId: binding.source_id,
      connectionId: instance,
      methodId: binding.method,
      generation: generation ?? binding.generation,
    };
  }
  function declaration(instance: string, stream: string): DeclarationBinding {
    const identity = base(instance);
    const found = config()!.declarations.find(
      (e) => e.sourceId === identity.sourceId && e.binding.stream === stream,
    );
    if (!found) throw new Error(`missing retained declaration: ${stream}`);
    return found.binding;
  }
  function append(value: WithoutRevision<ReplicaOperation>): ReplicaOperation {
    if (!db.inTransaction)
      throw new Error("replication capture requires canonical transaction");
    const prior = db
      .prepare("SELECT counter FROM pdpp_replica_clock WHERE id = 1")
      .get() as { counter: number };
    if (!Number.isSafeInteger(prior.counter + 1))
      throw new Error("replication counter exhausted");
    const counter = prior.counter + 1;
    const operation = replicaOperationSchema.parse({
      ...value,
      revision: { counter, writerId, operationId: randomUUID() },
    });
    db.prepare("UPDATE pdpp_replica_clock SET counter = ? WHERE id = 1").run(
      counter,
    );
    db.prepare("INSERT INTO pdpp_replica_operations VALUES (?, ?, ?)").run(
      counter,
      canonicalJson(operation),
      replicaOperationDigest(operation),
    );
    return operation;
  }
  function blobDescriptor(blobId: string) {
    const meta = db
      .prepare("SELECT * FROM pdpp_blobs WHERE blob_id = ?")
      .get(blobId) as
      { sha256: string; mime_type: string; size_bytes: number } | undefined;
    if (!meta) throw new Error("missing replication blob metadata");
    return {
      blobId,
      sha256: `sha256:${meta.sha256}`,
      mimeType: meta.mime_type,
      sizeBytes: meta.size_bytes,
    };
  }
  function captureBlob(instance: string, blobId: string) {
    if (!settings()) return;
    const identity = base(instance);
    const claimed = db
      .prepare(
        "SELECT generation FROM pdpp_blob_claims WHERE instance = ? AND blob_id = ?",
      )
      .get(instance, blobId) as { generation: number } | undefined;
    if (claimed?.generation !== identity.generation)
      throw new Error("missing current blob claim");
    const blob = blobDescriptor(blobId);
    if (!verifyBinary(db, "canonical", blobId, blob.sha256, blob.sizeBytes))
      throw new Error("unverified replication blob bytes");
    if (binaryLength(db, "pinned", blobId) === undefined)
      copyBinary(db, "canonical", blobId, "pinned");
    else if (!verifyBinary(db, "pinned", blobId, blob.sha256, blob.sizeBytes))
      throw new Error("corrupt pinned replica bytes");
    const previous = allOperations().some(
      (op) =>
        op.kind === "blob-claim" &&
        op.connectionId === instance &&
        op.generation === identity.generation &&
        op.blob.blobId === blobId,
    );
    if (!previous) append({ ...identity, kind: "blob-claim", blob });
  }
  function captureRecord(
    instance: string,
    stream: string,
    recordKey: string,
    semantics?: StreamSemantics,
    primaryKey?: string[],
    /** The declaration the canonical write was validated against, when known. */
    validatedAgainst?: DeclarationBinding,
  ) {
    if (!settings()) return;
    const identity = {
      ...base(instance),
      declaration: declaration(instance, stream),
      recordKey,
    };
    // The exported operation asserts the retained declaration. A write
    // validated against any other one must not be labelled with it (#427 A).
    if (
      validatedAgainst !== undefined &&
      canonicalJson(validatedAgainst) !== canonicalJson(identity.declaration)
    )
      throw new Error("replication declaration mismatch");
    if (
      (semantics !== undefined &&
        semantics !== identity.declaration.semantics) ||
      (primaryKey !== undefined &&
        canonicalJson(primaryKey) !==
          canonicalJson(identity.declaration.primaryKey))
    )
      throw new Error("replication declaration mismatch");
    const row = db
      .prepare(
        "SELECT * FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
      )
      .get(instance, stream, recordKey) as Row;
    if (row.deleted) {
      if (identity.declaration.semantics === "append_only")
        throw new Error("append-only replication tombstone");
      append({
        ...identity,
        kind: "delete",
        emittedAt: row.emitted_at,
        deletedAt: row.deleted_at!,
      });
    } else {
      const data = JSON.parse(row.data!);
      if (
        computeRecordKeyFromData(data, identity.declaration.primaryKey) !==
        recordKey
      )
        throw new Error("replication record key mismatch");
      const blobId = row.blob_id;
      if (blobId) captureBlob(instance, blobId);
      append({
        ...identity,
        kind: "upsert",
        emittedAt: row.emitted_at,
        data,
        blobs: blobId ? [blobDescriptor(blobId)] : [],
      });
    }
  }
  function captureLifecycle(
    instance: string,
    kind: "connection-register" | "connection-reset" | "connection-delete",
    generation?: number,
  ) {
    if (!settings()) return;
    const identity = base(instance, generation);
    if (kind === "connection-register")
      append({ ...identity, kind, generation: 1 });
    else if (kind === "connection-reset")
      append({
        ...identity,
        kind,
        previousGeneration: identity.generation - 1,
      });
    else append({ ...identity, kind });
  }
  function allOperations(): ReplicaOperation[] {
    return (
      db
        .prepare(
          "SELECT operation_json FROM pdpp_replica_operations ORDER BY sequence",
        )
        .all() as { operation_json: string }[]
    ).map((row) => JSON.parse(row.operation_json));
  }
  function captureCompletion(instance: string, stream: string) {
    if (!settings()) return;
    const binding = base(instance);
    const retained = declaration(instance, stream);
    const row = db
      .prepare(
        "SELECT * FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
      )
      .get(instance, stream) as
      | {
          source_collected_at: string;
          live_count: number;
          snapshot_sha256: string | null;
          collection_time_basis: string | null;
        }
      | undefined;
    if (!row) return;
    if (
      (row.snapshot_sha256 === null && row.collection_time_basis !== null) ||
      (row.snapshot_sha256 !== null &&
        row.collection_time_basis !== "host_run_finished")
    )
      throw new Error("invalid completion proof provenance");
    const proof =
      row.snapshot_sha256 === null
        ? {
            kind: "producer-asserted" as const,
            snapshotSha256: null,
            collectionTimeBasis: null,
          }
        : {
            kind: "native" as const,
            snapshotSha256: `sha256:${row.snapshot_sha256}`,
            collectionTimeBasis: "host_run_finished" as const,
          };
    const rows = db
      .prepare(
        "SELECT record_key AS recordKey, data AS dataJson FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
      )
      .all(instance, stream) as { recordKey: string; dataJson: string }[];
    if (rows.length !== row.live_count)
      throw new Error("stale replication completion");
    const digest = liveSnapshotDigest(
      {
        sourceId: binding.sourceId,
        instance,
        method: binding.methodId,
        generation: binding.generation,
        stream,
      },
      retained.primaryKey,
      rows,
    );
    if (row.snapshot_sha256 !== null && digest !== row.snapshot_sha256)
      throw new Error("stale replication completion digest");
    const dependencies = allOperations()
      .filter(
        (op) =>
          op.connectionId === instance &&
          op.kind !== "stream-complete" &&
          (op.kind.startsWith("connection-") ||
            (op.generation === binding.generation &&
              (!("declaration" in op) || op.declaration.stream === stream))),
      )
      .map((op) => ({
        writerId: op.revision.writerId,
        operationId: op.revision.operationId,
        digest: replicaOperationDigest(op),
      }));
    append({
      ...binding,
      kind: "stream-complete",
      declaration: retained,
      sourceCollectedAt: row.source_collected_at,
      liveCount: row.live_count,
      snapshotSha256: `sha256:${digest}`,
      proof,
      dependencies,
    });
  }
  function captureInvalidation(instance: string, stream: string) {
    if (!settings()) return;
    append({
      ...base(instance),
      kind: "stream-invalidate",
      declaration: declaration(instance, stream),
    });
  }
  function beginBaseline(input: BaselineConfiguration) {
    // Validate before persisting; canonical order makes identical retries stable.
    const normalized = {
      owner: input.owner,
      declarations: input.declarations.map((e) => ({
        sourceId: e.sourceId,
        binding: declarationBindingSchema.parse(e.binding),
      })),
    };
    if (!normalized.owner || normalized.declarations.some((e) => !e.sourceId))
      throw new Error("invalid replication configuration");
    const keys = normalized.declarations.map((e) =>
      canonicalJson([e.sourceId, e.binding.stream]),
    );
    if (new Set(keys).size !== keys.length)
      throw new Error("duplicate retained declaration");
    return db
      .transaction(() => {
        const prior = settings();
        if (prior) {
          if (prior.config_json !== canonicalJson(normalized))
            throw new Error("replication binding is immutable");
          return { watermark: prior.watermark };
        }
        db.prepare(
          "INSERT INTO pdpp_replica_settings (id, config_json, watermark) VALUES (1, ?, 0)",
        ).run(canonicalJson(normalized));
        // A legacy orphan is a migration error, never an omitted row.
        const orphan = db
          .prepare(
            "SELECT 1 FROM pdpp_records r LEFT JOIN pdpp_instance_binding b ON r.instance = b.instance WHERE b.source_id IS NULL OR b.method IS NULL LIMIT 1",
          )
          .get();
        if (orphan) throw new Error("unbound baseline records");
        const bindings = db
          .prepare("SELECT * FROM pdpp_instance_binding ORDER BY instance")
          .all() as Binding[];
        for (const binding of bindings) {
          if (!binding.source_id || !binding.method) {
            throw new Error("unbound baseline connection");
          }
          captureLifecycle(binding.instance, "connection-register", 1);
          for (
            let generation = 2;
            generation <= binding.generation;
            generation++
          )
            captureLifecycle(binding.instance, "connection-reset", generation);
          if (binding.deleted_at !== null)
            captureLifecycle(binding.instance, "connection-delete");
        }
        for (const row of db
          .prepare("SELECT * FROM pdpp_blob_claims ORDER BY instance, blob_id")
          .all() as { instance: string; blob_id: string }[])
          captureBlob(row.instance, row.blob_id);
        for (const row of db
          .prepare(
            "SELECT instance, stream, record_key FROM pdpp_records ORDER BY instance, stream, record_key",
          )
          .all() as { instance: string; stream: string; record_key: string }[])
          captureRecord(row.instance, row.stream, row.record_key);
        for (const row of db
          .prepare(
            "SELECT instance, stream FROM pdpp_stream_completion ORDER BY instance, stream",
          )
          .all() as { instance: string; stream: string }[])
          captureCompletion(row.instance, row.stream);
        const { counter } = db
          .prepare("SELECT counter FROM pdpp_replica_clock")
          .get() as { counter: number };
        db.prepare(
          "INSERT INTO pdpp_replica_baseline SELECT sequence FROM pdpp_replica_operations",
        ).run();
        db.prepare(
          "UPDATE pdpp_replica_settings SET watermark = ? WHERE id = 1",
        ).run(counter);
        return { watermark: counter };
      })
      .immediate();
  }
  function page(options: ReplicaPageOptions, baseline: boolean): ReplicaPage {
    const state = settings();
    if (!state) throw new Error("replication baseline required");
    const after =
      options.afterSequence ?? (baseline ? state.checkpoint : state.watermark);
    if (
      !Number.isSafeInteger(after) ||
      after < 0 ||
      !Number.isInteger(options.limit) ||
      options.limit < 1 ||
      options.limit > 1000
    )
      throw new RangeError("invalid replication page");
    if (!baseline && after < state.watermark)
      throw new RangeError("tail starts below baseline watermark");
    const rows = db
      .prepare(
        `SELECT sequence, operation_json FROM pdpp_replica_operations WHERE sequence > ? AND ${baseline ? "sequence IN (SELECT sequence FROM pdpp_replica_baseline)" : "sequence > " + state.watermark} ORDER BY sequence LIMIT ?`,
      )
      .all(after, options.limit + 1) as {
      sequence: number;
      operation_json: string;
    }[];
    const selected = rows.slice(0, options.limit);
    return {
      operations: selected.map((row) => JSON.parse(row.operation_json)),
      nextAfterSequence: selected.at(-1)?.sequence ?? after,
      hasMore: rows.length > options.limit,
    };
  }
  const exporter: ReplicationExport = {
    beginBaseline,
    readBaselinePage: (options) => page(options, true),
    readTailPage: (options) => page(options, false),
    getBaselineCheckpoint: () => {
      const row = settings();
      if (!row) throw new Error("replication baseline required");
      return row.checkpoint;
    },
    acknowledgeBaselinePage(expected, next) {
      db.transaction(() => {
        const row = settings();
        if (
          !row ||
          !Number.isSafeInteger(expected) ||
          !Number.isSafeInteger(next) ||
          expected < 0 ||
          next < expected ||
          next > row.watermark
        )
          throw new RangeError("invalid baseline checkpoint");
        if (row.checkpoint === next) return;
        if (row.checkpoint !== expected)
          throw new Error("baseline checkpoint conflict");
        db.prepare(
          "UPDATE pdpp_replica_settings SET checkpoint = ? WHERE id = 1",
        ).run(next);
      }).immediate();
    },
    readPinnedBlobChunks(blobId) {
      return readBinaryChunks(db, "pinned", blobId);
    },
    readPinnedBlobBytes(blobId) {
      const size = binaryLength(db, "pinned", blobId);
      if (size === undefined) return undefined;
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of readBinaryChunks(db, "pinned", blobId)) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }
      return bytes;
    },
  };
  return {
    exporter,
    captureRecord,
    captureLifecycle,
    captureBlob,
    captureCompletion,
    captureInvalidation,
  };
}
