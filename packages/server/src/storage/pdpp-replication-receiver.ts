import { createReplicaVisibilityView } from "./pdpp-replica-visibility-view.js";
import {
  binaryLength,
  binaryWriter,
  verifyBinary,
  copyBinary,
  deleteBinary,
  readBinary,
  type BinaryNamespace,
} from "./pdpp-binary-chunks.js";
import type { Database } from "better-sqlite3";
import {
  createReplicaCopies,
  REPLICA_REFETCH_BUDGET,
  ReplicaCopyRefused,
  type CopyPromotion,
  type StagedCopy,
} from "./pdpp-replica-copies.js";
import type {
  CopyDecision,
  FinalizedFact,
} from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import { createHash } from "node:crypto";
import {
  canonicalJson,
  replicaEnvelopeSchema,
  type ReplicaOperation,
  type RecordOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  planReplicaMerge,
  type MergeContext,
  type ReplicaMergePlan,
} from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { selectStreamCompletion } from "@opendatalabs/personal-server-ts-core/replication/completion";
import { replicaOperationDigest } from "./pdpp-replication-sqlite.js";
import { liveSnapshotDigest } from "./pdpp-stream-completion.js";
import type { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

import {
  replicaStateVisible,
  type ReplicaReader,
  type ReplicaVisibilityPolicy,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";
import {
  CursorExpiredError,
  decodeCursor,
  encodeCursor,
  type ChangesSinceCursorPayload,
  type ChangesSincePage,
  type ListRecordsOptions,
  type ChangesSinceOptions,
  type PdppVisibleRecord,
  type ListVisibleRecordsPage,
  type PdppReplicaReadStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

export const RECEIVER_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_replica_received (operation_json TEXT PRIMARY KEY, digest TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS pdpp_received_no_update BEFORE UPDATE ON pdpp_replica_received BEGIN SELECT RAISE(ABORT, 'received operations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_received_no_delete BEFORE DELETE ON pdpp_replica_received BEGIN SELECT RAISE(ABORT, 'received operations are append-only'); END;
CREATE TABLE IF NOT EXISTS pdpp_replica_quarantined_keys (instance TEXT NOT NULL, generation INTEGER NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL, PRIMARY KEY(instance,generation,stream,record_key));
CREATE TABLE IF NOT EXISTS pdpp_replica_quarantined_connections (instance TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS pdpp_replica_received_bytes (blob_id TEXT PRIMARY KEY, bytes BLOB NOT NULL);
`;

/**
 * Replica integrity facts. Only replica tables: no main table changes.
 * - integrity fences: how many times replica evidence hid data of a
 *   connection (key or connection quarantine, binding conflict). With the
 *   binding's reset_clock it forms the connection's integrity epoch.
 * - binding conflicts: a connection whose evidence names another source or
 *   method than its local mapping, or two sources. Append-only: later
 *   evidence, equivocation included, can never erase the fact.
 */
export const REPLICA_INTEGRITY_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_replica_integrity_fences (instance TEXT PRIMARY KEY, fences INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_replica_binding_conflicts (instance TEXT PRIMARY KEY, reason TEXT NOT NULL, evidence_json TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS pdpp_binding_conflicts_no_update BEFORE UPDATE ON pdpp_replica_binding_conflicts BEGIN SELECT RAISE(ABORT, 'binding conflicts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_binding_conflicts_no_delete BEFORE DELETE ON pdpp_replica_binding_conflicts BEGIN SELECT RAISE(ABORT, 'binding conflicts are append-only'); END;
`;

type Store = ReturnType<typeof createSqliteRecordStore>;
type Binding = {
  instance: string;
  source_id: string | null;
  method: string | null;
  generation: number;
  deleted_at: string | null;
};
type BlobDescriptor = Extract<ReplicaOperation, { kind: "blob-claim" }>["blob"];
interface StoredRow {
  data: string | null;
  version: number;
  emitted_at: string;
  deleted: number;
  deleted_at: string | null;
  blob_id: string | null;
}

/**
 * Internal port, deliberately absent from bootstrap and connector routes. The host
 * must verify a replica-specific credential before returning its owner. A payload,
 * a collector credential, and a source declaration are never authentication.
 * Connection ids are the registered canonical instance ids (the export profile).
 */
export function createReplicaReceiver(deps: {
  db: Database;
  store: Store;
  owner: string;
  authenticate: (credential: unknown) => string | undefined;
  declarations: () => MergeContext["declarations"];
  enabled?: boolean;
  visibilityPolicy?: ReplicaVisibilityPolicy;
}) {
  const { db, store, owner } = deps;
  let pendingEnabled = deps.enabled === true;
  db.exec(`CREATE TABLE IF NOT EXISTS pdpp_replica_pending_batches (
    id TEXT PRIMARY KEY, envelope_json TEXT NOT NULL, blobs_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','confirmed','quarantined')), reason TEXT
  ); CREATE TABLE IF NOT EXISTS pdpp_replica_pending_bytes (
    batch_id TEXT NOT NULL, blob_id TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(batch_id,blob_id)
  )`);
  type PendingBatch = {
    id: string;
    envelope_json: string;
    blobs_json: string;
    state: string;
  };
  const pendingBlobKey = (batchId: string, blobId: string) =>
    canonicalJson([batchId, blobId]);
  const pendingBatches = () =>
    db
      .prepare(
        "SELECT * FROM pdpp_replica_pending_batches WHERE state='pending' ORDER BY id",
      )
      .all() as PendingBatch[];
  function authorize(credential: unknown) {
    if (!owner || deps.authenticate(credential) !== owner)
      throw new Error("replica authority required for owner");
    const settings = db
      .prepare("SELECT config_json FROM pdpp_replica_settings WHERE id = 1")
      .get() as { config_json: string } | undefined;
    if (!settings || JSON.parse(settings.config_json).owner !== owner)
      throw new Error("same-owner replication baseline required");
  }
  const binding = (id: string) =>
    db
      .prepare("SELECT * FROM pdpp_instance_binding WHERE instance = ?")
      .get(id) as Binding | undefined;
  function validateMapping(operation: ReplicaOperation) {
    const local = binding(operation.connectionId);
    if (
      local?.source_id &&
      (local.source_id !== operation.sourceId ||
        local.method !== operation.methodId)
    )
      throw new Error("replica connection source or method mismatch");
  }
  /** Hide one key. Raises the connection's integrity epoch only when newly hidden. */
  function quarantineKey(
    instance: string,
    generation: number,
    stream: string,
    recordKey: string,
  ) {
    if (
      db
        .prepare(
          "INSERT OR IGNORE INTO pdpp_replica_quarantined_keys VALUES (?, ?, ?, ?)",
        )
        .run(instance, generation, stream, recordKey).changes > 0
    )
      store.fenceReplicaConnection(instance);
  }
  /** Hide a connection. Returns true, with a raised epoch, only when newly hidden. */
  function quarantineConnection(instance: string): boolean {
    const hidden =
      db
        .prepare(
          "INSERT OR IGNORE INTO pdpp_replica_quarantined_connections VALUES (?)",
        )
        .run(instance).changes > 0;
    if (hidden) store.fenceReplicaConnection(instance);
    return hidden;
  }
  /**
   * Durable binding-conflict facts from retained evidence, before planning:
   * two sources or methods for one connection id (equivocated variants
   * count), or evidence that disagrees with the local mapping. Each fact
   * quarantines only its connection; other connections keep importing.
   */
  function recordBindingConflicts(all: ReplicaOperation[]) {
    const byConnection = new Map<string, ReplicaOperation[]>();
    for (const op of all)
      byConnection.set(op.connectionId, [
        ...(byConnection.get(op.connectionId) ?? []),
        op,
      ]);
    for (const [id, ops] of byConnection) {
      const local = binding(id);
      const disagreeing = local?.source_id
        ? ops.find(
            (op) =>
              op.sourceId !== local.source_id || op.methodId !== local.method,
          )
        : undefined;
      if (disagreeing)
        store.markReplicaBindingConflict({
          connectionId: id,
          reason: "local_mapping_conflict",
          evidence: {
            sourceId: disagreeing.sourceId,
            methodId: disagreeing.methodId,
            revision: disagreeing.revision,
          },
        });
      else if (
        new Set(ops.map((op) => op.sourceId)).size > 1 ||
        new Set(ops.map((op) => op.methodId)).size > 1
      )
        store.markReplicaBindingConflict({
          connectionId: id,
          reason: "source_binding_conflict",
          evidence: [
            ...new Set(ops.map((op) => `${op.sourceId} ${op.methodId}`)),
          ]
            .sort()
            .slice(0, 8),
        });
    }
  }
  function retained(): ReplicaOperation[] {
    return (
      db
        .prepare(
          "SELECT operation_json FROM pdpp_replica_operations UNION SELECT operation_json FROM pdpp_replica_received",
        )
        .all() as { operation_json: string }[]
    ).map((row) => JSON.parse(row.operation_json));
  }
  const hash = (bytes: Uint8Array) =>
    `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
  function verifiedBytes(blob: BlobDescriptor): BinaryNamespace | undefined {
    const namespace =
      binaryLength(db, "received", blob.blobId) === undefined
        ? "canonical"
        : "received";
    return blob.blobId === blob.sha256 &&
      verifyBinary(db, namespace, blob.blobId, blob.sha256, blob.sizeBytes)
      ? namespace
      : undefined;
  }
  function materializeBlob(
    operation: Extract<ReplicaOperation, { kind: "upsert" }>,
    operations: ReplicaOperation[],
  ): boolean {
    const ref = operation.data.blob_ref as
      | {
          blob_id?: unknown;
          sha256?: unknown;
          size_bytes?: unknown;
          mime_type?: unknown;
        }
      | undefined;
    if (operation.blobs.length !== (ref ? 1 : 0)) return false;
    for (const blob of operation.blobs) {
      if (
        ref?.blob_id !== blob.blobId ||
        (ref.sha256 !== undefined &&
          ref.sha256 !== blob.sha256.replace("sha256:", "")) ||
        (ref.size_bytes !== undefined && ref.size_bytes !== blob.sizeBytes) ||
        (ref.mime_type !== undefined && ref.mime_type !== blob.mimeType)
      )
        return false;
      const claimed = operations.some(
        (op) =>
          op.kind === "blob-claim" &&
          op.owner === owner &&
          op.connectionId === operation.connectionId &&
          op.sourceId === operation.sourceId &&
          op.methodId === operation.methodId &&
          op.generation === operation.generation &&
          canonicalJson(op.blob) === canonicalJson(blob),
      );
      const bytes = verifiedBytes(blob);
      if (!claimed || !bytes) return false;
      const meta = store.getBlobMeta(blob.blobId);
      if (
        meta &&
        (meta.sha256 !== blob.sha256.slice(7) ||
          meta.mimeType !== blob.mimeType ||
          meta.sizeBytes !== blob.sizeBytes)
      )
        throw new Error("replica blob metadata conflict");
      db.prepare("INSERT OR IGNORE INTO pdpp_blobs VALUES (?, ?, ?, ?)").run(
        blob.blobId,
        blob.mimeType,
        blob.sizeBytes,
        blob.sha256.slice(7),
      );
      if (binaryLength(db, "canonical", blob.blobId) !== undefined) {
        if (
          !verifyBinary(
            db,
            "canonical",
            blob.blobId,
            blob.sha256,
            blob.sizeBytes,
          )
        )
          throw new Error("corrupt canonical blob bytes");
      } else copyBinary(db, bytes, blob.blobId, "canonical");
      db.prepare(
        "INSERT INTO pdpp_blob_claims VALUES (?, ?, ?) ON CONFLICT(blob_id, instance) DO UPDATE SET generation = excluded.generation",
      ).run(blob.blobId, operation.connectionId, operation.generation);
    }
    return true;
  }
  function write(
    instance: string,
    stream: string,
    key: string,
    operation: RecordOperation | null,
  ) {
    const current = db
      .prepare(
        "SELECT * FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
      )
      .get(instance, stream, key) as StoredRow | undefined;
    const data =
      operation?.kind === "upsert" ? canonicalJson(operation.data) : null;
    const emittedAt = operation?.emittedAt ?? current?.emitted_at;
    if (!emittedAt) return;
    const deletedAt =
      operation?.kind === "delete"
        ? operation.deletedAt
        : data === null
          ? emittedAt
          : null;
    if (
      current &&
      (current.data === null
        ? null
        : canonicalJson(JSON.parse(current.data))) === data &&
      current.emitted_at === emittedAt &&
      current.deleted_at === deletedAt
    )
      return;
    const version = (current?.version ?? 0) + 1;
    const { value: seq } = db
      .prepare(
        "UPDATE pdpp_write_clock SET value = value + 1 WHERE id = 1 RETURNING value",
      )
      .get() as { value: number };
    const blobId =
      operation?.kind === "upsert"
        ? (operation.blobs[0]?.blobId ?? null)
        : null;
    db.prepare(
      "INSERT INTO pdpp_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(instance,stream,record_key) DO UPDATE SET data=excluded.data, version=excluded.version, emitted_at=excluded.emitted_at, deleted=excluded.deleted, deleted_at=excluded.deleted_at, blob_id=excluded.blob_id",
    ).run(
      instance,
      stream,
      key,
      data,
      version,
      emittedAt,
      data === null ? 1 : 0,
      deletedAt,
      blobId,
    );
    db.prepare(
      "INSERT INTO pdpp_record_changes (instance,stream,record_key,version,data,emitted_at,deleted,deleted_at,written_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).run(
      instance,
      stream,
      key,
      version,
      data,
      emittedAt,
      data === null ? 1 : 0,
      deletedAt,
      seq,
    );
    db.prepare(
      "DELETE FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
    ).run(instance, stream);
    if (data === null)
      db.prepare(
        "DELETE FROM pdpp_record_arrival WHERE instance = ? AND stream = ? AND record_key = ?",
      ).run(instance, stream, key);
    else
      db.prepare(
        "INSERT INTO pdpp_record_arrival VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(arrival), 0) + 1 FROM pdpp_record_arrival WHERE instance = ?)) ON CONFLICT(instance,stream,record_key) DO UPDATE SET generation=excluded.generation,arrival=excluded.arrival",
      ).run(instance, stream, key, operation!.generation, instance);
    db.prepare(
      "UPDATE pdpp_record_arrival_clock SET value = value + 1 WHERE id = 1",
    ).run();
  }
  function reconcile(): ReplicaMergePlan {
    const all = retained();
    const context = { owner, declarations: deps.declarations() };
    // A retained disagreement is a connection-scoped fact, never a throw that
    // would block every import and retry (#428 F2).
    recordBindingConflicts(all);
    const unavailable: ReplicaOperation[] = [];
    const eligible = all.filter((op) => {
      const local = binding(op.connectionId);
      if (!local?.source_id) {
        unavailable.push(op);
        return false;
      }
      return !store.replicaBindingConflict(op.connectionId);
    });
    const plan = planReplicaMerge(context, eligible);
    if (unavailable.length)
      plan.pending.push({
        reason: "missing_local_connection",
        operations: unavailable,
      });
    // Lifecycle evidence gates canonical state, but never creates a connection or
    // changes its acquisition method. Only the local authority provisions that.
    for (const id of new Set(eligible.map((op) => op.connectionId))) {
      const local = binding(id)!;
      const entries = eligible.filter((op) => op.connectionId === id);
      const blocked = plan.conflicts.some(
        (issue) =>
          issue.reason !== "append_only_content_conflict" &&
          issue.reason !== "incompatible_record_declaration" &&
          issue.operations.some((op) => op.connectionId === id),
      );
      const deleted = plan.suppressed.some(
        (issue) =>
          issue.reason === "connection_deleted" &&
          issue.operations.some((op) => op.connectionId === id),
      );
      const missingLifecycle = plan.pending.some(
        (issue) =>
          issue.operations.some((op) => op.connectionId === id) &&
          [
            "missing_connection_registration",
            "missing_generation_reset",
          ].includes(issue.reason) &&
          issue.operations.some(
            (op) =>
              op.kind === "connection-register" ||
              op.kind === "connection-reset",
          ),
      );
      const generation = Math.max(
        1,
        ...entries
          .filter((op) => op.kind === "connection-reset")
          .map((op) => op.generation),
      );
      const newlyBlocked = blocked && quarantineConnection(id);
      const reset =
        !blocked && !missingLifecycle && generation > local.generation;
      // A receiver-derived deletion can become equivocated later. Retract only
      // that derived marker; an actual local deletion remains in the merge set.
      const retractDeletion =
        !deleted && local.deleted_at === "replica-deleted";
      if (deleted || blocked || reset) {
        for (const row of db
          .prepare(
            "SELECT stream,record_key FROM pdpp_records WHERE instance = ? AND deleted = 0",
          )
          .all(id) as { stream: string; record_key: string }[])
          write(id, row.stream, row.record_key, null);
        db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
          id,
        );
        db.prepare("DELETE FROM pdpp_blob_claims WHERE instance = ?").run(id);
      }
      if (
        (deleted && local.deleted_at === null) ||
        reset ||
        newlyBlocked ||
        retractDeletion
      ) {
        // Even an empty reset must expire a token at the old write horizon.
        const { value: fence } = db
          .prepare(
            "UPDATE pdpp_write_clock SET value = value + 1 WHERE id = 1 RETURNING value",
          )
          .get() as { value: number };
        db.prepare(
          "UPDATE pdpp_instance_binding SET generation = ?, deleted_at = ?, reset_clock = ? WHERE instance = ?",
        ).run(
          reset ? generation : local.generation,
          deleted
            ? (local.deleted_at ?? "replica-deleted")
            : retractDeletion
              ? null
              : local.deleted_at,
          fence,
          id,
        );
      }
    }
    for (const record of plan.records) {
      const { connectionId, stream, recordKey, generation } = record.identity;
      const local = binding(connectionId)!;
      if (local.deleted_at || generation !== local.generation) continue;
      if (record.quarantined)
        quarantineKey(connectionId, generation, stream, recordKey);
      if (isRecordQuarantined(connectionId, stream, recordKey)) {
        write(connectionId, stream, recordKey, null);
        continue;
      }
      const winner = record.winner;
      if (winner?.kind === "upsert" && !materializeBlob(winner, eligible)) {
        plan.pending.push({
          reason: "missing_or_invalid_blob",
          operations: [winner],
        });
        write(connectionId, stream, recordKey, null);
      } else write(connectionId, stream, recordKey, winner);
    }
    const materialized = new Set(
      plan.records.map((record) => canonicalJson(record.identity)),
    );
    for (const issue of [...plan.pending, ...plan.rejected]) {
      if (
        issue.reason !== "missing_declaration" &&
        issue.reason !== "invalid_record_data"
      )
        continue;
      for (const op of issue.operations) {
        if (op.kind !== "upsert" && op.kind !== "delete") continue;
        const identity = {
          owner: op.owner,
          sourceId: op.sourceId,
          connectionId: op.connectionId,
          generation: op.generation,
          stream: op.declaration.stream,
          recordKey: op.recordKey,
        };
        if (
          binding(op.connectionId)?.generation === op.generation &&
          !materialized.has(canonicalJson(identity))
        )
          write(op.connectionId, op.declaration.stream, op.recordKey, null);
      }
    }
    reconcileCompletions(eligible, plan);
    return plan;
  }
  function reconcileCompletions(
    operations: ReplicaOperation[],
    plan: ReplicaMergePlan,
  ) {
    const grouped = new Map<
      string,
      Extract<
        ReplicaOperation,
        { kind: "stream-complete" | "stream-invalidate" }
      >[]
    >();
    const declarations = deps.declarations();
    for (const op of operations) {
      if (op.kind !== "stream-complete" && op.kind !== "stream-invalidate")
        continue;
      if (
        !declarations.some(
          (d) =>
            d.sourceId === op.sourceId &&
            canonicalJson(d.binding) === canonicalJson(op.declaration),
        )
      ) {
        plan.pending.push({ reason: "missing_declaration", operations: [op] });
        continue;
      }
      const key = canonicalJson([
        op.connectionId,
        op.generation,
        op.declaration.stream,
      ]);
      grouped.set(key, [...(grouped.get(key) ?? []), op]);
    }
    for (const entries of grouped.values()) {
      const first = entries[0];
      const local = binding(first.connectionId)!;
      if (local.deleted_at || local.generation !== first.generation) continue;
      const stream = first.declaration.stream;
      if (
        db
          .prepare(
            "SELECT 1 FROM pdpp_replica_quarantined_connections WHERE instance = ? UNION ALL SELECT 1 FROM pdpp_replica_quarantined_keys WHERE instance = ? AND generation = ? AND stream = ? LIMIT 1",
          )
          .get(first.connectionId, first.connectionId, first.generation, stream)
      ) {
        db.prepare(
          "DELETE FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
        ).run(first.connectionId, stream);
        continue;
      }
      if (
        new Set(entries.map((op) => canonicalJson(op.declaration))).size > 1
      ) {
        plan.conflicts.push({
          reason: "incompatible_completion_declaration",
          operations: entries,
        });
        db.prepare(
          "DELETE FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
        ).run(first.connectionId, stream);
        continue;
      }
      const relevantIssue = [
        ...plan.pending,
        ...plan.conflicts,
        ...plan.rejected,
      ].some(
        (issue) =>
          issue.reason !== "missing_declaration" &&
          issue.operations.some(
            (op) =>
              op.connectionId === first.connectionId &&
              (!("declaration" in op) || op.declaration.stream === stream),
          ),
      );
      const declaration = deps
        .declarations()
        .find(
          (d) =>
            d.sourceId === first.sourceId &&
            canonicalJson(d.binding) === canonicalJson(first.declaration),
        );
      const completion = selectStreamCompletion(entries);
      const dependencies =
        completion?.dependencies.every((dep) => {
          const matches = operations.filter(
            (op) =>
              op.revision.writerId === dep.writerId &&
              op.revision.operationId === dep.operationId,
          );
          return (
            matches.length === 1 &&
            replicaOperationDigest(matches[0]) === dep.digest
          );
        }) && completion.dependencies.length > 0;
      const rows = db
        .prepare(
          "SELECT record_key AS recordKey, data AS dataJson FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
        )
        .all(first.connectionId, stream) as {
        recordKey: string;
        dataJson: string;
      }[];
      const digest = declaration
        ? liveSnapshotDigest(
            {
              sourceId: first.sourceId,
              instance: first.connectionId,
              method: first.methodId,
              generation: first.generation,
              stream,
            },
            declaration.binding.primaryKey,
            rows,
          )
        : undefined;
      if (
        completion &&
        declaration &&
        dependencies &&
        !relevantIssue &&
        rows.length === completion.liveCount &&
        `sha256:${digest}` === completion.snapshotSha256 &&
        (completion.proof.kind !== "native" ||
          completion.proof.snapshotSha256 === completion.snapshotSha256)
      ) {
        const seq = (
          db.prepare("SELECT value FROM pdpp_write_clock").get() as {
            value: number;
          }
        ).value;
        db.prepare(
          "INSERT INTO pdpp_stream_completion (instance,stream,method,generation,source_collected_at,write_seq,live_count,snapshot_sha256,collection_time_basis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(instance,stream) DO UPDATE SET method=excluded.method,generation=excluded.generation,source_collected_at=excluded.source_collected_at,write_seq=excluded.write_seq,live_count=excluded.live_count,snapshot_sha256=excluded.snapshot_sha256,collection_time_basis=excluded.collection_time_basis WHERE method IS NOT excluded.method OR generation IS NOT excluded.generation OR source_collected_at IS NOT excluded.source_collected_at OR live_count IS NOT excluded.live_count OR snapshot_sha256 IS NOT excluded.snapshot_sha256 OR collection_time_basis IS NOT excluded.collection_time_basis",
        ).run(
          first.connectionId,
          stream,
          first.methodId,
          first.generation,
          completion.sourceCollectedAt,
          seq,
          completion.liveCount,
          completion.proof.kind === "native" ? digest! : null,
          completion.proof.kind === "native" ? "host_run_finished" : null,
        );
      } else {
        db.prepare(
          "DELETE FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
        ).run(first.connectionId, stream);
        if (completion)
          plan.pending.push({
            reason: "unverified_completion",
            operations: [completion],
          });
      }
    }
  }
  function isRecordQuarantined(
    instance: string,
    stream: string,
    key: string,
  ): boolean {
    return !db
      .prepare(
        `SELECT 1 FROM (SELECT ? AS instance,? AS stream,? AS record_key) r WHERE ${store.unquarantinedRecordSql("r")}`,
      )
      .get(instance, stream, key);
  }
  const view = createReplicaVisibilityView({
    db,
    owner,
    declarations: deps.declarations,
    blobsValid: previewBlobsValid,
    unquarantinedRecordSql: store.unquarantinedRecordSql,
    integrityEpoch: store.replicaIntegrityEpoch,
  });
  store.setReplicaVisibilityObserver(view.flush);
  function includesPending(reader: ReplicaReader = "grant") {
    return (
      pendingEnabled &&
      replicaStateVisible("pending", reader, deps.visibilityPolicy)
    );
  }
  type IntegrityBoundChanges = ChangesSinceCursorPayload & {
    integrity?: Record<string, number>;
  };
  /**
   * Bind changes tokens to the integrity epoch of every requested connection,
   * as page cursors are. A moved epoch (a quarantine, a terminal batch)
   * expires both the page cursor and the session token, so a delta client
   * resyncs instead of missing withdrawn rows. Without the store capability
   * the store's reset fence alone applies. The field matches the one the
   * synthesis lane's store binds into its own tokens.
   */
  function bindChangesIntegrity(
    options: ChangesSinceOptions,
    read: () => ChangesSincePage,
  ): ChangesSincePage {
    const epochOf = store.replicaIntegrityEpoch;
    if (!epochOf) return read();
    const integrity = JSON.stringify(
      Object.fromEntries(
        [...new Set(options.instanceIds)].sort().map((id) => [id, epochOf(id)]),
      ),
    );
    for (const token of [options.cursor, options.changesSince]) {
      if (!token) continue;
      let payload: IntegrityBoundChanges;
      try {
        payload = decodeCursor(token) as IntegrityBoundChanges;
      } catch {
        continue; // The store refuses a malformed token as it does today.
      }
      if (
        payload.kind === "changes_since" &&
        JSON.stringify(payload.integrity ?? null) !== integrity
      )
        throw new CursorExpiredError();
    }
    const bind = (token: string | undefined) => {
      if (!token) return token;
      const payload = decodeCursor(token) as IntegrityBoundChanges;
      payload.integrity = JSON.parse(integrity) as Record<string, number>;
      return encodeCursor(payload);
    };
    const page = read();
    return {
      ...page,
      nextCursor: bind(page.nextCursor),
      nextChangesSince: bind(page.nextChangesSince),
    };
  }
  function readVisibleRecords(input: {
    reader?: ReplicaReader;
    connectionId: string;
    stream: string;
  }): PdppVisibleRecord[] {
    const rows: PdppVisibleRecord[] = [];
    let cursor: string | undefined;
    do {
      const page = api.readRecords({
        reader: input.reader,
        instanceIds: [input.connectionId],
        stream: input.stream,
        limit: 1000,
        order: "asc",
        cursor,
      });
      rows.push(...page.data);
      cursor = page.nextCursor;
    } while (cursor);
    return rows;
  }
  function pendingBlob(blobId: string): Uint8Array | undefined {
    const row = db
      .prepare(
        "SELECT b.bytes FROM pdpp_replica_pending_bytes b JOIN pdpp_replica_pending_batches p ON p.id=b.batch_id WHERE b.blob_id=? AND p.state='pending' LIMIT 1",
      )
      .get(blobId) as { bytes: Buffer } | undefined;
    if (row) return row.bytes;
    for (const batch of pendingBatches()) {
      const bytes = readBinary(db, "pending", pendingBlobKey(batch.id, blobId));
      if (bytes) return bytes;
    }
    return undefined;
  }
  /** Streams chunked pending custody; only legacy whole-row pending bytes are hashed in memory. */
  function pendingBlobVerified(blob: BlobDescriptor): boolean {
    const legacy = db
      .prepare(
        "SELECT b.bytes FROM pdpp_replica_pending_bytes b JOIN pdpp_replica_pending_batches p ON p.id=b.batch_id WHERE b.blob_id=? AND p.state='pending' LIMIT 1",
      )
      .get(blob.blobId) as { bytes: Buffer } | undefined;
    if (legacy)
      return (
        legacy.bytes.length === blob.sizeBytes &&
        hash(legacy.bytes) === blob.sha256
      );
    return pendingBatches().some((batch) =>
      verifyBinary(
        db,
        "pending",
        pendingBlobKey(batch.id, blob.blobId),
        blob.sha256,
        blob.sizeBytes,
      ),
    );
  }
  /** Canonical, received or pending bytes, legacy rows or chunks (#439). */
  function rawVisibleBlob(id: string): Uint8Array | undefined {
    return (
      readBinary(db, "canonical", id) ??
      readBinary(db, "received", id) ??
      pendingBlob(id)
    );
  }
  function verifiedVisibleBlob(id: string): Uint8Array | undefined {
    const meta = store.getBlobMeta(id) ?? view.getBlobMeta(id);
    const bytes = rawVisibleBlob(id);
    if (!meta || !bytes) return undefined;
    const digest = `sha256:${meta.sha256}`;
    return id === digest &&
      bytes.byteLength === meta.sizeBytes &&
      hash(bytes) === digest
      ? bytes
      : undefined;
  }
  function readSnapshot<T>(read: () => T): T {
    return db.transaction(read).deferred();
  }
  function previewBlobsValid(
    op: Extract<ReplicaOperation, { kind: "upsert" }>,
    operations: ReplicaOperation[],
  ): boolean {
    const ref = op.data.blob_ref as
      | {
          blob_id?: string;
          sha256?: string;
          size_bytes?: number;
          mime_type?: string;
        }
      | undefined;
    if (op.blobs.length !== (ref ? 1 : 0)) return false;
    return op.blobs.every((blob) => {
      if (
        ref?.blob_id !== blob.blobId ||
        (ref.sha256 !== undefined && ref.sha256 !== blob.sha256.slice(7)) ||
        (ref.size_bytes !== undefined && ref.size_bytes !== blob.sizeBytes) ||
        (ref.mime_type !== undefined && ref.mime_type !== blob.mimeType)
      )
        return false;
      const meta = store.getBlobMeta(blob.blobId);
      if (
        meta &&
        (meta.sha256 !== blob.sha256.slice(7) ||
          meta.mimeType !== blob.mimeType ||
          meta.sizeBytes !== blob.sizeBytes)
      )
        return false;
      if (
        binaryLength(db, "canonical", blob.blobId) !== undefined &&
        !store.getBlobBytes(blob.blobId)
      )
        return false;
      return (
        (verifiedBytes(blob) !== undefined || pendingBlobVerified(blob)) &&
        operations.some(
          (claim) =>
            claim.kind === "blob-claim" &&
            claim.connectionId === op.connectionId &&
            claim.generation === op.generation &&
            canonicalJson(claim.blob) === canonicalJson(blob),
        )
      );
    });
  }
  /**
   * Withdraw a connection from every reader: the quarantine fact (raises the
   * integrity epoch), canonical tombstones, claims and completion. Caller
   * holds the transaction and flushes the view.
   */
  function withdrawConnection(instance: string) {
    quarantineConnection(instance);
    for (const row of db
      .prepare(
        "SELECT stream,record_key FROM pdpp_records WHERE instance = ? AND deleted = 0",
      )
      .all(instance) as { stream: string; record_key: string }[])
      write(instance, row.stream, row.record_key, null);
    db.prepare("DELETE FROM pdpp_blob_claims WHERE instance = ?").run(instance);
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      instance,
    );
  }
  type ImportBlobs = {
    blobs?: { blobId: string; bytes: Uint8Array }[];
    stagedBlobs?: {
      blobId: string;
      key: string;
      sizeBytes: number;
      namespace?: "staging" | "pending";
    }[];
  };
  /** Import a validated, owner-checked envelope. Caller holds the transaction. */
  function importParsed(
    envelope: ReturnType<typeof replicaEnvelopeSchema.parse>,
    input: ImportBlobs,
  ): ReplicaMergePlan {
    for (const op of envelope.operations) validateMapping(op);
    for (const blob of input.blobs ?? []) {
      if (hash(blob.bytes) !== blob.blobId)
        throw new Error("corrupt replica blob bytes");
      if (binaryLength(db, "received", blob.blobId) !== undefined) {
        if (
          !verifyBinary(
            db,
            "received",
            blob.blobId,
            blob.blobId,
            blob.bytes.length,
          )
        )
          throw new Error("corrupt retained replica bytes");
      } else if (blob.bytes.length <= 1024 * 1024) {
        db.prepare("INSERT INTO pdpp_replica_received_bytes VALUES (?, ?)").run(
          blob.blobId,
          blob.bytes,
        );
      } else {
        const writer = binaryWriter(db, "received", blob.blobId);
        writer.write(blob.bytes);
        writer.finish();
      }
    }
    for (const blob of input.stagedBlobs ?? []) {
      const from = blob.namespace ?? "staging";
      if (!verifyBinary(db, from, blob.key, blob.blobId, blob.sizeBytes))
        throw new Error("corrupt replica blob bytes");
      if (binaryLength(db, "received", blob.blobId) !== undefined) {
        if (
          !verifyBinary(
            db,
            "received",
            blob.blobId,
            blob.blobId,
            blob.sizeBytes,
          )
        )
          throw new Error("corrupt retained replica bytes");
      } else copyBinary(db, from, blob.key, "received", blob.blobId);
    }
    for (const op of envelope.operations) {
      db.prepare(
        "INSERT OR IGNORE INTO pdpp_replica_received VALUES (?, ?)",
      ).run(canonicalJson(op), replicaOperationDigest(op));
      db.prepare(
        "UPDATE pdpp_replica_clock SET counter = MAX(counter, ?) WHERE id = 1",
      ).run(op.revision.counter);
    }
    const plan = reconcile();
    view.flush();
    return plan;
  }
  /**
   * Batch copies (contract v3.1). The legacy pending row of an id mirrors its
   * single `pending` copy, so #438's preview view and its triggers keep one
   * key per id. Pending bytes stay keyed (id, blobId): a blob id is its
   * content hash, so copies that share a blob share identical bytes, and a
   * blob is released only when no other retained copy of the id names it.
   */
  const copies = createReplicaCopies({
    db,
    owner,
    importEnvelope(envelope, blobs, id) {
      importParsed(envelope, {
        stagedBlobs: blobs.map((b) => ({
          blobId: b.blobId,
          key: pendingBlobKey(id, b.blobId),
          sizeBytes: b.size,
          namespace: "pending" as const,
        })),
      });
    },
    quarantineConnection: withdrawConnection,
    preview: {
      show(id, envelope, blobsJson) {
        const encoded = canonicalJson(envelope);
        const row = db
          .prepare(
            "SELECT state,envelope_json,blobs_json FROM pdpp_replica_pending_batches WHERE id=?",
          )
          .get(id) as PendingBatch | undefined;
        if (
          row?.state === "pending" &&
          row.envelope_json === encoded &&
          row.blobs_json === blobsJson
        )
          return;
        if (row?.state === "pending") view.removePending(id);
        db.prepare(
          "INSERT INTO pdpp_replica_pending_batches VALUES (?,?,?,'pending',NULL) ON CONFLICT(id) DO UPDATE SET envelope_json=excluded.envelope_json,blobs_json=excluded.blobs_json,state='pending',reason=NULL",
        ).run(id, encoded, blobsJson);
        view.addPending(id, envelope.operations);
      },
      hide(id, state) {
        if (
          db
            .prepare(
              "UPDATE pdpp_replica_pending_batches SET state=?,reason=? WHERE id=? AND state='pending'",
            )
            .run(state, state === "quarantined" ? "copy conflict" : null, id)
            .changes > 0
        )
          view.removePending(id);
      },
    },
    releaseBytes(id, blobIds) {
      for (const blobId of blobIds)
        deleteBinary(db, "pending", pendingBlobKey(id, blobId));
    },
    now: () => Date.now(),
  });
  const hasCopies = (id: string) =>
    db
      .prepare("SELECT 1 FROM pdpp_replica_copies WHERE id=? LIMIT 1")
      .get(id) !== undefined;
  /** Copy-path mutation: authenticated, one transaction, view flushed inside it. */
  function copyTransaction<T>(credential: unknown, effect: () => T): T {
    authorize(credential);
    return db
      .transaction(() => {
        const result = effect();
        view.flush();
        return result;
      })
      .immediate();
  }
  const api = {
    setPendingEnabled(enabled: boolean) {
      pendingEnabled = enabled;
    },
    /**
     * Batch-copy custody and promotion (contract v3.1). Trusted host hooks:
     * the caller verified every fragment's bytes against its own hash pair.
     */
    copies: {
      stage(input: {
        credential: unknown;
        copy: Omit<StagedCopy, "envelope" | "blobs"> & { envelope: unknown };
        blobs?: { blobId: string; bytes: Uint8Array }[];
        /** Verified transport staging, copied into pending custody. */
        stagedBlobs?: { blobId: string; key: string; sizeBytes: number }[];
        refetch?: { attempts: number; budget: number };
      }) {
        authorize(input.credential);
        const envelope = replicaEnvelopeSchema.parse(input.copy.envelope);
        if (
          envelope.owner !== owner ||
          envelope.operations.some((op) => op.owner !== owner)
        )
          throw new Error("wrong replica owner");
        for (const op of envelope.operations) validateMapping(op);
        for (const blob of input.blobs ?? [])
          if (hash(blob.bytes) !== blob.blobId)
            throw new Error("corrupt replica blob bytes");
        for (const blob of input.stagedBlobs ?? [])
          if (
            !verifyBinary(db, "staging", blob.key, blob.blobId, blob.sizeBytes)
          )
            throw new Error("corrupt replica blob bytes");
        const id = input.copy.id;
        return copyTransaction(input.credential, () => {
          const held = (blobId: string, size: number) =>
            verifyBinary(
              db,
              "pending",
              pendingBlobKey(id, blobId),
              blobId,
              size,
            );
          for (const blob of input.blobs ?? [])
            if (!held(blob.blobId, blob.bytes.length)) {
              const writer = binaryWriter(
                db,
                "pending",
                pendingBlobKey(id, blob.blobId),
              );
              writer.write(blob.bytes);
              writer.finish();
            }
          for (const blob of input.stagedBlobs ?? [])
            if (!held(blob.blobId, blob.sizeBytes))
              copyBinary(
                db,
                "staging",
                blob.key,
                "pending",
                pendingBlobKey(id, blob.blobId),
              );
          return copies.stage(
            {
              ...input.copy,
              envelope,
              blobs: [
                ...(input.blobs ?? []).map((b) => ({
                  blobId: b.blobId,
                  size: b.bytes.length,
                })),
                ...(input.stagedBlobs ?? []).map((b) => ({
                  blobId: b.blobId,
                  size: b.sizeBytes,
                })),
              ],
            },
            input.refetch ?? { attempts: 0, budget: REPLICA_REFETCH_BUDGET },
          );
        });
      },
      /** Append one verified finalized fact (F2). Returns true when new. */
      recordFact(input: {
        credential: unknown;
        id: string;
        scope: string;
        fragmentIndex: number;
        fact: FinalizedFact;
      }): boolean {
        return copyTransaction(input.credential, () =>
          copies.recordFact(input),
        );
      },
      decide: copies.decide,
      disposition: copies.disposition,
      list: copies.copies,
      apply(input: {
        credential: unknown;
        id: string;
        decision: CopyDecision;
      }) {
        copyTransaction(input.credential, () =>
          copies.apply(input.id, input.decision),
        );
      },
      promote(input: {
        credential: unknown;
        id: string;
        copyKey?: string;
      }): CopyPromotion {
        return copyTransaction(input.credential, () =>
          copies.promote({ id: input.id, copyKey: input.copyKey }),
        );
      },
      terminate(input: { credential: unknown; id: string; reason: string }) {
        copyTransaction(input.credential, () =>
          copies.terminate(input.id, input.reason),
        );
      },
    },
    stage(input: {
      credential: unknown;
      id: string;
      envelope: unknown;
      blobs?: { blobId: string; bytes: Uint8Array }[];
      /** Verified transport staging. Copied into durable chunked pending custody. */
      stagedBlobs?: { blobId: string; key: string; sizeBytes: number }[];
    }) {
      authorize(input.credential);
      // A batch with retained copies changes only through the copy path.
      if (hasCopies(input.id))
        throw new ReplicaCopyRefused("copy_path_required");
      if (!pendingEnabled) return;
      const envelope = replicaEnvelopeSchema.parse(input.envelope);
      if (
        envelope.owner !== owner ||
        envelope.operations.some((op) => op.owner !== owner)
      )
        throw new Error("wrong replica owner");
      for (const op of envelope.operations) validateMapping(op);
      for (const blob of input.blobs ?? [])
        if (hash(blob.bytes) !== blob.blobId)
          throw new Error("corrupt replica blob bytes");
      const encoded = canonicalJson(envelope);
      for (const blob of input.stagedBlobs ?? [])
        if (!verifyBinary(db, "staging", blob.key, blob.blobId, blob.sizeBytes))
          throw new Error("corrupt replica blob bytes");
      const blobs = canonicalJson([
        ...(input.blobs ?? []).map((b) => ({
          blobId: b.blobId,
          size: b.bytes.length,
        })),
        ...(input.stagedBlobs ?? []).map((b) => ({
          blobId: b.blobId,
          size: b.sizeBytes,
        })),
      ]);
      db.transaction(() => {
        const previous = db
          .prepare("SELECT * FROM pdpp_replica_pending_batches WHERE id=?")
          .get(input.id) as PendingBatch | undefined;
        if (previous?.state === "confirmed") {
          if (
            previous.envelope_json !== encoded ||
            previous.blobs_json !== blobs
          )
            throw new Error("confirmed replica batch is immutable");
          return;
        }
        if (
          previous &&
          (previous.envelope_json !== encoded || previous.blobs_json !== blobs)
        ) {
          db.prepare(
            "UPDATE pdpp_replica_pending_batches SET state='quarantined',reason='batch equivocation' WHERE id=?",
          ).run(input.id);
          view.removePending(input.id);
          view.flush();
          return;
        }
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_replica_pending_batches VALUES (?,?,?,'pending',NULL)",
        ).run(input.id, encoded, blobs);
        if (!previous) {
          for (const blob of input.blobs ?? [])
            db.prepare(
              "INSERT INTO pdpp_replica_pending_bytes VALUES (?,?,?)",
            ).run(input.id, blob.blobId, blob.bytes);
          for (const blob of input.stagedBlobs ?? [])
            copyBinary(
              db,
              "staging",
              blob.key,
              "pending",
              pendingBlobKey(input.id, blob.blobId),
            );
        }
        if (!previous) view.addPending(input.id, envelope.operations);
        view.flush();
      }).immediate();
    },
    /** Durable state of a staged batch, or undefined when never staged. */
    pendingState(
      id: string,
    ): "pending" | "confirmed" | "quarantined" | undefined {
      const row = db
        .prepare("SELECT state FROM pdpp_replica_pending_batches WHERE id=?")
        .get(id) as
        { state: "pending" | "confirmed" | "quarantined" } | undefined;
      return row?.state;
    },
    quarantine(input: { credential: unknown; id: string; reason: string }) {
      authorize(input.credential);
      // A copy-backed batch fails closed through the terminal transition.
      if (hasCopies(input.id))
        return api.copies.terminate({ ...input, reason: "finalized_conflict" });
      db.transaction(() => {
        db.prepare(
          "UPDATE pdpp_replica_pending_batches SET state='quarantined',reason=? WHERE id=? AND state='pending'",
        ).run(input.reason, input.id);
        view.removePending(input.id);
        view.flush();
      }).immediate();
    },
    /** Trusted host hook: caller must verify every fragment against finalized #433 evidence first. */
    promote(input: { credential: unknown; id: string }) {
      authorize(input.credential);
      // Bare promote of a copy-backed batch: refused unless exactly one copy.
      if (hasCopies(input.id)) {
        const result = api.copies.promote(input);
        if (result.kind !== "promoted")
          throw new ReplicaCopyRefused(
            result.kind === "terminal" ? result.reason : "wait_predecessor",
          );
        return;
      }
      return db
        .transaction(() => {
          const row = db
            .prepare("SELECT * FROM pdpp_replica_pending_batches WHERE id=?")
            .get(input.id) as PendingBatch | undefined;
          if (!row) throw new Error("pending replica batch not found");
          if (row.state === "quarantined")
            throw new Error("pending replica batch quarantined");
          if (row.state === "confirmed") return;
          const legacy = (
            db
              .prepare(
                "SELECT blob_id,bytes FROM pdpp_replica_pending_bytes WHERE batch_id=?",
              )
              .all(input.id) as { blob_id: string; bytes: Buffer }[]
          ).map((b) => ({ blobId: b.blob_id, bytes: b.bytes }));
          const chunked = (
            JSON.parse(row.blobs_json) as { blobId: string; size: number }[]
          ).filter(
            (b) =>
              !legacy.some((l) => l.blobId === b.blobId) &&
              binaryLength(
                db,
                "pending",
                pendingBlobKey(input.id, b.blobId),
              ) !== undefined,
          );
          const result = api.import({
            credential: input.credential,
            envelope: JSON.parse(row.envelope_json),
            blobs: legacy,
            stagedBlobs: chunked.map((b) => ({
              blobId: b.blobId,
              key: pendingBlobKey(input.id, b.blobId),
              sizeBytes: b.size,
              namespace: "pending" as const,
            })),
          });
          db.prepare(
            "UPDATE pdpp_replica_pending_batches SET state='confirmed' WHERE id=?",
          ).run(input.id);
          db.prepare(
            "DELETE FROM pdpp_replica_pending_bytes WHERE batch_id=?",
          ).run(input.id);
          for (const b of chunked)
            deleteBinary(db, "pending", pendingBlobKey(input.id, b.blobId));
          view.removePending(input.id);
          view.flush();
          return result;
        })
        .immediate();
    },
    connectionVisibility: view.connectionVisibility,
    readVisibleRecords,
    readRecords(
      input: ListRecordsOptions & { stream: string; reader?: ReplicaReader },
    ): ListVisibleRecordsPage {
      return readSnapshot(() => {
        if (
          !pendingEnabled &&
          !input.instanceIds.some((id) => view.connectionVisibility(id))
        ) {
          // A view cursor never continues on canonical pages: no mixed snapshots.
          const cursor = input.cursor && decodeCursor(input.cursor);
          if (cursor && cursor.kind === "list" && cursor.viewRevision)
            throw new CursorExpiredError();
          return store.listRecords(input.stream, input);
        }
        return view.listRecords(
          input.stream,
          input,
          input.reader ?? "grant",
          includesPending(input.reader),
        );
      });
    },
    readStore(input: { reader?: ReplicaReader } = {}): PdppReplicaReadStore & {
      connectionVisibility: typeof view.connectionVisibility;
    } {
      const reader = input.reader ?? "grant";
      const hasPreview = () => includesPending(reader);
      const needsReferenceGate = () =>
        hasPreview() || view.hasBindingConflictFacts;
      const refs = (id: string) =>
        readSnapshot(() =>
          needsReferenceGate()
            ? view.findBlobReferences(id, reader, hasPreview())
            : store.findBlobReferences(id),
        );
      const canReadBlob = (id: string) =>
        view.hasBlobReference(id, reader, hasPreview());
      return {
        connectionVisibility: view.connectionVisibility,
        getRecord: (instance: string, stream: string, key: string) =>
          readSnapshot(() =>
            hasPreview() || view.connectionVisibility(instance)
              ? view.getRecord(instance, stream, key, reader, hasPreview())
              : store.getRecord(instance, stream, key),
          ),
        listRecords: (stream: string, options: ListRecordsOptions) =>
          api.readRecords({ ...options, stream, reader }),
        listStreams: (ids: string[]) =>
          readSnapshot(() =>
            pendingEnabled || ids.some((id) => view.connectionVisibility(id))
              ? view.listStreams(ids, hasPreview(), reader)
              : store.listStreams(ids),
          ),
        // Changes sessions allocate a canonical horizon. Reserve the writer before
        // selecting policy so that the horizon and conflict fence cannot race.
        changesSince: (stream: string, options: ChangesSinceOptions) =>
          db
            .transaction(() => {
              const visible = options.instanceIds.filter((instance) => {
                const visibility = view.connectionVisibility(instance);
                return (
                  !visibility ||
                  replicaStateVisible(
                    visibility.state,
                    reader,
                    deps.visibilityPolicy,
                    "received",
                  )
                );
              });
              return bindChangesIntegrity(options, () =>
                store.changesSinceForInstances(stream, options, visible),
              );
            })
            .immediate(),
        getBlobBytes: (id: string) =>
          readSnapshot(() =>
            !needsReferenceGate()
              ? store.getBlobBytes(id)
              : canReadBlob(id)
                ? verifiedVisibleBlob(id)
                : undefined,
          ),
        getBlobMeta: (id: string) =>
          readSnapshot(() =>
            !needsReferenceGate()
              ? store.getBlobMeta(id)
              : canReadBlob(id)
                ? (store.getBlobMeta(id) ?? view.getBlobMeta(id))
                : undefined,
          ),
        findBlobReferences: refs,
        // Receipts describe canonical rows as stored: a preview or a hidden or
        // local-only connection shows other rows, so it gets none.
        listStreamCompletions: (instance: string) =>
          readSnapshot(() =>
            hasPreview() || view.connectionVisibility(instance)
              ? []
              : store.listStreamCompletions(instance),
          ),
      };
    },
    /** Called only after the transport proves a finalized immutable-slot conflict.
     * Keep evidence, but permanently retract the authority derived from its batch.
     */
    quarantineImported(input: {
      credential: unknown;
      envelope: unknown;
    }): void {
      authorize(input.credential);
      const envelope = replicaEnvelopeSchema.parse(input.envelope);
      if (
        envelope.owner !== owner ||
        envelope.operations.some((op) => op.owner !== owner)
      )
        throw new Error("wrong replica owner");
      db.transaction(() => {
        for (const op of envelope.operations) validateMapping(op);
        const records = envelope.operations.filter(
          (op): op is RecordOperation =>
            op.kind === "upsert" || op.kind === "delete",
        );
        const connections = new Set(
          envelope.operations
            .filter(
              (op) =>
                op.kind !== "upsert" &&
                op.kind !== "delete" &&
                (op.kind !== "blob-claim" ||
                  !records.some(
                    (record) =>
                      record.kind === "upsert" &&
                      record.connectionId === op.connectionId &&
                      record.generation === op.generation &&
                      record.blobs.some(
                        (blob) =>
                          canonicalJson(blob) === canonicalJson(op.blob),
                      ),
                  )),
            )
            .map((op) => op.connectionId),
        );
        for (const instance of connections) withdrawConnection(instance);
        for (const op of records) {
          quarantineKey(
            op.connectionId,
            op.generation,
            op.declaration.stream,
            op.recordKey,
          );
          if (binding(op.connectionId)?.generation === op.generation)
            write(op.connectionId, op.declaration.stream, op.recordKey, null);
        }
        // Incremental: each new quarantine fact raised its connection's
        // integrity epoch in this transaction, so saved cursors expire, and
        // reads apply the quarantine predicate. The record withdrawals above
        // marked their keys dirty; flush re-derives only those.
        view.flush();
      }).immediate();
    },
    import(input: {
      credential: unknown;
      envelope: unknown;
      blobs?: { blobId: string; bytes: Uint8Array }[];
      stagedBlobs?: {
        blobId: string;
        key: string;
        sizeBytes: number;
        namespace?: "staging" | "pending";
      }[];
    }): ReplicaMergePlan {
      authorize(input.credential);
      const envelope = replicaEnvelopeSchema.parse(input.envelope);
      if (
        envelope.owner !== owner ||
        envelope.operations.some((op) => op.owner !== owner)
      )
        throw new Error("wrong replica owner");
      return db.transaction(() => importParsed(envelope, input)).immediate();
    },
    /** Trusted host notification after declaration documents or validators change. */
    reconcileDeclarations(input: { credential: unknown }): ReplicaMergePlan {
      authorize(input.credential);
      return db
        .transaction(() => {
          const plan = reconcile();
          view.reconcileAll();
          return plan;
        })
        .immediate();
    },
    retry(input: { credential: unknown }): ReplicaMergePlan {
      authorize(input.credential);
      return db
        .transaction(() => {
          const plan = reconcile();
          view.flush();
          return plan;
        })
        .immediate();
    },
  };
  return api;
}
