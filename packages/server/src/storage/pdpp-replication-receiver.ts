import { createReplicaVisibilityView } from "./pdpp-replica-visibility-view.js";
import type { Database } from "better-sqlite3";
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
  type ListRecordsOptions,
  type ChangesSinceOptions,
  type PdppVisibleRecord,
  type ListVisibleRecordsPage,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

export const RECEIVER_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_replica_received (operation_json TEXT PRIMARY KEY, digest TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS pdpp_received_no_update BEFORE UPDATE ON pdpp_replica_received BEGIN SELECT RAISE(ABORT, 'received operations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_received_no_delete BEFORE DELETE ON pdpp_replica_received BEGIN SELECT RAISE(ABORT, 'received operations are append-only'); END;
CREATE TABLE IF NOT EXISTS pdpp_replica_quarantined_keys (instance TEXT NOT NULL, generation INTEGER NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL, PRIMARY KEY(instance,generation,stream,record_key));
CREATE TABLE IF NOT EXISTS pdpp_replica_quarantined_connections (instance TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS pdpp_replica_received_bytes (blob_id TEXT PRIMARY KEY, bytes BLOB NOT NULL);
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
  function verifiedBytes(blob: BlobDescriptor): Uint8Array | undefined {
    const row = db
      .prepare(
        "SELECT bytes FROM pdpp_replica_received_bytes WHERE blob_id = ?",
      )
      .get(blob.blobId) as { bytes: Buffer } | undefined;
    const bytes = row?.bytes ?? store.getBlobBytes(blob.blobId);
    return bytes &&
      bytes.byteLength === blob.sizeBytes &&
      hash(bytes) === blob.sha256 &&
      blob.blobId === blob.sha256
      ? bytes
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
      const existing = db
        .prepare("SELECT bytes FROM pdpp_blob_bytes WHERE blob_id = ?")
        .get(blob.blobId) as { bytes: Buffer } | undefined;
      if (
        existing &&
        (hash(existing.bytes) !== blob.sha256 ||
          existing.bytes.length !== blob.sizeBytes)
      )
        throw new Error("corrupt canonical blob bytes");
      db.prepare("INSERT OR IGNORE INTO pdpp_blob_bytes VALUES (?, ?)").run(
        blob.blobId,
        bytes,
      );
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
    const coverage = operation
      ? (db
          .prepare(
            "SELECT reset_generation FROM pdpp_additions_coverage WHERE instance = ?",
          )
          .get(instance) as { reset_generation: number | null } | undefined)
      : undefined;
    if (
      data !== null &&
      operation &&
      (!current || coverage?.reset_generation === operation.generation)
    ) {
      db.prepare(
        `INSERT OR IGNORE INTO pdpp_record_first_added
           (instance, stream, record_key, first_added_at, generation)
         SELECT ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), generation
         FROM pdpp_instance_binding
         WHERE instance = ? AND generation = ?`,
      ).run(instance, stream, key, instance, operation.generation);
    }
    db.prepare(
      `INSERT INTO pdpp_records
         (instance, stream, record_key, data, version, emitted_at, emitted_key, deleted, deleted_at, blob_id)
       VALUES (?, ?, ?, ?, ?, ?, pdpp_time_key(?), ?, ?, ?)
       ON CONFLICT(instance,stream,record_key) DO UPDATE SET
         data=excluded.data, version=excluded.version, emitted_at=excluded.emitted_at,
         emitted_key=excluded.emitted_key, deleted=excluded.deleted,
         deleted_at=excluded.deleted_at, blob_id=excluded.blob_id`,
    ).run(
      instance,
      stream,
      key,
      data,
      version,
      emittedAt,
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
    const unavailable: ReplicaOperation[] = [];
    const eligible = all.filter((op) => {
      validateMapping(op);
      if (!binding(op.connectionId)?.source_id) {
        unavailable.push(op);
        return false;
      }
      return true;
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
      const newlyBlocked =
        blocked &&
        db
          .prepare(
            "INSERT OR IGNORE INTO pdpp_replica_quarantined_connections VALUES (?)",
          )
          .run(id).changes > 0;
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
        if (reset) {
          db.prepare(
            "DELETE FROM pdpp_record_first_added WHERE instance = ?",
          ).run(id);
          db.prepare(
            `INSERT INTO pdpp_additions_coverage
               (instance, tracked_since, reset_generation)
             VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?)
             ON CONFLICT(instance) DO UPDATE SET
               tracked_since = excluded.tracked_since,
               reset_generation = excluded.reset_generation`,
          ).run(id, generation);
        }
      }
    }
    for (const record of plan.records) {
      const { connectionId, stream, recordKey, generation } = record.identity;
      const local = binding(connectionId)!;
      if (local.deleted_at || generation !== local.generation) continue;
      if (record.quarantined)
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_replica_quarantined_keys VALUES (?, ?, ?, ?)",
        ).run(connectionId, generation, stream, recordKey);
      if (isRecordQuarantined(connectionId, stream, recordKey)) {
        write(connectionId, stream, recordKey, null);
        continue;
      }
      const winner = record.current;
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
    visibilityPolicy: deps.visibilityPolicy,
    declarations: deps.declarations,
    blobsValid: previewBlobsValid,
    unquarantinedRecordSql: store.unquarantinedRecordSql,
  });
  store.setReplicaVisibilityObserver(view.flush);
  function includesPending(reader: ReplicaReader = "grant") {
    return (
      pendingEnabled &&
      replicaStateVisible("pending", reader, deps.visibilityPolicy)
    );
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
    return row?.bytes;
  }
  function rawVisibleBlob(id: string): Uint8Array | undefined {
    const row = db
      .prepare(
        "SELECT bytes FROM pdpp_blob_bytes WHERE blob_id=? UNION ALL SELECT bytes FROM pdpp_replica_received_bytes WHERE blob_id=? LIMIT 1",
      )
      .get(id, id) as { bytes: Buffer } | undefined;
    return row?.bytes ?? pendingBlob(id);
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
      const canonicalBytes = db
        .prepare("SELECT 1 FROM pdpp_blob_bytes WHERE blob_id=?")
        .get(blob.blobId);
      if (canonicalBytes && !store.getBlobBytes(blob.blobId)) return false;
      const bytes = verifiedBytes(blob) ?? pendingBlob(blob.blobId);
      return (
        bytes?.length === blob.sizeBytes &&
        hash(bytes) === blob.sha256 &&
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
  const api = {
    setPendingEnabled(enabled: boolean) {
      pendingEnabled = enabled === true;
    },
    stage(input: {
      credential: unknown;
      id: string;
      envelope: unknown;
      blobs?: { blobId: string; bytes: Uint8Array }[];
    }) {
      authorize(input.credential);
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
      const blobs = canonicalJson(
        (input.blobs ?? []).map((b) => ({
          blobId: b.blobId,
          size: b.bytes.length,
        })),
      );
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
        if (!previous)
          for (const blob of input.blobs ?? [])
            db.prepare(
              "INSERT INTO pdpp_replica_pending_bytes VALUES (?,?,?)",
            ).run(input.id, blob.blobId, blob.bytes);
        if (!previous) view.addPending(input.id, envelope.operations);
        view.flush();
      }).immediate();
    },
    quarantine(input: { credential: unknown; id: string; reason: string }) {
      authorize(input.credential);
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
      return db
        .transaction(() => {
          const row = db
            .prepare("SELECT * FROM pdpp_replica_pending_batches WHERE id=?")
            .get(input.id) as PendingBatch | undefined;
          if (!row) throw new Error("pending replica batch not found");
          if (row.state === "quarantined")
            throw new Error("pending replica batch quarantined");
          if (row.state === "confirmed") return;
          const result = api.import({
            credential: input.credential,
            envelope: JSON.parse(row.envelope_json),
            blobs: (
              db
                .prepare(
                  "SELECT blob_id,bytes FROM pdpp_replica_pending_bytes WHERE batch_id=?",
                )
                .all(input.id) as { blob_id: string; bytes: Buffer }[]
            ).map((b) => ({ blobId: b.blob_id, bytes: b.bytes })),
          });
          db.prepare(
            "UPDATE pdpp_replica_pending_batches SET state='confirmed' WHERE id=?",
          ).run(input.id);
          db.prepare(
            "DELETE FROM pdpp_replica_pending_bytes WHERE batch_id=?",
          ).run(input.id);
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
      if (
        !pendingEnabled &&
        !input.instanceIds.some((id) => view.connectionVisibility(id))
      )
        return store.listRecords(input.stream, input);
      return view.listRecords(
        input.stream,
        input,
        input.reader ?? "grant",
        includesPending(input.reader),
      );
    },
    readStore(input: { reader?: ReplicaReader } = {}) {
      const reader = input.reader ?? "grant";
      const hasPreview = () => includesPending(reader);
      const needsReferenceGate = () =>
        hasPreview() || view.hasBindingConflictFacts;
      const refs = (id: string) =>
        needsReferenceGate()
          ? view.findBlobReferences(id, reader, hasPreview())
          : store.findBlobReferences(id);
      const canReadBlob = (id: string) =>
        view.hasBlobReference(id, reader, hasPreview());
      return {
        connectionVisibility: view.connectionVisibility,
        visibleInstanceIds: (ids: string[]) =>
          ids.filter((instance) => {
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
          }),
        getRecord: (instance: string, stream: string, key: string) =>
          hasPreview() || view.connectionVisibility(instance)
            ? view.getRecord(instance, stream, key, reader, hasPreview())
            : store.getRecord(instance, stream, key),
        listRecords: (stream: string, options: ListRecordsOptions) =>
          api.readRecords({ ...options, stream, reader }),
        listStreams: (ids: string[]) =>
          pendingEnabled || ids.some((id) => view.connectionVisibility(id))
            ? view.listStreams(ids, hasPreview(), reader)
            : store.listStreams(ids),
        changesSince: (stream: string, options: ChangesSinceOptions) => {
          const visible = api.readStore({ reader }).visibleInstanceIds!(
            options.instanceIds,
          );
          return store.changesSinceForInstances(stream, options, visible);
        },
        getBlobBytes: (id: string) =>
          !needsReferenceGate()
            ? store.getBlobBytes(id)
            : canReadBlob(id)
              ? rawVisibleBlob(id)
              : undefined,
        getBlobMeta: (id: string) =>
          !needsReferenceGate()
            ? store.getBlobMeta(id)
            : canReadBlob(id)
              ? (store.getBlobMeta(id) ?? view.getBlobMeta(id))
              : undefined,
        findBlobReferences: refs,
      };
    },
    import(input: {
      credential: unknown;
      envelope: unknown;
      blobs?: { blobId: string; bytes: Uint8Array }[];
    }): ReplicaMergePlan {
      authorize(input.credential);
      const envelope = replicaEnvelopeSchema.parse(input.envelope);
      if (
        envelope.owner !== owner ||
        envelope.operations.some((op) => op.owner !== owner)
      )
        throw new Error("wrong replica owner");
      return db
        .transaction(() => {
          for (const op of envelope.operations) validateMapping(op);
          for (const blob of input.blobs ?? []) {
            if (hash(blob.bytes) !== blob.blobId)
              throw new Error("corrupt replica blob bytes");
            const previous = db
              .prepare(
                "SELECT bytes FROM pdpp_replica_received_bytes WHERE blob_id = ?",
              )
              .get(blob.blobId) as { bytes: Buffer } | undefined;
            if (
              previous &&
              (hash(previous.bytes) !== blob.blobId ||
                !Buffer.from(blob.bytes).equals(previous.bytes))
            )
              throw new Error("corrupt retained replica bytes");
            db.prepare(
              "INSERT OR IGNORE INTO pdpp_replica_received_bytes VALUES (?, ?)",
            ).run(blob.blobId, blob.bytes);
          }
          for (const op of envelope.operations) {
            db.prepare(
              "INSERT OR IGNORE INTO pdpp_replica_received VALUES (?, ?)",
            ).run(canonicalJson(op), replicaOperationDigest(op));
            db.prepare(
              "UPDATE pdpp_replica_clock SET counter = MAX(counter, ?) WHERE id = 1",
            ).run(op.revision.logical);
          }
          const plan = reconcile();
          view.flush();
          return plan;
        })
        .immediate();
    },
    retry(input: { credential: unknown }): ReplicaMergePlan {
      authorize(input.credential);
      return db
        .transaction(() => {
          const plan = reconcile();
          view.reconcileAll();
          return plan;
        })
        .immediate();
    },
  };
  return api;
}
