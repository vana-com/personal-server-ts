import { createReplicaVisibilityView } from "./pdpp-replica-visibility-view.js";
import {
  binaryLength,
  clearMalformedManifest,
  binaryWriter,
  verifyBinary,
  copyBinary,
  copyBinaryToCanonical,
  deleteBinary,
  readBinaryChunks,
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
import {
  blobReady,
  completionAvailability,
  connectionFromFacts,
  contradictsMapping,
  indexEvidence,
  recordRow,
  type ConnectionMapping,
  type ConnectionProjection,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-engine";
import { replicaOperationDigest } from "./pdpp-replication-sqlite.js";
import type { ReplicaRecordStore } from "./pdpp-replica-canonical-port.js";

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
  validateCursor,
  type VisibilitySnapshot,
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

/**
 * Invariant: removing a quarantine fact un-hides data, so it must raise the
 * connection's integrity epoch in the same transaction, exactly as adding
 * one does (fenceReplicaConnection). These triggers make that structural:
 * any DELETE of a key or connection fact fences its connection, so no
 * future removal path can forget it. pdpp-replica-invariants.test.ts (1).
 */
export const REPLICA_FACT_REMOVAL_MIGRATION = `
CREATE TRIGGER IF NOT EXISTS pdpp_quarantined_keys_removal_fence AFTER DELETE ON pdpp_replica_quarantined_keys BEGIN INSERT INTO pdpp_replica_integrity_fences VALUES (OLD.instance, 1) ON CONFLICT(instance) DO UPDATE SET fences = fences + 1; END;
CREATE TRIGGER IF NOT EXISTS pdpp_quarantined_connections_removal_fence AFTER DELETE ON pdpp_replica_quarantined_connections BEGIN INSERT INTO pdpp_replica_integrity_fences VALUES (OLD.instance, 1) ON CONFLICT(instance) DO UPDATE SET fences = fences + 1; END;
`;

type Store = Omit<ReplicaRecordStore, "unquarantinedRecordSql"> & {
  /**
   * The shared quarantine predicate. `generationSql` is the generation of the
   * aliased row's value; without it the binding's current generation applies.
   * A store that takes one argument ignores the second.
   */
  unquarantinedRecordSql(alias: string, generationSql?: string): string;
};
type Binding = {
  instance: string;
  source_id: string | null;
  method: string | null;
  generation: number;
  deleted_at: string | null;
};
type BlobDescriptor = Extract<ReplicaOperation, { kind: "blob-claim" }>["blob"];
type CompletionEvent = Extract<
  ReplicaOperation,
  { kind: "stream-complete" | "stream-invalidate" }
>;
interface StoredRow {
  data: string | null;
  version: number;
  emitted_at: string;
  deleted: number;
  deleted_at: string | null;
  blob_id: string | null;
}

/**
 * Internal port, absent from connector routes. Bootstrap builds it only through
 * `createNodeReplication`, behind `replication.enabled`. The host
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
  /** Blob ids whose bytes are verified against a descriptor, for `blobReady`. */
  function verifiedBlobs(blobs: readonly BlobDescriptor[]): Set<string> {
    return new Set(
      blobs.flatMap((blob) => (verifiedBytes(blob) ? [blob.blobId] : [])),
    );
  }
  /**
   * Persist the bytes and claims of an upsert `blobReady` accepted: metadata,
   * the canonical copy, and the connection's claim.
   */
  function persistBlobs(
    operation: Extract<ReplicaOperation, { kind: "upsert" }>,
  ) {
    for (const blob of operation.blobs) {
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
      } else copyBinaryToCanonical(db, verifiedBytes(blob)!, blob.blobId);
      db.prepare(
        "INSERT INTO pdpp_blob_claims VALUES (?, ?, ?) ON CONFLICT(blob_id, instance) DO UPDATE SET generation = excluded.generation",
      ).run(blob.blobId, operation.connectionId, operation.generation);
    }
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
    // Hiding a row that is already a tombstone keeps it. Rewriting it would
    // bump the version and replace the delete's deletedAt with emittedAt. A
    // later import for another connection re-plans this one (oracle D2).
    if (!operation && current?.data === null) return;
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
      "INSERT INTO pdpp_records (instance,stream,record_key,data,version,emitted_at,emitted_key,deleted,deleted_at,blob_id) VALUES (?, ?, ?, ?, ?, ?, pdpp_time_key(?), ?, ?, ?) ON CONFLICT(instance,stream,record_key) DO UPDATE SET data=excluded.data, version=excluded.version, emitted_at=excluded.emitted_at, emitted_key=excluded.emitted_key, deleted=excluded.deleted, deleted_at=excluded.deleted_at, blob_id=excluded.blob_id",
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
      "INSERT INTO pdpp_record_changes (instance,stream,record_key,version,data,emitted_at,emitted_key,deleted,deleted_at,written_at) VALUES (?, ?, ?, ?, ?, ?, pdpp_time_key(?), ?, ?, ?)",
    ).run(
      instance,
      stream,
      key,
      version,
      data,
      emittedAt,
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
  /** The host mapping of a connection, or undefined while unprovisioned. */
  function mappingOf(id: string): ConnectionMapping | undefined {
    const local = binding(id);
    return local?.source_id
      ? { sourceId: local.source_id, methodId: local.method ?? "" }
      : undefined;
  }
  /**
   * Adapter around the core engine. The engine decides each provisioned
   * connection's eligibility, which rows show and which completions are
   * available; this function persists those decisions in the canonical
   * tables and keeps Node's lifecycle fences.
   *
   * Node withdraws a terminal connection through its quarantine fact, which
   * readers apply, and not by deciding its rows: rows keep following the
   * evidence. So eligibility is judged here without the terminal fact, and
   * completions with it.
   */
  function reconcile(): ReplicaMergePlan {
    const all = retained();
    const context = { owner, declarations: deps.declarations() };
    const index = indexEvidence(all);
    const statuses = new Map<string, ConnectionProjection>();
    for (const id of new Set(all.map((op) => op.connectionId))) {
      const ops = all.filter((op) => op.connectionId === id);
      const mapping = mappingOf(id);
      // An unprovisioned connection whose evidence names two bindings
      // contradicts any mapping the host can provision later.
      const facts = index.connectionFacts(id, {
        mapping: mapping ?? {
          sourceId: ops[0].sourceId,
          methodId: ops[0].methodId,
        },
        terminal: false,
        appliedGeneration: binding(id)?.generation ?? 1,
      });
      // A retained disagreement is a durable, connection-scoped fact, never
      // a throw that would block every import and retry (#428 F2). It holds
      // even when terminal quarantine or equivocation outranks it (#426).
      if (contradictsMapping(facts))
        recordBindingConflict(id, ops, facts.mapping, !mapping);
      if (mapping) statuses.set(id, connectionFromFacts(context, facts));
    }
    const unavailable: ReplicaOperation[] = [];
    const eligible = all.filter((op) => {
      const connection = statuses.get(op.connectionId);
      if (!connection) unavailable.push(op);
      return connection !== undefined && !bindingConflict(connection);
    });
    // Variants that share a revision with eligible evidence enter the plan,
    // so the planner never materializes one side of an equivocation. Their
    // connections are unprovisioned or conflicted, so it shows none of them.
    const revisionKey = (op: ReplicaOperation) =>
      canonicalJson([op.revision.writerId, op.revision.operationId]);
    const included = new Set(eligible);
    const eligibleRevisions = new Set(eligible.map(revisionKey));
    const colliding = all.filter(
      (op) => !included.has(op) && eligibleRevisions.has(revisionKey(op)),
    );
    const plan = planReplicaMerge(context, [...eligible, ...colliding]);
    if (unavailable.length)
      plan.pending.push({
        reason: "missing_local_connection",
        operations: unavailable,
      });
    // Lifecycle evidence gates canonical state, but never creates a connection or
    // changes its acquisition method. Only the local authority provisions that.
    for (const [id, connection] of statuses) {
      if (bindingConflict(connection)) continue;
      const local = binding(id)!;
      const deleted = connection.status === "deleted";
      const blocked = connection.status === "withdrawn";
      const reset =
        connection.status === "active" &&
        connection.generation > local.generation;
      const newlyBlocked = blocked && quarantineConnection(id);
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
          reset ? connection.generation : local.generation,
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
      // `write` turns a withdrawal into a tombstone only for a stored row, so
      // the engine's "no prior row" case is the same as a withdrawal here.
      const row = recordRow(undefined, record, (op) =>
        blobReady(op, eligible, verifiedBlobs(op.blobs)),
      );
      const shown = row && row.state !== "withdrawn" ? row.winner : null;
      if (record.winner?.kind === "upsert" && !shown)
        plan.pending.push({
          reason: "missing_or_invalid_blob",
          operations: [record.winner],
        });
      if (shown?.kind === "upsert") persistBlobs(shown);
      write(connectionId, stream, recordKey, shown);
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
    reconcileCompletions(all, plan, index, context);
    return plan;
  }
  function bindingConflict(
    connection: ConnectionProjection,
  ): connection is Extract<ConnectionProjection, { status: "withdrawn" }> & {
    reason: "local_mapping_conflict" | "source_binding_conflict";
  } {
    return (
      connection.status === "withdrawn" &&
      (connection.reason === "local_mapping_conflict" ||
        connection.reason === "source_binding_conflict")
    );
  }
  /** Persist the engine's binding conflict with the evidence that shows it. */
  function recordBindingConflict(
    id: string,
    ops: readonly ReplicaOperation[],
    mapping: ConnectionMapping,
    unprovisioned: boolean,
  ) {
    const disagreeing = ops.find(
      (op) =>
        op.sourceId !== mapping.sourceId || op.methodId !== mapping.methodId,
    )!;
    store.markReplicaBindingConflict(
      unprovisioned
        ? {
            connectionId: id,
            reason: "source_binding_conflict",
            evidence: [
              ...new Set(ops.map((op) => `${op.sourceId} ${op.methodId}`)),
            ]
              .sort()
              .slice(0, 8),
          }
        : {
            connectionId: id,
            reason: "local_mapping_conflict",
            evidence: {
              sourceId: disagreeing.sourceId,
              methodId: disagreeing.methodId,
              revision: disagreeing.revision,
            },
          },
    );
  }
  /**
   * Persist the engine's completion availability for every provisioned
   * stream with completion evidence at its connection's generation. The
   * terminal quarantine fact applies here, unlike to rows.
   */
  function reconcileCompletions(
    all: readonly ReplicaOperation[],
    plan: ReplicaMergePlan,
    index: ReturnType<typeof indexEvidence>,
    context: MergeContext,
  ) {
    const issues = [...plan.pending, ...plan.conflicts, ...plan.rejected];
    const variantDigests = index.variantDigests(
      (id) => mappingOf(id) !== undefined,
    );
    const trusted = (op: CompletionEvent) =>
      context.declarations.some(
        (d) =>
          d.sourceId === op.sourceId &&
          canonicalJson(d.binding) === canonicalJson(op.declaration),
      );
    const visible = new Map<string, ConnectionProjection>();
    const grouped = new Map<string, CompletionEvent[]>();
    for (const op of all) {
      if (op.kind !== "stream-complete" && op.kind !== "stream-invalidate")
        continue;
      const mapping = mappingOf(op.connectionId);
      if (!mapping) continue;
      if (!trusted(op))
        plan.pending.push({ reason: "missing_declaration", operations: [op] });
      if (!visible.has(op.connectionId))
        visible.set(
          op.connectionId,
          connectionFromFacts(
            context,
            index.connectionFacts(op.connectionId, {
              mapping,
              terminal: !!db
                .prepare(
                  "SELECT 1 FROM pdpp_replica_quarantined_connections WHERE instance = ?",
                )
                .get(op.connectionId),
              appliedGeneration: binding(op.connectionId)!.generation,
            }),
          ),
        );
      if (visible.get(op.connectionId)!.generation !== op.generation) continue;
      const key = canonicalJson([op.connectionId, op.declaration.stream]);
      grouped.set(key, [...(grouped.get(key) ?? []), op]);
    }
    for (const events of grouped.values()) {
      const first = events[0];
      const { connectionId, generation } = first;
      const stream = first.declaration.stream;
      const connection = visible.get(connectionId)!;
      const available = completionAvailability({
        connection,
        connectionId,
        events,
        declarations: context.declarations,
        quarantinedKey: !!db
          .prepare(
            "SELECT 1 FROM pdpp_replica_quarantined_keys WHERE instance = ? AND generation = ? AND stream = ? LIMIT 1",
          )
          .get(connectionId, generation, stream),
        unresolved: issues.some(
          (issue) =>
            issue.reason !== "missing_declaration" &&
            issue.operations.some(
              (op) =>
                op.connectionId === connectionId &&
                (!("declaration" in op) || op.declaration.stream === stream),
            ),
        ),
        variantDigests,
        liveRows: db
          .prepare(
            "SELECT record_key AS recordKey, data AS dataJson FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
          )
          .all(connectionId, stream) as {
          recordKey: string;
          dataJson: string;
        }[],
      });
      if (available) {
        const completion = available.operation;
        const seq = (
          db.prepare("SELECT value FROM pdpp_write_clock").get() as {
            value: number;
          }
        ).value;
        const native = completion.proof.kind === "native";
        db.prepare(
          "INSERT INTO pdpp_stream_completion (instance,stream,method,generation,source_collected_at,write_seq,live_count,snapshot_sha256,collection_time_basis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(instance,stream) DO UPDATE SET method=excluded.method,generation=excluded.generation,source_collected_at=excluded.source_collected_at,write_seq=excluded.write_seq,live_count=excluded.live_count,snapshot_sha256=excluded.snapshot_sha256,collection_time_basis=excluded.collection_time_basis WHERE method IS NOT excluded.method OR generation IS NOT excluded.generation OR source_collected_at IS NOT excluded.source_collected_at OR live_count IS NOT excluded.live_count OR snapshot_sha256 IS NOT excluded.snapshot_sha256 OR collection_time_basis IS NOT excluded.collection_time_basis",
        ).run(
          connectionId,
          stream,
          first.methodId,
          generation,
          completion.sourceCollectedAt,
          seq,
          completion.liveCount,
          native ? completion.snapshotSha256.slice(7) : null,
          native ? "host_run_finished" : null,
        );
        continue;
      }
      db.prepare(
        "DELETE FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
      ).run(connectionId, stream);
      // Diagnostics only: the engine already decided.
      if (new Set(events.map((op) => canonicalJson(op.declaration))).size > 1)
        plan.conflicts.push({
          reason: "incompatible_completion_declaration",
          operations: events,
        });
      else {
        const completion = selectStreamCompletion(events);
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
    integrityEpoch: store.replicaIntegrityEpoch,
  });
  store.setReplicaVisibilityObserver(view.flush);
  store.setReplicaWriteBoundary(view.exclusive, view.snapshot);
  // A local write journals under the retained declaration. When retained
  // evidence for its key already names another declaration, or the stream is
  // append-only and the content differs, the write completes a conflict. The
  // merge must quarantine the key now, not at the next import. This is only a
  // trigger: `reconcile` alone decides, so the check may over-approximate.
  store.setReplicaLocalWriteObserver((instance, stream, recordKey) => {
    const retainedForKey = (
      db
        .prepare(
          "SELECT operation_json FROM pdpp_replica_view_operations WHERE instance=? AND stream=? AND record_key=? AND confirmed=1 AND kind IN ('upsert','delete')",
        )
        .all(instance, stream, recordKey) as { operation_json: string }[]
    ).map((row) => JSON.parse(row.operation_json) as RecordOperation);
    const declarations = new Set(
      retainedForKey.map((op) => canonicalJson(op.declaration)),
    );
    const contents = new Set(
      retainedForKey.map((op) =>
        canonicalJson(
          op.kind === "upsert" ? { data: op.data, blobs: op.blobs } : null,
        ),
      ),
    );
    if (
      declarations.size > 1 ||
      (contents.size > 1 &&
        retainedForKey.some((op) => op.declaration.semantics === "append_only"))
    )
      reconcile();
  });
  function includesPending(reader: ReplicaReader = "grant") {
    return (
      pendingEnabled &&
      replicaStateVisible("pending", reader, deps.visibilityPolicy)
    );
  }
  type IntegrityBoundChanges = ChangesSinceCursorPayload & {
    integrity?: Record<string, number>;
    visibilityEpoch?: string;
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
    stream: string,
    reader: ReplicaReader,
    options: ChangesSinceOptions,
    read: () => ChangesSincePage,
  ): ChangesSincePage {
    const epochOf = store.replicaIntegrityEpoch;
    if (!epochOf) return read();
    const integrityValue = Object.fromEntries(
      [...new Set(options.instanceIds)].sort().map((id) => [id, epochOf(id)]),
    );
    const integrity = JSON.stringify(integrityValue);
    const visibilityEpoch = store.replicaVisibilityEpoch(
      [...new Set(options.instanceIds)].sort(),
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
        (JSON.stringify(payload.integrity ?? null) !== integrity ||
          payload.visibilityEpoch !== visibilityEpoch)
      )
        throw new CursorExpiredError();
    }
    const bind = (token: string | undefined) => {
      if (!token) return token;
      const payload = decodeCursor(token) as IntegrityBoundChanges;
      payload.integrity = JSON.parse(integrity) as Record<string, number>;
      payload.visibilityEpoch = visibilityEpoch;
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
  /** One stored copy of a blob's bytes: a legacy whole row or #439 chunks. */
  type ByteCopy = { size: number; chunks: () => Iterable<Uint8Array> };
  /**
   * A stored copy, "absent", or "invalid": a published manifest whose size is
   * not a safe non-negative integer. The manifest is checked on its own,
   * because binaryLength reports a legacy row first and would mask it; a
   * legacy row's size is length(bytes) and is always valid.
   */
  function namespaceCopy(
    namespace: BinaryNamespace,
    id: string,
  ): ByteCopy | "absent" | "invalid" {
    const manifest = db
      .prepare(
        "SELECT size_bytes AS size FROM pdpp_binary_manifests WHERE namespace=? AND blob_id=?",
      )
      .get(namespace, id) as { size: unknown } | undefined;
    if (
      manifest &&
      !(
        typeof manifest.size === "number" &&
        Number.isSafeInteger(manifest.size) &&
        manifest.size >= 0
      )
    )
      return "invalid";
    const size = binaryLength(db, namespace, id);
    return size === undefined
      ? "absent"
      : { size, chunks: () => readBinaryChunks(db, namespace, id) };
  }
  /** Custody of batches still pending: legacy rows, then chunks, by batch. */
  function* pendingCopies(blobId: string): Generator<ByteCopy> {
    for (const row of db
      .prepare(
        "SELECT b.batch_id,length(b.bytes) AS size FROM pdpp_replica_pending_bytes b JOIN pdpp_replica_pending_batches p ON p.id=b.batch_id WHERE b.blob_id=? AND p.state='pending' ORDER BY b.batch_id",
      )
      .all(blobId) as { batch_id: string; size: number }[])
      yield {
        size: row.size,
        *chunks() {
          yield (
            db
              .prepare(
                "SELECT bytes FROM pdpp_replica_pending_bytes WHERE batch_id=? AND blob_id=?",
              )
              .get(row.batch_id, blobId) as { bytes: Buffer }
          ).bytes;
        },
      };
    for (const { id } of db
      .prepare(
        "SELECT id FROM pdpp_replica_pending_batches WHERE state='pending' ORDER BY id",
      )
      .all() as { id: string }[]) {
      const copy = namespaceCopy("pending", pendingBlobKey(id, blobId));
      if (typeof copy === "object") yield copy;
    }
  }
  /** Hashes a copy chunk by chunk; the whole value is never held. */
  function copyVerifies(copy: ByteCopy, digest: string, size: number) {
    if (copy.size !== size) return false;
    const sha = createHash("sha256");
    let length = 0;
    try {
      for (const bytes of copy.chunks()) {
        length += bytes.length;
        if (length > size) return false;
        sha.update(bytes);
      }
    } catch {
      return false;
    }
    return length === size && `sha256:${sha.digest("hex")}` === digest;
  }
  /**
   * The one verified copy a blob is served from, or undefined. It accepts what
   * import and promotion accept: every retained copy (canonical, received)
   * must verify, and the first of them serves. Without one, the first pending
   * custody copy that verifies serves. Legacy rows and chunks follow one rule.
   */
  function verifiedCopy(
    blobId: string,
    digest: string,
    size: number,
  ): ByteCopy | undefined {
    if (blobId !== digest) return undefined;
    const retained = (["canonical", "received"] as const)
      .map((namespace) => namespaceCopy(namespace, blobId))
      .filter((copy) => copy !== "absent");
    if (retained.length)
      return retained.every(
        (copy) => copy !== "invalid" && copyVerifies(copy, digest, size),
      )
        ? (retained[0] as ByteCopy)
        : undefined;
    for (const copy of pendingCopies(blobId))
      if (copyVerifies(copy, digest, size)) return copy;
    return undefined;
  }
  /**
   * Whole value for the byte route. Verification streams first, so a forged
   * size or digest allocates nothing; callers read in one snapshot, so the
   * assembled bytes are the verified ones.
   */
  function verifiedVisibleBlob(id: string): Uint8Array | undefined {
    const meta = store.getBlobMeta(id) ?? view.getBlobMeta(id);
    const copy =
      meta && verifiedCopy(id, `sha256:${meta.sha256}`, meta.sizeBytes);
    if (!copy) return undefined;
    const bytes = new Uint8Array(copy.size);
    let offset = 0;
    for (const chunk of copy.chunks()) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  }
  function readSnapshot<T>(read: () => T): T {
    return view.snapshot(read);
  }
  function readView(
    reader: ReplicaReader,
    cursor?: string,
  ): VisibilitySnapshot {
    return readSnapshot(() => {
      const payload = cursor ? decodeCursor(cursor) : undefined;
      const instanceIds = payload
        ? payload.kind === "list"
          ? (payload.instanceIds ?? [])
          : Object.keys(payload.integrity ?? {})
        : undefined;
      const snapshot = {
        visibilityEpoch: payload
          ? payload.kind === "list" && payload.viewRevision
            ? view.cursorVisibilityEpoch(
                payload.stream ?? "",
                instanceIds ?? [],
                reader,
                includesPending(reader),
              )
            : store.replicaVisibilityEpoch(instanceIds)
          : view.visibilityEpoch(),
        reader,
      };
      if (cursor && validateCursor(cursor, snapshot).kind === "expired")
        throw new CursorExpiredError();
      return snapshot;
    });
  }
  /**
   * The preview's blob readiness: the engine's `blobReady`, with bytes any
   * retained or pending custody copy verifies, and stored metadata that does
   * not contradict the descriptor.
   */
  function previewBlobsValid(
    op: Extract<ReplicaOperation, { kind: "upsert" }>,
    operations: ReplicaOperation[],
  ): boolean {
    const verified = new Set(
      op.blobs.flatMap((blob) =>
        verifiedCopy(blob.blobId, blob.sha256, blob.sizeBytes)
          ? [blob.blobId]
          : [],
      ),
    );
    return (
      blobReady(op, operations, verified) &&
      op.blobs.every((blob) => {
        const meta = store.getBlobMeta(blob.blobId);
        return (
          !meta ||
          (meta.sha256 === blob.sha256.slice(7) &&
            meta.mimeType === blob.mimeType &&
            meta.sizeBytes === blob.sizeBytes)
        );
      })
    );
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
      clearMalformedManifest(db, "received", blob.blobId);
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
      clearMalformedManifest(db, "received", blob.blobId);
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
    // Contract A: withdrawal through the one eligibility predicate only.
    // No canonical tombstones: they would destroy the rows a lifted
    // quarantine, or a conflicted owner's local projection, still needs.
    quarantineConnection(instance) {
      quarantineConnection(instance);
    },
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
    return view.exclusive(() => {
      const result = effect();
      view.flush();
      return result;
    });
  }
  const api = {
    setPendingEnabled(enabled: boolean) {
      pendingEnabled = enabled === true;
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
      view.exclusive(() => {
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
      });
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
      view.exclusive(() => {
        db.prepare(
          "UPDATE pdpp_replica_pending_batches SET state='quarantined',reason=? WHERE id=? AND state='pending'",
        ).run(input.reason, input.id);
        view.removePending(input.id);
        view.flush();
      });
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
      return view.exclusive(() => {
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
            binaryLength(db, "pending", pendingBlobKey(input.id, b.blobId)) !==
              undefined,
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
      });
    },
    connectionVisibility: view.connectionVisibility,
    readVisibleRecords,
    readView,
    readRecords(
      input: ListRecordsOptions & { stream: string; reader?: ReplicaReader },
    ): ListVisibleRecordsPage {
      return readSnapshot(() => {
        if (input.cursor) readView(input.reader ?? "grant", input.cursor);
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
      withReadSnapshot: typeof readSnapshot;
    } {
      const reader = input.reader ?? "grant";
      const hasPreview = () => includesPending(reader);
      const needsReferenceGate = () =>
        hasPreview() || view.hasBindingConflictFacts;
      const refs = (id: string) =>
        readSnapshot(() => {
          // The enclosing snapshot carries point reads across projection commits.
          return needsReferenceGate()
            ? view.findBlobReferences(id, reader, hasPreview())
            : store.findBlobReferences(id);
        });
      const canReadBlob = (id: string) =>
        view.hasBlobReference(id, reader, hasPreview());
      return {
        connectionVisibility: view.connectionVisibility,
        withReadSnapshot: readSnapshot,
        getRecord: (instance: string, stream: string, key: string) =>
          readSnapshot(() => {
            // The enclosing snapshot carries point reads atomically.
            return hasPreview() || view.connectionVisibility(instance)
              ? view.getRecord(instance, stream, key, reader, hasPreview())
              : store.getRecord(instance, stream, key);
          }),
        listRecords: (stream: string, options: ListRecordsOptions) =>
          api.readRecords({ ...options, stream, reader }),
        listStreams: (ids: string[]) =>
          readSnapshot(() => {
            return pendingEnabled ||
              ids.some((id) => view.connectionVisibility(id))
              ? view.listStreams(ids, hasPreview(), reader)
              : store.listStreams(ids);
          }),
        // Changes sessions allocate a canonical horizon. Reserve the writer before
        // selecting policy so that the horizon and conflict fence cannot race.
        changesSince: (stream: string, options: ChangesSinceOptions) =>
          view.exclusive(() => {
            readView(reader, options.cursor ?? options.changesSince);
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
            return bindChangesIntegrity(stream, reader, options, () =>
              store.changesSinceForInstances(stream, options, visible),
            );
          }),
        getBlobBytes: (id: string) =>
          readSnapshot(() => {
            // The enclosing snapshot carries blob-byte reads atomically.
            return !needsReferenceGate()
              ? store.getBlobBytes(id)
              : canReadBlob(id)
                ? verifiedVisibleBlob(id)
                : undefined;
          }),
        getBlobMeta: (id: string) =>
          readSnapshot(() => {
            // The enclosing snapshot carries blob-metadata reads atomically.
            return !needsReferenceGate()
              ? store.getBlobMeta(id)
              : canReadBlob(id)
                ? (store.getBlobMeta(id) ?? view.getBlobMeta(id))
                : undefined;
          }),
        findBlobReferences: refs,
        // Receipts describe canonical rows as stored: a preview or a hidden or
        // local-only connection shows other rows, so it gets none.
        listStreamCompletions: (instance: string) =>
          readSnapshot(() => {
            // The enclosing snapshot carries completion reads atomically.
            return hasPreview() || view.connectionVisibility(instance)
              ? []
              : store.listStreamCompletions(instance);
          }),
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
      view.exclusive(() => {
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
      });
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
      return view.exclusive(() => importParsed(envelope, input));
    },
    /** Trusted host notification after declaration documents or validators change. */
    reconcileDeclarations(input: { credential: unknown }): ReplicaMergePlan {
      authorize(input.credential);
      return view.exclusive(() => {
        const plan = reconcile();
        view.reconcileAll();
        return plan;
      });
    },
    /**
     * Runs `run` in one write transaction whose derived state is current.
     * Hosts that combine receiver calls with their own writes enter here, so
     * the nested receiver calls can trust the transaction's view.
     */
    atomically<T>(run: () => T): T {
      return view.exclusive(run);
    },
    retry(input: { credential: unknown }): ReplicaMergePlan {
      authorize(input.credential);
      return view.exclusive(() => {
        const plan = reconcile();
        view.flush();
        return plan;
      });
    },
  };
  return api;
}
