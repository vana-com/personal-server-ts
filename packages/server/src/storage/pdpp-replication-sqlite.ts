import {
  BINARY_CHUNKS_MIGRATION,
  binaryLength,
  readBinaryChunks,
  verifyBinary,
  copyBinary,
  deleteBinary,
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
import type { ReplicaRevision } from "@opendatalabs/personal-server-ts-core/replication/revision";
import { planReplicaRebinding } from "@opendatalabs/personal-server-ts-core/replication/rebinding";
import {
  replicaSchemaDigest,
  type ReplicaStreamSchema,
} from "@opendatalabs/personal-server-ts-core/replication/host-config";
import {
  computeRecordKeyFromData,
  type StreamSemantics,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { liveSnapshotDigest } from "./pdpp-stream-completion.js";

/** Inert until beginBaseline commits; only `createNodeReplication` begins it. */
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
/**
 * Its own migration: a database already past REPLICATION_MIGRATION must still
 * get the index that captureBlob's existence lookup relies on.
 */
export const REPLICA_BLOB_CLAIM_INDEX_MIGRATION = `
CREATE INDEX IF NOT EXISTS pdpp_replica_blob_claim_idx ON pdpp_replica_operations (json_extract(operation_json, '$.connectionId'), json_extract(operation_json, '$.generation'), json_extract(operation_json, '$.blob.blobId')) WHERE json_extract(operation_json, '$.kind') = 'blob-claim';
`;
/**
 * Binding generations (host contract §4.5). Generation 1 is the first
 * baseline's binding set; each rebinding adds the next. The history keeps
 * every binding any generation retained, with the stream schema its
 * operations validate against: SQL NULL when unknown (a database baselined
 * before this table existed, until a host supplies it), the JSON text `null`
 * when the stream declares none.
 */
export const REPLICA_BINDING_HISTORY_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_replica_binding_generations (generation INTEGER PRIMARY KEY CHECK (generation > 0), config_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_replica_declaration_history (source_id TEXT NOT NULL, binding_json TEXT NOT NULL, schema_json TEXT, first_generation INTEGER NOT NULL, PRIMARY KEY (source_id, binding_json));
INSERT OR IGNORE INTO pdpp_replica_binding_generations SELECT 1, config_json FROM pdpp_replica_settings WHERE id = 1;
INSERT OR IGNORE INTO pdpp_replica_declaration_history SELECT json_extract(d.value, '$.sourceId'), json_extract(d.value, '$.binding'), NULL, 1 FROM pdpp_replica_settings s, json_each(s.config_json, '$.declarations') d WHERE s.id = 1;
`;
export interface BaselineConfiguration {
  owner: string;
  /**
   * Trusted retained bindings, not supplied by connector ingest. Missing
   * entries fail closed. `schema` is the stream schema the binding's
   * `schemaDigest` names; the history keeps it so peers' operations under
   * this binding stay valid after a later rebinding.
   */
  declarations: {
    sourceId: string;
    binding: DeclarationBinding;
    schema?: ReplicaStreamSchema;
  }[];
}
/** One binding a generation of this database retained. */
export interface ReplicaDeclarationHistoryEntry {
  sourceId: string;
  binding: DeclarationBinding;
  /** Absent when this database never received it (see the migration). */
  schema?: ReplicaStreamSchema;
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
  /**
   * The first call baselines. A later call with another binding set rebinds
   * (`planReplicaRebinding`): a new binding generation, no operations. A
   * changed owner, or a changed shape of a retained stream, is refused.
   */
  beginBaseline(config: BaselineConfiguration): { watermark: number };
  /** Every binding any generation retained, oldest generation first. */
  declarationHistory(): ReplicaDeclarationHistoryEntry[];
  /** The current binding generation; 0 before the first baseline. */
  bindingGeneration(): number;
  readBaselinePage(options: ReplicaPageOptions): ReplicaPage;
  readTailPage(options: ReplicaPageOptions): ReplicaPage;
  getBaselineCheckpoint(): number;
  /**
   * A new writer identity re-captures the current state under its own writer
   * as a new baseline (see `rebaseline` below). `explaining` are the
   * operations the merge chose for that state (`explainState` on the
   * receiver). Undefined before a baseline began.
   */
  rebaseline(
    explaining: readonly ReplicaOperation[],
  ): { after: number } | undefined;
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

/** Records and completions a rebaseline re-issues in their retained order. */
function reissueKey(
  op: WithoutRevision<ReplicaOperation> | ReplicaOperation,
): string | undefined {
  if (op.kind === "upsert" || op.kind === "delete")
    return canonicalJson([
      "record",
      op.connectionId,
      op.generation,
      op.declaration.stream,
      op.recordKey,
    ]);
  if (op.kind === "stream-complete")
    return canonicalJson([
      "complete",
      op.connectionId,
      op.generation,
      op.declaration.stream,
    ]);
  return undefined;
}

/** What a record or completion operation leaves in the canonical state. */
function effect(op: WithoutRevision<ReplicaOperation>): string {
  if (op.kind === "upsert")
    return `upsert:${createHash("sha256").update(canonicalJson(op.data)).digest("hex")}`;
  if (op.kind === "stream-complete") return `complete:${op.snapshotSha256}`;
  return op.kind;
}

/** Owns original revisions, pinned values/bytes and exporter progress on the canonical DB. */
export function createReplicationJournal(
  db: Database,
  /** Read per operation, inside its canonical transaction. */
  writerId: () => string,
  /** Called after each own operation is appended, inside its transaction. */
  appended?: () => void,
) {
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
  /**
   * The binding a capture writes under: the current one for the stream. A
   * rebaseline also captures streams a rebinding retired, whose rows and
   * tombstones a new writer must still carry: their latest retained binding.
   * The re-issued operation then keeps the binding of the operation whose
   * effect it copies (`reissued`).
   */
  function declaration(instance: string, stream: string): DeclarationBinding {
    const identity = base(instance);
    const matches = (e: { sourceId: string; binding: DeclarationBinding }) =>
      e.sourceId === identity.sourceId && e.binding.stream === stream;
    const found =
      config()!.declarations.find(matches) ??
      (reissue ? declarationHistory().filter(matches).at(-1) : undefined);
    if (!found) throw new Error(`missing retained declaration: ${stream}`);
    return found.binding;
  }
  /**
   * While a rebaseline runs: the operation that explains each record and
   * completion (`reissueKey`), the one the merge chose.
   */
  let reissue:
    | Map<string, Extract<ReplicaOperation, { declaration: unknown }>>
    | undefined;
  /**
   * A re-issued operation takes the order of the operation that explains its
   * state, when it has the same effect: the counter, and that operation (or
   * its own origin) as origin. It also keeps that operation's declaration, so
   * after a rebinding it validates exactly where the original did. With
   * none, the state is a new write and takes a new counter; a rebaseline
   * skips a tombstone with none (`captureRecord`).
   */
  function reissued(value: WithoutRevision<ReplicaOperation>):
    | {
        revision: Pick<ReplicaRevision, "counter" | "origin">;
        declaration: DeclarationBinding;
      }
    | undefined {
    const key = reissueKey(value);
    const found = key === undefined ? undefined : reissue?.get(key);
    if (!found || effect(found) !== effect(value)) return undefined;
    const { counter, writerId, operationId, origin } = found.revision;
    return {
      revision: { counter, origin: origin ?? { writerId, operationId } },
      declaration: found.declaration,
    };
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
    const copy = reissued(value);
    const operation = replicaOperationSchema.parse({
      ...value,
      ...(copy && { declaration: copy.declaration }),
      revision: {
        counter,
        writerId: writerId(),
        operationId: randomUUID(),
        ...copy?.revision,
      },
    });
    db.prepare("UPDATE pdpp_replica_clock SET counter = ? WHERE id = 1").run(
      counter,
    );
    db.prepare("INSERT INTO pdpp_replica_operations VALUES (?, ?, ?)").run(
      counter,
      canonicalJson(operation),
      replicaOperationDigest(operation),
    );
    appended?.();
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
  const chunkedCanonical = (blobId: string) =>
    db
      .prepare(
        "SELECT 1 FROM pdpp_binary_manifests WHERE namespace='canonical' AND blob_id=?",
      )
      .get(blobId) !== undefined;
  /** Where a pin's bytes are: its own copy, or the canonical chunks it references. */
  function pinnedNamespace(blobId: string): "pinned" | "canonical" {
    return binaryLength(db, "pinned", blobId) === undefined &&
      db
        .prepare("SELECT 1 FROM pdpp_replica_blob_pins WHERE blob_id=?")
        .get(blobId) !== undefined &&
      chunkedCanonical(blobId)
      ? "canonical"
      : "pinned";
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
    // A large canonical blob is chunks only; the pin references them, and
    // they become the pinned copy if canonical storage drops the blob
    // (`pinReferenceKeepsBytes`). A pinned copy of such a blob, left when
    // canonical storage dropped it before, becomes a reference again. Main's
    // whole row has no such hook, so a small blob keeps its own pinned copy.
    if (chunkedCanonical(blobId)) {
      db.prepare("INSERT OR IGNORE INTO pdpp_replica_blob_pins VALUES (?)").run(
        blobId,
      );
      deleteBinary(db, "pinned", blobId);
    } else if (binaryLength(db, "pinned", blobId) === undefined)
      copyBinary(db, "canonical", blobId, "pinned");
    else if (!verifyBinary(db, "pinned", blobId, blob.sha256, blob.sizeBytes))
      throw new Error("corrupt pinned replica bytes");
    // Indexed by pdpp_replica_blob_claim_idx; the predicate must match it.
    const previous = db
      .prepare(
        "SELECT 1 FROM pdpp_replica_operations WHERE json_extract(operation_json, '$.kind') = 'blob-claim' AND json_extract(operation_json, '$.connectionId') = ? AND json_extract(operation_json, '$.generation') = ? AND json_extract(operation_json, '$.blob.blobId') = ? AND json_extract(operation_json, '$.revision.writerId') = ? LIMIT 1",
      )
      .get(instance, identity.generation, blobId, writerId());
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
      const tombstone = {
        ...identity,
        kind: "delete" as const,
        emittedAt: row.emitted_at,
        deletedAt: row.deleted_at!,
      };
      // A rebaseline copies a tombstone only from the delete the merge chose.
      // Any other tombstone hides a row locally (a withdrawal, a key
      // quarantine, a declaration wait, a reset): no one deleted it, and
      // publishing it would delete the row on every peer.
      if (reissue && !reissued(tombstone)) return;
      if (identity.declaration.semantics === "append_only")
        throw new Error("append-only replication tombstone");
      append(tombstone);
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
    // Only this writer's operations: a peer that missed an older writer's
    // batches still gets every dependency, from the rebaseline.
    const current = writerId();
    const dependencies = allOperations()
      .filter(
        (op) =>
          op.revision.writerId === current &&
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
  /** Lifecycle, blob claims, every record and tombstone, then completions. */
  function captureCurrentState() {
    const bindings = db
      .prepare("SELECT * FROM pdpp_instance_binding ORDER BY instance")
      .all() as Binding[];
    for (const binding of bindings) {
      if (!binding.source_id || !binding.method) {
        throw new Error("unbound baseline connection");
      }
      captureLifecycle(binding.instance, "connection-register", 1);
      for (let generation = 2; generation <= binding.generation; generation++)
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
  }
  function declarationHistory(): ReplicaDeclarationHistoryEntry[] {
    return (
      db
        .prepare(
          "SELECT source_id, binding_json, schema_json FROM pdpp_replica_declaration_history ORDER BY first_generation, source_id, binding_json",
        )
        .all() as {
        source_id: string;
        binding_json: string;
        schema_json: string | null;
      }[]
    ).map((row) => ({
      sourceId: row.source_id,
      binding: JSON.parse(row.binding_json) as DeclarationBinding,
      ...(row.schema_json === null
        ? {}
        : { schema: JSON.parse(row.schema_json) as ReplicaStreamSchema }),
    }));
  }
  function bindingGeneration(): number {
    return (
      db
        .prepare(
          "SELECT coalesce(max(generation), 0) AS generation FROM pdpp_replica_binding_generations",
        )
        .get() as { generation: number }
    ).generation;
  }
  /**
   * Add `entries` to the history at `generation`, and record a schema the
   * history did not know. A schema must match its binding's digest.
   */
  function retainDeclarations(
    entries: BaselineConfiguration["declarations"],
    generation: number,
  ) {
    const insert = db.prepare(
      "INSERT INTO pdpp_replica_declaration_history VALUES (?, ?, ?, ?) ON CONFLICT (source_id, binding_json) DO UPDATE SET schema_json = coalesce(schema_json, excluded.schema_json)",
    );
    for (const entry of entries)
      insert.run(
        entry.sourceId,
        canonicalJson(entry.binding),
        entry.schema === undefined ? null : canonicalJson(entry.schema),
        generation,
      );
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
    for (const e of input.declarations)
      if (
        e.schema !== undefined &&
        replicaSchemaDigest(e.schema) !== e.binding.schemaDigest
      )
        throw new Error(
          `retained declaration schema does not match its digest: ${e.sourceId} stream ${e.binding.stream}`,
        );
    return db
      .transaction(() => {
        // Method transitions are not journaled, so a replica could not follow them.
        // Check before the idempotent return: a transition made while the flag
        // was off must also block re-enabling an already-baselined database.
        const transitioned = db
          .prepare(
            "SELECT instance FROM pdpp_claude_transition UNION ALL SELECT instance FROM pdpp_strava_transition LIMIT 1",
          )
          .get() as { instance: string } | undefined;
        if (transitioned)
          throw new Error(
            `replication cannot be enabled: connection ${transitioned.instance} has a Strava or Claude method transition`,
          );
        const prior = settings();
        if (prior) {
          const current = JSON.parse(
            prior.config_json,
          ) as BaselineConfiguration;
          if (current.owner !== normalized.owner)
            throw new Error("replication owner is immutable");
          const plan = planReplicaRebinding(
            current.declarations,
            declarationHistory(),
            normalized.declarations,
          );
          if (plan.tag === "refused") throw new Error(plan.reason);
          let generation = bindingGeneration();
          if (plan.tag === "rebind") {
            // Nothing is journaled: every operation names its own binding,
            // and the older ones stay trusted (rebinding.ts).
            generation += 1;
            db.prepare(
              "UPDATE pdpp_replica_settings SET config_json = ? WHERE id = 1",
            ).run(canonicalJson(normalized));
            db.prepare(
              "INSERT INTO pdpp_replica_binding_generations VALUES (?, ?)",
            ).run(generation, canonicalJson(normalized));
          }
          retainDeclarations(input.declarations, generation);
          return { watermark: prior.watermark };
        }
        db.prepare(
          "INSERT INTO pdpp_replica_settings (id, config_json, watermark) VALUES (1, ?, 0)",
        ).run(canonicalJson(normalized));
        db.prepare(
          "INSERT INTO pdpp_replica_binding_generations VALUES (1, ?)",
        ).run(canonicalJson(normalized));
        retainDeclarations(input.declarations, 1);
        // A legacy orphan is a migration error, never an omitted row.
        const orphan = db
          .prepare(
            "SELECT 1 FROM pdpp_records r LEFT JOIN pdpp_instance_binding b ON r.instance = b.instance WHERE b.source_id IS NULL OR b.method IS NULL LIMIT 1",
          )
          .get();
        if (orphan) throw new Error("unbound baseline records");
        captureCurrentState();
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
  /**
   * The current state, re-captured under the current writer as a new
   * baseline. A new writer identity calls it before it publishes: a peer that
   * missed the old writer's batches, unpublished or refused, still converges.
   * Records and completions keep the order of the retained operation whose
   * effect they copy (`reissued`), so against every other writer the copy
   * wins and loses exactly where that operation does: it never overrides a
   * newer write, and never loses a tie the original won. A peer's operation
   * is re-issued the same way: the new writer signs it, its origin keeps the
   * peer's order. Lifecycle and blob-claim operations take new counters.
   *
   * Only the operation the merge chose explains a state (`explaining`). A
   * higher operation with the same effect may be one the merge rejected or
   * keeps pending; copying its order or binding would publish a baseline
   * that a peer with this device's trust refuses. A tombstone no delete
   * explains only hides a row here, so it is not re-issued.
   */
  function rebaseline(
    explaining: readonly ReplicaOperation[],
  ): { after: number } | undefined {
    if (!settings()) return undefined;
    const { counter: after } = db
      .prepare("SELECT counter FROM pdpp_replica_clock")
      .get() as { counter: number };
    reissue = new Map();
    for (const op of explaining) {
      const key = reissueKey(op);
      if (key !== undefined && "declaration" in op) reissue.set(key, op);
    }
    try {
      captureCurrentState();
    } finally {
      reissue = undefined;
    }
    const { counter } = db
      .prepare("SELECT counter FROM pdpp_replica_clock")
      .get() as { counter: number };
    db.prepare(
      "INSERT INTO pdpp_replica_baseline SELECT sequence FROM pdpp_replica_operations WHERE sequence > ?",
    ).run(after);
    db.prepare(
      "UPDATE pdpp_replica_settings SET watermark = ?, checkpoint = ? WHERE id = 1",
    ).run(counter, after);
    return { after };
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
    declarationHistory,
    bindingGeneration,
    rebaseline: (explaining) =>
      db.transaction(() => rebaseline(explaining)).immediate(),
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
      return readBinaryChunks(db, pinnedNamespace(blobId), blobId);
    },
    readPinnedBlobBytes(blobId) {
      const namespace = pinnedNamespace(blobId);
      const size = binaryLength(db, namespace, blobId);
      if (size === undefined) return undefined;
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of readBinaryChunks(db, namespace, blobId)) {
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
