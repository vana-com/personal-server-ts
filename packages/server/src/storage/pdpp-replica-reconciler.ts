import type { Database, Statement } from "better-sqlite3";
import {
  canonicalJson,
  type ReplicaOperation,
  type RecordOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  planReplicaMerge,
  type MergeContext,
  type MergeIssue,
  type ReplicaMergePlan,
} from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { selectStreamCompletion } from "@opendatalabs/personal-server-ts-core/replication/completion";
import {
  blobReady,
  completionAvailability,
  connectionFromFacts,
  contradictsMapping,
  recordRow,
  type ConnectionFacts,
  type ConnectionMapping,
  type ConnectionProjection,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-engine";
import { operationExpressions as X } from "./pdpp-replica-visibility-view.js";

/**
 * Durable state of the incremental reconciler. Replica tables only, created
 * by the receiver, so a database that never enabled replication has none.
 * - state: how far each retained table has been ingested (rowid frontiers).
 * - bindings, equivocations: per-connection facts that `connectionFromFacts`
 *   needs, kept as retained evidence arrives instead of re-read from it.
 * - connections: the last committed decision per connection, so a change is
 *   expanded to the connection's keys once, not on every import.
 * - blockers: keys with an unresolved issue; a completion of their stream
 *   cannot be available.
 * - dependencies: the operation ids each stream's retained completions pin,
 *   so an operation that arrives, or gains a variant, re-queues them.
 * - queue: work not yet reconciled. `background` marks entries of a paged
 *   pass that an import does not have to finish.
 */
export const RECONCILE_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_replica_reconcile_state (id INTEGER PRIMARY KEY CHECK (id = 1), operations_frontier INTEGER NOT NULL, received_frontier INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_replica_reconcile_bindings (instance TEXT NOT NULL, source_id TEXT NOT NULL, method_id TEXT NOT NULL, PRIMARY KEY (instance, source_id, method_id));
CREATE TABLE IF NOT EXISTS pdpp_replica_reconcile_equivocations (instance TEXT NOT NULL, writer TEXT NOT NULL, operation_id TEXT NOT NULL, PRIMARY KEY (instance, writer, operation_id));
CREATE TABLE IF NOT EXISTS pdpp_replica_reconcile_connections (instance TEXT PRIMARY KEY, decision_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pdpp_replica_reconcile_blockers (instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL, PRIMARY KEY (instance, stream, record_key));
CREATE TABLE IF NOT EXISTS pdpp_replica_reconcile_dependencies (writer TEXT NOT NULL, operation_id TEXT NOT NULL, instance TEXT NOT NULL, stream TEXT NOT NULL, PRIMARY KEY (writer, operation_id, instance, stream));
CREATE INDEX IF NOT EXISTS pdpp_replica_reconcile_dependencies_stream ON pdpp_replica_reconcile_dependencies (instance, stream);
CREATE TABLE IF NOT EXISTS pdpp_replica_reconcile_queue (kind INTEGER NOT NULL, instance TEXT NOT NULL, stream TEXT NOT NULL, record_key TEXT NOT NULL, expand INTEGER NOT NULL DEFAULT 0, background INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (kind, instance, stream, record_key));
CREATE INDEX IF NOT EXISTS pdpp_replica_reconcile_queue_order ON pdpp_replica_reconcile_queue (background, kind, instance, stream, record_key);
${["pdpp_replica_operations", "pdpp_replica_received"]
  .map(
    (table) =>
      `CREATE INDEX IF NOT EXISTS pdpp_replica_reconcile_completions_${table} ON ${table}(${X.instance},${X.stream}) WHERE ${X.kind} IN ('stream-complete','stream-invalidate');`,
  )
  .join("\n")}
`;

/** Queue entry kinds, in processing order: tombstones before winners. */
const CONNECTION = 0;
const WITHDRAW = 1;
const KEY = 2;
const COMPLETION = 3;
type Kind =
  typeof CONNECTION | typeof WITHDRAW | typeof KEY | typeof COMPLETION;
interface Entry {
  kind: Kind;
  instance: string;
  stream: string;
  record_key: string;
  expand: number;
  background: number;
}

/** Work one bounded call may load: retained operations and their JSON bytes. */
export interface ReplicaReconcilePage {
  operations: number;
  bytes: number;
}
/** Cumulative retained evidence the reconciler loaded. For bounds tests. */
export interface ReplicaReconcileStats {
  operations: number;
  bytes: number;
  entries: number;
}

type Binding = {
  source_id: string | null;
  method: string | null;
  generation: number;
  deleted_at: string | null;
};
type Upsert = Extract<ReplicaOperation, { kind: "upsert" }>;
type CompletionEvent = Extract<
  ReplicaOperation,
  { kind: "stream-complete" | "stream-invalidate" }
>;
/** What the decisions for one connection's keys depend on, outside its keys. */
interface Decision {
  projection: ConnectionProjection | { status: "unprovisioned" };
  world: World;
}
interface World {
  mapping: ConnectionMapping | null;
  generation: number | null;
  deletedAt: string | null;
  terminal: boolean;
  conflicted: boolean;
}

const RETAINED = ["pdpp_replica_operations", "pdpp_replica_received"] as const;
const LIFECYCLE =
  "('connection-register','connection-reset','connection-delete')";
const COMPLETIONS = "('stream-complete','stream-invalidate')";
const compareText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

const isBindingConflict = (
  projection: Decision["projection"],
): projection is Extract<ConnectionProjection, { status: "withdrawn" }> =>
  projection.status === "withdrawn" &&
  (projection.reason === "local_mapping_conflict" ||
    projection.reason === "source_binding_conflict");

/**
 * Incremental reconcile of retained history into the canonical tables.
 *
 * The canonical result equals a reconcile of the full retained set: a
 * connection's eligibility comes from `connectionFromFacts` over facts kept
 * as evidence arrives, and each key is planned by `planReplicaMerge` over the
 * connection's unique lifecycle and that key's operations only. Evidence
 * marks the keys, connections and completions it can change. A connection
 * whose decision changed is expanded to all of its keys and completions.
 *
 * The receiver supplies the canonical effects; this module decides which
 * work exists and does it in bounded pages.
 */
export function createReplicaReconciler(deps: {
  db: Database;
  owner: string;
  declarations: () => MergeContext["declarations"];
  effects: {
    binding(instance: string): Binding | undefined;
    write(
      instance: string,
      stream: string,
      key: string,
      operation: RecordOperation | null,
    ): void;
    quarantineKey(
      instance: string,
      generation: number,
      stream: string,
      recordKey: string,
    ): void;
    quarantineConnection(instance: string): boolean;
    isRecordQuarantined(instance: string, stream: string, key: string): boolean;
    verifiedBlobs(blobs: Upsert["blobs"]): Set<string>;
    persistBlobs(operation: Upsert): void;
    markBindingConflict(input: {
      connectionId: string;
      reason: "source_binding_conflict" | "local_mapping_conflict";
      evidence: unknown;
    }): boolean;
  };
}) {
  const { db, effects } = deps;
  db.exec(RECONCILE_MIGRATION);
  const statements = new Map<string, Statement>();
  const sql = (source: string) => {
    let statement = statements.get(source);
    if (!statement) {
      statement = db.prepare(source);
      statements.set(source, statement);
    }
    return statement;
  };
  const stats: ReplicaReconcileStats = { operations: 0, bytes: 0, entries: 0 };
  /** Charged by every retained read; a page stops when it is spent. */
  let meter = { operations: 0, bytes: 0 };

  /** Retained operations matching `where` in both tables, deduplicated, in JSON order. */
  function retained<T extends ReplicaOperation = ReplicaOperation>(
    where: string,
    params: readonly unknown[],
  ): T[] {
    const rows = sql(
      RETAINED.map(
        (table) => `SELECT operation_json FROM ${table} WHERE ${where}`,
      ).join(" UNION "),
    ).all(...params, ...params) as { operation_json: string }[];
    rows.sort((a, b) => compareText(a.operation_json, b.operation_json));
    for (const row of rows) {
      const bytes = Buffer.byteLength(row.operation_json, "utf8");
      meter.operations++;
      meter.bytes += bytes;
      stats.operations++;
      stats.bytes += bytes;
    }
    return rows.map((row) => JSON.parse(row.operation_json) as T);
  }
  /** Distinct (digest, connection) of every retained variant of one revision. */
  function variants(writer: string, operationId: string) {
    return sql(
      RETAINED.map(
        (table) =>
          `SELECT digest, ${X.instance} AS instance FROM ${table} WHERE ${X.writer} = ? AND ${X.operation_id} = ?`,
      ).join(" UNION "),
    ).all(writer, operationId, writer, operationId) as {
      digest: string;
      instance: string;
    }[];
  }

  // ------------------------------------------------------------ the queue
  function enqueue(
    kind: Kind,
    instance: string,
    stream = "",
    recordKey = "",
    options: { background?: boolean; expand?: boolean } = {},
  ) {
    sql(
      "INSERT INTO pdpp_replica_reconcile_queue VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(kind, instance, stream, record_key) DO UPDATE SET expand = max(expand, excluded.expand), background = min(background, excluded.background)",
    ).run(
      kind,
      instance,
      stream,
      recordKey,
      options.expand ? 1 : 0,
      options.background ? 1 : 0,
    );
  }
  /** Enqueue every row `select` returns as (instance, stream, record_key). */
  function enqueueAll(
    kind: Kind,
    select: string,
    params: readonly unknown[],
    background: boolean,
  ) {
    sql(
      `INSERT INTO pdpp_replica_reconcile_queue (kind, instance, stream, record_key, expand, background) SELECT ${kind}, instance, stream, record_key, 0, ${background ? 1 : 0} FROM (${select}) WHERE true ON CONFLICT(kind, instance, stream, record_key) DO UPDATE SET background = min(background, excluded.background)`,
    ).run(...params);
  }
  function take(kind: Kind, instance: string, stream = "", recordKey = "") {
    return sql(
      "DELETE FROM pdpp_replica_reconcile_queue WHERE kind = ? AND instance = ? AND stream = ? AND record_key = ? RETURNING *",
    ).get(kind, instance, stream, recordKey) as Entry | undefined;
  }
  /** Marks for what one operation can change. */
  function mark(op: ReplicaOperation) {
    switch (op.kind) {
      case "upsert":
      case "delete":
        enqueue(KEY, op.connectionId, op.declaration.stream, op.recordKey);
        return;
      case "blob-claim":
        // A claim makes the connection's upserts of that blob showable.
        enqueueAll(
          KEY,
          RETAINED.map(
            (table) =>
              `SELECT ${X.instance} AS instance, ${X.stream} AS stream, ${X.record_key} AS record_key FROM ${table} WHERE ${X.blob_id} = ? AND ${X.instance} = ? AND ${X.kind} = 'upsert'`,
          ).join(" UNION "),
          [op.blob.blobId, op.connectionId, op.blob.blobId, op.connectionId],
          false,
        );
        return;
      case "stream-complete":
      case "stream-invalidate":
        enqueue(COMPLETION, op.connectionId, op.declaration.stream);
        return;
      default:
        enqueue(CONNECTION, op.connectionId);
    }
  }
  /** Marks the upserts of every connection that show these blobs' bytes. */
  function touchBlobs(blobIds: readonly string[]) {
    for (const blobId of new Set(blobIds))
      enqueueAll(
        KEY,
        RETAINED.map(
          (table) =>
            `SELECT ${X.instance} AS instance, ${X.stream} AS stream, ${X.record_key} AS record_key FROM ${table} WHERE ${X.blob_id} = ? AND ${X.kind} = 'upsert'`,
        ).join(" UNION "),
        [blobId, blobId],
        false,
      );
  }

  // ------------------------------------------------------------ ingestion
  function frontiers() {
    return sql(
      "SELECT operations_frontier AS operations, received_frontier AS received FROM pdpp_replica_reconcile_state WHERE id = 1",
    ).get() as { operations: number; received: number } | undefined;
  }
  /** Connection facts of one new retained operation; marks what it changes. */
  function admit(op: ReplicaOperation) {
    if (
      sql(
        "INSERT OR IGNORE INTO pdpp_replica_reconcile_bindings VALUES (?, ?, ?)",
      ).run(op.connectionId, op.sourceId, op.methodId).changes > 0
    )
      enqueue(CONNECTION, op.connectionId);
    const found = variants(op.revision.writerId, op.revision.operationId);
    if (new Set(found.map((row) => row.digest)).size > 1)
      for (const { instance } of found)
        if (
          sql(
            "INSERT OR IGNORE INTO pdpp_replica_reconcile_equivocations VALUES (?, ?, ?)",
          ).run(instance, op.revision.writerId, op.revision.operationId)
            .changes > 0
        )
          enqueue(CONNECTION, instance);
    // Completions that pin this operation id: it arrived, or it has another
    // variant now. Either can change their availability.
    enqueueAll(
      COMPLETION,
      "SELECT instance, stream, '' AS record_key FROM pdpp_replica_reconcile_dependencies WHERE writer = ? AND operation_id = ?",
      [op.revision.writerId, op.revision.operationId],
      false,
    );
    mark(op);
  }
  /**
   * Admit every retained operation past the frontiers. Rowids of both tables
   * only grow: both are append-only, and the journal's sequence is its
   * Lamport counter.
   */
  function ingest() {
    const at = frontiers()!;
    const next = { ...at };
    for (const [table, field] of [
      ["pdpp_replica_operations", "operations"],
      ["pdpp_replica_received", "received"],
    ] as const)
      for (;;) {
        const rows = sql(
          `SELECT rowid AS id, operation_json FROM ${table} WHERE rowid > ? ORDER BY rowid LIMIT 512`,
        ).all(next[field]) as { id: number; operation_json: string }[];
        if (!rows.length) break;
        for (const row of rows)
          admit(JSON.parse(row.operation_json) as ReplicaOperation);
        next[field] = rows[rows.length - 1].id;
      }
    if (next.operations !== at.operations || next.received !== at.received)
      sql(
        "UPDATE pdpp_replica_reconcile_state SET operations_frontier = ?, received_frontier = ? WHERE id = 1",
      ).run(next.operations, next.received);
  }
  /**
   * A database whose retained evidence predates this state: derive the facts
   * in three set queries, and queue every connection for a full expansion.
   * The first import or step does that work, as the full reconcile it
   * replaces did on every call.
   */
  function bootstrap() {
    if (frontiers()) return;
    const union = (select: (table: string) => string) =>
      RETAINED.map(select).join(" UNION ");
    db.prepare(
      `INSERT OR IGNORE INTO pdpp_replica_reconcile_bindings ${union(
        (table) =>
          `SELECT ${X.instance}, json_extract(operation_json,'$.sourceId'), json_extract(operation_json,'$.methodId') FROM ${table}`,
      )}`,
    ).run();
    db.prepare(
      `INSERT OR IGNORE INTO pdpp_replica_reconcile_equivocations SELECT instance, writer, operation_id FROM (${union(
        (table) =>
          `SELECT ${X.instance} AS instance, ${X.writer} AS writer, ${X.operation_id} AS operation_id, digest FROM ${table}`,
      )}) v WHERE (SELECT count(DISTINCT digest) FROM (${union(
        (table) =>
          `SELECT digest FROM ${table} WHERE ${X.writer} = v.writer AND ${X.operation_id} = v.operation_id`,
      )})) > 1`,
    ).run();
    for (const { instance } of db
      .prepare("SELECT DISTINCT instance FROM pdpp_replica_reconcile_bindings")
      .all() as { instance: string }[])
      enqueue(CONNECTION, instance, "", "", { expand: true });
    const max = (table: string) =>
      (
        db
          .prepare(`SELECT coalesce(max(rowid), 0) AS id FROM ${table}`)
          .get() as {
          id: number;
        }
      ).id;
    db.prepare("INSERT INTO pdpp_replica_reconcile_state VALUES (1, ?, ?)").run(
      max("pdpp_replica_operations"),
      max("pdpp_replica_received"),
    );
  }
  db.transaction(bootstrap).immediate();

  // ---------------------------------------------------------- connections
  function worldOf(instance: string): World {
    const local = effects.binding(instance);
    return {
      mapping: local?.source_id
        ? { sourceId: local.source_id, methodId: local.method ?? "" }
        : null,
      generation: local?.generation ?? null,
      deletedAt: local?.deleted_at ?? null,
      terminal: !!sql(
        "SELECT 1 FROM pdpp_replica_quarantined_connections WHERE instance = ?",
      ).get(instance),
      conflicted: !!sql(
        "SELECT 1 FROM pdpp_replica_binding_conflicts WHERE instance = ?",
      ).get(instance),
    };
  }
  function decisionOf(instance: string): Decision | undefined {
    const row = sql(
      "SELECT decision_json FROM pdpp_replica_reconcile_connections WHERE instance = ?",
    ).get(instance) as { decision_json: string } | undefined;
    return row && (JSON.parse(row.decision_json) as Decision);
  }
  /** Lifecycle operations of a connection whose revision has one content. */
  let lifecycleCache = new Map<string, ReplicaOperation[]>();
  function lifecycle(instance: string) {
    const cached = lifecycleCache.get(instance);
    if (cached) return cached;
    const found = retained(`${X.instance} = ? AND ${X.kind} IN ${LIFECYCLE}`, [
      instance,
    ]).filter(
      (op) =>
        variants(op.revision.writerId, op.revision.operationId).length === 1,
    );
    lifecycleCache.set(instance, found);
    return found;
  }
  function bindingsOf(instance: string): ConnectionMapping[] {
    return (
      sql(
        "SELECT source_id AS sourceId, method_id AS methodId FROM pdpp_replica_reconcile_bindings WHERE instance = ? ORDER BY source_id, method_id",
      ).all(instance) as ConnectionMapping[]
    ).map(({ sourceId, methodId }) => ({ sourceId, methodId }));
  }
  function factsOf(
    instance: string,
    mapping: ConnectionMapping,
    terminal: boolean,
  ): ConnectionFacts {
    return {
      mapping,
      terminal,
      equivocated: !!sql(
        "SELECT 1 FROM pdpp_replica_reconcile_equivocations WHERE instance = ? LIMIT 1",
      ).get(instance),
      bindings: bindingsOf(instance),
      lifecycle: lifecycle(instance),
      appliedGeneration: effects.binding(instance)?.generation ?? 1,
    };
  }
  /** One retained operation of the connection, to name it in a plan issue. */
  function representative(instance: string) {
    const [first] = sql(
      RETAINED.map(
        (table) =>
          `SELECT operation_json FROM ${table} WHERE ${X.instance} = ? AND ${X.kind} IS NOT NULL`,
      ).join(" UNION ") + " ORDER BY operation_json LIMIT 1",
    ).all(instance, instance) as { operation_json: string }[];
    return first && (JSON.parse(first.operation_json) as ReplicaOperation);
  }
  /** Persist a binding conflict with the evidence that shows it (#428 F2). */
  function recordBindingConflict(
    instance: string,
    mapping: ConnectionMapping | null,
    bindings: readonly ConnectionMapping[],
  ) {
    if (
      sql(
        "SELECT 1 FROM pdpp_replica_binding_conflicts WHERE instance = ?",
      ).get(instance)
    )
      return;
    if (!mapping) {
      effects.markBindingConflict({
        connectionId: instance,
        reason: "source_binding_conflict",
        evidence: [
          ...new Set(bindings.map((b) => `${b.sourceId} ${b.methodId}`)),
        ]
          .sort()
          .slice(0, 8),
      });
      return;
    }
    const [disagreeing] = retained(
      `${X.instance} = ? AND (json_extract(operation_json,'$.sourceId') IS NOT ? OR json_extract(operation_json,'$.methodId') IS NOT ?)`,
      [instance, mapping.sourceId, mapping.methodId],
    );
    effects.markBindingConflict({
      connectionId: instance,
      reason: "local_mapping_conflict",
      evidence: {
        sourceId: disagreeing.sourceId,
        methodId: disagreeing.methodId,
        revision: disagreeing.revision,
      },
    });
  }
  /** Connection-level plan issues of a provisioned connection that is not active. */
  function connectionIssues(
    instance: string,
    projection: ConnectionProjection,
    plan: ReplicaMergePlan,
    context: MergeContext,
  ) {
    const unique = lifecycle(instance);
    const rep = representative(instance);
    const entries = [
      ...new Map(
        [...unique, ...(rep ? [rep] : [])].map((op) => [canonicalJson(op), op]),
      ).values(),
    ];
    if (
      projection.status === "withdrawn" &&
      projection.reason === "operation_id_equivocation"
    ) {
      for (const { writer, operation_id } of sql(
        "SELECT writer, operation_id FROM pdpp_replica_reconcile_equivocations WHERE instance = ?",
      ).all(instance) as { writer: string; operation_id: string }[])
        plan.conflicts.push({
          reason: "operation_id_equivocation",
          operations: retained(`${X.writer} = ? AND ${X.operation_id} = ?`, [
            writer,
            operation_id,
          ]),
        });
      if (unique.some((op) => op.kind === "connection-delete"))
        plan.suppressed.push({
          reason: "connection_deleted",
          operations: entries,
        });
      else
        plan.conflicts.push({
          reason: "incompatible_connection_binding",
          operations: entries,
        });
      return;
    }
    const lifecyclePlan = planReplicaMerge(context, entries);
    plan.conflicts.push(...lifecyclePlan.conflicts);
    plan.pending.push(...lifecyclePlan.pending);
    plan.suppressed.push(...lifecyclePlan.suppressed);
    plan.rejected.push(...lifecyclePlan.rejected);
  }

  /**
   * Decide one connection and apply its lifecycle effects, as the full
   * reconcile did for every connection. A changed decision (or `expand`)
   * queues all of the connection's keys and completions.
   */
  function reconcileConnection(
    instance: string,
    options: { background: boolean; expand: boolean },
    run: Run,
  ) {
    const bindings = bindingsOf(instance);
    if (!bindings.length) return; // No retained evidence names it.
    const { context, plan } = run;
    const before = decisionOf(instance);
    const world = worldOf(instance);
    const facts = factsOf(instance, world.mapping ?? bindings[0], false);
    // A retained disagreement is a durable, connection-scoped fact, never a
    // throw that would block every import and retry (#428 F2). It holds even
    // when terminal quarantine or equivocation outranks it (#426).
    if (contradictsMapping(facts))
      recordBindingConflict(instance, world.mapping, bindings);
    let projection: Decision["projection"];
    if (!world.mapping) {
      projection = { status: "unprovisioned" };
      const rep = representative(instance);
      if (rep)
        plan.pending.push({
          reason: "missing_local_connection",
          operations: [rep],
        });
    } else {
      projection = connectionFromFacts(context, facts);
      if (!isBindingConflict(projection)) {
        applyLifecycle(instance, projection, options.background);
        if (projection.status !== "active") {
          connectionIssues(instance, projection, plan, context);
          run.reported.add(instance);
        }
      }
    }
    const after: Decision = { projection, world: worldOf(instance) };
    const encoded = canonicalJson(after);
    if (options.expand || !before || canonicalJson(before) !== encoded) {
      if (projection.status === "active")
        enqueueAll(
          KEY,
          RETAINED.map(
            (table) =>
              `SELECT ${X.instance} AS instance, ${X.stream} AS stream, ${X.record_key} AS record_key FROM ${table} WHERE ${X.instance} = ? AND ${X.stream} IS NOT NULL AND ${X.record_key} IS NOT NULL`,
          ).join(" UNION "),
          [instance, instance],
          options.background,
        );
      if (world.mapping)
        enqueueAll(
          COMPLETION,
          RETAINED.map(
            (table) =>
              `SELECT ${X.instance} AS instance, ${X.stream} AS stream, '' AS record_key FROM ${table} WHERE ${X.kind} IN ${COMPLETIONS} AND ${X.instance} = ? AND ${X.stream} IS NOT NULL`,
          ).join(" UNION "),
          [instance, instance],
          options.background,
        );
      // Only mapped connections' variants count toward a dependency, so a
      // change here can change completions of other connections too.
      enqueueAll(
        COMPLETION,
        `SELECT DISTINCT d.instance, d.stream, '' AS record_key FROM pdpp_replica_reconcile_dependencies d WHERE d.instance <> ? AND EXISTS (${RETAINED.map(
          (table) =>
            `SELECT 1 FROM ${table} WHERE ${X.writer} = d.writer AND ${X.operation_id} = d.operation_id AND ${X.instance} = ?`,
        ).join(" UNION ALL ")})`,
        [instance, instance, instance],
        options.background,
      );
    }
    sql(
      "INSERT INTO pdpp_replica_reconcile_connections VALUES (?, ?) ON CONFLICT(instance) DO UPDATE SET decision_json = excluded.decision_json",
    ).run(instance, encoded);
  }
  /**
   * Lifecycle evidence gates canonical state, but never creates a connection
   * or changes its acquisition method. Only the local authority provisions
   * that. Rows the connection loses are queued as tombstones.
   */
  function applyLifecycle(
    instance: string,
    connection: ConnectionProjection,
    background: boolean,
  ) {
    const local = effects.binding(instance)!;
    const deleted = connection.status === "deleted";
    const blocked = connection.status === "withdrawn";
    const reset =
      connection.status === "active" &&
      connection.generation > local.generation;
    const newlyBlocked = blocked && effects.quarantineConnection(instance);
    // A receiver-derived deletion can become equivocated later. Retract only
    // that derived marker; an actual local deletion remains in the merge set.
    const retractDeletion = !deleted && local.deleted_at === "replica-deleted";
    if (deleted || blocked || reset) {
      enqueueAll(
        WITHDRAW,
        "SELECT instance, stream, record_key FROM pdpp_records WHERE instance = ? AND deleted = 0",
        [instance],
        background,
      );
      sql("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
        instance,
      );
      sql("DELETE FROM pdpp_blob_claims WHERE instance = ?").run(instance);
    }
    if (
      (deleted && local.deleted_at === null) ||
      reset ||
      newlyBlocked ||
      retractDeletion
    ) {
      // Even an empty reset must expire a token at the old write horizon.
      const { value: fence } = sql(
        "UPDATE pdpp_write_clock SET value = value + 1 WHERE id = 1 RETURNING value",
      ).get() as { value: number };
      sql(
        "UPDATE pdpp_instance_binding SET generation = ?, deleted_at = ?, reset_clock = ? WHERE instance = ?",
      ).run(
        reset ? connection.generation : local.generation,
        deleted
          ? (local.deleted_at ?? "replica-deleted")
          : retractDeletion
            ? null
            : local.deleted_at,
        fence,
        instance,
      );
    }
  }
  /**
   * Bring the connection's decision up to date before one of its keys or
   * completions is decided: a queued connection entry first, and a world
   * the decision did not see (a provisioned mapping, a quarantine fact).
   */
  function settleConnection(instance: string, background: boolean, run: Run) {
    const queued = take(CONNECTION, instance);
    if (queued)
      return reconcileConnection(
        instance,
        { background: queued.background === 1, expand: queued.expand === 1 },
        run,
      );
    const decision = decisionOf(instance);
    if (
      !decision ||
      canonicalJson(decision.world) !== canonicalJson(worldOf(instance))
    )
      reconcileConnection(instance, { background, expand: false }, run);
  }

  // ----------------------------------------------------------------- keys
  function withdrawKey(instance: string, stream: string, recordKey: string) {
    if (
      sql(
        "SELECT 1 FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ? AND deleted = 0",
      ).get(instance, stream, recordKey)
    )
      effects.write(instance, stream, recordKey, null);
  }
  function reconcileKey(
    instance: string,
    stream: string,
    recordKey: string,
    background: boolean,
    run: Run,
  ) {
    settleConnection(instance, background, run);
    if (take(WITHDRAW, instance, stream, recordKey))
      withdrawKey(instance, stream, recordKey);
    const decision = decisionOf(instance);
    if (!decision) return;
    const { context, plan } = run;
    const where = `${X.instance} = ? AND ${X.stream} = ? AND ${X.record_key} = ?`;
    const params = [instance, stream, recordKey];
    if (decision.projection.status === "unprovisioned") {
      plan.pending.push({
        reason: "missing_local_connection",
        operations: retained(where, params),
      });
      return;
    }
    if (isBindingConflict(decision.projection)) return;
    if (decision.projection.status !== "active") {
      // The plan names why the connection holds its records.
      if (!run.reported.has(instance)) {
        run.reported.add(instance);
        connectionIssues(instance, decision.projection, plan, context);
      }
      return;
    }
    const keyPlan = planReplicaMerge(context, [
      ...lifecycle(instance),
      ...retained(where, params),
    ]);
    let blocked = [
      ...keyPlan.pending,
      ...keyPlan.conflicts,
      ...keyPlan.rejected,
    ].some((issue) => issue.reason !== "missing_declaration");
    const local = effects.binding(instance)!;
    for (const record of keyPlan.records) {
      const { generation } = record.identity;
      if (local.deleted_at || generation !== local.generation) continue;
      if (record.quarantined)
        effects.quarantineKey(instance, generation, stream, recordKey);
      if (effects.isRecordQuarantined(instance, stream, recordKey)) {
        effects.write(instance, stream, recordKey, null);
        continue;
      }
      // `write` turns a withdrawal into a tombstone only for a stored row, so
      // the engine's "no prior row" case is the same as a withdrawal here.
      const row = recordRow(undefined, record, (op) =>
        blobReady(
          op,
          op.blobs.flatMap((blob) =>
            retained(
              `${X.blob_id} = ? AND ${X.instance} = ? AND ${X.kind} = 'blob-claim'`,
              [blob.blobId, instance],
            ),
          ),
          effects.verifiedBlobs(op.blobs),
        ),
      );
      const shown = row && row.state !== "withdrawn" ? row.winner : null;
      if (record.winner?.kind === "upsert" && !shown) {
        blocked = true;
        keyPlan.pending.push({
          reason: "missing_or_invalid_blob",
          operations: [record.winner],
        });
      }
      if (shown?.kind === "upsert") effects.persistBlobs(shown);
      effects.write(instance, stream, recordKey, shown);
    }
    const materialized = new Set(
      keyPlan.records.map((record) => canonicalJson(record.identity)),
    );
    for (const issue of [...keyPlan.pending, ...keyPlan.rejected]) {
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
          local.generation === op.generation &&
          !materialized.has(canonicalJson(identity))
        )
          effects.write(instance, stream, recordKey, null);
      }
    }
    sql(
      blocked
        ? "INSERT OR IGNORE INTO pdpp_replica_reconcile_blockers VALUES (?, ?, ?)"
        : "DELETE FROM pdpp_replica_reconcile_blockers WHERE instance = ? AND stream = ? AND record_key = ?",
    ).run(instance, stream, recordKey);
    for (const bucket of [
      "records",
      "conflicts",
      "rejected",
      "pending",
      "suppressed",
    ] as const)
      (plan[bucket] as unknown[]).push(...keyPlan[bucket]);
    enqueue(COMPLETION, instance, stream, "", { background });
  }

  // ---------------------------------------------------------- completions
  /**
   * Persist the engine's completion availability for one provisioned stream
   * with completion evidence at its connection's generation. The terminal
   * quarantine fact applies here, unlike to rows.
   */
  function reconcileCompletion(
    instance: string,
    stream: string,
    background: boolean,
    run: Run,
  ) {
    settleConnection(instance, background, run);
    // A queued key re-queues this completion once it is decided.
    if (
      sql(
        `SELECT 1 FROM pdpp_replica_reconcile_queue WHERE kind IN (${WITHDRAW}, ${KEY}) AND instance = ? AND stream = ? LIMIT 1`,
      ).get(instance, stream)
    )
      return;
    const local = effects.binding(instance);
    if (!local?.source_id) return;
    const mapping = { sourceId: local.source_id, methodId: local.method ?? "" };
    const { context, plan } = run;
    const trusted = (op: CompletionEvent) =>
      context.declarations.some(
        (d) =>
          d.sourceId === op.sourceId &&
          canonicalJson(d.binding) === canonicalJson(op.declaration),
      );
    const all = retained<CompletionEvent>(
      `${X.kind} IN ${COMPLETIONS} AND ${X.instance} = ? AND ${X.stream} = ?`,
      [instance, stream],
    );
    sql(
      "DELETE FROM pdpp_replica_reconcile_dependencies WHERE instance = ? AND stream = ?",
    ).run(instance, stream);
    for (const op of all)
      if (op.kind === "stream-complete")
        for (const dependency of op.dependencies)
          sql(
            "INSERT OR IGNORE INTO pdpp_replica_reconcile_dependencies VALUES (?, ?, ?, ?)",
          ).run(dependency.writerId, dependency.operationId, instance, stream);
    for (const op of all)
      if (!trusted(op))
        plan.pending.push({ reason: "missing_declaration", operations: [op] });
    if (!all.length) return;
    const connection = connectionFromFacts(
      context,
      factsOf(instance, mapping, worldOf(instance).terminal),
    );
    const events = all.filter((op) => op.generation === connection.generation);
    if (!events.length) return;
    const first = events[0];
    const { generation } = first;
    let liveRows: { recordKey: string; dataJson: string }[] | undefined;
    const loadLiveRows = () =>
      (liveRows ??= sql(
        "SELECT record_key AS recordKey, data AS dataJson FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
      ).all(instance, stream) as { recordKey: string; dataJson: string }[]);
    const available = completionAvailability({
      connection,
      connectionId: instance,
      events,
      declarations: context.declarations,
      quarantinedKey: !!sql(
        "SELECT 1 FROM pdpp_replica_quarantined_keys WHERE instance = ? AND generation = ? AND stream = ? LIMIT 1",
      ).get(instance, generation, stream),
      unresolved: !!sql(
        "SELECT 1 FROM pdpp_replica_reconcile_blockers WHERE instance = ? AND stream = ? LIMIT 1",
      ).get(instance, stream),
      variantDigests: (writerId, operationId) => [
        ...new Set(
          variants(writerId, operationId)
            .filter((row) => effects.binding(row.instance)?.source_id)
            .map((row) => row.digest),
        ),
      ],
      // Read once, and only once every cheaper condition holds.
      get liveRows() {
        return loadLiveRows();
      },
    });
    if (available) {
      const completion = available.operation;
      const seq = (
        sql("SELECT value FROM pdpp_write_clock").get() as { value: number }
      ).value;
      const native = completion.proof.kind === "native";
      sql(
        "INSERT INTO pdpp_stream_completion (instance,stream,method,generation,source_collected_at,write_seq,live_count,snapshot_sha256,collection_time_basis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(instance,stream) DO UPDATE SET method=excluded.method,generation=excluded.generation,source_collected_at=excluded.source_collected_at,write_seq=excluded.write_seq,live_count=excluded.live_count,snapshot_sha256=excluded.snapshot_sha256,collection_time_basis=excluded.collection_time_basis WHERE method IS NOT excluded.method OR generation IS NOT excluded.generation OR source_collected_at IS NOT excluded.source_collected_at OR live_count IS NOT excluded.live_count OR snapshot_sha256 IS NOT excluded.snapshot_sha256 OR collection_time_basis IS NOT excluded.collection_time_basis",
      ).run(
        instance,
        stream,
        first.methodId,
        generation,
        completion.sourceCollectedAt,
        seq,
        completion.liveCount,
        native ? completion.snapshotSha256.slice(7) : null,
        native ? "host_run_finished" : null,
      );
      return;
    }
    sql(
      "DELETE FROM pdpp_stream_completion WHERE instance = ? AND stream = ?",
    ).run(instance, stream);
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

  // ----------------------------------------------------------------- runs
  interface Run {
    context: MergeContext;
    plan: ReplicaMergePlan;
    /** Connections whose connection-level issues this run already reported. */
    reported: Set<string>;
  }
  /**
   * Reconcile queued work. `background: false` leaves a paged pass's entries
   * queued (an import finishes only what its evidence marked). Without a
   * page it drains everything in scope; with one it stops once the page is
   * spent, after at least one entry.
   */
  function drain(input: { background: boolean; page?: ReplicaReconcilePage }): {
    plan: ReplicaMergePlan;
    complete: boolean;
  } {
    ingest();
    const run: Run = {
      context: { owner: deps.owner, declarations: deps.declarations() },
      plan: {
        records: [],
        conflicts: [],
        rejected: [],
        pending: [],
        suppressed: [],
      },
      reported: new Set(),
    };
    meter = { operations: 0, bytes: 0 };
    // Retained evidence does not change during a drain: ingest ran above.
    lifecycleCache = new Map();
    const next = sql(
      input.background
        ? "SELECT * FROM pdpp_replica_reconcile_queue ORDER BY kind, instance, stream, record_key LIMIT 1"
        : "SELECT * FROM pdpp_replica_reconcile_queue WHERE background = 0 ORDER BY kind, instance, stream, record_key LIMIT 1",
    );
    let processed = 0;
    for (;;) {
      if (
        input.page &&
        processed > 0 &&
        (meter.operations >= input.page.operations ||
          meter.bytes >= input.page.bytes)
      )
        break;
      const entry = next.get() as Entry | undefined;
      if (!entry) break;
      take(entry.kind, entry.instance, entry.stream, entry.record_key);
      processed++;
      stats.entries++;
      const background = entry.background === 1;
      if (entry.kind === CONNECTION)
        reconcileConnection(
          entry.instance,
          { background, expand: entry.expand === 1 },
          run,
        );
      else if (entry.kind === WITHDRAW)
        withdrawKey(entry.instance, entry.stream, entry.record_key);
      else if (entry.kind === KEY)
        reconcileKey(
          entry.instance,
          entry.stream,
          entry.record_key,
          background,
          run,
        );
      else reconcileCompletion(entry.instance, entry.stream, background, run);
    }
    return { plan: normalize(run.plan), complete: !queued() };
  }
  function queued(): boolean {
    return !!sql("SELECT 1 FROM pdpp_replica_reconcile_queue LIMIT 1").get();
  }

  return {
    /** Mark what an imported envelope can change, retained duplicates included. */
    touch(operations: readonly ReplicaOperation[]) {
      ingest();
      for (const op of operations) mark(op);
    },
    touchBlobs,
    /** Mark one key, e.g. a local write that completes a conflict. */
    touchKey(instance: string, stream: string, recordKey: string) {
      ingest();
      enqueue(KEY, instance, stream, recordKey);
    },
    /** Mark a connection whose quarantine fact changed outside a reconcile. */
    touchConnection(instance: string) {
      enqueue(CONNECTION, instance);
    },
    /**
     * Queue a full pass: every connection, expanded to all its keys and
     * completions. Needed when declarations or validators change.
     */
    beginPass() {
      ingest();
      enqueueAll(
        CONNECTION,
        "SELECT DISTINCT instance, '' AS stream, '' AS record_key FROM pdpp_replica_reconcile_bindings",
        [],
        true,
      );
      sql(
        "UPDATE pdpp_replica_reconcile_queue SET expand = 1 WHERE kind = ?",
      ).run(CONNECTION);
    },
    drain,
    queued,
    stats: (): ReplicaReconcileStats => ({ ...stats }),
  };
}

/** The planner's normalization over a plan assembled from many partial plans. */
function normalize(plan: ReplicaMergePlan): ReplicaMergePlan {
  const bucket = (issues: MergeIssue[]) => {
    const merged = new Map<string, MergeIssue>();
    // One host issue per reason lists every operation it holds, as before.
    for (const issue of issues) {
      const key =
        issue.reason === "missing_local_connection"
          ? issue.reason
          : canonicalJson(issue);
      const prior = merged.get(key);
      merged.set(
        key,
        prior
          ? {
              reason: issue.reason,
              operations: [...prior.operations, ...issue.operations],
            }
          : { reason: issue.reason, operations: [...issue.operations] },
      );
    }
    const unique = new Map<string, MergeIssue>();
    for (const entry of merged.values()) {
      entry.operations = [
        ...new Map(
          entry.operations.map((op) => [canonicalJson(op), op]),
        ).values(),
      ].sort((a, b) => compareText(canonicalJson(a), canonicalJson(b)));
      unique.set(canonicalJson(entry), entry);
    }
    return [...unique.values()].sort((a, b) =>
      compareText(canonicalJson(a), canonicalJson(b)),
    );
  };
  const records = [
    ...new Map(
      plan.records.map((record) => [canonicalJson(record.identity), record]),
    ).values(),
  ].sort((a, b) =>
    compareText(canonicalJson(a.identity), canonicalJson(b.identity)),
  );
  return {
    records,
    conflicts: bucket(plan.conflicts),
    rejected: bucket(plan.rejected),
    pending: bucket(plan.pending),
    suppressed: bucket(plan.suppressed),
  };
}
