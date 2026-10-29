/**
 * Visibility engine contracts (replication phase 2).
 *
 * One browser-safe boundary between retained replica evidence and what a
 * host may show. The host supplies facts: retained evidence, its own
 * connection mappings, trusted declarations, verified blob bytes and terminal
 * quarantine facts. `evaluate` turns a snapshot and one change into a
 * `ProjectionDelta`. The host then commits that delta and its own checkpoint
 * atomically against the epoch the delta was evaluated at, and receives a
 * `VisibilityReceipt` that binds the evidence digest to the new epoch.
 *
 * `evaluate` here is the reference: it recomputes from the complete retained
 * evidence through `planReplicaMerge`, the full-history oracle. A bounded
 * engine (per-key reducers over durable indexes, `connectionFromFacts`) must
 * produce the same projection. `record-reducer.test.ts` and the server
 * replica oracle hold both to that. No host calls this module yet.
 *
 * Authority stays with the host: mappings, declarations, verified bytes and
 * terminal facts are never read from replicated evidence.
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { encodeLiveSnapshotDigestInput } from "../storage/pdpp-records/completion.js";
import {
  completionDependenciesCovered,
  operationDigest,
  selectStreamCompletion,
  type CompletionOperation,
} from "./completion.js";
import {
  canonicalJson,
  declarationShape,
  exactJson,
  type RecordOperation,
  type ReplicaOperation,
} from "./envelope.js";
import {
  planReplicaMerge,
  type MergeContext,
  type MergedRecord,
  type ReplicaMergePlan,
} from "./merge-plan.js";
import type { ReplicaVisibilityState } from "./visibility-policy.js";

export type BlobDescriptor = Extract<
  ReplicaOperation,
  { kind: "blob-claim" }
>["blob"];
type Upsert = Extract<RecordOperation, { kind: "upsert" }>;
type Delete = Extract<RecordOperation, { kind: "delete" }>;
type CompletionEvent = Extract<
  ReplicaOperation,
  { kind: "stream-complete" | "stream-invalidate" }
>;

// ------------------------------------------------------------------ epochs

declare const epochBrand: unique symbol;
/**
 * Version of one committed projection. It advances exactly when a commit
 * changes the projection, so it never counts imports, retries or checkpoints.
 * Branded so a write clock, sequence or row version cannot stand in for it.
 */
export type VisibilityEpoch = number & { readonly [epochBrand]: true };
export function visibilityEpoch(value: number): VisibilityEpoch {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new RangeError("visibility epoch must be a non-negative integer");
  return value as VisibilityEpoch;
}
export const INITIAL_VISIBILITY_EPOCH = visibilityEpoch(0);

// ------------------------------------------------------------- host facts

/** Host-provisioned binding of a connection id. Never derived from evidence. */
export interface ConnectionMapping {
  sourceId: string;
  methodId: string;
}

/** Facts only the host may establish. None of them comes from a batch. */
export interface VisibilityWorld {
  readonly owner: string;
  /** Retained, digest-verified declarations; validation uses that exact schema. */
  readonly declarations: MergeContext["declarations"];
  /** Locally provisioned connections. Unmapped evidence is retained, never shown. */
  readonly mappings: ReadonlyMap<string, ConnectionMapping>;
  /** Blob ids whose bytes the host verified against their content address. */
  readonly verifiedBlobs: ReadonlySet<string>;
  /** Connections with the host's absorbing terminal-quarantine fact. */
  readonly terminal: ReadonlySet<string>;
}

// ------------------------------------------------------------- projection

export type ConnectionWithdrawal =
  | "terminal_quarantine"
  | "operation_id_equivocation"
  /** Evidence names another source or method than the local mapping. */
  | "local_mapping_conflict"
  /** Evidence names two sources or methods for one connection id. */
  | "source_binding_conflict"
  | "invalid_generation_reset";

/**
 * Lifecycle eligibility of one mapped connection. `generation` is the
 * generation the projection has applied: it only advances while active.
 * - active: its records apply.
 * - held: lifecycle evidence is missing; rows keep their last state.
 * - withdrawn: an integrity conflict hides every row until repair.
 * - deleted: a connection deletion hides every row for good.
 */
export type ConnectionProjection =
  | { readonly status: "active"; readonly generation: number }
  | {
      readonly status: "held";
      readonly reason:
        "missing_connection_registration" | "missing_generation_reset";
      readonly generation: number;
    }
  | {
      readonly status: "withdrawn";
      readonly reason: ConnectionWithdrawal;
      readonly generation: number;
    }
  | { readonly status: "deleted"; readonly generation: number };

export type RowWithdrawal =
  /** The key's own evidence conflicts (append-only content or declaration). */
  | "quarantined"
  /** The winner references bytes or a claim the host cannot verify. */
  | "blob_unavailable"
  | "connection_withdrawn"
  | "connection_deleted"
  /** A reset made the row's generation obsolete. */
  | "superseded_generation";

/**
 * One materialized key. A key that was never materialized has no entry, and
 * a withdrawal never creates one. Rows never disappear: withdrawn rows keep
 * a tombstone so cursors and change history can show the removal.
 */
export type RowProjection =
  | { readonly state: "live"; readonly winner: Upsert }
  | { readonly state: "deleted"; readonly winner: Delete }
  | { readonly state: "withdrawn"; readonly reason: RowWithdrawal };

/** Present only while the completion is available; absence is not a failure. */
export interface CompletionProjection {
  readonly operation: CompletionOperation;
}

export interface VisibilityProjection {
  /** Key: connection id. Only mapped connections appear. */
  readonly connections: Readonly<Record<string, ConnectionProjection>>;
  /** Key: `rowId(connectionId, stream, recordKey)`. */
  readonly rows: Readonly<Record<string, RowProjection>>;
  /** Key: `completionId(connectionId, stream)`. */
  readonly completions: Readonly<Record<string, CompletionProjection>>;
}
export const EMPTY_PROJECTION: VisibilityProjection = Object.freeze({
  connections: Object.freeze(dict<ConnectionProjection>()),
  rows: Object.freeze(dict<RowProjection>()),
  completions: Object.freeze(dict<CompletionProjection>()),
});

export const rowId = (
  connectionId: string,
  stream: string,
  recordKey: string,
) => JSON.stringify([connectionId, stream, recordKey]);
export const completionId = (connectionId: string, stream: string) =>
  JSON.stringify([connectionId, stream]);

/** A visible row's reference to bytes. Hosts keep extra retention freely. */
export interface BlobReference {
  readonly blobId: string;
  readonly connectionId: string;
  readonly generation: number;
}

// ------------------------------------------------------- evaluate contract

/** The committed state an evaluation starts from, plus every retained fact. */
export interface EvidenceSnapshot {
  readonly epoch: VisibilityEpoch;
  readonly projection: VisibilityProjection;
  readonly world: VisibilityWorld;
  /** The complete retained evidence: losers, conflicts and tombstones included. */
  readonly evidence: readonly ReplicaOperation[];
}

/**
 * One change. `evidence` is what a batch (or a local write) can carry:
 * operations and bytes the host has verified. `host` is host authority:
 * provisioning, declarations and terminal facts. Received bytes can never
 * produce a `host` change.
 */
export type EvidenceChange =
  | {
      readonly kind: "evidence";
      readonly operations: readonly ReplicaOperation[];
      readonly verifiedBlobs?: readonly string[];
    }
  | {
      readonly kind: "host";
      readonly provision?: Readonly<Record<string, ConnectionMapping>>;
      readonly declarations?: MergeContext["declarations"];
      readonly terminal?: readonly string[];
    };

/**
 * What one change does to the projection. Entries are complete replacement
 * values for every changed key; unchanged keys are absent.
 */
export interface ProjectionDelta {
  /** The epoch the delta was evaluated at. Commit refuses any other. */
  readonly base: VisibilityEpoch;
  /** `evidenceDigest` of the facts after the change. */
  readonly evidenceDigest: string;
  /** Lifecycle eligibility and identity/binding conflicts. */
  readonly connections: Readonly<Record<string, ConnectionProjection>>;
  /** Live rows, tombstones and withdrawals. */
  readonly rows: Readonly<Record<string, RowProjection>>;
  /** `null` withdraws availability. */
  readonly completions: Readonly<Record<string, CompletionProjection | null>>;
  readonly blobs: {
    readonly attach: readonly BlobReference[];
    readonly release: readonly BlobReference[];
  };
  /**
   * Connections whose integrity fence must advance in the same commit: their
   * eligibility, reason or generation changed, or a key started or stopped
   * being quarantined. A cursor issued before a fence must not resume across it.
   */
  readonly fences: readonly string[];
}

/** Reference evaluation: recompute the full projection, return the difference. */
export function evaluate(
  snapshot: EvidenceSnapshot,
  change: EvidenceChange,
): ProjectionDelta {
  const { world, evidence } = applyChange(snapshot, change);
  const next = projectEvidence(snapshot.projection, world, evidence);
  return diffProjection(
    snapshot.epoch,
    snapshot.projection,
    next,
    evidenceDigest(world, evidence),
  );
}

/** The facts after a change, for the next snapshot. */
export function applyChange(
  snapshot: Pick<EvidenceSnapshot, "world" | "evidence">,
  change: EvidenceChange,
): { world: VisibilityWorld; evidence: readonly ReplicaOperation[] } {
  const { world } = snapshot;
  if (change.kind === "evidence")
    return {
      world: {
        ...world,
        verifiedBlobs: new Set([
          ...world.verifiedBlobs,
          ...(change.verifiedBlobs ?? []),
        ]),
      },
      evidence: [...snapshot.evidence, ...change.operations],
    };
  return {
    world: {
      ...world,
      mappings: new Map([
        ...world.mappings,
        ...Object.entries(change.provision ?? {}),
      ]),
      declarations: [...world.declarations, ...(change.declarations ?? [])],
      terminal: new Set([...world.terminal, ...(change.terminal ?? [])]),
    },
    evidence: snapshot.evidence,
  };
}

// ------------------------------------------------------------ the reference

/**
 * Step the projection from the complete retained evidence. A step, not a pure
 * function of evidence: a held connection and a key without eligible
 * evidence keep their prior rows.
 */
export function projectEvidence(
  prior: VisibilityProjection,
  world: VisibilityWorld,
  evidence: readonly ReplicaOperation[],
): VisibilityProjection {
  const plan = planReplicaMerge(
    { owner: world.owner, declarations: world.declarations },
    evidence,
  );
  const owned = evidence.filter((op) => op.owner === world.owner);
  const connections = dict(prior.connections);
  const rows = dict(prior.rows);
  for (const [id, mapping] of [...world.mappings].sort(byKey)) {
    const applied = own(prior.connections, id)?.generation ?? 1;
    const ops = owned.filter((op) => op.connectionId === id);
    const connection = connectionFromPlan(
      plan,
      world,
      id,
      mapping,
      ops,
      applied,
    );
    connections[id] = connection;
    stepConnectionRows(rows, id, applied, connection);
    if (connection.status !== "active") continue;
    for (const record of plan.records) {
      const { identity } = record;
      if (identity.connectionId !== id) continue;
      const key = rowId(id, identity.stream, identity.recordKey);
      const row = recordRow(own(rows, key), record, (op) =>
        blobReady(op, ops, world.verifiedBlobs),
      );
      if (row) rows[key] = row;
    }
  }
  const projection = { connections, rows, completions: dict() };
  return {
    ...projection,
    completions: projectCompletions(plan, world, owned, projection),
  };
}

/** Connection eligibility from the planner's issues: the oracle derivation. */
function connectionFromPlan(
  plan: ReplicaMergePlan,
  world: VisibilityWorld,
  id: string,
  mapping: ConnectionMapping,
  ops: readonly ReplicaOperation[],
  applied: number,
): ConnectionProjection {
  const touches = (reason: string, bucket: ReplicaMergePlan["conflicts"]) =>
    bucket.some(
      (issue) =>
        issue.reason === reason &&
        issue.operations.some((op) => op.connectionId === id),
    );
  const withdrawn = (reason: ConnectionWithdrawal) =>
    ({ status: "withdrawn", reason, generation: applied }) as const;
  // As in `connectionFromFacts`: only a deletion under the mapping deletes.
  if (
    plan.suppressed.some(
      (issue) =>
        issue.reason === "connection_deleted" &&
        issue.operations.some(
          (op) =>
            op.connectionId === id &&
            op.kind === "connection-delete" &&
            sameBinding(op, mapping),
        ),
    )
  )
    return { status: "deleted", generation: applied };
  if (world.terminal.has(id)) return withdrawn("terminal_quarantine");
  if (touches("operation_id_equivocation", plan.conflicts))
    return withdrawn("operation_id_equivocation");
  if (ops.some((op) => !sameBinding(op, mapping)))
    return withdrawn("local_mapping_conflict");
  if (touches("incompatible_connection_binding", plan.conflicts))
    return withdrawn("source_binding_conflict");
  // A mapped connection without any evidence has no registration either.
  if (!ops.some((op) => op.kind === "connection-register"))
    return {
      status: "held",
      reason: "missing_connection_registration",
      generation: applied,
    };
  if (touches("invalid_generation_reset", plan.conflicts))
    return withdrawn("invalid_generation_reset");
  // A reset gap is connection-wide; a single future-generation record is not.
  if (
    plan.pending.some(
      (issue) =>
        issue.reason === "missing_generation_reset" &&
        issue.operations.some(
          (op) => op.connectionId === id && op.kind === "connection-register",
        ),
    )
  )
    return {
      status: "held",
      reason: "missing_generation_reset",
      generation: applied,
    };
  return { status: "active", generation: lifecycleGeneration(ops) };
}

function lifecycleGeneration(ops: readonly ReplicaOperation[]) {
  return Math.max(
    1,
    ...ops
      .filter((op) => op.kind === "connection-reset")
      .map((op) => op.generation),
  );
}

// -------------------------------------------- shared bounded-engine pieces

/**
 * What a bounded engine must know about one connection, from its durable
 * indexes, before it partitions records by key. The record reducer sees one
 * key; it cannot see a cross-key or cross-connection operation-id collision.
 */
export interface ConnectionFacts {
  readonly mapping: ConnectionMapping;
  readonly terminal: boolean;
  /** A retained operation of this connection shares its (writerId, operationId) with other bytes anywhere. */
  readonly equivocated: boolean;
  /** Every (sourceId, methodId) retained evidence names for this connection id, equivocated variants included. */
  readonly bindings: readonly ConnectionMapping[];
  /** Retained lifecycle operations whose revision id has one content globally. */
  readonly lifecycle: readonly ReplicaOperation[];
  /** The generation the committed projection has applied. */
  readonly appliedGeneration: number;
}

const sameBinding = (
  op: Pick<ReplicaOperation, "sourceId" | "methodId">,
  mapping: ConnectionMapping,
) => op.sourceId === mapping.sourceId && op.methodId === mapping.methodId;

/**
 * Whether retained evidence names another source or method than the host
 * mapping. In `connectionFromFacts` it ranks below deletion under the
 * mapping, terminal quarantine and equivocation; a host that keeps the
 * disagreement as its own durable fact records it whenever this holds.
 */
export function contradictsMapping(
  facts: Pick<ConnectionFacts, "mapping" | "bindings">,
): boolean {
  const mapped = canonicalJson(facts.mapping);
  return facts.bindings.some((binding) => canonicalJson(binding) !== mapped);
}

/**
 * Connection eligibility from bounded facts. Must equal the planner derivation.
 * Precedence: a deletion whose source and method match the mapping, then
 * terminal quarantine, equivocation and a binding conflict. A deletion that
 * names another binding is not about this connection: it never deletes, and
 * counts only as binding-conflict evidence.
 */
export function connectionFromFacts(
  context: MergeContext,
  facts: ConnectionFacts,
): ConnectionProjection {
  const applied = facts.appliedGeneration;
  const withdrawn = (reason: ConnectionWithdrawal) =>
    ({ status: "withdrawn", reason, generation: applied }) as const;
  const plan = planReplicaMerge(context, facts.lifecycle);
  const has = (bucket: ReplicaMergePlan["conflicts"], reason: string) =>
    bucket.some((issue) => issue.reason === reason);
  // `lifecycle` holds only unequivocated operations, as the planner's groups.
  if (
    facts.lifecycle.some(
      (op) => op.kind === "connection-delete" && sameBinding(op, facts.mapping),
    )
  )
    return { status: "deleted", generation: applied };
  if (facts.terminal) return withdrawn("terminal_quarantine");
  if (facts.equivocated) return withdrawn("operation_id_equivocation");
  if (contradictsMapping(facts)) return withdrawn("local_mapping_conflict");
  if (has(plan.conflicts, "incompatible_connection_binding"))
    return withdrawn("source_binding_conflict");
  if (!facts.lifecycle.some((op) => op.kind === "connection-register"))
    return {
      status: "held",
      reason: "missing_connection_registration",
      generation: applied,
    };
  if (has(plan.conflicts, "invalid_generation_reset"))
    return withdrawn("invalid_generation_reset");
  if (has(plan.pending, "missing_generation_reset"))
    return {
      status: "held",
      reason: "missing_generation_reset",
      generation: applied,
    };
  return { status: "active", generation: lifecycleGeneration(facts.lifecycle) };
}

/** Facts the host alone establishes for one connection. */
export type HostConnectionFacts = Pick<
  ConnectionFacts,
  "mapping" | "terminal" | "appliedGeneration"
>;

/**
 * `ConnectionFacts` and dependency variants from the complete retained
 * evidence, for a host that keeps every operation (the Node receiver). A
 * bounded host reads the same facts from its durable indexes instead.
 */
export function indexEvidence(owned: readonly ReplicaOperation[]) {
  const revision = (op: ReplicaOperation) =>
    canonicalJson([op.revision.writerId, op.revision.operationId]);
  /** Revision id -> digest -> variant. */
  const variants = new Map<string, Map<string, ReplicaOperation>>();
  const byConnection = new Map<string, ReplicaOperation[]>();
  for (const op of owned) {
    const id = revision(op);
    variants.set(
      id,
      (variants.get(id) ?? new Map()).set(operationDigest(op), op),
    );
    byConnection.set(op.connectionId, [
      ...(byConnection.get(op.connectionId) ?? []),
      op,
    ]);
  }
  const unique = (op: ReplicaOperation) =>
    variants.get(revision(op))!.size === 1;
  return {
    connectionFacts(
      connectionId: string,
      host: HostConnectionFacts,
    ): ConnectionFacts {
      const mine = byConnection.get(connectionId) ?? [];
      return {
        ...host,
        equivocated: mine.some((op) => !unique(op)),
        bindings: mine.map(({ sourceId, methodId }) => ({
          sourceId,
          methodId,
        })),
        lifecycle: mine.filter(
          (op) => op.kind.startsWith("connection-") && unique(op),
        ),
      };
    },
    /** `CompletionFacts.variantDigests` over the connections `mapped` accepts. */
    variantDigests(mapped: (connectionId: string) => boolean) {
      return (writerId: string, operationId: string) =>
        [
          ...(variants.get(canonicalJson([writerId, operationId])) ?? []),
        ].flatMap(([digest, op]) => (mapped(op.connectionId) ? [digest] : []));
    },
  };
}

/**
 * Apply one connection's eligibility to its existing rows: withdraw them all
 * when it is withdrawn or deleted, or when its generation advances.
 */
export function stepConnectionRows(
  rows: Record<string, RowProjection>,
  connectionId: string,
  appliedGeneration: number,
  connection: ConnectionProjection,
) {
  const reason: RowWithdrawal | undefined =
    connection.status === "withdrawn"
      ? "connection_withdrawn"
      : connection.status === "deleted"
        ? "connection_deleted"
        : connection.status === "active" &&
            connection.generation > appliedGeneration
          ? "superseded_generation"
          : undefined;
  if (!reason) return;
  for (const key of Object.keys(rows))
    if ((JSON.parse(key) as string[])[0] === connectionId)
      rows[key] = { state: "withdrawn", reason };
}

/**
 * The row one merged record yields on an active connection, from its prior
 * row. Undefined means "no entry": a withdrawal never materializes a key.
 */
export function recordRow(
  prior: RowProjection | undefined,
  record: Pick<MergedRecord, "winner" | "quarantined">,
  blobReady: (winner: Upsert) => boolean,
): RowProjection | undefined {
  const withdraw = (reason: RowWithdrawal) =>
    prior ? ({ state: "withdrawn", reason } as const) : undefined;
  const winner = record.winner;
  if (record.quarantined || !winner) return withdraw("quarantined");
  if (winner.kind === "delete") return { state: "deleted", winner };
  return blobReady(winner)
    ? { state: "live", winner }
    : withdraw("blob_unavailable");
}

/**
 * Whether an upsert's bytes may be shown: its `blob_ref` agrees with its one
 * descriptor, the connection claims that descriptor at the same generation
 * and binding, and the host verified the bytes.
 */
export function blobReady(
  op: Upsert,
  claims: readonly ReplicaOperation[],
  verifiedBlobs: ReadonlySet<string>,
): boolean {
  const ref = op.data.blob_ref as Record<string, unknown> | undefined;
  if (op.blobs.length !== (ref ? 1 : 0)) return false;
  return op.blobs.every(
    (blob) =>
      ref!.blob_id === blob.blobId &&
      (ref!.sha256 === undefined || ref!.sha256 === blob.sha256.slice(7)) &&
      (ref!.size_bytes === undefined || ref!.size_bytes === blob.sizeBytes) &&
      (ref!.mime_type === undefined || ref!.mime_type === blob.mimeType) &&
      verifiedBlobs.has(blob.blobId) &&
      claims.some(
        (claim) =>
          claim.kind === "blob-claim" &&
          claim.connectionId === op.connectionId &&
          claim.generation === op.generation &&
          claim.sourceId === op.sourceId &&
          claim.methodId === op.methodId &&
          canonicalJson(claim.blob) === canonicalJson(blob),
      ),
  );
}

// ------------------------------------------------------------- completions

/** Everything one completion decision needs. A bounded engine reads it from indexes. */
export interface CompletionFacts {
  readonly connection: ConnectionProjection;
  readonly connectionId: string;
  /** Completion and invalidation events of this connection, generation and stream. */
  readonly events: readonly CompletionEvent[];
  readonly declarations: MergeContext["declarations"];
  /** A key of the stream is quarantined at this generation. */
  readonly quarantinedKey: boolean;
  /** An unresolved pending, conflicting or rejected operation touches the stream. */
  readonly unresolved: boolean;
  /**
   * Distinct digests of every retained variant of an operation id in a
   * host-mapped connection. Unmapped evidence never satisfies a dependency;
   * an unmapped variant that differs already withdraws the mapped connection
   * holding the other variant.
   */
  readonly variantDigests: (
    writerId: string,
    operationId: string,
  ) => readonly string[];
  /** The stream's live rows in the projection being committed. */
  readonly liveRows: readonly { recordKey: string; dataJson: string }[];
}

/**
 * The available completion, or null. Available means: the connection is
 * active on the events' generation, no key of the stream is quarantined, the
 * events under declarations the host trusts name exactly one declaration
 * shape (`declarationShape`),
 * the newest of those events is a completion, every dependency has exactly one retained variant with the
 * pinned digest, nothing touching the stream is unresolved, and the live rows
 * match the declared count and snapshot digest.
 */
export function completionAvailability(
  facts: CompletionFacts,
): CompletionProjection | null {
  const trusted = (op: CompletionEvent) =>
    facts.declarations.find(
      (entry) =>
        entry.sourceId === op.sourceId &&
        canonicalJson(entry.binding) === canonicalJson(op.declaration),
    );
  // An event under a declaration the host does not trust waits for it, as
  // an undeclared record operation does; it neither certifies nor withdraws.
  const events = facts.events.filter(trusted);
  const first = events[0];
  if (!first) return null;
  if (
    facts.connection.status !== "active" ||
    facts.connection.generation !== first.generation ||
    facts.quarantinedKey ||
    facts.unresolved
  )
    return null;
  // Versions of one declared stream (a rebinding) certify one stream; a
  // changed shape does not.
  if (new Set(events.map((op) => declarationShape(op.declaration))).size > 1)
    return null;
  const declaration = trusted(first)!;
  const completion = selectStreamCompletion(events);
  if (!completion) return null;
  if (!completionDependenciesCovered(completion, facts.variantDigests))
    return null;
  if (facts.liveRows.length !== completion.liveCount) return null;
  let digest: string;
  try {
    digest = `sha256:${bytesToHex(
      sha256(
        encodeLiveSnapshotDigestInput(
          {
            sourceId: first.sourceId,
            instance: facts.connectionId,
            method: first.methodId,
            generation: first.generation,
            stream: first.declaration.stream,
          },
          declaration.binding.primaryKey,
          facts.liveRows,
        ),
      ),
    )}`;
  } catch {
    return null;
  }
  if (digest !== completion.snapshotSha256) return null;
  if (
    completion.proof.kind === "native" &&
    completion.proof.snapshotSha256 !== completion.snapshotSha256
  )
    return null;
  return { operation: completion };
}

/** The reference: every mapped stream's completion from the full plan. */
function projectCompletions(
  plan: ReplicaMergePlan,
  world: VisibilityWorld,
  owned: readonly ReplicaOperation[],
  projection: Omit<VisibilityProjection, "completions">,
): Record<string, CompletionProjection> {
  const digests = new Map<string, Set<string>>();
  for (const op of owned) {
    if (!world.mappings.has(op.connectionId)) continue;
    const id = canonicalJson([op.revision.writerId, op.revision.operationId]);
    digests.set(id, (digests.get(id) ?? new Set()).add(operationDigest(op)));
  }
  const variantDigests = (writerId: string, operationId: string) => [
    ...(digests.get(canonicalJson([writerId, operationId])) ?? []),
  ];
  const groups = new Map<string, CompletionEvent[]>();
  for (const op of owned) {
    if (op.kind !== "stream-complete" && op.kind !== "stream-invalidate")
      continue;
    const connection = own(projection.connections, op.connectionId);
    if (!connection || connection.generation !== op.generation) continue;
    const key = completionId(op.connectionId, op.declaration.stream);
    groups.set(key, [...(groups.get(key) ?? []), op]);
  }
  const issues = [...plan.pending, ...plan.conflicts, ...plan.rejected];
  const result = dict<CompletionProjection>();
  for (const [key, events] of [...groups].sort(byKey)) {
    const [connectionId, stream] = JSON.parse(key) as [string, string];
    // Grouped above only when the connection is projected.
    const connection = own(projection.connections, connectionId)!;
    const inStream = (op: ReplicaOperation) =>
      op.connectionId === connectionId &&
      (!("declaration" in op) || op.declaration.stream === stream);
    const liveRows: { recordKey: string; dataJson: string }[] = [];
    for (const [id, row] of Object.entries(projection.rows)) {
      const [rowConnection, rowStream, recordKey] = JSON.parse(id) as string[];
      if (rowConnection !== connectionId || rowStream !== stream) continue;
      if (row.state === "live")
        liveRows.push({ recordKey, dataJson: canonicalJson(row.winner.data) });
    }
    const records = plan.records.filter(
      (record) =>
        record.identity.connectionId === connectionId &&
        record.identity.generation === connection.generation &&
        record.identity.stream === stream,
    );
    const claims = owned.filter((op) => op.connectionId === connectionId);
    const available = completionAvailability({
      connection,
      connectionId,
      events,
      declarations: world.declarations,
      quarantinedKey: records.some((record) => record.quarantined),
      // An unmaterializable winner is unresolved even if it never had a row.
      unresolved:
        records.some(
          (record) =>
            record.winner?.kind === "upsert" &&
            !blobReady(record.winner, claims, world.verifiedBlobs),
        ) ||
        issues.some(
          (issue) =>
            issue.reason !== "missing_declaration" &&
            issue.operations.some(inStream),
        ),
      variantDigests,
      liveRows,
    });
    if (available) result[key] = available;
  }
  return result;
}

// ------------------------------------------------------------------ deltas

/** The delta that turns `prior` into `next`. */
export function diffProjection(
  base: VisibilityEpoch,
  prior: VisibilityProjection,
  next: VisibilityProjection,
  digest: string,
): ProjectionDelta {
  const changed = <T>(
    before: Readonly<Record<string, T>>,
    after: Readonly<Record<string, T>>,
  ) => {
    const out = dict<T>();
    for (const key of Object.keys(after).sort())
      if (exactJson(own(before, key) ?? null) !== exactJson(after[key]))
        out[key] = after[key];
    return out;
  };
  const completions: Record<string, CompletionProjection | null> = changed(
    prior.completions,
    next.completions,
  );
  for (const key of Object.keys(prior.completions))
    if (!Object.hasOwn(next.completions, key)) completions[key] = null;
  const connections = changed(prior.connections, next.connections);
  const rows = changed(prior.rows, next.rows);
  const fences = new Set(Object.keys(connections));
  const quarantined = (row: RowProjection | undefined) =>
    row?.state === "withdrawn" && row.reason === "quarantined";
  for (const key of Object.keys(rows))
    if (quarantined(own(prior.rows, key)) !== quarantined(rows[key]))
      fences.add((JSON.parse(key) as string[])[0]);
  const before = blobReferences(prior);
  const after = blobReferences(next);
  return {
    base,
    evidenceDigest: digest,
    connections,
    rows,
    completions,
    blobs: {
      attach: [...after.keys()]
        .filter((k) => !before.has(k))
        .sort()
        .map((k) => after.get(k)!),
      release: [...before.keys()]
        .filter((k) => !after.has(k))
        .sort()
        .map((k) => before.get(k)!),
    },
    fences: [...fences].sort(),
  };
}

function blobReferences(projection: VisibilityProjection) {
  const refs = new Map<string, BlobReference>();
  for (const [id, row] of Object.entries(projection.rows)) {
    if (row.state !== "live") continue;
    const connectionId = (JSON.parse(id) as string[])[0];
    for (const blob of row.winner.blobs) {
      const ref = {
        blobId: blob.blobId,
        connectionId,
        generation: row.winner.generation,
      };
      refs.set(canonicalJson(ref), ref);
    }
  }
  return refs;
}

export function isEmptyDelta(delta: ProjectionDelta): boolean {
  return (
    !Object.keys(delta.connections).length &&
    !Object.keys(delta.rows).length &&
    !Object.keys(delta.completions).length &&
    !delta.blobs.attach.length &&
    !delta.blobs.release.length &&
    !delta.fences.length
  );
}

export function applyProjectionDelta(
  projection: VisibilityProjection,
  delta: ProjectionDelta,
): VisibilityProjection {
  const completions = dict(projection.completions);
  for (const [key, value] of Object.entries(delta.completions))
    if (value === null) delete completions[key];
    else completions[key] = value;
  return {
    connections: dict(projection.connections, delta.connections),
    rows: dict(projection.rows, delta.rows),
    completions,
  };
}

// ----------------------------------------------------------------- digests

const hash = (text: string) =>
  `sha256:${bytesToHex(sha256(new TextEncoder().encode(text)))}`;

/**
 * Digest of the facts a projection derives from. It names the evidence SET:
 * equal retained evidence and host facts give equal digests, whatever the
 * delivery order or duplication. Declaration validators are host code and
 * are identified by their binding.
 */
export function evidenceDigest(
  world: VisibilityWorld,
  evidence: readonly ReplicaOperation[],
): string {
  const sorted = (values: Iterable<string>) => [...new Set(values)].sort();
  return hash(
    exactJson({
      owner: world.owner,
      declarations: sorted(
        world.declarations.map((d) =>
          exactJson({ sourceId: d.sourceId, binding: d.binding }),
        ),
      ),
      mappings: sorted(
        [...world.mappings].map(([id, mapping]) => exactJson([id, mapping])),
      ),
      verifiedBlobs: sorted(world.verifiedBlobs),
      terminal: sorted(world.terminal),
      evidence: sorted(evidence.map((op) => hash(exactJson(op)))),
    }),
  );
}

// ------------------------------------------------------------ commit contract

/** Host-owned durable progress, committed in the same transaction. `null` deletes. */
export type CheckpointDelta = Readonly<Record<string, string | null>>;

export interface VisibilityReceipt {
  /** The epoch after the commit; equal to `previous` when nothing visible changed. */
  readonly epoch: VisibilityEpoch;
  readonly previous: VisibilityEpoch;
  readonly evidenceDigest: string;
  readonly deltaDigest: string;
  readonly checkpointDigest: string;
}

export class VisibilityEpochConflict extends Error {
  constructor(
    readonly expected: VisibilityEpoch,
    readonly actual: VisibilityEpoch,
  ) {
    super(`visibility epoch is ${actual}, expected ${expected}`);
    this.name = "VisibilityEpochConflict";
  }
}

/**
 * Host port. One atomic transaction: check that the committed epoch is
 * `expected` (and `delta.base`), apply the projection delta with its fences,
 * blob references and completions, apply the checkpoint, and advance the
 * epoch by one if and only if the delta is not empty. The host stores each
 * commit's `commitRequestDigest` with its receipt in the same transaction.
 * Retrying any committed request, even after later commits, returns its
 * original receipt and changes nothing. Any other stale commit throws
 * `VisibilityEpochConflict` and changes nothing; the caller re-evaluates
 * from a fresh snapshot. Known limit: receipt retention grows without bound,
 * one entry per distinct committed request; A5/A7 must bound it.
 */
export interface VisibilityCommitter {
  commit(
    expected: VisibilityEpoch,
    delta: ProjectionDelta,
    checkpoint: CheckpointDelta,
  ): Promise<VisibilityReceipt>;
}

export function deltaDigest(delta: ProjectionDelta): string {
  return hash(exactJson(delta));
}
export function checkpointDigest(checkpoint: CheckpointDelta): string {
  return hash(exactJson(checkpoint));
}
/** Identifies one commit request, for lost-acknowledgement replay. */
export function commitRequestDigest(
  expected: VisibilityEpoch,
  delta: ProjectionDelta,
  checkpoint: CheckpointDelta,
): string {
  return hash(
    exactJson([expected, deltaDigest(delta), checkpointDigest(checkpoint)]),
  );
}

/** Reference committer: the semantics every host committer must match. */
export function createMemoryVisibilityCommitter(
  initial: {
    epoch?: VisibilityEpoch;
    projection?: VisibilityProjection;
    checkpoint?: Readonly<Record<string, string>>;
  } = {},
) {
  let epoch = initial.epoch ?? INITIAL_VISIBILITY_EPOCH;
  let projection = initial.projection ?? EMPTY_PROJECTION;
  const checkpoint = dict<string>(initial.checkpoint ?? {});
  const receipts = new Map<string, VisibilityReceipt>();
  const committer: VisibilityCommitter & {
    read(): {
      epoch: VisibilityEpoch;
      projection: VisibilityProjection;
      checkpoint: Readonly<Record<string, string>>;
    };
  } = {
    async commit(expected, delta, changes) {
      const request = commitRequestDigest(expected, delta, changes);
      const committed = receipts.get(request);
      if (committed) return committed;
      if (delta.base !== expected || epoch !== expected)
        throw new VisibilityEpochConflict(expected, epoch);
      const receipt: VisibilityReceipt = {
        epoch: isEmptyDelta(delta) ? expected : visibilityEpoch(expected + 1),
        previous: expected,
        evidenceDigest: delta.evidenceDigest,
        deltaDigest: deltaDigest(delta),
        checkpointDigest: checkpointDigest(changes),
      };
      projection = applyProjectionDelta(projection, delta);
      for (const [key, value] of Object.entries(changes))
        if (value === null) delete checkpoint[key];
        else checkpoint[key] = value;
      epoch = receipt.epoch;
      receipts.set(request, receipt);
      return receipt;
    },
    read: () => ({ epoch, projection, checkpoint: dict(checkpoint) }),
  };
  return committer;
}

// ------------------------------------------------------- reader visibility

/**
 * The reader-policy state of a connection's data, for `replicaStateVisible`.
 * A binding conflict is "conflicted": the owner keeps seeing local-origin
 * rows with the conflict marker. Any other withdrawal is "quarantined".
 */
export function connectionVisibilityState(
  connection: ConnectionProjection,
): ReplicaVisibilityState {
  if (connection.status === "active") return "confirmed";
  if (connection.status === "held") return "pending";
  if (
    connection.status === "withdrawn" &&
    (connection.reason === "local_mapping_conflict" ||
      connection.reason === "source_binding_conflict")
  )
    return "conflicted";
  return "quarantined";
}

// ----------------------------------------------------------------- helpers

/**
 * A dictionary keyed by host strings. It has no prototype, so a connection id
 * or checkpoint key such as `__proto__` or `constructor` is an ordinary key.
 */
function dict<T>(...sources: Readonly<Record<string, T>>[]): Record<string, T> {
  const out = Object.create(null) as Record<string, T>;
  for (const source of sources)
    for (const key of Object.keys(source)) out[key] = source[key];
  return out;
}

/** Own-property lookup: never an inherited member. */
function own<T>(
  record: Readonly<Record<string, T>>,
  key: string,
): T | undefined {
  return Object.hasOwn(record, key) ? record[key] : undefined;
}

function byKey<T>(a: [string, T], b: [string, T]) {
  return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
}
