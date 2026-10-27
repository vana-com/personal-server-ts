/**
 * Frozen reference model for PDPP record replication (oracle design §1).
 *
 * This file is the judge for every replica port. It must stay independent of
 * the code it judges: it does not import the merge planner, the record
 * reducer, the visibility policy, or any store. It restates the contract in
 * one recompute from retained evidence. Handwritten vectors in
 * `reference.test.ts` pin it, so the reference and a port cannot agree on a
 * defect by sharing code.
 *
 * Scope: one owner, single-field string primary keys (`id`), declarations
 * that only accumulate. Each projection is a step from the previous one,
 * because the contract keeps some state through missing evidence: a
 * connection with no registration or a reset gap keeps its rows, and a key
 * with no eligible operation keeps its row. Everything else is a pure
 * function of the retained evidence.
 */
import {
  canonicalJson,
  type DeclarationBinding,
  type RecordOperation,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";

export interface RefDeclaration {
  sourceId: string;
  binding: DeclarationBinding;
}
export interface RefMapping {
  sourceId: string;
  methodId: string;
}
/** Facts the host supplies. None of them comes from replicated evidence. */
export interface RefWorld {
  owner: string;
  /** Locally provisioned connections. Unmapped evidence is retained, never shown. */
  mappings: ReadonlyMap<string, RefMapping>;
  /** Trusted declarations. Data is valid when `data.id` is a string equal to the key. */
  declarations: readonly RefDeclaration[];
  /** Blob ids whose verified bytes this view can read. */
  bytes: ReadonlySet<string>;
  /** Connections with the absorbing terminal-quarantine fact. */
  terminal: ReadonlySet<string>;
}
export type RefRow =
  { deleted: true } | { deleted: false; data: Record<string, unknown> };
export interface RefState {
  /** Key: `rowId(connection, stream, key)`. Absent means never materialized. */
  rows: Map<string, RefRow>;
  /** Active generation per connection that has applied a reset. Default 1. */
  generations: Map<string, number>;
  /** Revision id (`revisionId`) of the operation each materialized row shows. */
  winners: Map<string, string>;
}
export type RefConnectionStatus =
  "unmapped" | "withdrawn" | "deleted" | "held" | "active";

export const rowId = (connection: string, stream: string, key: string) =>
  JSON.stringify([connection, stream, key]);
export const parseRowId = (id: string) =>
  JSON.parse(id) as [connection: string, stream: string, key: string];
export const emptyRefState = (): RefState => ({
  rows: new Map(),
  generations: new Map(),
  winners: new Map(),
});
export const cloneRefState = (state: RefState): RefState => ({
  rows: new Map(state.rows),
  generations: new Map(state.generations),
  winners: new Map(state.winners),
});

export const revisionId = (op: ReplicaOperation) =>
  JSON.stringify([op.revision.writerId, op.revision.operationId]);
/** Lamport order: counter, then writer id, then operation id, by code unit. */
function compareRevision(a: ReplicaOperation, b: ReplicaOperation): number {
  const left = [
    a.revision.counter,
    a.revision.writerId,
    a.revision.operationId,
  ];
  const right = [
    b.revision.counter,
    b.revision.writerId,
    b.revision.operationId,
  ];
  for (let i = 0; i < 3; i++) {
    if (left[i] < right[i]) return -1;
    if (left[i] > right[i]) return 1;
  }
  return 0;
}
const isRecord = (op: ReplicaOperation): op is RecordOperation =>
  op.kind === "upsert" || op.kind === "delete";

function declared(world: RefWorld, op: RecordOperation) {
  return world.declarations.some(
    (d) =>
      d.sourceId === op.sourceId &&
      canonicalJson(d.binding) === canonicalJson(op.declaration),
  );
}
function validData(op: RecordOperation): boolean {
  if (op.kind === "delete") return op.declaration.semantics !== "append_only";
  const id = op.data.id;
  return typeof id === "string" && id === op.recordKey;
}
function blobReady(
  world: RefWorld,
  op: Extract<RecordOperation, { kind: "upsert" }>,
  claims: readonly ReplicaOperation[],
): boolean {
  const ref = op.data.blob_ref as Record<string, unknown> | undefined;
  if (op.blobs.length !== (ref ? 1 : 0)) return false;
  return op.blobs.every(
    (blob) =>
      ref!.blob_id === blob.blobId &&
      (ref!.sha256 === undefined || ref!.sha256 === blob.sha256.slice(7)) &&
      (ref!.size_bytes === undefined || ref!.size_bytes === blob.sizeBytes) &&
      (ref!.mime_type === undefined || ref!.mime_type === blob.mimeType) &&
      world.bytes.has(blob.blobId) &&
      claims.some(
        (claim) =>
          claim.kind === "blob-claim" &&
          claim.generation === op.generation &&
          claim.sourceId === op.sourceId &&
          claim.methodId === op.methodId &&
          canonicalJson(claim.blob) === canonicalJson(blob),
      ),
  );
}

/** Variants per (writerId, operationId), after removing exact duplicates. */
function variantsOf(evidence: readonly ReplicaOperation[]) {
  const byId = new Map<string, Map<string, ReplicaOperation>>();
  for (const op of evidence) {
    const variants = byId.get(revisionId(op)) ?? new Map();
    variants.set(canonicalJson(op), op);
    byId.set(revisionId(op), variants);
  }
  return byId;
}

/** Why a connection shows nothing new, or "active" when its records apply. */
export function refConnectionStatus(
  world: RefWorld,
  evidence: readonly ReplicaOperation[],
  connection: string,
): { status: RefConnectionStatus; generation: number } {
  const mapping = world.mappings.get(connection);
  if (!mapping) return { status: "unmapped", generation: 1 };
  const owned = evidence.filter((op) => op.owner === world.owner);
  const variants = variantsOf(owned);
  const equivocated = new Set<string>();
  const unique: ReplicaOperation[] = [];
  for (const group of variants.values()) {
    const ops = [...group.values()];
    if (ops.length > 1) for (const op of ops) equivocated.add(op.connectionId);
    else unique.push(ops[0]);
  }
  const all = owned.filter((op) => op.connectionId === connection);
  const ops = unique.filter((op) => op.connectionId === connection);
  // A connection deletion suppresses the connection first.
  if (ops.some((op) => op.kind === "connection-delete"))
    return { status: "deleted", generation: 1 };
  // Equivocated variants still count as binding evidence.
  const bindings = new Set(
    all.map((op) => JSON.stringify([op.sourceId, op.methodId])),
  );
  if (
    world.terminal.has(connection) ||
    equivocated.has(connection) ||
    bindings.size > 1 ||
    all.some(
      (op) =>
        op.sourceId !== mapping.sourceId || op.methodId !== mapping.methodId,
    )
  )
    return { status: "withdrawn", generation: 1 };
  if (!ops.some((op) => op.kind === "connection-register"))
    return { status: "held", generation: 1 };
  const resets = ops.filter(
    (op): op is Extract<ReplicaOperation, { kind: "connection-reset" }> =>
      op.kind === "connection-reset",
  );
  if (resets.some((op) => op.generation !== op.previousGeneration + 1))
    return { status: "withdrawn", generation: 1 };
  const generation = Math.max(1, ...resets.map((op) => op.generation));
  const generations = new Set([1, ...resets.map((op) => op.generation)]);
  if (generations.size !== generation) return { status: "held", generation };
  return { status: "active", generation };
}

/** Operations whose revision id carries one content. */
function uniqueOps(owned: readonly ReplicaOperation[]) {
  return [...variantsOf(owned).values()]
    .filter((group) => group.size === 1)
    .map((group) => [...group.values()][0]);
}

/** Valid record operations of one connection and generation, grouped by key. */
function keyedCandidates(
  world: RefWorld,
  unique: readonly ReplicaOperation[],
  connection: string,
  generation: number,
) {
  const keys = new Map<string, RecordOperation[]>();
  for (const op of unique) {
    if (op.connectionId !== connection || !isRecord(op)) continue;
    if (op.generation !== generation) continue;
    if (!declared(world, op) || !validData(op)) continue;
    const id = rowId(connection, op.declaration.stream, op.recordKey);
    keys.set(id, [...(keys.get(id) ?? []), op]);
  }
  return keys;
}

/**
 * A key's candidates conflict when they name two declarations, or when an
 * append-only key carries two contents. A conflict hides the key for good.
 */
function keyConflicted(candidates: readonly RecordOperation[]) {
  const bindings = new Set(
    candidates.map((op) => canonicalJson(op.declaration)),
  );
  const contents = new Set(
    candidates.map((op) =>
      canonicalJson(
        op.kind === "upsert" ? { data: op.data, blobs: op.blobs } : null,
      ),
    ),
  );
  return (
    bindings.size > 1 ||
    (candidates[0].declaration.semantics === "append_only" && contents.size > 1)
  );
}

/**
 * Whether the retained evidence has already quarantined a key on the
 * connection's active generation. The receiver refuses ordinary collector
 * writes to such a key (receiver.md: corruption-quarantine fences).
 */
export function refKeyQuarantined(
  world: RefWorld,
  evidence: readonly ReplicaOperation[],
  connection: string,
  stream: string,
  key: string,
): boolean {
  const { status, generation } = refConnectionStatus(
    world,
    evidence,
    connection,
  );
  if (status !== "active") return false;
  const owned = evidence.filter((op) => op.owner === world.owner);
  const candidates = keyedCandidates(
    world,
    uniqueOps(owned),
    connection,
    generation,
  ).get(rowId(connection, stream, key));
  return candidates !== undefined && keyConflicted(candidates);
}

/** Recompute every mapped connection from the complete retained evidence. */
export function refProject(
  prior: RefState,
  world: RefWorld,
  evidence: readonly ReplicaOperation[],
): RefState {
  const next = cloneRefState(prior);
  const owned = evidence.filter((op) => op.owner === world.owner);
  const unique = uniqueOps(owned);
  const withdraw = (id: string) => {
    next.winners.delete(id);
    if (next.rows.get(id)?.deleted === false)
      next.rows.set(id, { deleted: true });
  };
  const rowsOf = (connection: string) =>
    [...next.rows.keys()].filter((id) => parseRowId(id)[0] === connection);
  for (const connection of world.mappings.keys()) {
    const { status, generation } = refConnectionStatus(
      world,
      owned,
      connection,
    );
    if (status === "held") continue;
    if (status === "withdrawn" || status === "deleted") {
      for (const id of rowsOf(connection)) withdraw(id);
      continue;
    }
    if (generation > (next.generations.get(connection) ?? 1)) {
      for (const id of rowsOf(connection)) withdraw(id);
      next.generations.set(connection, generation);
    }
    const claims = owned.filter((op) => op.connectionId === connection);
    for (const [id, candidates] of keyedCandidates(
      world,
      unique,
      connection,
      generation,
    )) {
      candidates.sort(compareRevision);
      const winner = candidates[candidates.length - 1];
      if (keyConflicted(candidates)) withdraw(id);
      else if (winner.kind === "delete") {
        next.rows.set(id, { deleted: true });
        next.winners.set(id, revisionId(winner));
      } else if (blobReady(world, winner, claims)) {
        next.rows.set(id, { deleted: false, data: winner.data });
        next.winners.set(id, revisionId(winner));
      } else withdraw(id);
    }
  }
  return next;
}

/** Live rows only; withdrawn and never-seen keys are both "not readable". */
export function refLive(state: RefState): Map<string, Record<string, unknown>> {
  const live = new Map<string, Record<string, unknown>>();
  for (const [id, row] of state.rows) if (!row.deleted) live.set(id, row.data);
  return live;
}

/**
 * Whether a local write is admissible: the connection is mapped, registered,
 * on its active generation, and neither withdrawn nor deleted. A rejected
 * local write must leave every durable fact unchanged.
 */
export function refLocalWritable(
  world: RefWorld,
  evidence: readonly ReplicaOperation[],
  op: RecordOperation,
): boolean {
  const { status, generation } = refConnectionStatus(
    world,
    evidence,
    op.connectionId,
  );
  return (
    status === "active" &&
    op.generation === generation &&
    declared(world, op) &&
    validData(op)
  );
}

/**
 * Owner rows that must carry the pending marker: live preview rows whose
 * winning operation exists only in pending custody, or whose content differs
 * from the confirmed row.
 */
export function refPendingRows(
  canon: RefState,
  preview: RefState,
  confirmed: readonly ReplicaOperation[],
): string[] {
  const known = new Set(confirmed.map(revisionId));
  const confirmedLive = refLive(canon);
  return [...refLive(preview)]
    .filter(
      ([id, data]) =>
        !known.has(preview.winners.get(id) ?? "") ||
        canonicalJson(data) !== canonicalJson(confirmedLive.get(id) ?? null),
    )
    .map(([id]) => id)
    .sort();
}
