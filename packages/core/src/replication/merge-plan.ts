import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import { canonicalJson, replicaOperationSchema } from "./envelope.js";
import type {
  DeclarationBinding,
  RecordOperation,
  ReplicaOperation,
  SourceObservation,
  UpstreamAccount,
} from "./envelope.js";
import { connectionKey } from "./identity.js";
import { compareRevisions } from "./revision.js";

export const OWNER_DELETE_GRACE_PERIOD_MS = 30 * 24 * 60 * 60 * 1000;
export const REPLICA_POLICY = {
  mutableOrder:
    "source-version-dominance, then known-order-by-frontier, then finality-capped-observation-time, then hlc-logical-writer-operation",
  uncertaintyWindowMs: 300_000,
  retainLosers: true,
  sourceObservationsOrderDeletes: "by-observation-order",
  ownerRemoval: "remove-wins, explicit restore only",
  appendOnlyConflict: "quarantine-until-separately-authorized-repair",
  authorization: "single-issuer-data-and-connection-evidence-only",
} as const;

export interface MergeContext {
  owner: string;
  declarations: readonly {
    sourceId: string;
    binding: DeclarationBinding;
    validateData: (data: Record<string, unknown>) => boolean;
  }[];
  /** Finalized block time by batch; missing means the batch is still unfinalized. */
  finalizedAt?: (batchId: string) => number | undefined;
  now?: number;
  /** Record keys already re-observed during the current daily refresh window. */
  reobservedRecordKeys?: readonly string[];
}
export interface MergeIssue {
  reason: string;
  operations: ReplicaOperation[];
}
export type RecordState = "settled" | "unsettled" | "conflict" | "quarantined";
export interface MergedRecord {
  identity: {
    owner: string;
    sourceId: string;
    connectionId: string;
    generation: number;
    stream: string;
    recordKey: string;
  };
  current: RecordOperation | null;
  candidates: RecordOperation[];
  state: RecordState;
  ownerControl: "visible" | "hidden" | "deleted";
  refreshRequested: boolean;
  flags: string[];
  payloadRetained: boolean;
  suppressionMarker: {
    recordKey: string;
    observations: {
      operationId: string;
      contentHash: string;
      observedAt: string;
      finalizedAt: number | null;
    }[];
    removals: {
      operationId: string;
      deletedAt: number;
      finalizedAt: number;
    }[];
  } | null;
}
export interface ReplicaMergePlan {
  records: MergedRecord[];
  conflicts: MergeIssue[];
  rejected: MergeIssue[];
  pending: MergeIssue[];
  suppressed: MergeIssue[];
  quarantined: MergeIssue[];
}

/** Recompute the derived view from the complete retained operation set. */
export function planReplicaMerge(
  context: MergeContext,
  input: readonly ReplicaOperation[],
): ReplicaMergePlan {
  const result: ReplicaMergePlan = {
    records: [],
    conflicts: [],
    rejected: [],
    pending: [],
    suppressed: [],
    quarantined: [],
  };
  const issue = (
    bucket: MergeIssue[],
    reason: string,
    operations: ReplicaOperation[],
  ) => bucket.push({ reason, operations });
  const byId = new Map<string, Map<string, ReplicaOperation>>();
  for (const raw of input) {
    const operation = replicaOperationSchema.parse(raw);
    if (operation.owner !== context.owner) {
      issue(result.rejected, "wrong_owner", [operation]);
      continue;
    }
    const id = canonicalJson([
      operation.revision.writerId,
      operation.revision.operationId,
    ]);
    const variants = byId.get(id) ?? new Map<string, ReplicaOperation>();
    variants.set(canonicalJson(operation), operation);
    byId.set(id, variants);
  }
  const equivocated = new Set<string>();
  const operations: ReplicaOperation[] = [];
  for (const variants of byId.values()) {
    if (variants.size > 1) {
      const colliding = [...variants.values()];
      colliding.forEach((op) => equivocated.add(connectionKey(op)));
      issue(result.quarantined, "operation_id_equivocation", colliding);
    } else operations.push([...variants.values()][0]);
  }
  const operationIds = new Set(operations.map((op) => op.revision.operationId));
  const incompleteResolutions = new Set<string>();
  const resolutionById = new Map(
    operations
      .filter((op) => op.kind === "owner-resolve")
      .map((op) => [op.revision.operationId, op]),
  );
  const resolutionPath: string[] = [];
  const resolutionCycles = new Set<string>();
  const visitedResolutions = new Set<string>();
  const visitResolution = (id: string): void => {
    const pathIndex = resolutionPath.indexOf(id);
    if (pathIndex >= 0) {
      resolutionPath
        .slice(pathIndex)
        .forEach((cycleId) => resolutionCycles.add(cycleId));
      return;
    }
    if (visitedResolutions.has(id)) return;
    const resolution = resolutionById.get(id);
    if (!resolution) return;
    resolutionPath.push(id);
    resolution.candidates.forEach(visitResolution);
    resolutionPath.pop();
    visitedResolutions.add(id);
  };
  resolutionById.forEach((_resolution, id) => visitResolution(id));
  for (const id of resolutionCycles) {
    const resolution = resolutionById.get(id);
    if (resolution) {
      incompleteResolutions.add(id);
      issue(result.rejected, "resolution_cycle", [resolution]);
    }
  }
  for (const op of operations) {
    if (
      op.kind === "owner-resolve" &&
      op.candidates.some((candidate) => !operationIds.has(candidate))
    ) {
      incompleteResolutions.add(op.revision.operationId);
      issue(result.pending, "resolution_dependency_missing", [op]);
    }
  }
  const connections = new Map<string, ReplicaOperation[]>();
  const sourceBindings = new Map<string, Set<string>>();
  for (const op of operations) {
    const key = connectionKey(op);
    connections.set(key, [...(connections.get(key) ?? []), op]);
    const logicalId = canonicalJson([op.owner, op.connectionId]);
    sourceBindings.set(
      logicalId,
      (sourceBindings.get(logicalId) ?? new Set()).add(op.sourceId),
    );
  }
  for (const [key, entries] of connections) {
    if (equivocated.has(key)) continue;
    if (
      sourceBindings.get(
        canonicalJson([entries[0].owner, entries[0].connectionId]),
      )!.size > 1
    ) {
      issue(result.quarantined, "incompatible_connection_binding", entries);
      continue;
    }
    const registrations = entries.filter(
      (op) => op.kind === "connection-register",
    );
    if (!registrations.length) {
      issue(result.pending, "missing_connection_registration", entries);
      continue;
    }
    const boundAccount = registrations[0].upstreamAccount;
    if (
      new Set(registrations.map((op) => canonicalJson(op.upstreamAccount)))
        .size > 1
    ) {
      issue(
        result.quarantined,
        "connection_account_binding_conflict",
        registrations,
      );
      continue;
    }
    const mismatches = entries.filter(
      (op) => !sameAccount(op.upstreamAccount, boundAccount),
    );
    if (mismatches.length) {
      issue(result.quarantined, "upstream_account_mismatch", mismatches);
      entries.splice(
        0,
        entries.length,
        ...entries.filter((op) =>
          sameAccount(op.upstreamAccount, boundAccount),
        ),
      );
    }
    if (entries.some((op) => op.kind === "connection-delete")) {
      issue(result.suppressed, "connection_deleted", entries);
      continue;
    }
    const methods = new Set(entries.map((op) => op.methodId));
    const sources = new Set(entries.map((op) => op.sourceId));
    if (methods.size !== 1 || sources.size !== 1) {
      issue(result.quarantined, "incompatible_connection_binding", entries);
      continue;
    }
    const resets = entries.filter((op) => op.kind === "connection-reset");
    if (resets.some((op) => op.generation !== op.previousGeneration + 1)) {
      issue(result.conflicts, "invalid_generation_reset", entries);
      continue;
    }
    const generation = Math.max(1, ...resets.map((op) => op.generation));
    if (
      new Set([1, ...resets.map((op) => op.generation)]).size !== generation
    ) {
      issue(result.pending, "missing_generation_reset", entries);
      continue;
    }
    const groups = new Map<string, RecordOperation[]>();
    for (const op of entries) {
      if (
        op.kind === "owner-resolve" &&
        incompleteResolutions.has(op.revision.operationId)
      )
        continue;
      if (!("declaration" in op)) continue;
      if (op.generation < generation) {
        issue(result.suppressed, "old_generation", [op]);
        continue;
      }
      if (op.generation > generation) {
        issue(result.pending, "missing_generation_reset", [op]);
        continue;
      }
      const declared = context.declarations.find(
        (d) =>
          d.sourceId === op.sourceId &&
          canonicalJson(d.binding) === canonicalJson(op.declaration),
      );
      if (!declared) {
        issue(result.pending, "missing_declaration", [op]);
        continue;
      }
      if (
        op.kind === "source-delete" &&
        op.origin === "complete-scan" &&
        !declared.binding.completeScanDeletes
      ) {
        issue(result.rejected, "undeclared_complete_scan_delete", [op]);
        continue;
      }
      if (
        (op.kind === "upsert" || op.kind === "source-delete") &&
        op.sourceVersion
      ) {
        const order = declared.binding.sourceVersionOrder;
        const validVersion =
          order === "ordered-integer"
            ? /^\d+$/.test(op.sourceVersion.value)
            : order === "ordered-rfc3339"
              ? !Number.isNaN(Date.parse(op.sourceVersion.value))
              : order === "equality-only";
        if (!validVersion) {
          issue(result.rejected, "invalid_source_version", [op]);
          continue;
        }
      }
      if (op.kind === "upsert") {
        let valid = false;
        try {
          valid =
            computeRecordKeyFromData(op.data, declared.binding.primaryKey) ===
              op.recordKey && declared.validateData(op.data);
        } catch {
          /* invalid payload */
        }
        if (!valid) {
          issue(result.rejected, "invalid_record_data", [op]);
          continue;
        }
        if (op.sourceVersion && op.sourceVersion.domain.length === 0) {
          issue(result.rejected, "invalid_source_version", [op]);
          continue;
        }
      }
      const recordId = canonicalJson([op.declaration.stream, op.recordKey]);
      groups.set(recordId, [...(groups.get(recordId) ?? []), op]);
    }
    for (const values of groups.values()) {
      const record = mergeRecord(context, values);
      result.records.push(record);
      if (record.state === "conflict")
        issue(result.conflicts, "source_observation_conflict", values);
      if (record.state === "quarantined")
        issue(
          result.quarantined,
          record.flags.includes("incompatible-declaration")
            ? "incompatible_record_declaration"
            : "append_only_content_conflict",
          values,
        );
    }
  }
  normalizeIssues(result);
  result.records.sort((a, b) =>
    text(canonicalJson(a.identity), canonicalJson(b.identity)),
  );
  return result;
}

/** App projection: only confirmed values without quarantine or owner suppression. */
export function appView(record: MergedRecord): RecordOperation | null {
  if (
    record.state === "quarantined" ||
    record.ownerControl !== "visible" ||
    !record.payloadRetained
  )
    return null;
  if (!record.current || record.current.kind !== "upsert") return null;
  if (
    (record.state === "unsettled" || record.state === "conflict") &&
    record.candidates.some((candidate) => candidate.kind === "source-delete")
  )
    return null;
  return record.current;
}

function mergeRecord(
  context: MergeContext,
  input: RecordOperation[],
): MergedRecord {
  const all = dedupe(input);
  const observations = all.filter(
    (op): op is SourceObservation =>
      op.kind === "upsert" || op.kind === "source-delete",
  );
  const ownerOps = all.filter((op) => op.kind.startsWith("owner-"));
  const activeRemovals = ownerOps
    .filter((op) => op.kind === "owner-hide" || op.kind === "owner-delete")
    .filter(
      (remove) =>
        !ownerOps.some(
          (restore) =>
            restore.kind === "owner-restore" &&
            restore.parents.includes(remove.revision.operationId),
        ),
    );
  const ownerControl = activeRemovals.some((op) => op.kind === "owner-delete")
    ? "deleted"
    : activeRemovals.length
      ? "hidden"
      : "visible";
  const finalizedAt = (op: RecordOperation) =>
    op.batchId ? context.finalizedAt?.(op.batchId) : undefined;
  const purgedDeletes = ownerOps.filter(
    (op) =>
      op.kind === "owner-delete" &&
      context.now !== undefined &&
      finalizedAt(op) !== undefined &&
      context.now >= finalizedAt(op)! + OWNER_DELETE_GRACE_PERIOD_MS,
  );
  const erased = purgedDeletes.length > 0;
  const purgedRemovalIds = new Set(
    purgedDeletes.map((op) => op.revision.operationId),
  );
  const purgedRestoreTimes = ownerOps
    .filter(
      (op) =>
        op.kind === "owner-restore" &&
        op.parents.some((id) => purgedRemovalIds.has(id)),
    )
    .map((op) => op.revision.wallMs);
  const declaration = all[0].declaration;
  const incompatibleDeclaration =
    new Set(all.map((op) => canonicalJson(op.declaration))).size > 1;
  const resolutions = ownerOps.filter((op) => op.kind === "owner-resolve");
  const byOperationId = new Map(all.map((op) => [op.revision.operationId, op]));
  const resolvedIds = new Set<string>();
  const markResolved = (id: string): void => {
    if (resolvedIds.has(id)) return;
    resolvedIds.add(id);
    const nested = byOperationId.get(id);
    if (nested?.kind === "owner-resolve")
      nested.candidates.forEach(markResolved);
  };
  resolutions.forEach((op) => {
    if (op.kind === "owner-resolve") op.candidates.forEach(markResolved);
  });
  let candidates: SourceObservation[] = [
    ...observations.filter((op) => !resolvedIds.has(op.revision.operationId)),
    ...resolutions
      .filter((op) => !resolvedIds.has(op.revision.operationId))
      .map((op) => materializeResolution(op, byOperationId))
      .filter((op): op is SourceObservation => op !== null),
  ];
  const dominance = sourceDominance(candidates, declaration.sourceVersionOrder);
  const unconfirmedScans = observations.filter(
    (op) =>
      op.kind === "source-delete" &&
      op.origin === "complete-scan" &&
      (!op.confirmationOf ||
        !observations.some(
          (prior) =>
            prior.kind === "source-delete" &&
            prior.origin === "complete-scan" &&
            prior.revision.operationId === op.confirmationOf &&
            prior.recordKey === op.recordKey &&
            canonicalJson(prior.declaration) ===
              canonicalJson(op.declaration) &&
            prior.revision.wallMs < op.revision.wallMs,
        )),
  );
  candidates = candidates.filter(
    (op) => !dominance.dominated.has(op) && !unconfirmedScans.includes(op),
  );
  const ownerResolutionConflict = resolutions.some((left, index) =>
    resolutions
      .slice(index + 1)
      .some(
        (right) =>
          resolutionPayload(left, byOperationId) !==
            resolutionPayload(right, byOperationId) &&
          !knownBefore(left, right) &&
          !knownBefore(right, left) &&
          left.candidates.some((id) => right.candidates.includes(id)),
      ),
  );
  if (purgedRestoreTimes.length)
    candidates = candidates.filter((op) =>
      purgedRestoreTimes.some((time) => op.revision.wallMs > time),
    );
  const effective = (op: SourceObservation) => {
    const observedAt = Date.parse(op.emittedAt);
    const observationTime = Number.isNaN(observedAt)
      ? op.revision.wallMs
      : observedAt;
    return Math.min(observationTime, finalizedAt(op) ?? observationTime);
  };
  const uniquePayloads = new Set(candidates.map(payloadIdentity));
  const maxima = candidates.filter(
    (candidate) =>
      !candidates.some(
        (other) => other !== candidate && knownBefore(candidate, other),
      ),
  );
  maxima.sort(
    (a, b) =>
      effective(a) - effective(b) || compareRevisions(a.revision, b.revision),
  );
  const current = maxima[maxima.length - 1] ?? null;
  const epsilon = REPLICA_POLICY.uncertaintyWindowMs;
  const closeDisagreement =
    current !== null &&
    candidates.some(
      (candidate) =>
        payloadIdentity(candidate) !== payloadIdentity(current) &&
        !knownBefore(candidate, current) &&
        Math.abs(effective(candidate) - effective(current)) <= epsilon,
    );
  const sourceVersionConflict = dominance.conflicting;
  const unobservable = declaration.reobservable === false;
  const appendOnlyConflict =
    declaration.semantics === "append_only" && uniquePayloads.size > 1;
  const alreadyReobserved =
    context.reobservedRecordKeys?.includes(all[0].recordKey) ?? false;
  const state =
    incompatibleDeclaration || appendOnlyConflict
      ? "quarantined"
      : sourceVersionConflict ||
          ownerResolutionConflict ||
          (closeDisagreement && unobservable)
        ? "conflict"
        : (closeDisagreement && !alreadyReobserved) || unconfirmedScans.length
          ? "unsettled"
          : "settled";
  const retainedAfterRestore =
    purgedRestoreTimes.length > 0 &&
    candidates.some(
      (op) =>
        op.kind === "upsert" &&
        purgedRestoreTimes.some((time) => op.revision.wallMs > time),
    );
  const suppressionMarker = erased
    ? {
        recordKey: all[0].recordKey,
        observations: observations.map((op) => ({
          operationId: op.revision.operationId,
          contentHash: op.contentHash,
          observedAt: op.emittedAt,
          finalizedAt: finalizedAt(op) ?? null,
        })),
        removals: purgedDeletes.map((op) => ({
          operationId: op.revision.operationId,
          deletedAt: op.revision.wallMs,
          finalizedAt: finalizedAt(op)!,
        })),
      }
    : null;
  if (erased)
    candidates = candidates.map((op) =>
      op.kind === "upsert" &&
      !purgedRestoreTimes.some((time) => op.revision.wallMs > time)
        ? { ...op, data: {}, blobs: [] }
        : op,
    );
  return {
    identity: {
      owner: all[0].owner,
      sourceId: all[0].sourceId,
      connectionId: all[0].connectionId,
      generation: all[0].generation,
      stream: declaration.stream,
      recordKey: all[0].recordKey,
    },
    current:
      erased && !retainedAfterRestore && current?.kind === "upsert"
        ? null
        : current,
    candidates,
    state,
    ownerControl,
    refreshRequested: state === "unsettled" && !alreadyReobserved,
    flags: incompatibleDeclaration ? ["incompatible-declaration"] : [],
    payloadRetained: !erased || retainedAfterRestore,
    suppressionMarker,
  };
}

function sourceDominance(
  ops: SourceObservation[],
  order: DeclarationBinding["sourceVersionOrder"],
): { dominated: Set<SourceObservation>; conflicting: boolean } {
  const dominated = new Set<SourceObservation>();
  let conflicting = false;
  if (!order) return { dominated, conflicting };
  for (const a of ops)
    for (const b of ops) {
      if (
        a === b ||
        !a.sourceVersion ||
        !b.sourceVersion ||
        a.sourceVersion.domain !== b.sourceVersion.domain ||
        a.sourceVersion.incarnation !== b.sourceVersion.incarnation
      )
        continue;
      const cmp = compareVersion(
        a.sourceVersion.value,
        b.sourceVersion.value,
        order,
      );
      if (cmp === null) continue;
      if (cmp < 0) dominated.add(a);
      if (cmp === 0 && payloadIdentity(a) !== payloadIdentity(b))
        conflicting = true;
    }
  return { dominated, conflicting };
}
function compareVersion(
  a: string,
  b: string,
  order: NonNullable<DeclarationBinding["sourceVersionOrder"]>,
): number | null {
  if (order === "equality-only") return a === b ? 0 : null;
  if (order === "ordered-integer") {
    try {
      const left = BigInt(a);
      const right = BigInt(b);
      return left < right ? -1 : left > right ? 1 : 0;
    } catch {
      return null;
    }
  }
  const left = Date.parse(a);
  const right = Date.parse(b);
  if (Number.isNaN(left) || Number.isNaN(right)) return null;
  return left < right ? -1 : left > right ? 1 : 0;
}
function payloadIdentity(op: RecordOperation): string {
  return canonicalJson(
    op.kind === "upsert" ? { data: op.data, blobs: op.blobs } : null,
  );
}
function materializeResolution(
  resolution: Extract<RecordOperation, { kind: "owner-resolve" }>,
  byOperationId: Map<string, RecordOperation>,
  path = new Set<string>(),
): SourceObservation | null {
  if (path.has(resolution.revision.operationId)) return null;
  const nextPath = new Set(path).add(resolution.revision.operationId);
  const selected = byOperationId.get(resolution.choice);
  const selectedObservation =
    selected?.kind === "owner-resolve"
      ? materializeResolution(selected, byOperationId, nextPath)
      : selected?.kind === "upsert" || selected?.kind === "source-delete"
        ? selected
        : null;
  const evidence = resolution.candidates
    .map((id) => byOperationId.get(id))
    .flatMap((candidate): SourceObservation[] => {
      if (!candidate) return [];
      if (candidate.kind === "owner-resolve") {
        const nested = materializeResolution(
          candidate,
          byOperationId,
          nextPath,
        );
        return nested ? [nested] : [];
      }
      return candidate.kind === "upsert" || candidate.kind === "source-delete"
        ? [candidate]
        : [];
    });
  const template = selectedObservation ?? evidence[0];
  if (!template) return null;
  const emittedAt =
    evidence
      .map((op) => op.emittedAt)
      .sort()
      .at(-1) ?? template.emittedAt;
  const version = resolution.version ?? selectedObservation?.sourceVersion;
  const common = {
    ...template,
    batchId: resolution.batchId,
    frontier: resolution.frontier,
    revision: resolution.revision,
    emittedAt,
    contentHash: resolution.resolvedValue?.contentHash ?? template.contentHash,
    ...(version ? { sourceVersion: version } : { sourceVersion: undefined }),
  };
  if (resolution.resolvedValue?.kind === "source-delete")
    return {
      ...common,
      kind: "source-delete",
      origin: "source-event",
      confirmationOf: undefined,
    };
  if (resolution.resolvedValue?.kind === "upsert")
    return {
      ...common,
      kind: "upsert",
      data: resolution.resolvedValue.data,
      blobs: resolution.resolvedValue.blobs,
    };
  if (selectedObservation)
    return { ...common, ...selectedObservation, ...common };
  return null;
}
function resolutionPayload(
  resolution: Extract<RecordOperation, { kind: "owner-resolve" }>,
  byOperationId: Map<string, RecordOperation>,
): string {
  const value = materializeResolution(resolution, byOperationId);
  return value
    ? payloadIdentity(value)
    : canonicalJson(resolution.resolvedValue);
}
function knownBefore(a: RecordOperation, b: RecordOperation): boolean {
  return (
    (a.revision.writerId === b.revision.writerId &&
      (a.revision.wallMs < b.revision.wallMs ||
        (a.revision.wallMs === b.revision.wallMs &&
          a.revision.logical < b.revision.logical))) ||
    (b.frontier[a.revision.writerId] !== undefined &&
      (b.frontier[a.revision.writerId].wallMs > a.revision.wallMs ||
        (b.frontier[a.revision.writerId].wallMs === a.revision.wallMs &&
          b.frontier[a.revision.writerId].logical >= a.revision.logical)))
  );
}
function sameAccount(a: UpstreamAccount, b: UpstreamAccount): boolean {
  return a.issuer === b.issuer && a.subject === b.subject;
}
function dedupe<T extends RecordOperation>(ops: T[]): T[] {
  return [...new Map(ops.map((op) => [canonicalJson(op), op])).values()];
}
function normalizeIssues(result: ReplicaMergePlan): void {
  for (const bucket of [
    result.conflicts,
    result.rejected,
    result.pending,
    result.suppressed,
    result.quarantined,
  ]) {
    const unique = new Map<string, MergeIssue>();
    for (const item of bucket) {
      item.operations = [
        ...new Map(
          item.operations.map((op) => [canonicalJson(op), op]),
        ).values(),
      ].sort((a, b) => text(canonicalJson(a), canonicalJson(b)));
      unique.set(canonicalJson(item), item);
    }
    bucket.splice(
      0,
      bucket.length,
      ...[...unique.values()].sort((a, b) =>
        text(canonicalJson(a), canonicalJson(b)),
      ),
    );
  }
}
function text(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
