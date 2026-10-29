import {
  canonicalJson,
  replicaEnvelopeSchema,
  replicaOperationSchema,
  replicaTextParts,
  type ReplicaOperation,
  type ReplicaEnvelope,
  type RecordOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  planReplicaMerge,
  type MergeContext,
} from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  planIngest,
  type PdppRecordRow,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/portable";
import { sha256, toBytes } from "viem";
import {
  REPLICA_MAX_OPERATIONS,
  REPLICA_MAX_PAYLOAD_ENVELOPE_BYTES,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import { createReplicaRecordReducer } from "@opendatalabs/personal-server-ts-core/replication/record-reducer";
import {
  reissuedFrom,
  replicaOperationEffect,
  replicaUpsertEffect,
} from "@opendatalabs/personal-server-ts-core/replication/rebaseline";
import {
  operationDigest,
  type CompletionOperation,
} from "@opendatalabs/personal-server-ts-core/replication/completion";
import {
  blobReady as engineBlobReady,
  completionAvailability,
  connectionFromFacts,
  type ConnectionProjection,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-engine";
import {
  replicaStateVisible,
  replicaPendingMetadata,
  type ReplicaReader,
  type ReplicaVisibilityPolicy,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";
import {
  LITE_CANONICAL_BATCH_BYTES,
  LITE_CANONICAL_MAX_OPERATION_BYTES,
  type LiteCanonicalPersistence,
  type LiteCanonicalTransaction,
  type LiteBlobDescriptor,
  type LiteStagingId,
} from "./canonical-persistence.js";

/**
 * A refusal that the batch's content or the store's immutable state decides:
 * the same input fails the same way on every retry. A replica import that
 * throws it stops retrying (`ReplicaCopyRefused` on the engine host).
 */
export class LiteCanonicalRefusal extends Error {
  readonly code = "lite_canonical_refused";
  constructor(
    readonly reason:
      | "batch_too_large"
      | "operation_too_large"
      | "wrong_owner"
      | "connection_binding_mismatch"
      | "partition_too_large"
      | "commit_id_reused"
      | "blob_metadata_conflict",
    message: string,
  ) {
    super(message);
    this.name = "LiteCanonicalRefusal";
  }
}

export type LiteOperationDraft = ReplicaOperation extends infer T
  ? T extends ReplicaOperation
    ? Omit<T, "revision">
    : never
  : never;
interface Clock {
  writerId: string;
  counter: number;
  sequence: number;
}
interface Connection {
  sourceId: string;
  methodId: string;
}
export interface LiteCommitReceipt {
  sequence: number;
  operationCount: number;
}
export interface LiteReplicaReadOptions {
  reader?: ReplicaReader;
}
type CompletionEvent = Extract<
  ReplicaOperation,
  { kind: "stream-complete" | "stream-invalidate" }
>;
/** Per key: whether it keeps its stream's completion unavailable. */
interface CompletionBlocker {
  stream: string;
  quarantined: boolean;
  unresolved: boolean;
}
export type LiteVisibleRecord = PdppRecordRow;
interface PendingBatch {
  id: string;
  fingerprint: string;
  /** Batches staged before envelope parts keep the envelope here. */
  envelope?: ReplicaEnvelope;
  /** How many `pendingPartKey` values hold the canonical envelope JSON. */
  parts?: number;
  state: "pending" | "quarantined" | "confirmed";
  reason?: string;
  blobs: LiteBlobDescriptor[];
}
const pendingKey = (id: string) => `pending-batches/${keyDigest(id)}`;
/**
 * Stored key layout. Layout 1 kept `journal/`, `outbox/` and `mutations/`;
 * layout 2 keeps one `log/` pointer per local operation. A store opened with
 * any other layout fails closed instead of reading it.
 */
const LAYOUT_VERSION = 2;
const LAYOUT_KEY = "canonical-layout-version";
/** One local commit, in sequence order. It points at the retained operation. */
interface LogEntry {
  batchId: string;
  operationKey: string;
  sequence: number;
  /** The record row's version after this operation (record operations only). */
  rowVersion?: number;
}
const logKey = (sequence: number) =>
  `log/${String(sequence).padStart(16, "0")}`;
/** A store with a clock was created by some layout; it must be this one. */
async function checkLayout(tx: LiteCanonicalTransaction) {
  if ((await tx.get("clock")) === undefined) return;
  const layout = (await get<number>(tx, LAYOUT_KEY)) ?? 1;
  if (layout !== LAYOUT_VERSION)
    throw new Error(
      layout > LAYOUT_VERSION
        ? `canonical layout ${layout} is newer than this build (${LAYOUT_VERSION})`
        : `canonical layout ${layout} is no longer supported (this build reads ${LAYOUT_VERSION}); clear the canonical store and import again`,
    );
}
/** A Node batch targets 32 MiB, so a pending envelope is kept in parts. */
const pendingPartKey = (id: string, part: number) =>
  `pending-envelopes/${keyDigest(id)}/${String(part).padStart(8, "0")}`;
const PENDING_PART_BYTES = 128 * 1024;
/** Bump when a derived pending index changes; older databases need `retry`. */
const PENDING_INDEX_VERSION = 3;
const PREVIEW_BLOB_REFS = "preview-blob-refs/";
/**
 * Writes that decide what a reader sees, by connection digest. Row and
 * overlay values and connection control facts count; retained evidence and
 * pending indexes do not, because their visible effects land in these rows.
 */
function viewKey(
  key: string,
): { digest: string; preview: boolean } | undefined {
  if (key.startsWith("preview/rows/"))
    return { digest: key.split("/")[2], preview: true };
  if (
    key.startsWith("rows/") ||
    key.startsWith("connection-generation/") ||
    key.startsWith("binding-conflicts/") ||
    key.startsWith("connections/") ||
    key.startsWith(CONNECTION_QUARANTINE)
  )
    return { digest: key.split("/")[1], preview: false };
  return undefined;
}
/** Original value of each view key a transaction first wrote, by transaction. */
const viewWrites = new WeakMap<
  LiteCanonicalTransaction,
  { base: LiteCanonicalTransaction; first: Map<string, string | undefined> }
>();
function trackViews(base: LiteCanonicalTransaction): LiteCanonicalTransaction {
  const first = new Map<string, string | undefined>();
  const note = async (key: string) => {
    if (viewKey(key) && !first.has(key)) first.set(key, await base.get(key));
  };
  const tx: LiteCanonicalTransaction = {
    get: (key) => base.get(key),
    put: async (key, value) => {
      await note(key);
      await base.put(key, value);
    },
    delete: async (key) => {
      await note(key);
      await base.delete(key);
    },
    scan: (prefix, after) => base.scan(prefix, after),
    attachBlob: (stagingId, expected) => base.attachBlob(stagingId, expected),
    blob: (blobId) => base.blob(blobId),
  };
  viewWrites.set(tx, { base, first });
  return tx;
}
/** Net changes so far: a key counts only when it differs from its first value. */
async function changedViews(tx: LiteCanonicalTransaction) {
  const writes = viewWrites.get(tx);
  if (!writes)
    throw new Error("view changes read from an untracked transaction");
  const canonical = new Set<string>();
  const preview = new Set<string>();
  for (const [key, before] of writes.first) {
    if ((await writes.base.get(key)) === before) continue;
    const view = viewKey(key)!;
    (view.preview ? preview : canonical).add(view.digest);
  }
  return { canonical, preview };
}
const digest = (value: unknown) =>
  `sha256:${sha256(toBytes(canonicalJson(value))).slice(2)}`;
/** The fingerprint `stagePending` and `pendingBatch` report for an envelope. */
export const litePendingFingerprint = (envelope: unknown) =>
  digest(replicaEnvelopeSchema.parse(envelope));
// Fixed-size internal keys fit the existing native 512-character key bound.
const keyDigest = (value: unknown) => digest(value).slice(7);
const operationId = (op: ReplicaOperation) =>
  keyDigest([op.revision.writerId, op.revision.operationId]);
const connectionPrefix = (id: string) => `entries/${keyDigest(id)}/`;
const recordId = (stream: string, key: string) => keyDigest([stream, key]);
const rowKey = (connection: string, stream: string, key: string) =>
  `rows/${keyDigest(connection)}/${recordId(stream, key)}`;
const operationPath = (op: ReplicaOperation) => {
  const suffix =
    op.kind === "upsert" || op.kind === "delete"
      ? `records/${recordId(op.declaration.stream, op.recordKey)}/`
      : op.kind === "blob-claim"
        ? `claims/${keyDigest(op.blob.blobId)}/`
        : op.kind === "stream-complete" || op.kind === "stream-invalidate"
          ? "completions/"
          : "lifecycle/";
  return `${connectionPrefix(op.connectionId)}${suffix}${digest(op)}`;
};
const maxWindowBytes = 4 * 1024 * 1024;
const encoder = new TextEncoder();

async function get<T>(
  tx: LiteCanonicalTransaction,
  key: string,
): Promise<T | undefined> {
  const value = await tx.get(key);
  return value === undefined ? undefined : (JSON.parse(value) as T);
}
const put = (tx: LiteCanonicalTransaction, key: string, value: unknown) =>
  tx.put(key, canonicalJson(value));
async function* scan(tx: LiteCanonicalTransaction, prefix: string) {
  let after: string | undefined;
  do {
    const page = await tx.scan(prefix, after);
    for (const entry of page.entries) yield entry;
    if (
      page.after !== undefined &&
      (page.after === after || !page.entries.length)
    )
      throw new Error("invalid native scan cursor");
    after = page.after;
  } while (after !== undefined);
}
/** Whether a prefix holds any entry, read through the validating page walker. */
async function any(tx: LiteCanonicalTransaction, prefix: string) {
  for await (const _ of scan(tx, prefix)) return true;
  return false;
}
async function operations(
  tx: LiteCanonicalTransaction,
  prefix: string,
): Promise<ReplicaOperation[]> {
  const result: ReplicaOperation[] = [];
  let bytes = 0;
  for await (const entry of scan(tx, prefix)) {
    bytes += encoder.encode(entry.value).length;
    if (bytes > maxWindowBytes)
      throw new LiteCanonicalRefusal(
        "partition_too_large",
        "replica merge partition exceeds 4 MiB; native repair required",
      );
    result.push(replicaOperationSchema.parse(JSON.parse(entry.value)));
  }
  return result;
}
/**
 * Log entries after `after` with their retained operations: one native scan
 * page, at most 512 KiB of operation bytes. An empty page reports `reported`.
 */
async function logPage(
  tx: LiteCanonicalTransaction,
  after: number,
  reported = after,
) {
  const page = await tx.scan("log/", logKey(after));
  const entries: (LogEntry & { operation: ReplicaOperation })[] = [];
  let bytes = 0;
  for (const { value } of page.entries) {
    const entry = JSON.parse(value) as LogEntry;
    const operation = await tx.get(entry.operationKey);
    if (!operation) throw new Error("missing immutable outbox operation");
    bytes += encoder.encode(operation).length;
    if (bytes > 512 * 1024) break;
    entries.push({
      ...entry,
      operation: replicaOperationSchema.parse(JSON.parse(operation)),
    });
  }
  return {
    entries,
    nextAfterSequence: entries.at(-1)?.sequence ?? reported,
    hasMore: page.after !== undefined || entries.length < page.entries.length,
  };
}

/**
 * Bounds a received envelope part by part before schema parsing builds it:
 * its header, its operation count and each operation. The whole envelope has
 * no bound, because the store keeps it in parts.
 */
function refuseOversizedEnvelope(raw: unknown) {
  const { operations, ...header } = (raw ?? {}) as { operations?: unknown };
  if (
    encoder.encode(canonicalJson(header)).length >
      REPLICA_MAX_PAYLOAD_ENVELOPE_BYTES ||
    (Array.isArray(operations) && operations.length > REPLICA_MAX_OPERATIONS)
  )
    throw new LiteCanonicalRefusal(
      "batch_too_large",
      "replica envelope exceeds its header or operation count bound",
    );
  if (Array.isArray(operations))
    for (const op of operations)
      if (
        encoder.encode(canonicalJson(op)).length >
        LITE_CANONICAL_MAX_OPERATION_BYTES
      )
        throw new LiteCanonicalRefusal(
          "operation_too_large",
          "replica operation exceeds the native value bound",
        );
}
/** A pending batch's envelope, from its parts or as staged before them. */
async function pendingEnvelope(
  tx: LiteCanonicalTransaction,
  batch: PendingBatch,
): Promise<ReplicaEnvelope> {
  if (batch.envelope) return batch.envelope;
  let json = "";
  for (let part = 0; part < (batch.parts ?? 0); part++) {
    const text = await tx.get(pendingPartKey(batch.id, part));
    if (text === undefined) throw new Error("pending envelope part missing");
    json += text;
  }
  return replicaEnvelopeSchema.parse(JSON.parse(json));
}

/**
 * Experimental canonical persistence port. No runtime/route/publisher wiring.
 * Lifecycle plus one record's retained variants enter the EXISTING merge planner;
 * a scope's record bodies are never loaded together. Native transactions hide all
 * intermediate rows, blob references, log entries and import receipts.
 */
/** Absorbing terminal-batch fact per connection (contract v3.1 A, H). */
const CONNECTION_QUARANTINE = "connection-quarantine/";
/** Operations a writer change re-exported, which their log entries point at. */
const REEXPORTED = "reexported/";

export function createLiteCanonicalStore(deps: {
  persistence: LiteCanonicalPersistence;
  context: () => MergeContext;
  authenticateReplica: (credential: unknown) => string | undefined;
  enabled?: boolean;
  visibilityPolicy?: ReplicaVisibilityPolicy;
  newId?: () => string;
  /** Called after each local batch commits, so replication steps soon. */
  localCommitted?: () => void;
}) {
  // Every transaction checks the stored layout first, so no reader or
  // writer can reach entries of another layout.
  const persistence: LiteCanonicalPersistence = {
    transaction: (run) =>
      deps.persistence.transaction(async (tx) => {
        await checkLayout(tx);
        return run(tx);
      }),
    stageBlob: (descriptor, chunks) =>
      deps.persistence.stageBlob(descriptor, chunks),
    readBlob: (blobId) => deps.persistence.readBlob(blobId),
  };
  const newId = deps.newId ?? (() => globalThis.crypto.randomUUID());
  function enabled() {
    if (deps.enabled !== true)
      throw new Error("Lite canonical replication disabled");
  }
  async function clock(
    tx: LiteCanonicalTransaction,
    context = deps.context(),
  ): Promise<Clock> {
    const owner = await get<string>(tx, "owner");
    if (!context.owner || (owner !== undefined && owner !== context.owner))
      throw new Error("immutable canonical owner binding");
    await put(tx, "owner", context.owner);
    const stored = await get<Clock>(tx, "clock");
    if (stored) return stored;
    const initial = { writerId: newId(), counter: 0, sequence: 0 };
    await put(tx, "clock", initial);
    await put(tx, LAYOUT_KEY, LAYOUT_VERSION);
    await put(tx, "pending-index-version", PENDING_INDEX_VERSION);
    return initial;
  }
  async function mapping(tx: LiteCanonicalTransaction, op: ReplicaOperation) {
    const local = await get<Connection>(
      tx,
      `connections/${keyDigest(op.connectionId)}`,
    );
    if (
      local &&
      (local.sourceId !== op.sourceId || local.methodId !== op.methodId)
    )
      throw new LiteCanonicalRefusal(
        "connection_binding_mismatch",
        "replica connection source or method mismatch",
      );
    return local;
  }
  async function retain(
    tx: LiteCanonicalTransaction,
    op: ReplicaOperation,
    dirty: Set<string>,
  ) {
    await put(
      tx,
      `retained-connections/${keyDigest(op.connectionId)}`,
      op.connectionId,
    );
    const bindingPath = `binding-evidence/${keyDigest(op.connectionId)}`;
    const binding = { sourceId: op.sourceId, methodId: op.methodId };
    const priorBinding = await get<Connection>(tx, bindingPath);
    const conflictPath = `binding-conflicts/${keyDigest(op.connectionId)}`;
    // The first binding that differs: with the first binding it shows the
    // conflict to `connectionFromFacts`. Written once, so no view moves again.
    if (
      priorBinding &&
      canonicalJson(priorBinding) !== canonicalJson(binding)
    ) {
      if (!(await tx.get(conflictPath))) await put(tx, conflictPath, binding);
    } else await put(tx, bindingPath, binding);
    const opKey = operationPath(op);
    await put(tx, opKey, op);
    if (op.kind === "upsert" || op.kind === "delete") {
      await put(
        tx,
        `keys/${keyDigest(op.connectionId)}/${recordId(op.declaration.stream, op.recordKey)}`,
        { stream: op.declaration.stream, key: op.recordKey },
      );
    }
    const index = `revisions/${operationId(op)}/`;
    await put(tx, `${index}${digest(op)}`, {
      connectionId: op.connectionId,
      opKey,
    });
    const variants: { connectionId: string; opKey: string }[] = [];
    for await (const entry of scan(tx, index))
      variants.push(JSON.parse(entry.value));
    if (variants.length > 1) {
      for (const variant of variants) {
        await put(
          tx,
          `equivocations/${keyDigest(variant.connectionId)}/${operationId(op)}`,
          variants,
        );
        dirty.add(variant.connectionId);
      }
    }
    dirty.add(op.connectionId);
    return { collision: variants.length > 1, opKey };
  }
  /**
   * The engine's `blobReady` over this connection's retained claims and the
   * bytes Lite holds. Canonical state needs confirmed bytes; the owner
   * preview also accepts bytes that only a pending batch carries.
   */
  async function blobReady(
    tx: LiteCanonicalTransaction,
    op: Extract<RecordOperation, { kind: "upsert" }>,
    pendingBytes = false,
  ) {
    const claims: ReplicaOperation[] = [];
    const verified = new Set<string>();
    for (const blob of op.blobs) {
      for await (const entry of scan(
        tx,
        `${connectionPrefix(op.connectionId)}claims/${keyDigest(blob.blobId)}/`,
      ))
        claims.push(replicaOperationSchema.parse(JSON.parse(entry.value)));
      if (
        (await tx.blob(blob.blobId)) &&
        (pendingBytes ||
          (await get(tx, `confirmed-blobs/${keyDigest(blob.blobId)}`)))
      )
        verified.add(blob.blobId);
    }
    if (!engineBlobReady(op, claims, verified)) return false;
    for (const blob of op.blobs)
      if (canonicalJson(await tx.blob(blob.blobId)) !== canonicalJson(blob))
        throw new LiteCanonicalRefusal(
          "blob_metadata_conflict",
          "replica blob metadata conflict",
        );
    return true;
  }
  /**
   * The engine's eligibility for one connection, from Lite's indexes: the
   * terminal-batch fact, equivocations, retained bindings and the
   * connection's globally unique lifecycle. A withdrawn connection is hidden
   * from every reader. An unprovisioned connection has no projection; it is
   * judged against its first retained binding, so that its quarantine answer
   * and the blob gate still see its terminal fact, equivocations and
   * conflicting bindings.
   */
  async function connectionState(
    tx: LiteCanonicalTransaction,
    id: string,
    context: MergeContext,
  ) {
    const d = keyDigest(id);
    const lifecycle: ReplicaOperation[] = [];
    for (const op of await operations(tx, `${connectionPrefix(id)}lifecycle/`))
      if (!(await any(tx, `equivocations/${d}/${operationId(op)}`)))
        lifecycle.push(op);
    const mapped = await get<Connection>(tx, `connections/${d}`);
    const bindings = [
      await get<Connection>(tx, `binding-evidence/${d}`),
      await get<Connection>(tx, `binding-conflicts/${d}`),
    ].filter((binding): binding is Connection => binding !== undefined);
    const connection = connectionFromFacts(context, {
      mapping: mapped ?? bindings[0] ?? { sourceId: "", methodId: "" },
      terminal: !!(await get(tx, `${CONNECTION_QUARANTINE}${d}`)),
      equivocated: await any(tx, `equivocations/${d}/`),
      bindings,
      lifecycle,
      appliedGeneration:
        (await get<number>(tx, `connection-generation/${d}`)) ?? 1,
    });
    return {
      lifecycle,
      mapped,
      connection,
      blocked: connection.status === "withdrawn",
    };
  }
  async function reconcile(
    tx: LiteCanonicalTransaction,
    id: string,
    context: MergeContext,
    only?: readonly { stream: string; key: string }[],
    canonical?: LiteCanonicalTransaction,
  ) {
    const { lifecycle, mapped, connection, blocked } = await connectionState(
      tx,
      id,
      context,
    );
    const pendingLifecycle = connection.status === "held";
    const deleted = connection.status === "deleted";
    const generation = connection.generation;
    const activeGeneration =
      (await get<number>(tx, `connection-generation/${keyDigest(id)}`)) ?? 1;
    const reset =
      connection.status === "active" && generation > activeGeneration;
    // Completion inputs are kept for canonical rows of provisioned, active
    // connections only; the preview certifies nothing.
    const certify =
      canonical === undefined && !!mapped && connection.status === "active";
    // Keep canonical lifecycle suppression in the source view. Only provisional
    // removals are omitted when deriving the value they would provisionally remove.
    const sourceLifecycle: ReplicaOperation[] = [];
    const provisionalResets: ReplicaOperation[] = [];
    let provisionalRemoval = false;
    if (canonical && !blocked && !pendingLifecycle && (deleted || reset))
      for (const op of lifecycle) {
        if (
          (op.kind === "connection-reset" || op.kind === "connection-delete") &&
          !(await canonical.get(operationPath(op)))
        ) {
          provisionalRemoval = true;
          if (op.kind === "connection-reset") provisionalResets.push(op);
        } else sourceLifecycle.push(op);
      }
    const keys = only
      ? only.map((key) => ({ value: canonicalJson(key) }))
      : scan(tx, `keys/${keyDigest(id)}/`);
    for await (const entry of keys) {
      const { stream, key } = JSON.parse(entry.value) as {
        stream: string;
        key: string;
      };
      const reducer = createReplicaRecordReducer(context, lifecycle);
      let sourceReducer:
        ReturnType<typeof createReplicaRecordReducer> | undefined;
      let sourceGeneration = 0;
      // An unresolved pending or rejected operation of the key, as the
      // planner judges it alone with the lifecycle; conflicts quarantine.
      let unresolved = false;
      if (!blocked && !pendingLifecycle && (!deleted || provisionalRemoval)) {
        for await (const variant of scan(
          tx,
          `${connectionPrefix(id)}records/${recordId(stream, key)}/`,
        )) {
          const op = replicaOperationSchema.parse(JSON.parse(variant.value));
          if (op.kind !== "upsert" && op.kind !== "delete")
            throw new Error("invalid record partition");
          if (!deleted) reducer.push(op);
          if (certify) {
            const issues = planReplicaMerge(context, [...lifecycle, op]);
            unresolved ||= [...issues.pending, ...issues.rejected].some(
              (issue) => issue.reason !== "missing_declaration",
            );
          }
          if (provisionalRemoval && op.generation >= sourceGeneration) {
            // As in the planner, a newer eligible generation supersedes older
            // evidence. Retain just that generation's bounded reducer state.
            const candidate =
              op.generation === sourceGeneration
                ? sourceReducer!
                : createReplicaRecordReducer(context, [
                    ...sourceLifecycle,
                    ...provisionalResets.filter(
                      (reset) => reset.generation <= op.generation,
                    ),
                  ]);
            candidate.push(op);
            if (candidate.record !== undefined) {
              sourceGeneration = op.generation;
              sourceReducer = candidate;
            }
          }
        }
      }
      const record = reducer.record;
      const winner = mapped ? record?.winner : undefined;
      const materialized =
        winner?.kind === "upsert" &&
        (await blobReady(tx, winner, canonical !== undefined))
          ? winner
          : winner?.kind === "delete"
            ? winner
            : null;
      const path = rowKey(id, stream, key);
      if (certify) {
        const blocker: CompletionBlocker = {
          stream,
          quarantined: record?.quarantined === true,
          // An unmaterializable winner is unresolved even without a row.
          unresolved:
            unresolved || (winner?.kind === "upsert" && !materialized),
        };
        const blockerPath = `completion-blockers/${keyDigest(id)}/${recordId(stream, key)}`;
        if (blocker.quarantined || blocker.unresolved)
          await put(tx, blockerPath, blocker);
        else await tx.delete(blockerPath);
      }
      if (canonical) await tx.delete(path);
      let prior = await get<PdppRecordRow>(tx, path);
      const source = mapped ? sourceReducer?.record?.winner : undefined;
      if (
        !prior &&
        !materialized &&
        source?.kind === "upsert" &&
        (await blobReady(tx, source, canonical !== undefined))
      )
        prior = {
          instance: id,
          stream,
          recordKey: key,
          version: 1,
          emittedAt: source.emittedAt,
          deleted: false,
          data: source.data,
        };
      const priorGeneration = await get<number>(tx, `row-generation/${path}`);
      // A validated reset withdraws live rows before applying its generation,
      // even when the new winner has identical content and emitted time.
      if (reset && prior && !prior.deleted) {
        prior = {
          instance: prior.instance,
          stream: prior.stream,
          recordKey: prior.recordKey,
          version: prior.version + 1,
          emittedAt: prior.emittedAt,
          deleted: true,
          deletedAt: prior.emittedAt,
        };
        await put(tx, path, prior);
        await put(tx, `row-generation/${path}`, generation);
      }
      // The Node receiver's lifecycle cleanup touches live rows only. Preserve
      // an existing tombstone's original deletion time/version under a reset,
      // and under a withdrawn winner (oracle D2 on the Lite port).
      if (!materialized && prior?.deleted) continue;
      // Match the receiver: missing lifecycle/declaration evidence does not
      // retract a previously materialized row. A validated reset does.
      if (
        !blocked &&
        !deleted &&
        (pendingLifecycle ||
          (!record && (priorGeneration ?? generation) === generation))
      )
        continue;
      // A derived withdrawal keeps a tombstone if this key was once visible.
      if (!materialized && !prior) continue;
      const data = materialized?.kind === "upsert" ? materialized.data : null;
      const emittedAt = materialized?.emittedAt ?? prior!.emittedAt;
      const deletedAt =
        materialized?.kind === "delete" ? materialized.deletedAt : emittedAt;
      if (
        prior &&
        prior.emittedAt === emittedAt &&
        (prior.deleted
          ? data === null && prior.deletedAt === deletedAt
          : data !== null && canonicalJson(prior.data) === canonicalJson(data))
      )
        continue;
      const base = {
        instance: id,
        stream,
        recordKey: key,
        version: (prior?.version ?? 0) + 1,
        emittedAt,
      };
      const row: PdppRecordRow =
        data === null
          ? { ...base, deleted: true, deletedAt }
          : { ...base, deleted: false, data };
      // A confirmed winner that shows the canonical content needs no preview
      // row; a pending winner always gets one, so the owner sees its marker.
      if (
        canonical &&
        winner &&
        (await canonical.get(operationPath(winner))) !== undefined &&
        sameContent(canonicalJson(row), await canonical.get(path))
      ) {
        await tx.delete(path);
        continue;
      }
      await put(tx, path, row);
      await put(tx, `row-generation/${path}`, generation);
    }
    if (!blocked && !pendingLifecycle)
      await put(tx, `connection-generation/${keyDigest(id)}`, generation);
    if (canonical === undefined)
      await certifyCompletions(
        tx,
        id,
        context,
        mapped ? connection : undefined,
      );
  }
  /**
   * Persist the engine's completion availability for each stream of a
   * connection, from Lite's indexes: completion evidence at the
   * connection's generation, the per-key blockers `reconcile` keeps, live
   * canonical rows, and dependency variants of provisioned connections.
   * Reads every canonical row of a stream that has completion evidence.
   */
  async function certifyCompletions(
    tx: LiteCanonicalTransaction,
    id: string,
    context: MergeContext,
    connection: ConnectionProjection | undefined,
  ) {
    const d = keyDigest(id);
    const available = new Map<string, CompletionOperation>();
    const events = new Map<string, CompletionEvent[]>();
    if (connection?.status === "active")
      for await (const entry of scan(
        tx,
        `${connectionPrefix(id)}completions/`,
      )) {
        const op = replicaOperationSchema.parse(JSON.parse(entry.value));
        if (
          (op.kind !== "stream-complete" && op.kind !== "stream-invalidate") ||
          op.generation !== connection.generation
        )
          continue;
        const stream = op.declaration.stream;
        events.set(stream, [...(events.get(stream) ?? []), op]);
      }
    if (connection && events.size) {
      const blockers = new Map<string, CompletionBlocker>();
      for await (const entry of scan(tx, `completion-blockers/${d}/`)) {
        const blocker = JSON.parse(entry.value) as CompletionBlocker;
        const prior = blockers.get(blocker.stream);
        blockers.set(blocker.stream, {
          stream: blocker.stream,
          quarantined: blocker.quarantined || !!prior?.quarantined,
          unresolved: blocker.unresolved || !!prior?.unresolved,
        });
      }
      const live = new Map<string, { recordKey: string; dataJson: string }[]>();
      for await (const entry of scan(tx, `rows/${d}/`)) {
        const row = JSON.parse(entry.value) as PdppRecordRow;
        if (row.deleted || !events.has(row.stream)) continue;
        live.set(row.stream, [
          ...(live.get(row.stream) ?? []),
          { recordKey: row.recordKey, dataJson: canonicalJson(row.data) },
        ]);
      }
      const variants = new Map<string, string[]>();
      for (const list of events.values())
        for (const op of list)
          if (op.kind === "stream-complete")
            for (const dependency of op.dependencies) {
              const revision = keyDigest([
                dependency.writerId,
                dependency.operationId,
              ]);
              if (variants.has(revision)) continue;
              const digests = new Set<string>();
              for await (const entry of scan(tx, `revisions/${revision}/`)) {
                const variant = JSON.parse(entry.value) as {
                  connectionId: string;
                  opKey: string;
                };
                // Unmapped evidence never satisfies a dependency.
                if (
                  !(await tx.get(
                    `connections/${keyDigest(variant.connectionId)}`,
                  ))
                )
                  continue;
                const value = await tx.get(variant.opKey);
                if (value === undefined)
                  throw new Error("missing retained replica operation");
                digests.add(operationDigest(JSON.parse(value)));
              }
              variants.set(revision, [...digests]);
            }
      for (const [stream, list] of events) {
        const result = completionAvailability({
          connection,
          connectionId: id,
          events: list,
          declarations: context.declarations,
          quarantinedKey: !!blockers.get(stream)?.quarantined,
          unresolved: !!blockers.get(stream)?.unresolved,
          variantDigests: (writerId, operationId) =>
            variants.get(keyDigest([writerId, operationId])) ?? [],
          liveRows: live.get(stream) ?? [],
        });
        if (result) available.set(stream, result.operation);
      }
    }
    const prefix = `stream-completions/${d}/`;
    for await (const entry of scan(tx, prefix)) {
      const stream = (JSON.parse(entry.value) as CompletionOperation)
        .declaration.stream;
      if (!available.has(stream)) await tx.delete(entry.key);
    }
    for (const [stream, operation] of available)
      await put(tx, `${prefix}${keyDigest(stream)}`, operation);
  }
  /**
   * The current canonical state as new local operations of `writerId`, in
   * the outbox, after skipping every unpublished one: lifecycle, blob
   * claims, records and tombstones, then certified completions, per
   * provisioned connection. Each record and completion copies the
   * operation the merge chose for it (core `rebaseline.ts`): the copy keeps
   * its counter, origin and declaration, so it orders against every other
   * writer exactly as the original. Lifecycle and claims take new counters.
   * Each copy is kept under `reexported/`, like any logged operation;
   * canonical state does not change. A row the merge does not explain, such
   * as one whose stream this store no longer declares, is not re-exported
   * (`skipped`): Lite keeps no binding history to write it under.
   */
  async function reexport(
    tx: LiteCanonicalTransaction,
    current: Clock,
    writerId: string,
    context: MergeContext,
  ) {
    // Skip every unpublished entry: the new writer's chain carries its
    // effect instead. The log keeps them.
    await put(tx, "outbox-ack", current.sequence);
    current.writerId = writerId;
    let reissued = 0;
    let skipped = 0;
    const issue = async (
      draft: LiteOperationDraft,
      copy?: Extract<ReplicaOperation, { declaration: unknown }>,
    ): Promise<ReplicaOperation> => {
      const kept = copy && reissuedFrom(copy);
      if (!kept && !Number.isSafeInteger(current.counter + 1))
        throw new Error("replication counter exhausted");
      const counter = kept ? kept.revision.counter : current.counter + 1;
      const op = replicaOperationSchema.parse({
        ...draft,
        ...(kept && { declaration: kept.declaration }),
        revision: {
          counter,
          writerId,
          operationId: newId(),
          ...(kept && { origin: kept.revision.origin }),
        },
      });
      current.counter = Math.max(current.counter, counter);
      current.sequence += 1;
      const sequence = String(current.sequence).padStart(16, "0");
      await put(tx, `${REEXPORTED}${sequence}`, op);
      const entry: LogEntry = {
        batchId: `rebaseline/${writerId}`,
        operationKey: `${REEXPORTED}${sequence}`,
        sequence: current.sequence,
      };
      if (op.kind === "upsert" || op.kind === "delete") {
        const row = await get<PdppRecordRow>(
          tx,
          rowKey(op.connectionId, op.declaration.stream, op.recordKey),
        );
        if (row) entry.rowVersion = row.version;
      }
      await put(tx, logKey(current.sequence), entry);
      reissued += 1;
      return op;
    };
    for await (const entry of scan(tx, "retained-connections/")) {
      const id = JSON.parse(entry.value) as string;
      const d = keyDigest(id);
      const mapped = await get<Connection>(tx, `connections/${d}`);
      if (!mapped) continue;
      const { connection, lifecycle } = await connectionState(tx, id, context);
      if (connection.status !== "active" && connection.status !== "deleted")
        continue;
      const generation = connection.generation;
      const base = {
        owner: context.owner,
        sourceId: mapped.sourceId,
        connectionId: id,
        methodId: mapped.methodId,
      };
      // What a completion of each stream depends on: the new writer's
      // lifecycle and claims, and its operations of that stream.
      const shared: ReplicaOperation[] = [];
      const byStream = new Map<string, ReplicaOperation[]>();
      shared.push(
        await issue({
          ...base,
          generation: 1,
          kind: "connection-register",
        } as LiteOperationDraft),
      );
      for (let next = 2; next <= generation; next++)
        shared.push(
          await issue({
            ...base,
            generation: next,
            kind: "connection-reset",
            previousGeneration: next - 1,
          } as LiteOperationDraft),
        );
      if (connection.status === "deleted")
        shared.push(
          await issue({
            ...base,
            generation,
            kind: "connection-delete",
          } as LiteOperationDraft),
        );
      const claimed = new Set<string>();
      const claim = async (blob: LiteBlobDescriptor) => {
        if (claimed.has(blob.blobId)) return;
        claimed.add(blob.blobId);
        shared.push(
          await issue({
            ...base,
            generation,
            kind: "blob-claim",
            blob,
          } as LiteOperationDraft),
        );
      };
      for await (const entry of scan(tx, `${connectionPrefix(id)}claims/`)) {
        const op = replicaOperationSchema.parse(JSON.parse(entry.value));
        if (
          op.kind === "blob-claim" &&
          op.generation === generation &&
          (await tx.blob(op.blob.blobId)) &&
          (await get(tx, `confirmed-blobs/${keyDigest(op.blob.blobId)}`))
        )
          await claim(op.blob);
      }
      for await (const entry of scan(tx, `rows/${d}/`)) {
        const row = JSON.parse(entry.value) as PdppRecordRow;
        const reducer = createReplicaRecordReducer(context, lifecycle);
        for await (const variant of scan(
          tx,
          `${connectionPrefix(id)}records/${recordId(row.stream, row.recordKey)}/`,
        )) {
          const op = replicaOperationSchema.parse(JSON.parse(variant.value));
          if (op.kind !== "upsert" && op.kind !== "delete")
            throw new Error("invalid record partition");
          reducer.push(op);
        }
        // The operation the merge chose explains the row.
        const source = reducer.record?.winner;
        if (
          !source ||
          replicaOperationEffect(source) !==
            (row.deleted ? "delete" : replicaUpsertEffect(row.data))
        ) {
          skipped += 1;
          continue;
        }
        if (source.kind === "upsert")
          for (const blob of source.blobs) await claim(blob);
        const { revision: _, ...draft } = source;
        const op = await issue(
          { ...draft, ...base, generation } as LiteOperationDraft,
          source,
        );
        byStream.set(row.stream, [...(byStream.get(row.stream) ?? []), op]);
      }
      for await (const entry of scan(tx, `stream-completions/${d}/`)) {
        const certified = replicaOperationSchema.parse(JSON.parse(entry.value));
        if (certified.kind !== "stream-complete") continue;
        // The certified completion is the one the merge chose.
        const { revision: _, ...draft } = certified;
        await issue(
          {
            ...draft,
            ...base,
            generation,
            dependencies: [
              ...shared,
              ...(byStream.get(certified.declaration.stream) ?? []),
            ].map((op) => ({
              writerId: op.revision.writerId,
              operationId: op.revision.operationId,
              digest: operationDigest(op),
            })),
          } as LiteOperationDraft,
          certified,
        );
      }
    }
    return { reissued, skipped };
  }
  async function commit(input: {
    id: string;
    operations?: LiteOperationDraft[];
    envelope?: unknown;
    credential?: unknown;
    blobs?: { stagingId: LiteStagingId; descriptor: LiteBlobDescriptor }[];
    promotion?: { id: string; fingerprint: string };
  }): Promise<LiteCommitReceipt> {
    enabled();
    if (
      !input.id ||
      input.id.length > 256 ||
      (input.operations === undefined) === (input.envelope === undefined)
    )
      throw new Error("exactly one local batch or replica envelope required");
    const context = deps.context();
    const local = input.operations !== undefined;
    if (
      !context.owner ||
      (!local && deps.authenticateReplica(input.credential) !== context.owner)
    )
      throw new Error("replica authority required for owner");
    if (!local) refuseOversizedEnvelope(input.envelope);
    const envelope = local
      ? undefined
      : replicaEnvelopeSchema.parse(input.envelope);
    if (
      envelope &&
      (envelope.owner !== context.owner ||
        envelope.operations.some((op) => op.owner !== context.owner))
    )
      throw new LiteCanonicalRefusal("wrong_owner", "wrong replica owner");
    // A local request id also fences the original, unrevised inputs after lost ack.
    const encoded = canonicalJson(local ? input.operations : envelope);
    if (local && encoder.encode(encoded).length > LITE_CANONICAL_BATCH_BYTES)
      throw new LiteCanonicalRefusal(
        "batch_too_large",
        "canonical batch exceeds 192 KiB; split before commit",
      );
    const fingerprint = `sha256:${sha256(toBytes(encoded)).slice(2)}`;
    return persistence.transaction(async (base) => {
      const tx = trackViews(base);
      if (local) {
        // One write boundary for every local operation kind. Quarantine is
        // checked before clocks, staged attachments, receipts, or the log.
        for (const connectionId of new Set(
          input.operations!.map((op) => op.connectionId),
        )) {
          if ((await connectionState(tx, connectionId, context)).blocked)
            throw new Error("local connection is quarantined");
        }
      }
      if (input.promotion) {
        const batch = await get<PendingBatch>(
          tx,
          pendingKey(input.promotion.id),
        );
        if (
          !batch ||
          batch.state === "quarantined" ||
          batch.fingerprint !== input.promotion.fingerprint
        )
          throw new Error("pending promotion conflict");
      }
      const current = await clock(tx, context);
      await ensurePendingIndex(tx, context);
      const receiptKey = `${local ? "local" : "import"}/${keyDigest(input.id)}`;
      const prior = await get<{
        fingerprint: string;
        receipt: LiteCommitReceipt;
      }>(tx, receiptKey);
      if (prior) {
        if (prior.fingerprint !== fingerprint)
          throw new LiteCanonicalRefusal(
            "commit_id_reused",
            "commit id reused with different content",
          );
        if (local) return prior.receipt;
        // Retry imports can supply formerly absent bytes/declarations. Retaining
        // exact operations again is idempotent; canonical writes compare content.
      }
      const newlyConfirmed: string[] = [];
      for (const blob of input.blobs ?? []) {
        await tx.attachBlob(blob.stagingId, blob.descriptor);
        if (await confirmBlob(tx, blob.descriptor.blobId))
          newlyConfirmed.push(blob.descriptor.blobId);
      }
      const dirty = new Set<string>();
      const changed = new Map<
        string,
        Map<string, { stream: string; key: string }>
      >();
      const full = new Set<string>();
      if (input.promotion)
        for (const blob of (await get<PendingBatch>(
          tx,
          pendingKey(input.promotion.id),
        ))!.blobs)
          if (await confirmBlob(tx, blob.blobId))
            newlyConfirmed.push(blob.blobId);
      for (const blobId of newlyConfirmed)
        for (const id of await claimants(tx, blobId)) {
          dirty.add(id);
          full.add(id);
        }
      const accepted: ReplicaOperation[] = [];
      for (const raw of local ? input.operations! : envelope!.operations) {
        let op: ReplicaOperation;
        if (local) {
          if (!Number.isSafeInteger(current.counter + 1))
            throw new Error("replication counter exhausted");
          op = replicaOperationSchema.parse({
            ...raw,
            revision: {
              counter: current.counter + 1,
              writerId: current.writerId,
              operationId: newId(),
            },
          });
        } else op = replicaOperationSchema.parse(raw);
        if (op.owner !== context.owner)
          throw new LiteCanonicalRefusal(
            "wrong_owner",
            "wrong operation owner",
          );
        const mapped = await mapping(tx, op);
        if (local && !mapped)
          throw new Error("local connection must be provisioned by host");
        if (local) {
          const lifecycle = await operations(
            tx,
            `${connectionPrefix(op.connectionId)}lifecycle/`,
          );
          const plan = planReplicaMerge(context, [...lifecycle, op]);
          const collisions = await tx.scan(
            `equivocations/${keyDigest(op.connectionId)}/`,
          );
          if (
            collisions.entries.length ||
            (await get(
              tx,
              `binding-conflicts/${keyDigest(op.connectionId)}`,
            )) ||
            plan.pending.length ||
            plan.rejected.length ||
            plan.conflicts.length ||
            (op.kind !== "connection-delete" &&
              plan.suppressed.some(
                (issue) =>
                  issue.reason === "connection_deleted" ||
                  issue.reason === "old_generation",
              ))
          )
            throw new Error("local batch violates replica contract");
        }
        if (local && (op.kind === "upsert" || op.kind === "delete")) {
          const declaration = context.declarations.find(
            (d) =>
              d.sourceId === op.sourceId &&
              canonicalJson(d.binding) === canonicalJson(op.declaration),
          );
          if (!declaration) throw new Error("missing retained declaration");
          const row = await get<PdppRecordRow>(
            tx,
            rowKey(op.connectionId, op.declaration.stream, op.recordKey),
          );
          const decision = planIngest(
            0,
            {
              instance: op.connectionId,
              stream: op.declaration.stream,
              key:
                op.declaration.primaryKey.length === 1
                  ? op.kind === "upsert"
                    ? (op.data[op.declaration.primaryKey[0]] as string)
                    : op.recordKey
                  : JSON.parse(op.recordKey),
              data: op.kind === "upsert" ? op.data : null,
              emitted_at: op.emittedAt,
              op: op.kind,
            },
            declaration.binding.semantics,
            declaration.binding.primaryKey,
            () =>
              row
                ? { deleted: row.deleted, data: row.deleted ? null : row.data }
                : undefined,
            (_s, _i, data) =>
              declaration.validateData(data) ? null : "invalid_record_data",
          );
          if (decision.outcome.outcome === "rejected")
            throw new Error(decision.outcome.reason);
          if (decision.outcome.outcome === "unchanged") continue;
          if (op.kind === "upsert" && !(await blobReady(tx, op)))
            throw new Error("missing_or_invalid_blob");
        }
        const confirmedBlobs =
          op.kind === "blob-claim"
            ? [op.blob]
            : op.kind === "upsert"
              ? op.blobs
              : [];
        // Bytes that only a pending batch carries stay pending: a confirmed
        // claim must not adopt them.
        for (const blob of confirmedBlobs)
          if (
            (await tx.blob(blob.blobId)) &&
            !(await get(tx, `pending-blobs/${keyDigest(blob.blobId)}`))
          )
            await put(tx, `confirmed-blobs/${keyDigest(blob.blobId)}`, true);
        current.counter = Math.max(current.counter, op.revision.counter);
        const { collision, opKey } = await retain(tx, op, dirty);
        const address =
          op.kind === "upsert" || op.kind === "delete"
            ? { stream: op.declaration.stream, key: op.recordKey }
            : undefined;
        if (address) {
          const keys = changed.get(op.connectionId) ?? new Map();
          keys.set(recordId(address.stream, address.key), address);
          changed.set(op.connectionId, keys);
        } else full.add(op.connectionId);
        if (collision) for (const id of dirty) full.add(id);
        accepted.push(op);
        // Keep subsequent same-batch local content decisions on staged canonical rows.
        if (local) {
          await reconcile(
            tx,
            op.connectionId,
            context,
            address && !collision ? [address] : undefined,
          );
          current.sequence += 1;
          const entry: LogEntry = {
            batchId: input.id,
            operationKey: opKey,
            sequence: current.sequence,
          };
          if (op.kind === "upsert" || op.kind === "delete") {
            const row = await get<PdppRecordRow>(
              tx,
              rowKey(op.connectionId, op.declaration.stream, op.recordKey),
            );
            if (!row) throw new Error("local record was not materialized");
            entry.rowVersion = row.version;
          }
          await put(tx, logKey(current.sequence), entry);
        }
      }
      for (const id of dirty)
        await reconcile(
          tx,
          id,
          context,
          full.has(id)
            ? undefined
            : changed.get(id)
              ? [...changed.get(id)!.values()]
              : undefined,
        );
      if (local && accepted.length) {
        // Reject invalid lifecycle/generation batches before any acknowledgment.
        for (const id of dirty) {
          const lifecycle = await operations(
            tx,
            `${connectionPrefix(id)}lifecycle/`,
          );
          const own = accepted.filter((op) => op.connectionId === id);
          const plan = planReplicaMerge(context, [...lifecycle, ...own]);
          if (
            plan.pending.length ||
            plan.rejected.length ||
            plan.conflicts.length ||
            plan.suppressed.some((issue) => issue.reason === "old_generation")
          )
            throw new Error("local batch violates replica contract");
        }
      }
      await put(tx, "clock", current);
      const receipt = prior?.receipt ?? {
        sequence: current.sequence,
        operationCount: accepted.length,
      };
      await put(tx, receiptKey, { fingerprint, receipt });
      if (input.promotion) {
        const path = pendingKey(input.promotion.id);
        const batch = (await get<PendingBatch>(tx, path))!;
        await put(tx, path, { ...batch, state: "confirmed" });
        await indexPending(tx, batch, false, context);
      }
      const previewDirty = new Set(dirty);
      for (const op of accepted) {
        if (await refreshPendingRevision(tx, op, previewDirty))
          for (const id of previewDirty) full.add(id);
      }
      for (const id of previewDirty)
        await refreshPreview(
          tx,
          id,
          context,
          full.has(id) ? undefined : [...(changed.get(id)?.values() ?? [])],
        );
      await advanceChanged(tx, previewDirty);
      return receipt;
    });
  }
  function authenticate(credential: unknown) {
    const context = deps.context();
    if (
      !context.owner ||
      deps.authenticateReplica(credential) !== context.owner
    )
      throw new Error("replica authority required for owner");
    return context;
  }
  // Merge two native keyset pages. The earlier continuation boundary limits
  // both inputs, so no unconsumed entry can be skipped on the next page.
  async function mergedPage(
    tx: LiteCanonicalTransaction,
    namespace: string,
    prefix: string,
    after?: string,
    formatExtra?: (value: string) => string,
  ) {
    const [base, extra] = await Promise.all([
      tx.scan(prefix, after),
      tx.scan(
        `${namespace}${prefix}`,
        after === undefined ? undefined : `${namespace}${after}`,
      ),
    ]);
    const boundaries = [base.after, extra.after?.slice(namespace.length)]
      .filter((key): key is string => key !== undefined)
      .sort();
    const boundary = boundaries[0];
    const entries = new Map(
      base.entries.map((entry) => [entry.key, entry.value]),
    );
    for (const entry of extra.entries)
      entries.set(
        entry.key.slice(namespace.length),
        formatExtra ? formatExtra(entry.value) : entry.value,
      );
    const sorted = [...entries]
      .filter(([key]) => boundary === undefined || key <= boundary)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const page: { key: string; value: string }[] = [];
    let bytes = 0;
    for (const [key, value] of sorted) {
      const size = encoder.encode(value).length;
      if (page.length && (page.length === 100 || bytes + size > 512 * 1024))
        break;
      page.push({ key, value });
      bytes += size;
    }
    return {
      entries: page,
      ...(boundary !== undefined || page.length < sorted.length
        ? { after: page.at(-1)?.key ?? boundary }
        : {}),
    };
  }
  function previewRows(tx: LiteCanonicalTransaction): LiteCanonicalTransaction {
    return {
      ...tx,
      get: async (key) => (await tx.get(`preview/${key}`)) ?? tx.get(key),
      scan: (prefix, after) =>
        mergedPage(tx, "preview/", prefix, after, (value) =>
          canonicalJson({ ...JSON.parse(value), ...replicaPendingMetadata() }),
        ),
    };
  }
  // Only writers use this view. Retained canonical and active pending partitions
  // feed the same reducer; derived rows are durable but never enter canonical data.
  /**
   * A preview row equals its canonical row when it shows the same content. Its
   * version and emitted time may differ, for example after a pending reset
   * re-adds a row. The owner sees such a row without a pending marker, as on
   * Node.
   */
  function sameContent(preview: string, canonical: string | undefined) {
    if (preview === canonical) return true;
    if (canonical === undefined) return false;
    const a = JSON.parse(preview) as PdppRecordRow;
    const b = JSON.parse(canonical) as PdppRecordRow;
    return (
      !a.deleted &&
      !b.deleted &&
      canonicalJson(a.data) === canonicalJson(b.data)
    );
  }
  function pendingMaterializer(
    tx: LiteCanonicalTransaction,
  ): LiteCanonicalTransaction {
    return {
      ...tx,
      get: async (key) => {
        if (
          key.startsWith("binding-evidence/") ||
          key.startsWith("binding-conflicts/")
        ) {
          const id = key.slice(key.indexOf("/") + 1);
          const canonical = await get<Connection>(tx, `binding-evidence/${id}`);
          const bindings = new Set<string>(
            canonical ? [canonicalJson(canonical)] : [],
          );
          for await (const entry of scan(tx, `pending-bindings/${id}/`))
            bindings.add(
              canonicalJson(
                (JSON.parse(entry.value) as { binding: Connection }).binding,
              ),
            );
          const [first, second] = bindings;
          if (key.startsWith("binding-evidence/")) return first;
          return (await tx.get(key)) ?? second;
        }
        return tx.get(key);
      },
      put: async (key, value) => {
        if (!key.startsWith("rows/")) return;
        const before = await tx.get(`preview/${key}`);
        await tx.put(`preview/${key}`, value);
        await indexPreviewBlobRef(tx, key, before, value);
      },
      delete: async (key) => {
        const before = await tx.get(`preview/${key}`);
        await tx.delete(`preview/${key}`);
        await indexPreviewBlobRef(tx, key, before, undefined);
      },
      scan: (prefix, after) => mergedPage(tx, "pending-index/", prefix, after),
    };
  }
  /**
   * Blob id -> preview rows that reference it, kept in the same write as the
   * preview row. Only preview rows can reference pending-only bytes: a
   * canonical upsert commits its bytes and marks the blob confirmed. So this
   * index is the visible-reference set of every include-pending reader;
   * confirmed-only readers never see pending bytes.
   */
  async function indexPreviewBlobRef(
    tx: LiteCanonicalTransaction,
    path: string,
    before: string | undefined,
    after: string | undefined,
  ) {
    const blobOf = (value: string | undefined) => {
      if (value === undefined) return undefined;
      const row = JSON.parse(value) as PdppRecordRow;
      if (row.deleted) return undefined;
      const id = (row.data.blob_ref as { blob_id?: unknown } | undefined)
        ?.blob_id;
      return typeof id === "string" ? id : undefined;
    };
    const old = blobOf(before);
    const next = blobOf(after);
    if (old === next) return;
    if (old !== undefined)
      await tx.delete(
        `${PREVIEW_BLOB_REFS}${keyDigest(old)}/${keyDigest(path)}`,
      );
    if (next !== undefined)
      await put(
        tx,
        `${PREVIEW_BLOB_REFS}${keyDigest(next)}/${keyDigest(path)}`,
        path,
      );
  }
  async function refreshPreview(
    tx: LiteCanonicalTransaction,
    id: string,
    context: MergeContext,
    only?: readonly { stream: string; key: string }[],
  ) {
    // Each key starts from canonical rows, never yesterday's preview. Reconcile
    // streams native key pages on lifecycle fanout instead of collecting a scope.
    await reconcile(pendingMaterializer(tx), id, context, only, tx);
  }
  async function advancePreview(tx: LiteCanonicalTransaction, id: string) {
    const path = `preview-revision/${keyDigest(id)}`;
    await put(tx, path, ((await get<number>(tx, path)) ?? 0) + 1);
  }
  async function advanceCanonicalView(
    tx: LiteCanonicalTransaction,
    id: string,
  ) {
    const path = `canonical-view-revision/${keyDigest(id)}`;
    await put(tx, path, ((await get<number>(tx, path)) ?? 0) + 1);
    await advancePreview(tx, id);
  }
  /**
   * Advance only the connections whose visible state this transaction changed.
   * An unchanged retry, a repeated import or a repeated promotion keeps every
   * cursor (oracle D4). Canonical changes also move the owner view.
   */
  async function advanceChanged(
    tx: LiteCanonicalTransaction,
    ids: Iterable<string>,
  ) {
    const { canonical, preview } = await changedViews(tx);
    let changed = false;
    for (const id of new Set(ids)) {
      const digest = keyDigest(id);
      if (canonical.has(digest)) {
        await advanceCanonicalView(tx, id);
        changed = true;
      } else if (preview.has(digest)) {
        await advancePreview(tx, id);
        changed = true;
      }
    }
    if (changed)
      await put(
        tx,
        "visibility-epoch",
        ((await get<number>(tx, "visibility-epoch")) ?? 0) + 1,
      );
  }
  async function refreshPendingRevision(
    tx: LiteCanonicalTransaction,
    op: ReplicaOperation,
    dirty: Set<string>,
  ) {
    const prefix = `revisions/${operationId(op)}/`;
    const variants: { connectionId: string; opKey: string }[] = [];
    for await (const entry of scan(pendingMaterializer(tx), prefix))
      variants.push(JSON.parse(entry.value));
    for (const id of new Set([
      op.connectionId,
      ...variants.map((v) => v.connectionId),
    ])) {
      const key = `pending-index/equivocations/${keyDigest(id)}/${operationId(op)}`;
      if (
        variants.length > 1 &&
        variants.some((variant) => variant.connectionId === id)
      )
        await put(tx, key, variants);
      else await tx.delete(key);
      dirty.add(id);
    }
    return variants.length > 1;
  }
  async function indexPending(
    tx: LiteCanonicalTransaction,
    batch: PendingBatch,
    active: boolean,
    context: MergeContext,
  ) {
    const dirty = new Set<string>();
    const full = new Set<string>();
    const changed = new Map<
      string,
      Map<string, { stream: string; key: string }>
    >();
    for (const op of (await pendingEnvelope(tx, batch)).operations) {
      await put(
        tx,
        `pending-index/retained-connections/${keyDigest(op.connectionId)}`,
        op.connectionId,
      );
      const path = operationPath(op);
      const refs = `pending-refs/${digest(op)}/`;
      const ref = `${refs}${keyDigest(batch.id)}`;
      const existed = await tx.get(`pending-index/${path}`);
      if (active) await put(tx, ref, true);
      else await tx.delete(ref);
      const remains = (await tx.scan(refs)).entries.length > 0;
      if (remains) await put(tx, `pending-index/${path}`, op);
      else await tx.delete(`pending-index/${path}`);
      const binding = { sourceId: op.sourceId, methodId: op.methodId };
      const bindingKey = `pending-bindings/${keyDigest(op.connectionId)}/${keyDigest(binding)}`;
      const priorBinding = await get<{ count: number; binding: Connection }>(
        tx,
        bindingKey,
      );
      const count =
        (priorBinding?.count ?? 0) + (remains ? 1 : 0) - (existed ? 1 : 0);
      if (count) await put(tx, bindingKey, { count, binding });
      else await tx.delete(bindingKey);
      const revisionKey = `pending-index/revisions/${operationId(op)}/${digest(op)}`;
      if (remains)
        await put(tx, revisionKey, {
          connectionId: op.connectionId,
          opKey: path,
        });
      else await tx.delete(revisionKey);
      const wasCollision = !!(await tx.get(
        `pending-index/equivocations/${keyDigest(op.connectionId)}/${operationId(op)}`,
      ));
      const collision = await refreshPendingRevision(tx, op, dirty);
      if (collision || wasCollision) for (const id of dirty) full.add(id);
      if (op.kind === "upsert" || op.kind === "delete") {
        const address = { stream: op.declaration.stream, key: op.recordKey };
        await put(
          tx,
          `pending-index/keys/${keyDigest(op.connectionId)}/${recordId(address.stream, address.key)}`,
          address,
        );
        const keys = changed.get(op.connectionId) ?? new Map();
        keys.set(recordId(address.stream, address.key), address);
        changed.set(op.connectionId, keys);
      } else full.add(op.connectionId);
    }
    for (const id of dirty)
      await refreshPreview(
        tx,
        id,
        context,
        full.has(id) ? undefined : [...(changed.get(id)?.values() ?? [])],
      );
    if (!active) {
      for (const [id, keys] of changed)
        for (const { stream, key } of keys.values())
          if (
            !(
              await tx.scan(
                `pending-index/${connectionPrefix(id)}records/${recordId(stream, key)}/`,
              )
            ).entries.length
          )
            await tx.delete(
              `pending-index/keys/${keyDigest(id)}/${recordId(stream, key)}`,
            );
      for (const id of dirty)
        if (
          !(await tx.scan(`pending-index/${connectionPrefix(id)}`)).entries
            .length
        )
          await tx.delete(
            `pending-index/retained-connections/${keyDigest(id)}`,
          );
    }
    for (const blob of batch.blobs) {
      const path = `pending-blob-active/${keyDigest(blob.blobId)}/${keyDigest(batch.id)}`;
      if (active) await put(tx, path, true);
      else await tx.delete(path);
    }
    await advanceChanged(tx, dirty);
  }
  async function ensurePendingIndex(
    tx: LiteCanonicalTransaction,
    context: MergeContext,
  ) {
    const version = await get<number>(tx, "pending-index-version");
    if (version === PENDING_INDEX_VERSION) return;
    // One-time upgrade belongs to an authenticated writer, never a record read.
    if (version === 2) {
      // Version 3 adds the visible blob-reference index over existing rows.
      for await (const entry of scan(tx, "preview/rows/"))
        await indexPreviewBlobRef(
          tx,
          entry.key.slice("preview/".length),
          undefined,
          entry.value,
        );
      await put(tx, "pending-index-version", PENDING_INDEX_VERSION);
      return;
    }
    for await (const entry of scan(tx, "pending-batches/")) {
      const batch = JSON.parse(entry.value) as PendingBatch;
      if (batch.state === "pending")
        await indexPending(tx, batch, true, context);
    }
    // Version 2 receipts bind each connection's canonical and pending snapshots.
    // Initialize them during this one-time writer upgrade, never during a read.
    for await (const entry of scan(
      pendingMaterializer(tx),
      "retained-connections/",
    ))
      await advanceCanonicalView(tx, JSON.parse(entry.value) as string);
    await put(tx, "pending-index-version", PENDING_INDEX_VERSION);
  }
  async function readView(
    tx: LiteCanonicalTransaction,
    options: LiteReplicaReadOptions,
  ) {
    if (!replicaStateVisible("pending", options.reader, deps.visibilityPolicy))
      return tx;
    if ((await get(tx, "pending-index-version")) !== PENDING_INDEX_VERSION)
      throw new Error(
        "pending preview requires reconciliation; call retry before owner reads",
      );
    return previewRows(tx);
  }
  /** A confirmed claim is usable only while a current live row references it. */
  async function hasCurrentConfirmedReference(
    tx: LiteCanonicalTransaction,
    blobId: string,
    context: MergeContext,
  ) {
    for await (const entry of scan(tx, "retained-connections/")) {
      const id = JSON.parse(entry.value) as string;
      const digest = keyDigest(id);
      if (
        !(await any(tx, `${connectionPrefix(id)}claims/${keyDigest(blobId)}/`))
      )
        continue;
      const { connection, blocked } = await connectionState(tx, id, context);
      if (blocked || connection.status !== "active") continue;
      for await (const rowEntry of scan(tx, `rows/${digest}/`)) {
        const row = JSON.parse(rowEntry.value) as PdppRecordRow;
        if (row.deleted) continue;
        const generation = await get<number>(
          tx,
          `row-generation/${rowEntry.key}`,
        );
        if (generation !== connection.generation) continue;
        const reference = (
          row.data.blob_ref as { blob_id?: unknown } | undefined
        )?.blob_id;
        if (reference === blobId) return true;
      }
    }
    return false;
  }
  async function blobReadState(
    tx: LiteCanonicalTransaction,
    blobId: string,
    options: LiteReplicaReadOptions,
  ) {
    const previewReader = replicaStateVisible(
      "pending",
      options.reader,
      deps.visibilityPolicy,
    );
    const pendingBytes = await get(tx, `pending-blobs/${keyDigest(blobId)}`);
    const confirmed = await get(tx, `confirmed-blobs/${keyDigest(blobId)}`);
    let visible = false;
    if (confirmed) {
      visible = await hasCurrentConfirmedReference(tx, blobId, deps.context());
      if (previewReader) {
        await readView(tx, options);
        visible ||= await any(tx, `${PREVIEW_BLOB_REFS}${keyDigest(blobId)}/`);
      }
    } else if (pendingBytes && previewReader) {
      // Pending bytes need a live reference this reader sees, and an active
      // batch that carries them. One batch can stage the record and another
      // the bytes; either can later be withdrawn independently.
      await readView(tx, options);
      visible =
        (await any(tx, `${PREVIEW_BLOB_REFS}${keyDigest(blobId)}/`)) &&
        (await any(tx, `pending-blob-active/${keyDigest(blobId)}/`));
    }
    return {
      visible,
      epoch: (await get<number>(tx, "visibility-epoch")) ?? 0,
    };
  }
  /** Mark a blob's bytes confirmed. True when they were not confirmed before. */
  async function confirmBlob(tx: LiteCanonicalTransaction, blobId: string) {
    const path = `confirmed-blobs/${keyDigest(blobId)}`;
    if (await get(tx, path)) return false;
    await put(tx, path, true);
    return true;
  }
  /**
   * Connections with a retained claim on the blob. A row on any of them can
   * turn visible when the blob's bytes become confirmed.
   */
  async function claimants(tx: LiteCanonicalTransaction, blobId: string) {
    const ids: string[] = [];
    for await (const entry of scan(tx, "retained-connections/")) {
      const id = JSON.parse(entry.value) as string;
      if (await any(tx, `${connectionPrefix(id)}claims/${keyDigest(blobId)}/`))
        ids.push(id);
    }
    return ids;
  }
  async function visibleRow(
    tx: LiteCanonicalTransaction,
    view: LiteCanonicalTransaction,
    path: string,
  ): Promise<LiteVisibleRecord | undefined> {
    const row = await get<PdppRecordRow>(view, path);
    if (!row || view === tx || (await tx.get(path)) === (await view.get(path)))
      return row;
    return { ...row, ...replicaPendingMetadata() };
  }
  return {
    /** Host hook: caller authenticates/decrypts transport and verifies its hash before staging. */
    async stagePending(input: {
      id: string;
      envelope: unknown;
      credential: unknown;
      blobs?: { stagingId: LiteStagingId; descriptor: LiteBlobDescriptor }[];
    }) {
      enabled();
      const context = authenticate(input.credential);
      if (!input.id || input.id.length > 256)
        throw new Error("invalid pending batch id");
      refuseOversizedEnvelope(input.envelope);
      const envelope = replicaEnvelopeSchema.parse(input.envelope);
      if (
        envelope.owner !== context.owner ||
        envelope.operations.some((op) => op.owner !== context.owner)
      )
        throw new LiteCanonicalRefusal("wrong_owner", "wrong replica owner");
      if (planReplicaMerge(context, envelope.operations).rejected.length)
        throw new Error("invalid pending replica operations");
      const fingerprint = digest(envelope);
      return persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const path = pendingKey(input.id);
        const prior = await get<PendingBatch>(tx, path);
        if (prior && prior.fingerprint !== fingerprint)
          throw new LiteCanonicalRefusal(
            "commit_id_reused",
            "pending id reused with different content",
          );
        if (prior && prior.state !== "pending")
          return { fingerprint, state: prior.state };
        for (const op of envelope.operations) await mapping(tx, op);
        for (const blob of input.blobs ?? []) {
          if (
            !envelope.operations.some(
              (op) =>
                op.kind === "blob-claim" &&
                canonicalJson(op.blob) === canonicalJson(blob.descriptor),
            )
          )
            throw new Error("pending blob requires matching claim");
          if (
            (await tx.blob(blob.descriptor.blobId)) &&
            !(await get(
              tx,
              `pending-blobs/${keyDigest(blob.descriptor.blobId)}`,
            ))
          )
            await put(
              tx,
              `confirmed-blobs/${keyDigest(blob.descriptor.blobId)}`,
              true,
            );
          await tx.attachBlob(blob.stagingId, blob.descriptor);
          await put(
            tx,
            `pending-blobs/${keyDigest(blob.descriptor.blobId)}`,
            true,
          );
        }
        const blobs = [
          ...new Map(
            [
              ...(prior?.blobs ?? []),
              ...(input.blobs ?? []).map((blob) => blob.descriptor),
            ].map((blob) => [blob.blobId, blob]),
          ).values(),
        ];
        // A restaged batch keeps the envelope it stored first.
        const parts = prior
          ? undefined
          : replicaTextParts(canonicalJson(envelope), PENDING_PART_BYTES);
        for (const [part, text] of (parts ?? []).entries())
          await tx.put(pendingPartKey(input.id, part), text);
        const batch: PendingBatch = {
          ...prior,
          id: input.id,
          fingerprint,
          state: "pending",
          blobs,
          ...(parts && { parts: parts.length }),
        };
        await put(tx, path, batch);
        await indexPending(tx, { ...batch, envelope }, true, context);
        return { fingerprint, state: "pending" as const };
      });
    },
    /** Trusted finality hook; fingerprint must come from independently verified finalized evidence. */
    async promotePending(input: {
      id: string;
      credential: unknown;
      fingerprint: string;
    }) {
      enabled();
      const context = authenticate(input.credential);
      const batch = await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const path = pendingKey(input.id);
        const value = await get<PendingBatch>(tx, path);
        if (!value) throw new Error("unknown pending batch");
        if (
          value.state === "confirmed" &&
          value.fingerprint !== input.fingerprint
        )
          throw new Error(
            "cannot quarantine confirmed batch through pending hook",
          );
        if (value.fingerprint !== input.fingerprint) {
          await put(tx, path, {
            ...value,
            state: "quarantined",
            reason: "divergent finalized commitment",
          });
          await indexPending(tx, value, false, context);
          return undefined;
        }
        if (value.state === "quarantined")
          throw new Error("pending batch quarantined");
        return pendingEnvelope(tx, value);
      });
      if (!batch) throw new Error("divergent finalized commitment");
      return commit({
        id: input.id,
        envelope: batch,
        credential: input.credential,
        promotion: input,
      });
    },
    async quarantinePending(input: {
      id: string;
      credential: unknown;
      reason: string;
    }) {
      enabled();
      const context = authenticate(input.credential);
      await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const path = pendingKey(input.id);
        const value = await get<PendingBatch>(tx, path);
        if (!value) throw new Error("unknown pending batch");
        if (value.state === "confirmed")
          throw new Error(
            "cannot quarantine confirmed batch through pending hook",
          );
        await put(tx, path, {
          ...value,
          state: "quarantined",
          reason: input.reason,
        });
        await indexPending(tx, value, false, context);
      });
    },
    /** Trusted host provisioning only; never called by replica or collector input. */
    async provisionConnection(id: string, connection: Connection) {
      enabled();
      if (!id || !connection.sourceId || !connection.methodId)
        throw new Error("invalid connection mapping");
      await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        const context = deps.context();
        const current = await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const prior = await get<Connection>(tx, `connections/${keyDigest(id)}`);
        if (prior && canonicalJson(prior) !== canonicalJson(connection))
          throw new Error("immutable connection binding");
        const retained = await get<Connection>(
          tx,
          `binding-evidence/${keyDigest(id)}`,
        );
        if (
          (retained && canonicalJson(retained) !== canonicalJson(connection)) ||
          (await get(tx, `binding-conflicts/${keyDigest(id)}`))
        )
          throw new Error("retained connection source or method mismatch");
        await put(tx, `connections/${keyDigest(id)}`, connection);
        await reconcile(tx, id, context);
        await refreshPreview(tx, id, context);
        await advanceChanged(tx, [id]);
        await put(tx, "clock", current);
      });
    },
    /**
     * Replication's writer identity (host contract §3.2): local operations
     * from now on name `writerId`. The first time a writer binds, every
     * unpublished local operation is dropped from the outbox and the current
     * canonical state is re-exported under it (`reexport`), so a phone with
     * local writes before its first enable, or after a writer rotation,
     * still converges. Binding the writer already exported is a no-op.
     */
    async rebaseline(writerId: string) {
      enabled();
      if (!writerId) throw new Error("invalid replica writer");
      return persistence.transaction(async (base) => {
        const tx = trackViews(base);
        const context = deps.context();
        const current = await clock(tx, context);
        if ((await get<string>(tx, "export-writer")) === writerId)
          return undefined;
        const result = await reexport(tx, current, writerId, context);
        await put(tx, "export-writer", writerId);
        await put(tx, "clock", current);
        return result;
      });
    },
    /** A staged pending batch's state and fingerprint, if any. */
    async pendingBatch(id: string) {
      enabled();
      return persistence.transaction(async (tx) => {
        const batch = await get<PendingBatch>(tx, pendingKey(id));
        return batch && { state: batch.state, fingerprint: batch.fingerprint };
      });
    },
    commitLocal: (
      id: string,
      operations: LiteOperationDraft[],
      blobs?: { stagingId: LiteStagingId; descriptor: LiteBlobDescriptor }[],
    ) =>
      commit({ id, operations, blobs }).then((receipt) => {
        deps.localCommitted?.();
        return receipt;
      }),
    import: (input: {
      id: string;
      envelope: unknown;
      credential: unknown;
      blobs?: { stagingId: LiteStagingId; descriptor: LiteBlobDescriptor }[];
    }) => commit(input),
    /** True when reconcile withdraws this connection from every reader. */
    async isConnectionQuarantined(connectionId: string): Promise<boolean> {
      enabled();
      return persistence.transaction(
        async (tx) =>
          (await connectionState(tx, connectionId, deps.context())).blocked,
      );
    },
    /**
     * Trusted host hook for a terminal batch (contract v3.1 A, H): record
     * the absorbing connection-quarantine fact and withdraw the connection
     * from every reader in the same transaction. The view revisions advance,
     * so open page cursors expire. Rows stay retained; nothing is deleted.
     */
    async quarantineConnection(input: {
      credential: unknown;
      connectionId: string;
      reason: string;
    }) {
      enabled();
      const context = deps.context();
      if (
        !context.owner ||
        deps.authenticateReplica(input.credential) !== context.owner
      )
        throw new Error("replica authority required for owner");
      const id = input.connectionId;
      if (!id || !input.reason)
        throw new Error("invalid connection quarantine");
      await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const path = `${CONNECTION_QUARANTINE}${keyDigest(id)}`;
        if (await get(tx, path)) return;
        await put(tx, path, { reason: input.reason });
        await reconcile(tx, id, context);
        await refreshPreview(tx, id, context);
        await advanceChanged(tx, [id]);
      });
    },
    /** Invoke after trusted declaration/validator changes. Continue until after is absent. */
    async retry(input: { credential: unknown; after?: string }) {
      enabled();
      const context = deps.context();
      if (
        !context.owner ||
        deps.authenticateReplica(input.credential) !== context.owner
      )
        throw new Error("replica authority required for owner");
      return persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const page = await mergedPage(
          tx,
          "pending-index/",
          "retained-connections/",
          input.after,
        );
        for (const entry of page.entries) {
          const id = JSON.parse(entry.value) as string;
          await reconcile(tx, id, context);
          await refreshPreview(tx, id, context);
          await advanceChanged(tx, [id]);
        }
        return { after: page.after };
      });
    },
    async readRecord(
      connection: string,
      stream: string,
      key: string,
      options: LiteReplicaReadOptions = {},
    ) {
      enabled();
      return persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx);
        const view = await readView(tx, options);
        return visibleRow(tx, view, rowKey(connection, stream, key));
      });
    },
    /**
     * The certified completions of a connection's canonical streams, by
     * stream. A completion describes canonical rows as stored, so a reader
     * that sees the pending preview gets none, as on Node.
     */
    async readStreamCompletions(
      connection: string,
      options: LiteReplicaReadOptions = {},
    ): Promise<CompletionOperation[]> {
      enabled();
      if (replicaStateVisible("pending", options.reader, deps.visibilityPolicy))
        return [];
      return persistence.transaction(async (tx) => {
        const completions: CompletionOperation[] = [];
        for await (const entry of scan(
          tx,
          `stream-completions/${keyDigest(connection)}/`,
        ))
          completions.push(JSON.parse(entry.value) as CompletionOperation);
        return completions.sort((a, b) =>
          a.declaration.stream < b.declaration.stream ? -1 : 1,
        );
      });
    },
    /** Host-only current-row page. Includes tombstones; not a public query cursor. */
    async readConnectionPage(
      connection: string,
      after?: string,
      options: LiteReplicaReadOptions = {},
    ) {
      enabled();
      if (!connection) throw new Error("connection required");
      const prefix = `rows/${keyDigest(connection)}/`;
      if (after !== undefined && !after.startsWith(prefix))
        throw new Error("invalid canonical connection cursor");
      return persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx);
        const view = await readView(tx, options);
        const mode = view === tx ? "canonical" : "pending";
        const revision =
          (await get<number>(
            tx,
            `${mode === "canonical" ? "canonical-view-revision" : "preview-revision"}/${keyDigest(connection)}`,
          )) ?? 0;
        const cursorPrefix = `${prefix}cursor/v2/${revision}/${mode}/`;
        if (after !== undefined && !after.startsWith(cursorPrefix))
          throw new Error("canonical connection cursor expired");
        const page = await view.scan(
          prefix,
          after === undefined
            ? undefined
            : `${prefix}${after.slice(cursorPrefix.length)}`,
        );
        const visible = page.entries.map(
          (entry) => JSON.parse(entry.value) as LiteVisibleRecord,
        );
        const rows: LiteVisibleRecord[] = [];
        let bytes = 2; // JSON array delimiters; pending metadata counts too.
        for (const row of visible) {
          const size =
            encoder.encode(canonicalJson(row)).length + (rows.length ? 1 : 0);
          if (rows.length && bytes + size > 512 * 1024) break;
          rows.push(row);
          bytes += size;
        }
        const next =
          rows.length < page.entries.length
            ? page.entries[rows.length - 1].key
            : page.after;
        return {
          rows,
          after:
            next === undefined
              ? undefined
              : `${cursorPrefix}${next.slice(prefix.length)}`,
        };
      });
    },
    /**
     * Internal bounded page of every local commit after a sequence, including
     * acknowledged ones. Never a public PDPP cursor or grant-relative read.
     */
    async readLogPage(afterSequence = 0) {
      enabled();
      if (!Number.isSafeInteger(afterSequence) || afterSequence < 0)
        throw new Error("invalid log offset");
      return persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx);
        return logPage(tx, afterSequence);
      });
    },
    /** Local commits after `afterSequence` that are not yet acknowledged. */
    async readOutboxPage(afterSequence = 0) {
      enabled();
      if (!Number.isSafeInteger(afterSequence) || afterSequence < 0)
        throw new Error("invalid outbox offset");
      return persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx);
        const acknowledged = (await get<number>(tx, "outbox-ack")) ?? 0;
        const page = await logPage(
          tx,
          Math.max(afterSequence, acknowledged),
          afterSequence,
        );
        return {
          entries: page.entries.map(({ sequence, batchId, operation }) => ({
            sequence,
            batchId,
            operation,
          })),
          nextAfterSequence: page.nextAfterSequence,
          hasMore: page.hasMore,
        };
      });
    },
    /** Moves the outbox past `next`. The log keeps every entry. */
    async acknowledgeOutbox(expected: number, next: number) {
      enabled();
      if (
        !Number.isSafeInteger(expected) ||
        !Number.isSafeInteger(next) ||
        expected < 0 ||
        next < expected
      )
        throw new Error("invalid outbox acknowledgment");
      await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        const current = await clock(tx);
        const actual = (await get<number>(tx, "outbox-ack")) ?? 0;
        if (actual === next) return;
        if (actual !== expected || next > current.sequence)
          throw new Error("outbox acknowledgment conflict");
        await put(tx, "outbox-ack", next);
      });
    },
    /**
     * The engine published every outbox operation up to `next` and the
     * gateway confirmed its registration: move the outbox past them. The log
     * keeps every entry. Monotonic; a lower or repeated acknowledgment is a
     * no-op.
     */
    async acknowledgePublished(next: number) {
      enabled();
      if (!Number.isSafeInteger(next) || next < 0)
        throw new Error("invalid outbox acknowledgment");
      await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        const current = await clock(tx);
        if (next > current.sequence)
          throw new Error("outbox acknowledgment conflict");
        if (next <= ((await get<number>(tx, "outbox-ack")) ?? 0)) return;
        await put(tx, "outbox-ack", next);
      });
    },
    async stageBlob(
      descriptor: LiteBlobDescriptor,
      chunks: AsyncIterable<Uint8Array>,
      signal?: AbortSignal,
    ) {
      enabled();
      await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx);
      });
      let totalBytes = 0;
      const capped = async function* () {
        for await (const chunk of chunks) {
          signal?.throwIfAborted();
          const next = totalBytes + chunk.length;
          if (!Number.isSafeInteger(next) || next > descriptor.sizeBytes)
            throw new Error("staged blob exceeds declared size");
          totalBytes = next;
          yield chunk;
        }
        signal?.throwIfAborted();
        if (totalBytes !== descriptor.sizeBytes)
          throw new Error("staged blob length does not match descriptor");
      };
      return persistence.stageBlob(descriptor, capped());
    },
    async *readBlob(blobId: string, options: LiteReplicaReadOptions = {}) {
      enabled();
      const state = await persistence.transaction(async (base) => {
        const tx = trackViews(base);
        await clock(tx);
        return blobReadState(tx, blobId, options);
      });
      if (!state.visible) throw new Error("missing committed blob");
      for await (const chunk of persistence.readBlob(blobId)) {
        const current = await persistence.transaction(async (base) => {
          const tx = trackViews(base);
          await clock(tx);
          return blobReadState(tx, blobId, options);
        });
        if (!current.visible || current.epoch !== state.epoch)
          throw new Error("visibility changed during blob read");
        yield chunk;
      }
    },
  };
}
