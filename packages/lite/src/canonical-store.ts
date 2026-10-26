import {
  canonicalJson,
  replicaEnvelopeSchema,
  replicaOperationSchema,
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
  type CanonicalMutation,
  type PdppRecordRow,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/portable";
import { sha256, toBytes } from "viem";
import { createReplicaRecordReducer } from "@opendatalabs/personal-server-ts-core/replication/record-reducer";
import {
  replicaStateVisible,
  replicaPendingMetadata,
  type ReplicaReader,
  type ReplicaVisibilityPolicy,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";
import type {
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
  LiteBlobDescriptor,
} from "./canonical-persistence.js";

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
export type LiteVisibleRecord = PdppRecordRow;
interface PendingBatch {
  id: string;
  fingerprint: string;
  envelope: ReplicaEnvelope;
  state: "pending" | "quarantined" | "confirmed";
  reason?: string;
  blobs: LiteBlobDescriptor[];
}
const pendingKey = (id: string) => `pending-batches/${keyDigest(id)}`;
/** Bump when a derived pending index changes; older databases need `retry`. */
const PENDING_INDEX_VERSION = 3;
const PREVIEW_BLOB_REFS = "preview-blob-refs/";
const digest = (value: unknown) =>
  `sha256:${sha256(toBytes(canonicalJson(value))).slice(2)}`;
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
      throw new Error(
        "replica merge partition exceeds 4 MiB; native repair required",
      );
    result.push(replicaOperationSchema.parse(JSON.parse(entry.value)));
  }
  return result;
}

/**
 * Experimental canonical persistence port. No runtime/route/publisher wiring.
 * Lifecycle plus one record's retained variants enter the EXISTING merge planner;
 * a scope's record bodies are never loaded together. Native transactions hide all
 * intermediate rows, blob references, journal entries, outbox and import receipts.
 */
/** Absorbing terminal-batch fact per connection (contract v3.1 A, H). */
const CONNECTION_QUARANTINE = "connection-quarantine/";

export function createLiteCanonicalStore(deps: {
  persistence: LiteCanonicalPersistence;
  context: () => MergeContext;
  authenticateReplica: (credential: unknown) => string | undefined;
  enabled?: boolean;
  visibilityPolicy?: ReplicaVisibilityPolicy;
  newId?: () => string;
}) {
  const persistence = deps.persistence;
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
      throw new Error("replica connection source or method mismatch");
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
    if (
      priorBinding &&
      canonicalJson(priorBinding) !== canonicalJson(binding)
    ) {
      await put(tx, `binding-conflicts/${keyDigest(op.connectionId)}`, true);
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
  async function blobReady(
    tx: LiteCanonicalTransaction,
    op: Extract<RecordOperation, { kind: "upsert" }>,
  ) {
    const ref = op.data.blob_ref as Record<string, unknown> | undefined;
    if (op.blobs.length !== (ref ? 1 : 0)) return false;
    for (const blob of op.blobs) {
      if (
        ref?.blob_id !== blob.blobId ||
        (ref.sha256 !== undefined && ref.sha256 !== blob.sha256.slice(7)) ||
        (ref.mime_type !== undefined && ref.mime_type !== blob.mimeType) ||
        (ref.size_bytes !== undefined && ref.size_bytes !== blob.sizeBytes)
      )
        return false;
      let claimed = false;
      for await (const entry of scan(
        tx,
        `${connectionPrefix(op.connectionId)}claims/${keyDigest(blob.blobId)}/`,
      )) {
        const claim = replicaOperationSchema.parse(JSON.parse(entry.value));
        if (
          claim.kind === "blob-claim" &&
          claim.generation === op.generation &&
          claim.sourceId === op.sourceId &&
          claim.methodId === op.methodId &&
          canonicalJson(claim.blob) === canonicalJson(blob)
        ) {
          claimed = true;
          break;
        }
      }
      if (!claimed) return false;
      const existing = await tx.blob(blob.blobId);
      if (!existing) return false;
      if (canonicalJson(existing) !== canonicalJson(blob))
        throw new Error("replica blob metadata conflict");
    }
    return true;
  }
  /**
   * Reconcile's whole blocking decision for one connection, shared with the
   * confirmed-blob gate so the two cannot drift: the terminal-batch fact,
   * binding conflicts, equivocations, lifecycle-plan conflicts, and retained
   * binding evidence that disagrees with the local mapping. A blocked
   * connection is withdrawn from every reader.
   */
  async function blocking(
    tx: LiteCanonicalTransaction,
    id: string,
    context: MergeContext,
  ) {
    const lifecycle = await operations(tx, `${connectionPrefix(id)}lifecycle/`);
    const lifecyclePlan = planReplicaMerge(context, lifecycle);
    const mapped = await get<Connection>(tx, `connections/${keyDigest(id)}`);
    const binding = await get<Connection>(
      tx,
      `binding-evidence/${keyDigest(id)}`,
    );
    const blocked =
      !!(await get(tx, `${CONNECTION_QUARANTINE}${keyDigest(id)}`)) ||
      !!(await get(tx, `binding-conflicts/${keyDigest(id)}`)) ||
      (await any(tx, `equivocations/${keyDigest(id)}/`)) ||
      lifecyclePlan.conflicts.length > 0 ||
      !!(mapped && binding && canonicalJson(mapped) !== canonicalJson(binding));
    return { lifecycle, lifecyclePlan, mapped, blocked };
  }
  async function reconcile(
    tx: LiteCanonicalTransaction,
    id: string,
    context: MergeContext,
    only?: readonly { stream: string; key: string }[],
    canonical?: LiteCanonicalTransaction,
  ) {
    const { lifecycle, lifecyclePlan, mapped, blocked } = await blocking(
      tx,
      id,
      context,
    );
    const pendingLifecycle = lifecyclePlan.pending.length > 0;
    const deleted = lifecyclePlan.suppressed.some(
      (issue) => issue.reason === "connection_deleted",
    );
    const generation = Math.max(
      1,
      ...lifecycle
        .filter((op) => op.kind === "connection-reset")
        .map((op) => op.generation),
    );
    const activeGeneration =
      (await get<number>(tx, `connection-generation/${keyDigest(id)}`)) ?? 1;
    const reset =
      !blocked && !pendingLifecycle && generation > activeGeneration;
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
      if (!blocked && !pendingLifecycle && (!deleted || provisionalRemoval)) {
        for await (const variant of scan(
          tx,
          `${connectionPrefix(id)}records/${recordId(stream, key)}/`,
        )) {
          const op = replicaOperationSchema.parse(JSON.parse(variant.value));
          if (op.kind !== "upsert" && op.kind !== "delete")
            throw new Error("invalid record partition");
          if (!deleted) reducer.push(op);
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
        winner?.kind === "upsert" && (await blobReady(tx, winner))
          ? winner
          : winner?.kind === "delete"
            ? winner
            : null;
      const path = rowKey(id, stream, key);
      if (canonical) await tx.delete(path);
      let prior = await get<PdppRecordRow>(tx, path);
      const source = mapped ? sourceReducer?.record?.winner : undefined;
      if (
        !prior &&
        !materialized &&
        source?.kind === "upsert" &&
        (await blobReady(tx, source))
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
      // an existing tombstone's original deletion time/version under a reset.
      if (!materialized && !record && prior?.deleted) continue;
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
      await put(tx, path, row);
      await put(tx, `row-generation/${path}`, generation);
    }
    if (!blocked && !pendingLifecycle)
      await put(tx, `connection-generation/${keyDigest(id)}`, generation);
  }
  async function commit(input: {
    id: string;
    operations?: LiteOperationDraft[];
    envelope?: unknown;
    credential?: unknown;
    blobs?: { stagingId: string; descriptor: LiteBlobDescriptor }[];
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
    const envelope = local
      ? undefined
      : replicaEnvelopeSchema.parse(input.envelope);
    if (
      envelope &&
      (envelope.owner !== context.owner ||
        envelope.operations.some((op) => op.owner !== context.owner))
    )
      throw new Error("wrong replica owner");
    // A local request id also fences the original, unrevised inputs after lost ack.
    const encoded = canonicalJson(local ? input.operations : envelope);
    if (encoder.encode(encoded).length > 192 * 1024)
      throw new Error("canonical batch exceeds 192 KiB; split before commit");
    const fingerprint = `sha256:${sha256(toBytes(encoded)).slice(2)}`;
    return persistence.transaction(async (tx) => {
      if (local) {
        // One write boundary for every local operation kind. Quarantine is
        // checked before clocks, staged attachments, receipts, or journals.
        for (const connectionId of new Set(
          input.operations!.map((op) => op.connectionId),
        )) {
          if ((await blocking(tx, connectionId, context)).blocked)
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
          throw new Error("commit id reused with different content");
        if (local) return prior.receipt;
        // Retry imports can supply formerly absent bytes/declarations. Retaining
        // exact operations again is idempotent; canonical writes compare content.
      }
      for (const blob of input.blobs ?? []) {
        await tx.attachBlob(blob.stagingId, blob.descriptor);
        await put(
          tx,
          `confirmed-blobs/${keyDigest(blob.descriptor.blobId)}`,
          true,
        );
      }
      const dirty = new Set<string>();
      const changed = new Map<
        string,
        Map<string, { stream: string; key: string }>
      >();
      const full = new Set<string>();
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
          throw new Error("wrong operation owner");
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
        for (const blob of confirmedBlobs)
          if (await tx.blob(blob.blobId))
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
          await put(
            tx,
            `journal/${String(current.sequence).padStart(16, "0")}`,
            op,
          );
          await put(
            tx,
            `outbox/${String(current.sequence).padStart(16, "0")}`,
            {
              batchId: input.id,
              operationKey: opKey,
              sequence: current.sequence,
            },
          );
          if (op.kind === "upsert" || op.kind === "delete") {
            const value = await get<PdppRecordRow>(
              tx,
              rowKey(op.connectionId, op.declaration.stream, op.recordKey),
            );
            if (!value) throw new Error("local record was not materialized");
            const mutation: CanonicalMutation = {
              sequence: current.sequence,
              operationId: op.revision.operationId,
              writerId: op.revision.writerId,
              sourceId: op.sourceId,
              connectionId: op.connectionId,
              method: op.methodId,
              generation: op.generation,
              stream: op.declaration.stream,
              recordKey: op.recordKey,
              operation: op.kind,
              value,
              blobIds:
                op.kind === "upsert" ? op.blobs.map((b) => b.blobId) : [],
            };
            await put(
              tx,
              `mutations/${String(current.sequence).padStart(16, "0")}`,
              mutation,
            );
          }
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
        for (const blob of batch.blobs)
          await put(tx, `confirmed-blobs/${keyDigest(blob.blobId)}`, true);
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
      for (const id of dirty) await advanceCanonicalView(tx, id);
      for (const id of previewDirty)
        if (!dirty.has(id)) await advancePreview(tx, id);
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
          if (key.startsWith("binding-evidence/"))
            return bindings.values().next().value;
          return (
            (await tx.get(key)) ?? (bindings.size > 1 ? "true" : undefined)
          );
        }
        return tx.get(key);
      },
      put: async (key, value) => {
        if (!key.startsWith("rows/")) return;
        const before = await tx.get(`preview/${key}`);
        if (value === (await tx.get(key))) {
          await tx.delete(`preview/${key}`);
          await indexPreviewBlobRef(tx, key, before, undefined);
        } else {
          await tx.put(`preview/${key}`, value);
          await indexPreviewBlobRef(tx, key, before, value);
        }
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
    for (const op of batch.envelope.operations) {
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
    for (const id of dirty) await advancePreview(tx, id);
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
  /**
   * True when connections claim the blob and every one of them is
   * quarantined. A quarantined connection's confirmed bytes are not served,
   * as on Node; bytes another live connection claims still are. Quarantined
   * means `blocking`, the decision `reconcile` withdraws a connection on.
   */
  async function claimedOnlyByQuarantined(
    tx: LiteCanonicalTransaction,
    blobId: string,
  ) {
    let claimed = false;
    for await (const entry of scan(tx, "retained-connections/")) {
      const id = JSON.parse(entry.value) as string;
      if (
        !(await any(tx, `${connectionPrefix(id)}claims/${keyDigest(blobId)}/`))
      )
        continue;
      if (!(await blocking(tx, id, deps.context())).blocked) return false;
      claimed = true;
    }
    return claimed;
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
      blobs?: { stagingId: string; descriptor: LiteBlobDescriptor }[];
    }) {
      enabled();
      const context = authenticate(input.credential);
      if (!input.id || input.id.length > 256)
        throw new Error("invalid pending batch id");
      const envelope = replicaEnvelopeSchema.parse(input.envelope);
      if (
        envelope.owner !== context.owner ||
        envelope.operations.some((op) => op.owner !== context.owner)
      )
        throw new Error("wrong replica owner");
      if (encoder.encode(canonicalJson(envelope)).length > 192 * 1024)
        throw new Error("canonical batch exceeds 192 KiB; split before commit");
      if (planReplicaMerge(context, envelope.operations).rejected.length)
        throw new Error("invalid pending replica operations");
      const fingerprint = digest(envelope);
      return persistence.transaction(async (tx) => {
        await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const path = pendingKey(input.id);
        const prior = await get<PendingBatch>(tx, path);
        if (prior && prior.fingerprint !== fingerprint)
          throw new Error("pending id reused with different content");
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
        const batch: PendingBatch = {
          id: input.id,
          envelope,
          fingerprint,
          state: "pending",
          blobs,
        };
        await put(tx, path, batch);
        await indexPending(tx, batch, true, context);
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
      const batch = await persistence.transaction(async (tx) => {
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
        return value;
      });
      if (!batch) throw new Error("divergent finalized commitment");
      return commit({
        id: input.id,
        envelope: batch.envelope,
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
      await persistence.transaction(async (tx) => {
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
      await persistence.transaction(async (tx) => {
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
        await advanceCanonicalView(tx, id);
        await put(tx, "clock", current);
      });
    },
    commitLocal: (
      id: string,
      operations: LiteOperationDraft[],
      blobs?: { stagingId: string; descriptor: LiteBlobDescriptor }[],
    ) => commit({ id, operations, blobs }),
    import: (input: {
      id: string;
      envelope: unknown;
      credential: unknown;
      blobs?: { stagingId: string; descriptor: LiteBlobDescriptor }[];
    }) => commit(input),
    /** True when reconcile withdraws this connection from every reader. */
    async isConnectionQuarantined(connectionId: string): Promise<boolean> {
      enabled();
      return persistence.transaction(
        async (tx) =>
          (await blocking(tx, connectionId, deps.context())).blocked,
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
      await persistence.transaction(async (tx) => {
        await clock(tx, context);
        await ensurePendingIndex(tx, context);
        const path = `${CONNECTION_QUARANTINE}${keyDigest(id)}`;
        if (await get(tx, path)) return;
        await put(tx, path, { reason: input.reason });
        await reconcile(tx, id, context);
        await refreshPreview(tx, id, context);
        await advanceCanonicalView(tx, id);
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
      return persistence.transaction(async (tx) => {
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
          await advanceCanonicalView(tx, id);
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
      return persistence.transaction(async (tx) => {
        await clock(tx);
        const view = await readView(tx, options);
        return visibleRow(tx, view, rowKey(connection, stream, key));
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
      return persistence.transaction(async (tx) => {
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
    /** Internal bounded keyset pages; never a public PDPP cursor or grant-relative read. */
    async readPage(kind: "journal" | "mutations" | "outbox", after?: string) {
      enabled();
      return persistence.transaction(async (tx) => {
        await clock(tx);
        return tx.scan(`${kind}/`, after);
      });
    },
    async readOutboxPage(afterSequence = 0) {
      enabled();
      if (!Number.isSafeInteger(afterSequence) || afterSequence < 0)
        throw new Error("invalid outbox offset");
      return persistence.transaction(async (tx) => {
        await clock(tx);
        const page = await tx.scan(
          "outbox/",
          `outbox/${String(afterSequence).padStart(16, "0")}`,
        );
        const entries: {
          sequence: number;
          batchId: string;
          operation: ReplicaOperation;
        }[] = [];
        let bytes = 0;
        for (const entry of page.entries) {
          const pointer = JSON.parse(entry.value) as {
            sequence: number;
            batchId: string;
            operationKey: string;
          };
          const value = await tx.get(pointer.operationKey);
          if (!value) throw new Error("missing immutable outbox operation");
          bytes += encoder.encode(value).length;
          if (bytes > 512 * 1024) break;
          entries.push({
            sequence: pointer.sequence,
            batchId: pointer.batchId,
            operation: replicaOperationSchema.parse(JSON.parse(value)),
          });
        }
        return {
          entries,
          nextAfterSequence: entries.at(-1)?.sequence ?? afterSequence,
          hasMore:
            page.after !== undefined || entries.length < page.entries.length,
        };
      });
    },
    async acknowledgeOutbox(expected: number, next: number) {
      enabled();
      if (
        !Number.isSafeInteger(expected) ||
        !Number.isSafeInteger(next) ||
        expected < 0 ||
        next < expected
      )
        throw new Error("invalid outbox acknowledgment");
      await persistence.transaction(async (tx) => {
        const current = await clock(tx);
        const actual = (await get<number>(tx, "outbox-ack")) ?? 0;
        if (actual === next) return;
        if (actual !== expected || next > current.sequence)
          throw new Error("outbox acknowledgment conflict");
        for await (const entry of scan(tx, "outbox/")) {
          if (Number(entry.key.slice(7)) > next) break;
          await tx.delete(entry.key);
        }
        await put(tx, "outbox-ack", next);
      });
    },
    async stageBlob(
      descriptor: LiteBlobDescriptor,
      chunks: AsyncIterable<Uint8Array>,
    ) {
      enabled();
      await persistence.transaction(async (tx) => {
        await clock(tx);
      });
      return persistence.stageBlob(descriptor, chunks);
    },
    async *readBlob(blobId: string, options: LiteReplicaReadOptions = {}) {
      enabled();
      await persistence.transaction(async (tx) => {
        await clock(tx);
      });
      const visible = await persistence.transaction(async (tx) => {
        if (
          !(await get(tx, `pending-blobs/${keyDigest(blobId)}`)) ||
          (await get(tx, `confirmed-blobs/${keyDigest(blobId)}`))
        )
          return !(await claimedOnlyByQuarantined(tx, blobId));
        if (
          !replicaStateVisible("pending", options.reader, deps.visibilityPolicy)
        )
          return false;
        // Pending bytes need a live reference this reader sees, as on Node,
        // and an active batch that carries them. The two are independent: one
        // batch can stage the record and another the bytes, and a later
        // deletion or operation-ID variant can hide the record while its
        // carrier stays active.
        await readView(tx, options); // throws until the writer upgraded the indexes
        return (
          (await any(tx, `${PREVIEW_BLOB_REFS}${keyDigest(blobId)}/`)) &&
          (await any(tx, `pending-blob-active/${keyDigest(blobId)}/`))
        );
      });
      if (!visible) throw new Error("missing committed blob");
      yield* persistence.readBlob(blobId);
    },
  };
}
