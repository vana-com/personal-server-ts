import {
  canonicalJson,
  replicaEnvelopeSchema,
  replicaOperationSchema,
  type ReplicaOperation,
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
export function createLiteCanonicalStore(deps: {
  persistence: LiteCanonicalPersistence;
  context: () => MergeContext;
  authenticateReplica: (credential: unknown) => string | undefined;
  enabled?: boolean;
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
    const base = connectionPrefix(op.connectionId);
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
    const suffix =
      op.kind === "upsert" || op.kind === "delete"
        ? `records/${recordId(op.declaration.stream, op.recordKey)}/`
        : op.kind === "blob-claim"
          ? `claims/${keyDigest(op.blob.blobId)}/`
          : op.kind === "stream-complete" || op.kind === "stream-invalidate"
            ? "completions/"
            : "lifecycle/";
    const opKey = `${base}${suffix}${digest(op)}`;
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
  async function reconcile(
    tx: LiteCanonicalTransaction,
    id: string,
    context: MergeContext,
    only?: readonly { stream: string; key: string }[],
  ) {
    const lifecycle = await operations(tx, `${connectionPrefix(id)}lifecycle/`);
    const mapped = await get<Connection>(tx, `connections/${keyDigest(id)}`);
    const binding = await get<Connection>(
      tx,
      `binding-evidence/${keyDigest(id)}`,
    );
    const equivocations = await tx.scan(`equivocations/${keyDigest(id)}/`);
    const lifecyclePlan = planReplicaMerge(context, lifecycle);
    const blocked =
      !!(await get(tx, `binding-conflicts/${keyDigest(id)}`)) ||
      equivocations.entries.length > 0 ||
      lifecyclePlan.conflicts.length > 0 ||
      !!(mapped && binding && canonicalJson(mapped) !== canonicalJson(binding));
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
    const keys = only
      ? only.map((key) => ({ value: canonicalJson(key) }))
      : scan(tx, `keys/${keyDigest(id)}/`);
    for await (const entry of keys) {
      const { stream, key } = JSON.parse(entry.value) as {
        stream: string;
        key: string;
      };
      const reducer = createReplicaRecordReducer(context, lifecycle);
      if (!blocked && !deleted && !pendingLifecycle) {
        for await (const variant of scan(
          tx,
          `${connectionPrefix(id)}records/${recordId(stream, key)}/`,
        )) {
          const op = replicaOperationSchema.parse(JSON.parse(variant.value));
          if (op.kind !== "upsert" && op.kind !== "delete")
            throw new Error("invalid record partition");
          reducer.push(op);
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
      let prior = await get<PdppRecordRow>(tx, path);
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
      const current = await clock(tx, context);
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
      for (const blob of input.blobs ?? [])
        await tx.attachBlob(blob.stagingId, blob.descriptor);
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
      return receipt;
    });
  }
  return {
    /** Trusted host provisioning only; never called by replica or collector input. */
    async provisionConnection(id: string, connection: Connection) {
      enabled();
      if (!id || !connection.sourceId || !connection.methodId)
        throw new Error("invalid connection mapping");
      await persistence.transaction(async (tx) => {
        const context = deps.context();
        const current = await clock(tx, context);
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
        const page = await tx.scan("retained-connections/", input.after);
        for (const entry of page.entries)
          await reconcile(tx, JSON.parse(entry.value) as string, context);
        return { after: page.after };
      });
    },
    async readRecord(connection: string, stream: string, key: string) {
      enabled();
      return persistence.transaction(async (tx) => {
        await clock(tx);
        return get<PdppRecordRow>(tx, rowKey(connection, stream, key));
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
    async *readBlob(blobId: string) {
      enabled();
      await persistence.transaction(async (tx) => {
        await clock(tx);
      });
      yield* persistence.readBlob(blobId);
    },
  };
}
