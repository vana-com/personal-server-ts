/**
 * The replication phase engine on PS-Lite: core's shared engine
 * (`core/replication/engine.ts`, also Node's) bound to the Lite ports. Every
 * storage effect runs inside one native transaction, asynchronously.
 *
 * - Relational replication state uses `tx.sql` (host contract §4.3).
 * - Local operations come from the canonical store's outbox, under the
 *   writer identity the canonical clock is bound to.
 * - Received batches use core's copy custody (`replication/copies.ts`); a
 *   promoted copy imports through the canonical store.
 * - Received blob bytes are replica bytes attached in the outcome
 *   transaction, then published as canonical blobs with `tx.publishBlob`.
 * - A new writer (first enable with local writes, rotation) re-exports the
 *   canonical state into the outbox (canonical `rebaseline`, core
 *   `rebaseline.ts` rules), so the baseline is empty and the tail carries it.
 * - The outbox drops what the gateway confirmed (`acknowledgePublished`).
 */
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import type { ReplicaVisibilityPolicy } from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";
import {
  createReplicaEngine,
  type ReplicaEngine,
  type ReplicaEngineConfig,
  type ReplicaEngineHost,
  type ReplicaEngineStagedWriter,
  type ReplicaEngineStaging,
} from "@opendatalabs/personal-server-ts-core/replication/engine";
import {
  perform,
  runEffectAsync,
  sql,
  type ReplicaEffect,
} from "@opendatalabs/personal-server-ts-core/replication/effects";
import {
  ReplicaCoordinatorConflict,
  type AsyncReplicaCoordinatorStatePort,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import { REPLICA_LOCK_SCHEMA } from "@opendatalabs/personal-server-ts-core/replication/coordinator-state";
import { REPLICA_PAYLOAD_MIGRATION } from "@opendatalabs/personal-server-ts-core/replication/payload";
import {
  REPLICA_COPY_MIGRATION,
  ReplicaCopyRefused,
  replicaCopies,
  type StagedCopy,
} from "@opendatalabs/personal-server-ts-core/replication/copies";
import { REPLICA_REFETCH_BUDGET } from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import {
  REPLICA_WRITER_IDENTITY_MIGRATION,
  currentReplicaWriterIdentity,
  enableReplicaWriterIdentity,
  establishReplicaWriterIdentity,
  rotateReplicaWriterIdentity,
  type ReplicaWriterIdentity,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity-store";
import {
  replicaEnvelopeSchema,
  type ReplicaEnvelope,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { Admission } from "@opendatalabs/personal-server-ts-core/replication/limits";
import {
  LITE_CANONICAL_MAX_OPERATION_BYTES,
  type LiteBlobDescriptor,
  type LiteCanonicalPersistence,
  type LiteCanonicalTransaction,
  type LiteStagingId,
} from "./canonical-persistence.js";
import {
  createLiteCanonicalStore,
  LiteCanonicalRefusal,
  litePendingFingerprint,
} from "./canonical-store.js";
import {
  LITE_REPLICA_TRANSIENT_MIGRATION,
  reclaimLiteTransientBytes,
} from "./replication-storage.js";
import { createLiteReplicaCoordinatorState } from "./replication-coordinator-state.js";
import type {
  LiteReplicaPersistence,
  LiteReplicaTransaction,
} from "./replication-ports.js";

type Tx = LiteReplicaTransaction;
type Fx<T> = ReplicaEffect<T, Tx>;

const FRAME_BYTES = 128 * 1024;

/**
 * Received blob bytes a retained copy holds, keyed (id, blobId) like Node's
 * pending namespace. A blob id is its content hash, so copies of one batch
 * that share a blob share these bytes.
 */
const LITE_REPLICA_CUSTODY_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_lite_replica_custody (
  id TEXT NOT NULL, blob_id TEXT NOT NULL, bytes_id TEXT NOT NULL,
  PRIMARY KEY (id, blob_id));`;

/** One in-tx operation of the native transaction. */
const inTx = <T>(call: (tx: Tx) => Promise<T>): Fx<T> => perform(call);

/** Every blob descriptor an envelope names, by blob id. */
function descriptors(envelope: ReplicaEnvelope) {
  const found = new Map<string, LiteBlobDescriptor>();
  for (const op of envelope.operations) {
    if (op.kind === "blob-claim") found.set(op.blob.blobId, op.blob);
    if (op.kind === "upsert")
      for (const blob of op.blobs) found.set(blob.blobId, blob);
  }
  return found;
}

/**
 * A staged byte stream: `write` hands frames to the native stage with
 * backpressure, `complete` closes it and returns its id. The digest is
 * checked natively when the outcome transaction attaches the bytes.
 */
function stageStream(persistence: LiteReplicaPersistence) {
  const queue: (Uint8Array | null)[] = [];
  let wake: (() => void) | undefined;
  let taken: (() => void) | undefined;
  let failure: unknown;
  const notify = () => {
    wake?.();
    wake = undefined;
  };
  const id = persistence.stageBytes(
    (async function* () {
      for (;;) {
        while (!queue.length) {
          if (failure) throw failure;
          await new Promise<void>((resolve) => (wake = resolve));
        }
        const frame = queue.shift()!;
        taken?.();
        taken = undefined;
        if (frame === null) return;
        yield frame;
      }
    })(),
  );
  // A failed stage is reported by write/complete; never leave it unobserved.
  id.catch(() => undefined);
  return {
    async write(bytes: Uint8Array) {
      for (let i = 0; i < bytes.length; i += FRAME_BYTES) {
        queue.push(bytes.slice(i, i + FRAME_BYTES));
        const consumed = new Promise<void>((resolve) => (taken = resolve));
        notify();
        await Promise.race([consumed, id.then(() => consumed)]);
      }
    },
    complete() {
      queue.push(null);
      notify();
      return id;
    },
    fail(error: unknown) {
      failure = error;
      notify();
    },
  };
}

export interface LiteReplicaEngineInput {
  persistence: LiteReplicaPersistence;
  /** The canonical store's trusted context, as `createLiteCanonicalStore` takes it. */
  canonical: {
    context: () => MergeContext;
    authenticateReplica: (credential: unknown) => string | undefined;
    visibilityPolicy?: ReplicaVisibilityPolicy;
    newId?: () => string;
  };
  /** Host-independent engine configuration (transport, authority, limits). */
  engine: ReplicaEngineConfig;
}

/** The core engine on Lite, plus the writer rotation a host calls itself. */
export interface LiteReplicaEngine extends ReplicaEngine {
  /**
   * A new nonce under the same registration, after a restore, clone or
   * reinstall (host contract §3.2). Call it before the engine steps again;
   * the next step re-exports the canonical state under the new writer.
   */
  rotateWriter(input?: { nonce?: string }): Promise<ReplicaWriterIdentity>;
}

export function createLiteReplicaEngine(
  input: LiteReplicaEngineInput,
): LiteReplicaEngine {
  const { persistence, canonical, engine: config } = input;
  const now = config.now ?? (() => Date.now());
  let migrated: Promise<void> | undefined;
  const migrate = () =>
    (migrated ??= persistence
      .transaction(async (tx) => {
        for (const migration of [
          REPLICA_LOCK_SCHEMA,
          REPLICA_PAYLOAD_MIGRATION,
          REPLICA_COPY_MIGRATION,
          REPLICA_WRITER_IDENTITY_MIGRATION,
          LITE_REPLICA_CUSTODY_MIGRATION,
          LITE_REPLICA_TRANSIENT_MIGRATION,
        ])
          await tx.sql.exec(migration);
      })
      .catch((error: unknown) => {
        // A failed migration is tried again by the next step.
        migrated = undefined;
        throw error;
      }));
  const run = async <T>(effect: Fx<T>): Promise<T> => {
    await migrate();
    return persistence.transaction((tx) => runEffectAsync(effect, tx));
  };

  /**
   * The canonical store inside one native transaction. A received blob's
   * bytes are attached replica bytes, so its canonical attach publishes
   * them (`publishBlob`) instead of a staged blob.
   */
  const receiving = new WeakMap<Tx, LiteCanonicalTransaction>();
  const canonicalIn = (tx: Tx) => {
    let view = receiving.get(tx);
    if (!view) {
      view = {
        get: (key) => tx.get(key),
        put: (key, value) => tx.put(key, value),
        delete: (key) => tx.delete(key),
        scan: (prefix, after) => tx.scan(prefix, after),
        blob: (blobId) => tx.blob(blobId),
        attachBlob: (bytesId, expected) => tx.publishBlob(bytesId, expected),
      };
      receiving.set(tx, view);
    }
    const bound = view;
    const scoped: LiteCanonicalPersistence = {
      transaction: (work) => work(bound),
      stageBlob: (descriptor, chunks) =>
        persistence.stageBlob(descriptor, chunks),
      readBlob: (blobId) => persistence.readBlob(blobId),
    };
    return createLiteCanonicalStore({
      persistence: scoped,
      enabled: true,
      context: canonical.context,
      authenticateReplica: canonical.authenticateReplica,
      visibilityPolicy: canonical.visibilityPolicy,
      newId: canonical.newId,
    });
  };
  const store = <T>(
    call: (store: ReturnType<typeof createLiteCanonicalStore>) => Promise<T>,
  ): Fx<T> => inTx((tx) => call(canonicalIn(tx)));
  function authorize(credential: unknown) {
    const owner = canonical.context().owner;
    if (!owner || canonical.authenticateReplica(credential) !== owner)
      throw new Error("replica authority required for owner");
  }
  function* custody(id: string, blobs: StagedCopy["blobs"]) {
    const held: { stagingId: LiteStagingId; blobId: string }[] = [];
    for (const blob of blobs) {
      const row = yield* sql.get<{ bytes_id: string }>(
        "SELECT bytes_id FROM pdpp_lite_replica_custody WHERE id=? AND blob_id=?",
        id,
        blob.blobId,
      );
      if (!row) throw new Error("missing replica blob custody");
      held.push({
        stagingId: row.bytes_id as LiteStagingId,
        blobId: blob.blobId,
      });
    }
    return held;
  }
  function* blobsFor(
    id: string,
    envelope: ReplicaEnvelope,
    blobs: StagedCopy["blobs"],
    claimed: boolean,
  ): Fx<{ stagingId: LiteStagingId; descriptor: LiteBlobDescriptor }[]> {
    const named = descriptors(envelope);
    const claims = new Set(
      envelope.operations.flatMap((op) =>
        op.kind === "blob-claim" ? [op.blob.blobId] : [],
      ),
    );
    return (yield* custody(id, blobs)).flatMap((blob) => {
      const descriptor = named.get(blob.blobId);
      // A pending preview stages only claimed blobs (canonical rule).
      return descriptor && (!claimed || claims.has(blob.blobId))
        ? [{ stagingId: blob.stagingId, descriptor }]
        : [];
    });
  }

  /** A promoted copy into canonical state, from its pending preview if any. */
  function* importCanonical(
    envelope: ReplicaEnvelope,
    blobs: StagedCopy["blobs"],
    id: string,
  ): Fx<void> {
    const fingerprint = litePendingFingerprint(envelope);
    const pending = yield* store((s) => s.pendingBatch(id));
    if (pending?.state === "pending" && pending.fingerprint === fingerprint)
      yield* store((s) =>
        s.promotePending({ id, credential: config.credential, fingerprint }),
      );
    else {
      const attached = yield* blobsFor(id, envelope, blobs, false);
      yield* store((s) =>
        s.import({
          id,
          envelope,
          credential: config.credential,
          blobs: attached,
        }),
      );
    }
  }

  const copies = replicaCopies<Tx>({
    get owner() {
      return canonical.context().owner;
    },
    *importEnvelope(envelope, blobs, id) {
      try {
        yield* importCanonical(envelope, blobs, id);
      } catch (error) {
        // The same batch fails the same way again: stop retrying it.
        if (error instanceof LiteCanonicalRefusal)
          throw new ReplicaCopyRefused(`canonical_${error.reason}`);
        throw error;
      }
    },
    quarantineConnection: (connectionId) =>
      store((s) =>
        s.quarantineConnection({
          credential: config.credential,
          connectionId,
          reason: "finalized_conflict",
        }),
      ),
    preview: {
      *show(id, envelope, blobsJson) {
        const pending = yield* store((s) => s.pendingBatch(id));
        // The canonical pending row of an id never changes content: another
        // copy's preview hides the old one instead of replacing it.
        if (
          pending &&
          pending.fingerprint !== litePendingFingerprint(envelope)
        ) {
          if (pending.state === "pending")
            yield* store((s) =>
              s.quarantinePending({
                id,
                credential: config.credential,
                reason: "copy conflict",
              }),
            );
          return;
        }
        const blobs = yield* blobsFor(
          id,
          envelope,
          JSON.parse(blobsJson) as StagedCopy["blobs"],
          true,
        );
        try {
          yield* store((s) =>
            s.stagePending({
              id,
              envelope,
              credential: config.credential,
              blobs,
            }),
          );
        } catch (error) {
          // No preview for a batch the store refuses; promotion fails
          // closed on it (`importEnvelope`).
          if (!(error instanceof LiteCanonicalRefusal)) throw error;
        }
      },
      *hide(id, state) {
        const pending = yield* store((s) => s.pendingBatch(id));
        if (pending?.state === "pending")
          yield* store((s) =>
            s.quarantinePending({
              id,
              credential: config.credential,
              reason: state === "quarantined" ? "copy conflict" : state,
            }),
          );
      },
    },
    *releaseBytes(id, blobIds) {
      for (const blobId of blobIds) {
        const row = yield* sql.get<{ bytes_id: string }>(
          "SELECT bytes_id FROM pdpp_lite_replica_custody WHERE id=? AND blob_id=?",
          id,
          blobId,
        );
        if (!row) continue;
        yield* inTx((tx) => tx.releaseBytes(row.bytes_id));
        yield* sql.run(
          "DELETE FROM pdpp_lite_replica_custody WHERE id=? AND blob_id=?",
          id,
          blobId,
        );
      }
    },
    *savepoint(effect) {
      yield* sql.exec("SAVEPOINT lite_replica_import");
      try {
        const result = yield* effect;
        yield* sql.exec("RELEASE lite_replica_import");
        return result;
      } catch (error) {
        yield* sql.exec("ROLLBACK TO lite_replica_import");
        yield* sql.exec("RELEASE lite_replica_import");
        throw error;
      }
    },
    now,
  });
  const hasCopies = (id: string) =>
    sql.get("SELECT 1 FROM pdpp_replica_copies WHERE id=? LIMIT 1", id);

  // One engine per database. The lock row fences a step left over from an
  // earlier boot; this flag serializes steps of this boot.
  let active = false;
  const door = {
    admitted: () => true,
    beginStep(parent: AbortSignal | undefined) {
      const controller = new AbortController();
      const abort = () => controller.abort(parent?.reason);
      parent?.addEventListener("abort", abort, { once: true });
      if (parent?.aborted) abort();
      return {
        signal: controller.signal,
        close: () => parent?.removeEventListener("abort", abort),
      };
    },
    assertStepOpen(signal: AbortSignal) {
      signal.throwIfAborted();
    },
    assertTransactionOpen(signal: AbortSignal) {
      signal.throwIfAborted();
    },
  };

  const host: ReplicaEngineHost<Tx> = {
    run,
    // Every Lite effect already runs as one native transaction.
    immediate: (effect) => effect,
    transaction: (effect) => effect,
    commit(effect, context, signal) {
      door.assertTransactionOpen(signal);
      return runEffectAsync(effect, context as Tx);
    },
    cleanup(effect) {
      void run(effect).catch(() => undefined);
    },
    captureWrites: (effect) => effect,
    door,
    randomId: () => globalThis.crypto.randomUUID(),
    lock: {
      busy: () => active,
      async acquire(token) {
        active = true;
        try {
          await migrate();
          await persistence.transaction(async (tx) => {
            await tx.sql.run(
              "INSERT INTO pdpp_transport_lock (id,pid,token) VALUES (1,0,?) ON CONFLICT(id) DO UPDATE SET pid=0,token=excluded.token",
              [token],
            );
          });
        } catch (error) {
          active = false;
          throw error;
        }
      },
      async release(token) {
        active = false;
        await persistence.transaction((tx) =>
          tx.sql.run("DELETE FROM pdpp_transport_lock WHERE id=1 AND token=?", [
            token,
          ]),
        );
      },
    },
    identity: {
      current: () => currentReplicaWriterIdentity(),
      enable: (request) =>
        enableReplicaWriterIdentity({
          ...request,
          current: () => run(currentReplicaWriterIdentity()),
          establish: (record) =>
            run(
              (function* () {
                const identity = yield* establishReplicaWriterIdentity(
                  {
                    // The runtime admits only an open door (`replication-runtime.ts`).
                    admitted: function* () {
                      return true;
                    },
                    // Local writes before the first identity are re-exported
                    // under it (canonical `rebaseline`).
                    journalEmpty: function* () {
                      return true;
                    },
                  },
                  { owner: request.owner, server: request.server, record },
                );
                yield* store((s) => s.rebaseline(identity.operationWriter));
                return identity;
              })(),
            ),
        }),
    },
    coordinatorState({
      owner,
      signal,
      enabled,
    }): AsyncReplicaCoordinatorStatePort<Tx> {
      const port = createLiteReplicaCoordinatorState({ persistence, owner });
      return {
        ...port,
        async commit(expected, next, checkpoint) {
          const step = signal();
          if (!step || !enabled()) throw new ReplicaCoordinatorConflict();
          door.assertStepOpen(step);
          return port.commit(expected, next, async (tx) => {
            const result = await checkpoint(tx);
            door.assertTransactionOpen(step);
            return result;
          });
        },
      };
    },
    staging({ repositoryId, owner, assertOpen }): ReplicaEngineStaging<Tx> {
      type Handle = { bytesId: string; sizeBytes: number };
      const open = new Map<Admission, Set<{ fail(error: unknown): void }>>();
      return {
        begin(admission): ReplicaEngineStagedWriter<Handle> {
          if (
            admission.repositoryId !== repositoryId ||
            admission.owner !== owner
          )
            throw new Error("admission authority mismatch");
          const stream = stageStream(persistence);
          const writers = open.get(admission) ?? new Set();
          writers.add(stream);
          open.set(admission, writers);
          let sizeBytes = 0;
          let closed = false;
          return {
            async write(bytes) {
              if (closed) throw new Error("staged object writer is closed");
              assertOpen();
              const next = sizeBytes + bytes.length;
              if (
                !Number.isSafeInteger(next) ||
                next > admission.payloadBytes
              ) {
                stream.fail(
                  new Error("staged object exceeds admitted payload"),
                );
                throw new Error("staged object exceeds admitted payload");
              }
              await stream.write(bytes);
              sizeBytes = next;
            },
            async complete() {
              if (closed) throw new Error("staged object writer is closed");
              assertOpen();
              closed = true;
              writers.delete(stream);
              return { bytesId: await stream.complete(), sizeBytes };
            },
          };
        },
        verify(handle, expected) {
          if ((handle as Handle).sizeBytes !== expected.sizeBytes)
            throw new Error("staged object verification failed");
        },
        attach(handle, expected) {
          const { bytesId } = handle as Handle;
          return inTx(async (tx) => {
            await tx.attachBytes(bytesId, {
              length: expected.sizeBytes,
              sha256: expected.sha256.replace(/^sha256:/, ""),
            });
            return bytesId;
          });
        },
        abort(admission) {
          for (const writer of open.get(admission) ?? [])
            writer.fail(new Error("staged object aborted"));
          open.delete(admission);
        },
        // Unattached native stages are discarded by the host; none outlive
        // it. Bytes the storage adapter attached and a crash kept from its
        // release are reclaimed before the step's first transfer.
        reclaimAdmission: () => 0,
        cleanup: () => 0,
        cleanupAttachedTemporaryBytes: () =>
          run(inTx(reclaimLiteTransientBytes)),
      };
    },
    // Lite staging keeps no rows that could lose their bytes.
    *sweepStages() {},
    exporter: {
      // A new Lite writer re-exports its state into the outbox
      // (`rebaseline`), so its baseline is empty and every operation is in
      // the tail.
      *readBaselinePage({ afterSequence }) {
        return {
          operations: [],
          nextAfterSequence: afterSequence ?? 0,
          hasMore: false,
        };
      },
      *readTailPage({ afterSequence, limit }) {
        const page = yield* store((s) => s.readOutboxPage(afterSequence ?? 0));
        const taken = page.entries.slice(0, limit);
        return {
          operations: taken.map((entry) => entry.operation),
          nextAfterSequence: taken.at(-1)?.sequence ?? afterSequence ?? 0,
          hasMore: page.hasMore || taken.length < page.entries.length,
        };
      },
      *getBaselineCheckpoint() {
        return 0;
      },
      *acknowledgeBaselinePage() {},
      // `establish` already re-exported for the current identity; this is
      // a no-op unless the writer changed since.
      *rebaseline() {
        const identity = yield* currentReplicaWriterIdentity();
        if (identity)
          yield* store((s) => s.rebaseline(identity.operationWriter));
        return undefined;
      },
      acknowledgePublished: (next) =>
        store((s) => s.acknowledgePublished(next)),
      readPinnedBlobChunks: (blobId) => persistence.readBlob(blobId),
    },
    receiver: {
      // The canonical store always admits pending previews.
      setPendingEnabled() {},
      *quarantine({ credential, id, reason }) {
        authorize(credential);
        // A copy-backed batch fails closed through the terminal transition.
        if (yield* hasCopies(id)) {
          yield* copies.terminate(id, "finalized_conflict");
          return;
        }
        const pending = yield* store((s) => s.pendingBatch(id));
        if (pending?.state === "pending")
          yield* store((s) => s.quarantinePending({ id, credential, reason }));
      },
      // One step runs the whole pass, a connection per store transaction,
      // so no page is ever left queued.
      *reconcileStep({ credential }) {
        let after: string | undefined;
        do {
          after = (yield* store((s) => s.retry({ credential, after }))).after;
        } while (after !== undefined);
        // The canonical store does not report what still waits.
        return { plan: { pending: [] }, complete: true };
      },
      *reconcileQueued() {
        return false;
      },
      copies: {
        list: (id) => copies.copies(id),
        decide: (id, refetch) => copies.decide(id, refetch),
        *apply({ credential, id, decision }) {
          authorize(credential);
          yield* copies.apply(id, decision);
        },
        *stage({ credential, copy, stagedBlobs, refetch }) {
          authorize(credential);
          const envelope = replicaEnvelopeSchema.parse(copy.envelope);
          const owner = canonical.context().owner;
          if (
            envelope.owner !== owner ||
            envelope.operations.some((op) => op.owner !== owner)
          )
            throw new Error("wrong replica owner");
          for (const blob of stagedBlobs) {
            const held = yield* sql.get(
              "SELECT 1 FROM pdpp_lite_replica_custody WHERE id=? AND blob_id=?",
              copy.id,
              blob.blobId,
            );
            if (held) yield* inTx((tx) => tx.releaseBytes(blob.key));
            else
              yield* sql.run(
                "INSERT INTO pdpp_lite_replica_custody (id,blob_id,bytes_id) VALUES (?,?,?)",
                copy.id,
                blob.blobId,
                blob.key,
              );
          }
          return yield* copies.stage(
            {
              ...copy,
              envelope,
              blobs: stagedBlobs.map((blob) => ({
                blobId: blob.blobId,
                size: blob.sizeBytes,
              })),
            },
            refetch ?? { attempts: 0, budget: REPLICA_REFETCH_BUDGET },
          );
        },
        *recordFact({ credential, ...fact }) {
          authorize(credential);
          return yield* copies.recordFact(fact);
        },
        *promote({ credential, id, copyKey }) {
          authorize(credential);
          return yield* copies.promote({ id, copyKey });
        },
      },
    },
    *bindings() {
      const connections: { key: string; value: string }[] = [];
      let after: string | undefined;
      do {
        const page = yield* inTx((tx) => tx.scan("connections/", after));
        connections.push(...page.entries);
        after = page.after;
      } while (after !== undefined);
      return connections;
    },
  };
  // Constructing does no storage work: the first call creates the engine,
  // which migrates. A runtime that is off never calls it.
  let created: ReplicaEngine | undefined;
  // The phone admits no operation its canonical store cannot retain.
  const maxOperationBytes = Math.min(
    config.resourceLimits?.maxOperationBytes ??
      LITE_CANONICAL_MAX_OPERATION_BYTES,
    LITE_CANONICAL_MAX_OPERATION_BYTES,
  );
  const engine = () =>
    (created ??= createReplicaEngine(host, {
      ...config,
      resourceLimits: { ...config.resourceLimits, maxOperationBytes },
    }));
  return {
    rotateWriter: (request = {}) =>
      run(
        rotateReplicaWriterIdentity(
          {
            *admitted() {
              return door.admitted();
            },
          },
          request,
        ),
      ),
    get ready() {
      return engine().ready;
    },
    step: (request) => engine().step(request),
    cycle: () => engine().cycle(),
    retryVersionSquats: () => engine().retryVersionSquats(),
    readmitUnsupported: () => engine().readmitUnsupported(),
    readmitFragments: () => engine().readmitFragments(),
    onDependencyChanged: (key) => engine().onDependencyChanged(key),
  };
}
