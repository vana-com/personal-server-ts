/**
 * Node host for the replica transport engine (core `replication/engine.ts`).
 * The phase logic lives in core and is shared with PS-Lite; this file binds
 * it to one better-sqlite3 connection: synchronous transactions, the
 * process writer lock, the replication door, chunked staging and the
 * receiver's atomic boundary.
 */
import type { Database } from "better-sqlite3";
import { randomUUID } from "node:crypto";
import {
  createReplicaEngine,
  type ReplicaEngineConfig,
  type ReplicaEngineHost,
  type ReplicaEngineStaging,
} from "@opendatalabs/personal-server-ts-core/replication/engine";
import {
  perform,
  runEffectSync,
  type ReplicaEffect,
  type ReplicaEffectContext,
} from "@opendatalabs/personal-server-ts-core/replication/effects";
import { ReplicaCoordinatorConflict } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import { deleteBinary } from "./pdpp-binary-chunks.js";
import { createSqliteReplicaCoordinatorState } from "./pdpp-replica-coordinator-state.js";
import { nodeReplicaContext } from "./pdpp-replica-sql.js";
import {
  assertReplicationStepOpen,
  assertReplicationTransactionOpen,
  beginReplicationStep,
  captureWrites,
  replicationAdmitted,
} from "./pdpp-replication-door.js";
import type { ReplicationExport } from "./pdpp-replication-sqlite.js";
import {
  currentReplicaWriterIdentity,
  enableReplicaWriterIdentity,
} from "./pdpp-replica-writer-identity.js";
import type { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import {
  createReplicaStagingStore,
  STAGED_OBJECT_CLEANUP_BATCH,
  STAGED_OBJECT_LEASE_MS,
} from "./pdpp-replica-staging.js";

export {
  REPLICA_BATCH_BYTES,
  REPLICA_BATCH_OPERATIONS,
  REPLICA_RECONCILE_PAGE,
  REPLICA_REGISTRATION_INTENT_TIMEOUT_MS,
  REPLICA_VERSION_SQUAT_ATTEMPTS,
  REPLICA_VERSION_SQUAT_WINDOW_MS,
  ReplicaAuthorityError,
  ReplicaCarrierMismatchError,
} from "@opendatalabs/personal-server-ts-core/replication/engine";

// One process owns a transport writer per database; other local instances serialize cycles.
const activeDatabases = new Set<Database | string>();
const ownedTokens = new Set<string>();

/** Unattached stages expire after one hour; cleanup deletes at most this many. */
export const REPLICA_STAGED_OBJECT_LEASE_MS = STAGED_OBJECT_LEASE_MS;
export const REPLICA_STAGED_OBJECT_CLEANUP_BATCH = STAGED_OBJECT_CLEANUP_BATCH;

/** Node answers every storage call synchronously; a promise here is a bug. */
function settled<T>(value: T | PromiseLike<T>): T {
  if (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { then?: unknown }).then === "function"
  )
    throw new Error("replica engine returned a promise on Node");
  return value as T;
}

export function createReplicaTransportWorker(
  deps: ReplicaEngineConfig & {
    db: Database;
    exporter: ReplicationExport;
    receiver: ReturnType<typeof createReplicaReceiver>;
    /** Narrow deterministic seam for failures at the staging-store boundary. */
    createStagingStore?: typeof createReplicaStagingStore;
  },
) {
  const { db, exporter, receiver } = deps;
  const context = nodeReplicaContext(db);
  type C = ReplicaEffectContext;
  const run = <T>(effect: ReplicaEffect<T, C>) =>
    runEffectSync(effect, context);
  /** A synchronous Node call, as one effect operation. */
  const sync = <T>(call: () => T): ReplicaEffect<T, C> => perform(call);
  const databaseKey = db.name && db.name !== ":memory:" ? db.name : db;

  function acquireWriter(token: string) {
    db.transaction(() => {
      const holder = db
        .prepare("SELECT pid,token FROM pdpp_transport_lock WHERE id=1")
        .get() as { pid: number; token: string } | undefined;
      if (holder?.pid === process.pid && !ownedTokens.has(holder.token)) {
        db.prepare("DELETE FROM pdpp_transport_lock WHERE id=1").run();
      } else if (holder) {
        try {
          process.kill(holder.pid, 0);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ESRCH") {
            db.prepare("DELETE FROM pdpp_transport_lock WHERE id=1").run();
          } else throw error;
        }
        if (db.prepare("SELECT 1 FROM pdpp_transport_lock WHERE id=1").get())
          throw Object.assign(
            new Error("replica database worker already active"),
            { code: "replica_worker_active" },
          );
      }
      db.prepare("INSERT INTO pdpp_transport_lock VALUES (1,?,?)").run(
        process.pid,
        token,
      );
    }).immediate();
    ownedTokens.add(token);
  }

  const host: ReplicaEngineHost<C> = {
    run,
    immediate: (effect) =>
      sync(() => db.transaction(() => run(effect)).immediate()),
    transaction: (effect) => sync(() => db.transaction(() => run(effect))()),
    commit(effect, _context, signal) {
      // The receiver's own boundary: its plans read and write derived state,
      // which a transaction opened on the raw connection would not refresh.
      if (db.inTransaction) assertReplicationTransactionOpen(db, signal);
      else assertReplicationStepOpen(db, signal);
      return receiver.atomically(() => run(effect));
    },
    cleanup: (effect) => {
      run(effect);
    },
    captureWrites: (effect) => sync(() => captureWrites(db, () => run(effect))),
    randomId: () => randomUUID(),
    door: {
      admitted: () => replicationAdmitted(db),
      beginStep: (signal) => beginReplicationStep(db, signal),
      assertStepOpen: (signal) => assertReplicationStepOpen(db, signal),
      assertTransactionOpen: (signal) =>
        assertReplicationTransactionOpen(db, signal),
    },
    lock: {
      busy: () => activeDatabases.has(databaseKey),
      acquire(token) {
        acquireWriter(token);
        activeDatabases.add(databaseKey);
      },
      release(token) {
        activeDatabases.delete(databaseKey);
        try {
          db.prepare(
            "DELETE FROM pdpp_transport_lock WHERE id=1 AND token=?",
          ).run(token);
        } finally {
          ownedTokens.delete(token);
        }
      },
    },
    identity: {
      current: () => sync(() => currentReplicaWriterIdentity(db)),
      enable: (input) => enableReplicaWriterIdentity({ db, ...input }),
    },
    coordinatorState: ({ owner, signal: stepSignal, enabled: isEnabled }) =>
      createSqliteReplicaCoordinatorState({
        db,
        owner,
        atomically: (attempt) => {
          const signal = stepSignal();
          if (!signal || !isEnabled()) throw new ReplicaCoordinatorConflict();
          assertReplicationStepOpen(db, signal);
          return receiver.atomically(() => {
            const result = attempt();
            assertReplicationTransactionOpen(db, signal);
            return result;
          });
        },
      }),
    staging({ injected, ...input }): ReplicaEngineStaging<C> {
      const create = injected
        ? (deps.createStagingStore ?? createReplicaStagingStore)
        : createReplicaStagingStore;
      const store = create({ db, ...input });
      return {
        begin: (admission) => store.begin(admission),
        verify: (handle, expected) =>
          store.verify(handle as Parameters<typeof store.verify>[0], expected),
        attach: (handle, expected) =>
          sync(() =>
            store.attach(
              handle as Parameters<typeof store.attach>[0],
              expected,
            ),
          ),
        abort: (admission) => store.abort(admission),
        reclaimAdmission: (admission) => store.reclaimAdmission(admission),
        cleanup: () => store.cleanup(),
        cleanupAttachedTemporaryBytes: () =>
          store.cleanupAttachedTemporaryBytes(),
      };
    },
    sweepStages: () =>
      sync(() => {
        const untrackedStages = db
          .prepare(
            `SELECT m.blob_id FROM pdpp_binary_manifests m
             WHERE m.namespace='staging'
               AND NOT EXISTS (
                 SELECT 1 FROM pdpp_transport_staged_objects s
                 WHERE s.namespace_key=m.blob_id
               )
             ORDER BY m.blob_id LIMIT ?`,
          )
          .all(STAGED_OBJECT_CLEANUP_BATCH) as { blob_id: string }[];
        for (const row of untrackedStages)
          deleteBinary(db, "staging", row.blob_id);
      }),
    exporter: {
      readBaselinePage: (options) =>
        sync(() => exporter.readBaselinePage(options)),
      readTailPage: (options) => sync(() => exporter.readTailPage(options)),
      getBaselineCheckpoint: () => sync(() => exporter.getBaselineCheckpoint()),
      acknowledgeBaselinePage: (expected, next) =>
        sync(() => exporter.acknowledgeBaselinePage(expected, next)),
      // The receiver's merge chose these operations for current state; the
      // baseline copies only what this device's trust accepted.
      rebaseline: () =>
        sync(() =>
          exporter.rebaseline(
            receiver.explainState({ credential: deps.credential }),
          ),
        ),
      declarationHistory: () => sync(() => exporter.declarationHistory()),
      // Node's journal is append-only and stays: rebaseline and completion
      // dependencies read it (`pdpp-replication-sqlite.ts`).
      acknowledgePublished: () => sync(() => undefined),
      readPinnedBlobChunks: (blobId) => exporter.readPinnedBlobChunks(blobId),
    },
    receiver: {
      setPendingEnabled: (value) => receiver.setPendingEnabled(value),
      quarantine: (input) => sync(() => receiver.quarantine(input)),
      reconcileStep: (input) => sync(() => receiver.reconcileStep(input)),
      reconcileQueued: () => sync(() => receiver.reconcileQueued()),
      copies: {
        list: (id) => sync(() => receiver.copies.list(id)),
        decide: (id, refetch) =>
          sync(() => receiver.copies.decide(id, refetch)),
        apply: (input) => sync(() => receiver.copies.apply(input)),
        stage: (input) => sync(() => receiver.copies.stage(input)),
        recordFact: (input) => sync(() => receiver.copies.recordFact(input)),
        promote: (input) => sync(() => receiver.copies.promote(input)),
      },
    },
    bindings: () =>
      sync(() =>
        db
          .prepare(
            "SELECT instance,source_id,method,generation,deleted_at FROM pdpp_instance_binding ORDER BY instance",
          )
          .all(),
      ),
  };
  const engine = createReplicaEngine(host, deps);
  return {
    step: engine.step,
    cycle: engine.cycle,
    /** Owner acknowledgement resumes an exhausted writer after its wait and recovery window. */
    retryVersionSquats: (): number => settled(engine.retryVersionSquats()),
    /** See the engine: re-admit Unsupported batches after a capability change. */
    readmitUnsupported: (): number => settled(engine.readmitUnsupported()),
    /** See the engine: fetch again slots quarantined for missing fragments. */
    readmitFragments: (): number => settled(engine.readmitFragments()),
    /** A host-observed dependency change (e.g. `mapping:<connection>`). Idempotent. */
    onDependencyChanged: (key: string): number =>
      settled(engine.onDependencyChanged(key)),
  };
}
