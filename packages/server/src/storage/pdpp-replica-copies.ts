import type { Database } from "better-sqlite3";
import type { ReplicaEnvelope } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type {
  CopyDecision,
  FinalizedFact,
} from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import {
  perform,
  runEffectSync,
  type ReplicaEffect,
} from "@opendatalabs/personal-server-ts-core/replication/effects";
import {
  replicaCopies,
  REPLICA_COPY_MIGRATION,
  type StagedCopy,
} from "@opendatalabs/personal-server-ts-core/replication/copies";
import { nodeReplicaContext } from "./pdpp-replica-sql.js";

/**
 * Batch-copy retention, finalized-fact history and batch disposition
 * (contract v3.1, replica-copy-promotion-contract-1021-v3.md) on Node. The
 * transitions are core's (`core/replication/copies.ts`), shared with PS-Lite;
 * this binds them to one better-sqlite3 connection. Every transition is one
 * SQLite transaction and idempotent under replay.
 */
export {
  REPLICA_COPY_MIGRATION,
  ReplicaCopyRefused,
  type CopyFragment,
  type CopyPromotion,
  type StagedCopy,
} from "@opendatalabs/personal-server-ts-core/replication/copies";
export { REPLICA_REFETCH_BUDGET } from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";

export function createReplicaCopies(deps: {
  db: Database;
  owner: string;
  /** Import an envelope into canonical state (the receiver's import). */
  importEnvelope(
    envelope: ReplicaEnvelope,
    blobs: StagedCopy["blobs"],
    id: string,
  ): void;
  /**
   * Withdraw a connection from every reader: connection quarantine, canonical
   * withdrawal and an integrity epoch raise, in the caller's transaction.
   */
  quarantineConnection(instance: string): void;
  /**
   * The single pending preview of a batch, keyed by id: at most one copy is
   * ever `pending` (contract B), so the read side keeps its id key.
   */
  preview: {
    show(id: string, envelope: ReplicaEnvelope, blobsJson: string): void;
    hide(id: string, state: "confirmed" | "quarantined"): void;
  };
  /** Drop pending custody bytes no retained copy still needs. */
  releaseBytes(id: string, blobIds: readonly string[]): void;
  now: () => number;
}) {
  const { db } = deps;
  const context = nodeReplicaContext(db);
  const run = <T>(effect: ReplicaEffect<T>) => runEffectSync(effect, context);
  const copies = replicaCopies({
    owner: deps.owner,
    importEnvelope: (envelope, blobs, id) =>
      perform(() => deps.importEnvelope(envelope, blobs, id)),
    quarantineConnection: (instance) =>
      perform(() => deps.quarantineConnection(instance)),
    preview: {
      show: (id, envelope, blobsJson) =>
        perform(() => deps.preview.show(id, envelope, blobsJson)),
      hide: (id, state) => perform(() => deps.preview.hide(id, state)),
    },
    releaseBytes: (id, blobIds) =>
      perform(() => deps.releaseBytes(id, blobIds)),
    // A nested better-sqlite3 transaction is a savepoint.
    savepoint: (effect) => perform(() => db.transaction(() => run(effect))()),
    now: deps.now,
  });
  const immediate = <T>(effect: ReplicaEffect<T>) =>
    db.transaction(() => run(effect)).immediate();

  return {
    REPLICA_COPY_MIGRATION,
    decide: (id: string, refetch: { attempts: number; budget: number }) =>
      run(copies.decide(id, refetch)),
    disposition: (id: string) => run(copies.disposition(id)),
    copies: (id: string) => run(copies.copies(id)),
    /**
     * Retain one valid copy (contract §3 "Stage copy", amendment C), then
     * decide and apply the quarantine set. Returns the copy key and decision.
     * An input failing a validity check is recorded as a reject only.
     */
    stage: (copy: StagedCopy, refetch: { attempts: number; budget: number }) =>
      immediate(copies.stage(copy, refetch)),
    /**
     * Append a verified finalized fact for one registered slot (F2). A fact
     * from another owner is refused (a diagnostic, never a fact). Returns
     * true when it is new.
     */
    recordFact: (input: {
      id: string;
      scope: string;
      fragmentIndex: number;
      fact: FinalizedFact;
    }) => run(copies.recordFact(input)),
    /** Apply a non-promoting decision's durable effects (coordinator step). */
    apply(id: string, decision: CopyDecision) {
      immediate(copies.apply(id, decision));
    },
    terminate(id: string, reason: string) {
      immediate(copies.terminate(id, reason));
    },
    /** Promote one copy (contract §3, amendments E and F). */
    promote: (input: { id: string; copyKey?: string }) =>
      immediate(copies.promote(input)),
  };
}
export type ReplicaCopies = ReturnType<typeof createReplicaCopies>;
