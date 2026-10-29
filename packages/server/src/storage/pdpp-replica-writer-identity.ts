import type { ReplicationTimers } from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import type { Database } from "better-sqlite3";
import type {
  ReplicaRosterPort,
  ReplicaRosterRecord,
} from "@opendatalabs/personal-server-ts-core/replication/roster";
import {
  perform,
  runEffectSync,
  type ReplicaEffect,
} from "@opendatalabs/personal-server-ts-core/replication/effects";
import * as identity from "@opendatalabs/personal-server-ts-core/replication/writer-identity-store";
import type {
  ReplicaWriterIdentity,
  ReplicaWriterIdentityHost,
  ReplicaWriterIdentityState,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity-store";
import { ReplicationRefusedError } from "@opendatalabs/personal-server-ts-core/replication/door";
import type { ReplicaWriterRotation } from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import { replicationAdmitted } from "./pdpp-replication-door.js";
import { nodeReplicaContext } from "./pdpp-replica-sql.js";

/**
 * This server's replica writer identity (host contract §3.2) on Node. The
 * rules are core's (`core/replication/writer-identity-store.ts`), shared with
 * PS-Lite; this binds them to one better-sqlite3 connection, its door and
 * its replica journal.
 */
export {
  REPLICA_WRITER_IDENTITY_MIGRATION,
  ReplicaWriterIdentityError,
  type ReplicaWriterIdentity,
  type ReplicaWriterIdentityState,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity-store";

const run = <T>(db: Database, effect: ReplicaEffect<T>) =>
  runEffectSync(effect, nodeReplicaContext(db));
const host = (db: Database): ReplicaWriterIdentityHost => ({
  admitted: () => perform(() => replicationAdmitted(db)),
  journalEmpty: () =>
    perform(
      () => !db.prepare("SELECT 1 FROM pdpp_replica_operations LIMIT 1").get(),
    ),
});

/** The current identity, or undefined before the first enable. */
export function currentReplicaWriterIdentity(
  db: Database,
): ReplicaWriterIdentity | undefined {
  return run(db, identity.currentReplicaWriterIdentity());
}

/**
 * Create or update the identity from this server's own gateway record.
 * Idempotent for the current registration. A new registration id (the
 * address registered again) starts a new incarnation with a new nonce.
 *
 * The first identity requires an empty replica journal: operations captured
 * before it carry another writer id, which receivers refuse. A database that
 * captured under the old random writer ids starts fresh. Throws
 * `ReplicationRefusedError` instead of writing once the door is closed.
 */
export function establishReplicaWriterIdentity(
  db: Database,
  input: {
    owner: string;
    server: string;
    record: ReplicaRosterRecord | null;
    nonce?: string;
  },
): ReplicaWriterIdentity {
  return db
    .transaction(() =>
      run(db, identity.establishReplicaWriterIdentity(host(db), input)),
    )
    .immediate();
}

/**
 * A new nonce under the same registration, before new writes. Hosts call it
 * after a replication reset and after restoring or cloning a database: both
 * copies would otherwise continue the same writer sequences. On a database
 * whose replication door is closed it throws `ReplicationRefusedError` and
 * writes nothing: that database never replicates again, so it has no writer
 * to rotate, and a restore path may ignore the refusal.
 */
export function rotateReplicaWriterIdentity(
  db: Database,
  input: { nonce?: string } = {},
): ReplicaWriterIdentity {
  return db
    .transaction(() =>
      run(db, identity.rotateReplicaWriterIdentity(host(db), input)),
    )
    .immediate();
}

/**
 * The boot step for a host's rotation request (host contract §3.2). A host
 * asks when it cannot rule out that this database is a copy: a restore, a
 * clone, a reinstall onto existing data. `replicationEnabled` is this boot's
 * result from the replication door. Run it after the door and before any
 * record store of this boot captures a write. A database without an identity
 * yet reports `no_identity`: its first identity draws a new nonce anyway.
 */
export function rotateReplicaWriterIdentityAtBoot(
  db: Database,
  input: { requested: boolean; replicationEnabled: boolean },
): ReplicaWriterRotation {
  if (!input.requested) return "not_requested";
  if (!input.replicationEnabled) return "replication_off";
  try {
    rotateReplicaWriterIdentity(db);
    return "rotated";
  } catch (error) {
    if (
      error instanceof identity.ReplicaWriterIdentityError &&
      error.code === "replica_identity_not_registered"
    )
      return "no_identity";
    if (error instanceof ReplicationRefusedError) return "replication_off";
    throw error;
  }
}

/** See core `enableReplicaWriterIdentity`. */
export function enableReplicaWriterIdentity(input: {
  db: Database;
  owner: string;
  server: string;
  roster: ReplicaRosterPort;
  signal?: AbortSignal;
  deadlineMs?: number;
  timers?: Pick<ReplicationTimers, "setTimeout" | "clearTimeout">;
}): Promise<ReplicaWriterIdentityState> {
  return identity.enableReplicaWriterIdentity({
    ...input,
    current: () => currentReplicaWriterIdentity(input.db),
    establish: (record) =>
      establishReplicaWriterIdentity(input.db, { ...input, record }),
  });
}
