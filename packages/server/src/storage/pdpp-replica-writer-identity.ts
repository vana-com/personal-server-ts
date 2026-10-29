import type { Database } from "better-sqlite3";
import {
  ReplicaRosterUnavailableError,
  type ReplicaRosterPort,
  type ReplicaRosterRecord,
} from "@opendatalabs/personal-server-ts-core/replication/roster";
import {
  deriveReplicaWriters,
  randomReplicaWriterNonce,
  replicaWriterSeedSchema,
  type ReplicaWriterRotation,
  type ReplicaWriterSeed,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import { REPLICA_ATTEMPT_TIMEOUT_MS } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import type { ReplicationTimers } from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import {
  ReplicationRefusedError,
  type ReplicationRefusal,
} from "@opendatalabs/personal-server-ts-core/replication/door";
import { replicationAdmitted } from "./pdpp-replication-door.js";

/**
 * This server's replica writer identity (host contract §3.2). Each row is one
 * incarnation: the gateway registration and writer nonce it was derived
 * from, and the two writer ids. The current identity is the highest
 * incarnation. Rows are never changed, so an
 * older writer id can never be derived again on this database.
 */
export const REPLICA_WRITER_IDENTITY_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_replica_writer_identity (
  incarnation INTEGER PRIMARY KEY AUTOINCREMENT,
  owner TEXT NOT NULL,
  server TEXT NOT NULL,
  server_id TEXT NOT NULL,
  writer_nonce TEXT NOT NULL UNIQUE,
  transport_writer TEXT NOT NULL UNIQUE,
  operation_writer TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS pdpp_replica_writer_identity_no_update BEFORE UPDATE ON pdpp_replica_writer_identity
BEGIN SELECT RAISE(ABORT, 'replica writer identity is append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_replica_writer_identity_no_delete BEFORE DELETE ON pdpp_replica_writer_identity
BEGIN SELECT RAISE(ABORT, 'replica writer identity is append-only'); END;
`;

export interface ReplicaWriterIdentity {
  incarnation: number;
  seed: ReplicaWriterSeed;
  transportWriter: string;
  operationWriter: string;
}

type Row = {
  incarnation: number;
  owner: string;
  server: string;
  server_id: string;
  writer_nonce: string;
  transport_writer: string;
  operation_writer: string;
};

/** Writer identity cannot be created or changed for this database. */
export class ReplicaWriterIdentityError extends Error {
  constructor(
    readonly code:
      | "replica_identity_requires_fresh_journal"
      | "replica_identity_owner_mismatch"
      | "replica_identity_not_registered",
  ) {
    super(code);
    this.name = "ReplicaWriterIdentityError";
  }
}

/** The current identity, or undefined before the first enable. */
export function currentReplicaWriterIdentity(
  db: Database,
): ReplicaWriterIdentity | undefined {
  const row = db
    .prepare(
      "SELECT * FROM pdpp_replica_writer_identity ORDER BY incarnation DESC LIMIT 1",
    )
    .get() as Row | undefined;
  return row
    ? {
        incarnation: row.incarnation,
        seed: {
          owner: row.owner,
          server: row.server,
          serverId: row.server_id,
          writerNonce: row.writer_nonce,
        },
        transportWriter: row.transport_writer,
        operationWriter: row.operation_writer,
      }
    : undefined;
}

/**
 * The only identity write. Run inside the caller's transaction, so the door
 * check and the insert are atomic: once the door is closed, no identity is
 * established or rotated.
 */
function insert(db: Database, seed: ReplicaWriterSeed) {
  if (!replicationAdmitted(db))
    throw new ReplicationRefusedError("reenable_refused");
  const s = replicaWriterSeedSchema.parse(seed);
  const writers = deriveReplicaWriters(s);
  db.prepare(
    "INSERT INTO pdpp_replica_writer_identity (owner,server,server_id,writer_nonce,transport_writer,operation_writer) VALUES (?,?,?,?,?,?)",
  ).run(
    s.owner,
    s.server,
    s.serverId,
    s.writerNonce,
    writers.transport,
    writers.operation,
  );
  return currentReplicaWriterIdentity(db)!;
}

/** Registered now, under this owner. Anything else is not registered for it. */
function registeredId(record: ReplicaRosterRecord | null, owner: string) {
  if (
    !record ||
    record.revokedAt !== null ||
    record.owner.toLowerCase() !== owner
  )
    throw new ReplicaWriterIdentityError("replica_identity_not_registered");
  return record.id.toLowerCase();
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
  const owner = input.owner.toLowerCase();
  const server = input.server.toLowerCase();
  return db
    .transaction(() => {
      const serverId = registeredId(input.record, owner);
      const current = currentReplicaWriterIdentity(db);
      if (current && current.seed.owner !== owner)
        throw new ReplicaWriterIdentityError("replica_identity_owner_mismatch");
      if (
        current &&
        current.seed.server === server &&
        current.seed.serverId === serverId
      )
        return current;
      if (
        !current &&
        db.prepare("SELECT 1 FROM pdpp_replica_operations LIMIT 1").get()
      )
        throw new ReplicaWriterIdentityError(
          "replica_identity_requires_fresh_journal",
        );
      return insert(db, {
        owner,
        server,
        serverId,
        writerNonce: input.nonce ?? randomReplicaWriterNonce(),
      });
    })
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
    .transaction(() => {
      const current = currentReplicaWriterIdentity(db);
      if (!current)
        throw new ReplicaWriterIdentityError("replica_identity_not_registered");
      return insert(db, {
        ...current.seed,
        writerNonce: input.nonce ?? randomReplicaWriterNonce(),
      });
    })
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
      error instanceof ReplicaWriterIdentityError &&
      error.code === "replica_identity_not_registered"
    )
      return "no_identity";
    if (error instanceof ReplicationRefusedError) return "replication_off";
    throw error;
  }
}

export type ReplicaWriterIdentityState =
  | { tag: "ready"; identity: ReplicaWriterIdentity }
  | {
      tag: "waiting";
      reason: "server_not_registered" | "roster_unavailable";
    }
  /** The replication door closed; it stays closed. */
  | { tag: "refused"; reason: ReplicationRefusal };

/**
 * One bounded roster read. A gateway that never answers must not hold the
 * single-flight step, so the read races a deadline: on it the lookup's signal
 * aborts, the late answer is dropped and the read counts as unavailable,
 * which `enableReplicaWriterIdentity` already settles as a Wait. The host's
 * own abort is forwarded to the lookup.
 */
async function readRoster(input: {
  roster: ReplicaRosterPort;
  server: string;
  signal?: AbortSignal;
  deadlineMs: number;
  timers: Pick<ReplicationTimers, "setTimeout" | "clearTimeout">;
}): Promise<ReplicaRosterRecord | null> {
  const lookup = new AbortController();
  const forward = () => lookup.abort(input.signal!.reason);
  if (input.signal?.aborted) forward();
  else input.signal?.addEventListener("abort", forward, { once: true });
  let timer: unknown;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = input.timers.setTimeout(() => {
      const error = new DOMException("replica roster deadline", "TimeoutError");
      lookup.abort(error);
      reject(new ReplicaRosterUnavailableError({ cause: error }));
    }, input.deadlineMs);
  });
  try {
    return await Promise.race([
      input.roster.server(input.server.toLowerCase() as `0x${string}`, {
        signal: lookup.signal,
      }),
      deadline,
    ]);
  } finally {
    input.timers.clearTimeout(timer);
    input.signal?.removeEventListener("abort", forward);
  }
}

const defaultTimers: Pick<ReplicationTimers, "setTimeout" | "clearTimeout"> = {
  setTimeout: (run, ms) => globalThis.setTimeout(run, ms),
  clearTimeout: (handle) =>
    globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/**
 * Enable step: read this server's own roster record and establish or
 * update the identity from it. Waits while the server is not registered,
 * revoked, or registered under another owner. While the roster is
 * unavailable an existing identity stays usable; a missing one waits. A read
 * that outlasts `deadlineMs` (default: the coordinator's attempt deadline)
 * counts as unavailable. The roster read writes nothing; if the door closes during it, the identity
 * write refuses.
 */
export async function enableReplicaWriterIdentity(input: {
  db: Database;
  owner: string;
  server: string;
  roster: ReplicaRosterPort;
  signal?: AbortSignal;
  deadlineMs?: number;
  timers?: Pick<ReplicationTimers, "setTimeout" | "clearTimeout">;
}): Promise<ReplicaWriterIdentityState> {
  let record: ReplicaRosterRecord | null;
  try {
    record = await readRoster({
      roster: input.roster,
      server: input.server,
      signal: input.signal,
      deadlineMs: input.deadlineMs ?? REPLICA_ATTEMPT_TIMEOUT_MS,
      timers: input.timers ?? defaultTimers,
    });
  } catch (error) {
    if (!(error instanceof ReplicaRosterUnavailableError)) throw error;
    const current = currentReplicaWriterIdentity(input.db);
    return current &&
      current.seed.server === input.server.toLowerCase() &&
      current.seed.owner === input.owner.toLowerCase()
      ? { tag: "ready", identity: current }
      : { tag: "waiting", reason: "roster_unavailable" };
  }
  try {
    return {
      tag: "ready",
      identity: establishReplicaWriterIdentity(input.db, { ...input, record }),
    };
  } catch (error) {
    if (
      error instanceof ReplicaWriterIdentityError &&
      error.code === "replica_identity_not_registered"
    )
      return { tag: "waiting", reason: "server_not_registered" };
    if (error instanceof ReplicationRefusedError)
      return { tag: "refused", reason: error.reason };
    throw error;
  }
}
