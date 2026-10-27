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
  type ReplicaWriterSeed,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";

/**
 * This server's replica writer identity (host contract §3.2). Each row is one
 * incarnation: the gateway registration and writer nonce it was derived
 * from, the two writer ids, and the first journal sequence it owns. The
 * current identity is the highest incarnation. Rows are never changed, so an
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
  operation_writer TEXT NOT NULL UNIQUE,
  first_sequence INTEGER NOT NULL CHECK (first_sequence >= 1)
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
  /** Journal operations below this sequence belong to older incarnations. */
  firstSequence: number;
}

type Row = {
  incarnation: number;
  owner: string;
  server: string;
  server_id: string;
  writer_nonce: string;
  transport_writer: string;
  operation_writer: string;
  first_sequence: number;
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
        firstSequence: row.first_sequence,
      }
    : undefined;
}

function insert(db: Database, seed: ReplicaWriterSeed) {
  const s = replicaWriterSeedSchema.parse(seed);
  const writers = deriveReplicaWriters(s);
  const { last } = db
    .prepare(
      "SELECT coalesce(max(sequence), 0) AS last FROM pdpp_replica_operations",
    )
    .get() as { last: number };
  db.prepare(
    "INSERT INTO pdpp_replica_writer_identity (owner,server,server_id,writer_nonce,transport_writer,operation_writer,first_sequence) VALUES (?,?,?,?,?,?,?)",
  ).run(
    s.owner,
    s.server,
    s.serverId,
    s.writerNonce,
    writers.transport,
    writers.operation,
    last + 1,
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
 * captured under the old random writer ids starts fresh.
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
 * copies would otherwise continue the same writer sequences.
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

export type ReplicaWriterIdentityState =
  | { tag: "ready"; identity: ReplicaWriterIdentity }
  | {
      tag: "waiting";
      reason: "server_not_registered" | "roster_unavailable";
    };

/**
 * Enable step: read this server's own roster record and establish or
 * update the identity from it. Waits while the server is not registered,
 * revoked, or registered under another owner. While the roster is
 * unavailable an existing identity stays usable; a missing one waits.
 */
export async function enableReplicaWriterIdentity(input: {
  db: Database;
  owner: string;
  server: string;
  roster: ReplicaRosterPort;
  signal?: AbortSignal;
}): Promise<ReplicaWriterIdentityState> {
  let record: ReplicaRosterRecord | null;
  try {
    record = await input.roster.server(
      input.server.toLowerCase() as `0x${string}`,
      { signal: input.signal },
    );
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
    throw error;
  }
}
