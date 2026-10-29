/**
 * This server's replica writer identity (host contract §3.2), as storage
 * effects Node (`server/src/storage/pdpp-replica-writer-identity.ts`) and
 * PS-Lite (`lite/src/replication-engine.ts`) both run. Each row is one
 * incarnation: the gateway registration and writer nonce it was derived
 * from, and the two writer ids. The current identity is the highest
 * incarnation. Rows are never changed, so an older writer id can never be
 * derived again on this database.
 */
import {
  ReplicaRosterUnavailableError,
  type ReplicaRosterPort,
  type ReplicaRosterRecord,
} from "./roster.js";
import {
  deriveReplicaWriters,
  randomReplicaWriterNonce,
  replicaWriterSeedSchema,
  type ReplicaWriterSeed,
} from "./writer-identity.js";
import { ReplicationRefusedError, type ReplicationRefusal } from "./door.js";
import { sql, type ReplicaEffect } from "./effects.js";
import { REPLICA_ATTEMPT_TIMEOUT_MS } from "./coordinator.js";
import type { ReplicationTimers } from "./host-driver.js";

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

/**
 * What a boot rotation that threw means (host contract §3.2): a database
 * without an identity yet (`no_identity`; its first identity draws a new
 * nonce anyway) or a closed door (`replication_off`). `undefined` for a real
 * failure, which the host rethrows.
 */
export function replicaWriterRotationOutcome(
  error: unknown,
): "no_identity" | "replication_off" | undefined {
  if (
    error instanceof ReplicaWriterIdentityError &&
    error.code === "replica_identity_not_registered"
  )
    return "no_identity";
  if (error instanceof ReplicationRefusedError) return "replication_off";
  return undefined;
}

/** The current identity, or undefined before the first enable. */
export function* currentReplicaWriterIdentity(): ReplicaEffect<
  ReplicaWriterIdentity | undefined
> {
  const row = yield* sql.get<Row>(
    "SELECT * FROM pdpp_replica_writer_identity ORDER BY incarnation DESC LIMIT 1",
  );
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

/** What the identity writes need from their host, in its transaction. */
export interface ReplicaWriterIdentityHost {
  /** The replication door is open. */
  admitted(): ReplicaEffect<boolean>;
  /** No operation was captured locally yet (the first identity needs this). */
  journalEmpty(): ReplicaEffect<boolean>;
}

/**
 * The only identity write. Run inside the caller's transaction, so the door
 * check and the insert are atomic: once the door is closed, no identity is
 * established or rotated.
 */
function* insert(
  host: Pick<ReplicaWriterIdentityHost, "admitted">,
  seed: ReplicaWriterSeed,
): ReplicaEffect<ReplicaWriterIdentity> {
  if (!(yield* host.admitted()))
    throw new ReplicationRefusedError("reenable_refused");
  const s = replicaWriterSeedSchema.parse(seed);
  const writers = deriveReplicaWriters(s);
  yield* sql.run(
    "INSERT INTO pdpp_replica_writer_identity (owner,server,server_id,writer_nonce,transport_writer,operation_writer) VALUES (?,?,?,?,?,?)",
    s.owner,
    s.server,
    s.serverId,
    s.writerNonce,
    writers.transport,
    writers.operation,
  );
  return (yield* currentReplicaWriterIdentity())!;
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
 * Create or update the identity from this server's own gateway record, in
 * the caller's write transaction. Idempotent for the current registration.
 * A new registration id (the address registered again) starts a new
 * incarnation with a new nonce.
 *
 * The first identity requires an empty replica journal: operations captured
 * before it carry another writer id, which receivers refuse. Throws
 * `ReplicationRefusedError` instead of writing once the door is closed.
 */
export function* establishReplicaWriterIdentity(
  host: ReplicaWriterIdentityHost,
  input: {
    owner: string;
    server: string;
    record: ReplicaRosterRecord | null;
    nonce?: string;
  },
): ReplicaEffect<ReplicaWriterIdentity> {
  const owner = input.owner.toLowerCase();
  const server = input.server.toLowerCase();
  const serverId = registeredId(input.record, owner);
  const current = yield* currentReplicaWriterIdentity();
  if (current && current.seed.owner !== owner)
    throw new ReplicaWriterIdentityError("replica_identity_owner_mismatch");
  if (
    current &&
    current.seed.server === server &&
    current.seed.serverId === serverId
  )
    return current;
  if (!current && !(yield* host.journalEmpty()))
    throw new ReplicaWriterIdentityError(
      "replica_identity_requires_fresh_journal",
    );
  return yield* insert(host, {
    owner,
    server,
    serverId,
    writerNonce: input.nonce ?? randomReplicaWriterNonce(),
  });
}

/**
 * A new nonce under the same registration, before new writes, in the
 * caller's write transaction. See the Node host for when to call it.
 */
export function* rotateReplicaWriterIdentity(
  host: Pick<ReplicaWriterIdentityHost, "admitted">,
  input: { nonce?: string } = {},
): ReplicaEffect<ReplicaWriterIdentity> {
  const current = yield* currentReplicaWriterIdentity();
  if (!current)
    throw new ReplicaWriterIdentityError("replica_identity_not_registered");
  return yield* insert(host, {
    ...current.seed,
    writerNonce: input.nonce ?? randomReplicaWriterNonce(),
  });
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
 * counts as unavailable. The roster read writes nothing; if the door closes
 * during it, the identity write refuses.
 *
 * `current` reads the identity; `establish` runs
 * `establishReplicaWriterIdentity` in one write transaction.
 */
export async function enableReplicaWriterIdentity(input: {
  owner: string;
  server: string;
  roster: ReplicaRosterPort;
  signal?: AbortSignal;
  deadlineMs?: number;
  timers?: Pick<ReplicationTimers, "setTimeout" | "clearTimeout">;
  current():
    | ReplicaWriterIdentity
    | undefined
    | Promise<ReplicaWriterIdentity | undefined>;
  establish(
    record: ReplicaRosterRecord | null,
  ): ReplicaWriterIdentity | Promise<ReplicaWriterIdentity>;
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
    const current = await input.current();
    return current &&
      current.seed.server === input.server.toLowerCase() &&
      current.seed.owner === input.owner.toLowerCase()
      ? { tag: "ready", identity: current }
      : { tag: "waiting", reason: "roster_unavailable" };
  }
  try {
    return { tag: "ready", identity: await input.establish(record) };
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
