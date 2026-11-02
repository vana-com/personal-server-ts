/**
 * The durable coordinator rotation over SQL, shared by every host. Node runs
 * these effects synchronously inside the receiver's write transaction;
 * PS-Lite runs them inside its native transaction. Both adapters pass
 * `replicaCoordinatorStateContract`.
 *
 * Ownership is the token in `pdpp_transport_lock`. The adapter does NOT
 * acquire or replace it: Node's PID lock and Lite's boot owner write it.
 */
import {
  perform,
  sql,
  type ReplicaEffect,
  type ReplicaEffectContext,
} from "./effects.js";
import {
  ReplicaCoordinatorConflict,
  type ReplicaCoordinatorState,
  type ReplicaRotation,
} from "./coordinator.js";

/** Additive, idempotent forward open; no existing row/table is rewritten. */
export const REPLICA_COORDINATOR_SCHEMA = `
CREATE TABLE IF NOT EXISTS pdpp_transport_coordinator (
  id INTEGER PRIMARY KEY CHECK(id=1),
  version INTEGER NOT NULL DEFAULT 0 CHECK(version>=0),
  rotation_json TEXT NOT NULL
);
INSERT OR IGNORE INTO pdpp_transport_coordinator(id,version,rotation_json)
  VALUES(1,0,'{"writers":{}}');
`;

/** The exclusive-owner table both hosts write. Node adds a PID; Lite writes 0. */
export const REPLICA_LOCK_SCHEMA =
  "CREATE TABLE IF NOT EXISTS pdpp_transport_lock (id INTEGER PRIMARY KEY CHECK(id=1), pid INTEGER NOT NULL, token TEXT NOT NULL);";

const PHASES = new Set([
  "retain",
  "prepare",
  "publish",
  "discover",
  "download",
  "fetch",
  "revalidate",
  "import",
  "reconcile",
]);

function validate(rotation: ReplicaRotation): void {
  if (
    !rotation ||
    !rotation.writers ||
    typeof rotation.writers !== "object" ||
    Array.isArray(rotation.writers) ||
    (rotation.nextPhase !== undefined && !PHASES.has(rotation.nextPhase)) ||
    Object.entries(rotation.writers).some(
      ([phase, writer]) => !PHASES.has(phase) || typeof writer !== "string",
    )
  )
    throw new Error("invalid replica coordinator rotation");
}

/** Who this adapter acts for; read at every check, never cached. */
export type ReplicaCoordinatorOwner = () => string | undefined;

function* currentOwner(owner: ReplicaCoordinatorOwner): ReplicaEffect<string> {
  const current = owner();
  const held = yield* sql.get<{ token: string }>(
    "SELECT token FROM pdpp_transport_lock WHERE id=1",
  );
  if (!current || held?.token !== current)
    throw new ReplicaCoordinatorConflict();
  return current;
}

/** The current rotation, only for the owner that holds the lock. */
export function* loadReplicaCoordinatorState(
  owner: ReplicaCoordinatorOwner,
): ReplicaEffect<ReplicaCoordinatorState> {
  const held = yield* currentOwner(owner);
  const row = yield* sql.get<{ version: number; rotation_json: string }>(
    "SELECT version,rotation_json FROM pdpp_transport_coordinator WHERE id=1",
  );
  if (!row || !Number.isSafeInteger(row.version) || row.version < 0)
    throw new Error("invalid replica coordinator revision");
  const rotation = JSON.parse(row.rotation_json) as ReplicaRotation;
  validate(rotation);
  return { ...rotation, owner: held, version: row.version };
}

/**
 * Check owner and revision, run `checkpoint`, check the owner again, then
 * write the rotation at the next revision. The caller runs this whole effect
 * in ONE write transaction, so any throw rolls back checkpoint and rotation.
 */
export function* commitReplicaCoordinatorState<
  T,
  C extends ReplicaEffectContext = ReplicaEffectContext,
>(
  owner: ReplicaCoordinatorOwner,
  expected: ReplicaCoordinatorState,
  next: ReplicaRotation,
  checkpoint: (context: C) => T | Promise<T>,
): ReplicaEffect<{ state: ReplicaCoordinatorState; result: T }, C> {
  const current = yield* loadReplicaCoordinatorState(owner);
  if (current.owner !== expected.owner || current.version !== expected.version)
    throw new ReplicaCoordinatorConflict();
  if (expected.version === Number.MAX_SAFE_INTEGER)
    throw new RangeError("replica coordinator revision exhausted");
  validate(next);
  const result = yield* perform<T, C>(checkpoint);
  // Even a nested callback cannot replace the owner and leave a receipt.
  if ((yield* currentOwner(owner)) !== expected.owner)
    throw new ReplicaCoordinatorConflict();
  const { changes } = yield* sql.run(
    `UPDATE pdpp_transport_coordinator
          SET version=version+1,rotation_json=? WHERE id=1 AND version=?`,
    JSON.stringify(next),
    expected.version,
  );
  if (changes !== 1) throw new ReplicaCoordinatorConflict();
  const state = yield* loadReplicaCoordinatorState(owner);
  if (
    state.version !== expected.version + 1 ||
    state.nextPhase !== next.nextPhase ||
    JSON.stringify(state.writers) !== JSON.stringify(next.writers)
  )
    throw new ReplicaCoordinatorConflict();
  return { state, result };
}
