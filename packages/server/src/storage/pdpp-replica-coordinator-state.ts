import type { Database } from "better-sqlite3";
import {
  ReplicaCoordinatorConflict,
  type ReplicaCoordinatorState,
  type ReplicaCoordinatorStatePort,
  type ReplicaRotation,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator";

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

/**
 * This adapter does NOT acquire or replace Node's exclusive writer lock.
 * It only fences the existing token inside the receiver's write transaction.
 * Registration intent/recovery tables and their state machine are untouched.
 */
export function createSqliteReplicaCoordinatorState(input: {
  db: Database;
  owner: () => string | undefined;
  /** Use receiver.atomically: all attempt projection work shares this boundary. */
  atomically: <T>(run: () => T) => T;
}): ReplicaCoordinatorStatePort {
  const { db } = input;
  const phases = new Set([
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
  const validate = (rotation: ReplicaRotation): void => {
    if (
      !rotation ||
      !rotation.writers ||
      typeof rotation.writers !== "object" ||
      Array.isArray(rotation.writers) ||
      (rotation.nextPhase !== undefined && !phases.has(rotation.nextPhase)) ||
      Object.entries(rotation.writers).some(
        ([phase, writer]) => !phases.has(phase) || typeof writer !== "string",
      )
    )
      throw new Error("invalid replica coordinator rotation");
  };
  const currentOwner = (): string => {
    const owner = input.owner();
    const held = db
      .prepare("SELECT token FROM pdpp_transport_lock WHERE id=1")
      .get() as { token: string } | undefined;
    if (!owner || held?.token !== owner) throw new ReplicaCoordinatorConflict();
    return owner;
  };
  const load = (): ReplicaCoordinatorState => {
    const owner = currentOwner();
    const row = db
      .prepare(
        "SELECT version,rotation_json FROM pdpp_transport_coordinator WHERE id=1",
      )
      .get() as { version: number; rotation_json: string } | undefined;
    if (!row || !Number.isSafeInteger(row.version) || row.version < 0)
      throw new Error("invalid replica coordinator revision");
    const rotation = JSON.parse(row.rotation_json) as ReplicaRotation;
    validate(rotation);
    return { ...rotation, owner, version: row.version };
  };
  return {
    load,
    commit(expected, next, checkpoint) {
      return input.atomically(() => {
        if (!db.inTransaction)
          throw new Error("coordinator requires a write transaction");
        const current = load();
        if (
          current.owner !== expected.owner ||
          current.version !== expected.version
        )
          throw new ReplicaCoordinatorConflict();
        if (expected.version === Number.MAX_SAFE_INTEGER)
          throw new RangeError("replica coordinator revision exhausted");
        validate(next);
        const result = checkpoint();
        // Even a nested callback cannot replace the owner and leave a receipt.
        if (currentOwner() !== expected.owner)
          throw new ReplicaCoordinatorConflict();
        const changed = db
          .prepare(
            `UPDATE pdpp_transport_coordinator
          SET version=version+1,rotation_json=? WHERE id=1 AND version=?`,
          )
          .run(JSON.stringify(next), expected.version).changes;
        if (changed !== 1) throw new ReplicaCoordinatorConflict();
        const state = load();
        if (
          state.version !== expected.version + 1 ||
          state.nextPhase !== next.nextPhase ||
          JSON.stringify(state.writers) !== JSON.stringify(next.writers)
        )
          throw new ReplicaCoordinatorConflict();
        return { state, result };
      });
    },
  };
}
