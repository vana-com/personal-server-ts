/**
 * The coordinator's durable rotation on PS-Lite: core's shared SQL effects
 * (`core/replication/coordinator-state.ts`, also Node's) run inside the
 * native transaction. Passes `replicaCoordinatorStateContract`.
 *
 * Ownership: a phone runs one PS. Each boot takes the lock with a fresh
 * token (`acquireLiteReplicaOwner`), so a step left over from an earlier
 * boot can no longer commit. There is no PID to check.
 */
import type { AsyncReplicaCoordinatorStatePort } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  commitReplicaCoordinatorState,
  loadReplicaCoordinatorState,
  REPLICA_COORDINATOR_SCHEMA,
  REPLICA_LOCK_SCHEMA,
  type ReplicaCoordinatorOwner,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator-state";
import { runEffectAsync } from "@opendatalabs/personal-server-ts-core/replication/effects";
import type {
  LiteReplicaPersistence,
  LiteReplicaTransaction,
} from "./replication-ports.js";

/** Take the replication lock for this boot. Returns the new owner token. */
export async function acquireLiteReplicaOwner(
  persistence: LiteReplicaPersistence,
  token: string = globalThis.crypto.randomUUID(),
): Promise<string> {
  await persistence.transaction(async (tx) => {
    await tx.sql.exec(REPLICA_LOCK_SCHEMA);
    await tx.sql.exec(REPLICA_COORDINATOR_SCHEMA);
    await tx.sql.run(
      "INSERT INTO pdpp_transport_lock (id,pid,token) VALUES (1,0,?) ON CONFLICT(id) DO UPDATE SET pid=0,token=excluded.token",
      [token],
    );
  });
  return token;
}

export function createLiteReplicaCoordinatorState(input: {
  persistence: LiteReplicaPersistence;
  owner: ReplicaCoordinatorOwner;
}): AsyncReplicaCoordinatorStatePort<LiteReplicaTransaction> {
  const { persistence, owner } = input;
  return {
    async: true,
    load: () =>
      persistence.transaction((tx) =>
        runEffectAsync(loadReplicaCoordinatorState(owner), tx),
      ),
    commit: (expected, next, checkpoint) =>
      persistence.transaction((tx) =>
        runEffectAsync(
          commitReplicaCoordinatorState(owner, expected, next, () =>
            checkpoint(tx),
          ),
          tx,
        ),
      ),
  };
}
