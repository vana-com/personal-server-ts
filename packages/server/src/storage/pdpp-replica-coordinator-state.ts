import type { Database } from "better-sqlite3";
import type { ReplicaCoordinatorStatePort } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  commitReplicaCoordinatorState,
  loadReplicaCoordinatorState,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator-state";
import { runEffectSync } from "@opendatalabs/personal-server-ts-core/replication/effects";
import { nodeReplicaContext } from "./pdpp-replica-sql.js";

export { REPLICA_COORDINATOR_SCHEMA } from "@opendatalabs/personal-server-ts-core/replication/coordinator-state";

/**
 * This adapter does NOT acquire or replace Node's exclusive writer lock.
 * It only fences the existing token inside the receiver's write transaction.
 * Registration intent/recovery tables and their state machine are untouched.
 * The rotation rules are core's, shared with PS-Lite's adapter.
 */
export function createSqliteReplicaCoordinatorState(input: {
  db: Database;
  owner: () => string | undefined;
  /** Use receiver.atomically: all attempt projection work shares this boundary. */
  atomically: <T>(run: () => T) => T;
}): ReplicaCoordinatorStatePort {
  const { db } = input;
  const context = nodeReplicaContext(db);
  return {
    load: () =>
      runEffectSync(loadReplicaCoordinatorState(input.owner), context),
    commit(expected, next, checkpoint) {
      return input.atomically(() => {
        if (!db.inTransaction)
          throw new Error("coordinator requires a write transaction");
        return runEffectSync(
          commitReplicaCoordinatorState(input.owner, expected, next, () =>
            checkpoint(),
          ),
          context,
        );
      });
    },
  };
}
