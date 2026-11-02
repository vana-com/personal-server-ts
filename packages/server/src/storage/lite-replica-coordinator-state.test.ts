import { expect, it } from "vitest";
import {
  REPLICA_COORDINATOR_SCHEMA,
  REPLICA_LOCK_SCHEMA,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator-state";
import {
  replicaCoordinatorStateContract,
  type ReplicaCoordinatorContractHarness,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator-state.test-utils";
import {
  createLiteReplicaCoordinatorState,
  type LiteReplicaTransaction,
} from "@opendatalabs/personal-server-ts-lite";
import { createSqliteLiteReplicaPersistence } from "./lite-replica-sqlite.test-utils.js";

// PS-Lite's asynchronous port runs the same contract as Node's synchronous one
// (pdpp-replica-coordinator-state.test.ts), over an asynchronous transaction.
async function open(): Promise<
  ReplicaCoordinatorContractHarness<LiteReplicaTransaction>
> {
  const store = createSqliteLiteReplicaPersistence();
  const { port: persistence } = store;
  await persistence.transaction(async (tx) => {
    await tx.sql.exec(REPLICA_LOCK_SCHEMA);
    await tx.sql.exec(REPLICA_COORDINATOR_SCHEMA);
    await tx.sql.exec("CREATE TABLE checkpoints(value TEXT NOT NULL)");
  });
  const inTx = <T>(
    context: LiteReplicaTransaction | undefined,
    run: (tx: LiteReplicaTransaction) => Promise<T>,
  ) => (context ? run(context) : persistence.transaction(run));
  return {
    port: (owner) =>
      createLiteReplicaCoordinatorState({ persistence, owner: () => owner }),
    acquire: (owner) =>
      persistence.transaction(async (tx) => {
        await tx.sql.run("INSERT INTO pdpp_transport_lock VALUES(1,0,?)", [
          owner,
        ]);
      }),
    recover: (owner, context) =>
      inTx(context, async (tx) => {
        await tx.sql.run("UPDATE pdpp_transport_lock SET token=? WHERE id=1", [
          owner,
        ]);
      }),
    checkpoint: (value, context) =>
      inTx(context, async (tx) => {
        await tx.sql.run("INSERT INTO checkpoints VALUES(?)", [value]);
      }),
    receipts: () =>
      persistence.transaction(async (tx) =>
        (
          await tx.sql.all("SELECT value FROM checkpoints ORDER BY rowid", [])
        ).map((row) => row.value as string),
      ),
    failCursorWrites: (fail) =>
      persistence.transaction((tx) =>
        tx.sql.exec(
          fail
            ? "CREATE TRIGGER fail_cursor BEFORE UPDATE ON pdpp_transport_coordinator BEGIN SELECT RAISE(ABORT,'cursor write failed'); END;"
            : "DROP TRIGGER fail_cursor",
        ),
      ),
    close: () => store.close(),
  };
}

replicaCoordinatorStateContract({ test: it, expect }, open);
