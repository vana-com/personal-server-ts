/**
 * The replication door on a Node database (see `core/replication/door.ts`).
 *
 * The first enabled open creates `pdpp_replica_door`, one row that records
 * the enable and holds a capture guard, and AFTER triggers on every canonical
 * table a replicated mutation writes. A trigger marks the row `uncaptured`
 * when it fires while the guard is 0. Capture and import transactions set the
 * guard to 1 at their start and back to 0 before they commit
 * (`captureWrites`), so only a write outside them marks the row. The fence is
 * plain SQL, so it also catches a build that knows nothing of replication.
 *
 * A database that never enabled replication gets none of this: the flag-off
 * open only probes `sqlite_master` for the table.
 */
import type { Database, Statement } from "better-sqlite3";
import {
  ReplicationRefusedError,
  type ReplicationDoorStatus,
} from "@opendatalabs/personal-server-ts-core/replication/door";

/** The flag-off open's only replica statement. Read-only. */
export const REPLICATION_DOOR_PROBE =
  "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pdpp_replica_door'";

/**
 * Canonical tables a replicated mutation writes, and the operations fenced on
 * each. Blob claims fence INSERT and UPDATE only: startup GC deletes stale
 * claims on every open, and a claim is otherwise removed only with a binding
 * change, which `pdpp_instance_binding` fences.
 */
const FENCED: readonly [table: string, operations: readonly string[]][] = [
  ["pdpp_records", ["INSERT", "UPDATE", "DELETE"]],
  ["pdpp_instance_binding", ["INSERT", "UPDATE", "DELETE"]],
  ["pdpp_stream_completion", ["INSERT", "UPDATE", "DELETE"]],
  ["pdpp_claude_transition", ["INSERT", "UPDATE", "DELETE"]],
  ["pdpp_strava_transition", ["INSERT", "UPDATE", "DELETE"]],
  ["pdpp_blob_claims", ["INSERT", "UPDATE"]],
];

const TRIGGERS = FENCED.flatMap(([table, operations]) =>
  operations.map((operation) => ({
    name: `pdpp_replica_door_${table}_${operation.toLowerCase()}`,
    table,
    operation,
  })),
);

export const REPLICATION_DOOR_SCHEMA = `
CREATE TABLE IF NOT EXISTS pdpp_replica_door (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  capturing INTEGER NOT NULL DEFAULT 0 CHECK (capturing IN (0, 1)),
  uncaptured INTEGER NOT NULL DEFAULT 0 CHECK (uncaptured IN (0, 1)),
  off INTEGER NOT NULL DEFAULT 0 CHECK (off IN (0, 1))
);
${TRIGGERS.map(
  ({ name, table, operation }) =>
    `CREATE TRIGGER IF NOT EXISTS ${name} AFTER ${operation} ON ${table}
WHEN (SELECT capturing = 0 AND uncaptured = 0 FROM pdpp_replica_door WHERE id = 1)
BEGIN UPDATE pdpp_replica_door SET uncaptured = 1 WHERE id = 1; END;`,
).join("\n")}
`;

/** Closing the door is final, so the fence has nothing left to guard. */
const CLOSE_DOOR = `
UPDATE pdpp_replica_door SET off = 1 WHERE id = 1 AND off = 0;
${TRIGGERS.map(({ name }) => `DROP TRIGGER IF EXISTS ${name};`).join("\n")}
`;

function hasDoor(db: Database): boolean {
  return db.prepare(REPLICATION_DOOR_PROBE).get() !== undefined;
}

/** A database a pre-door build enabled: baselined, with no record of off periods. */
function enabledWithoutDoor(db: Database): boolean {
  return (
    db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pdpp_replica_settings'",
      )
      .get() !== undefined &&
    db.prepare("SELECT 1 FROM pdpp_replica_settings").get() !== undefined
  );
}

/**
 * The enabled open's door check. Creates the door and fence on the first
 * enable; throws `ReplicationRefusedError` when the door is closed. Run after
 * the canonical schema exists and before any replica write.
 */
export function admitReplication(db: Database): void {
  db.transaction(() => {
    if (hasDoor(db)) {
      // Admit only a door row that is exactly open. A committed
      // `capturing = 1` cannot survive a rollback, so it is corruption, and it
      // would silence every trigger. Refusing also closes the door for good.
      const door = db
        .prepare(
          "SELECT capturing, uncaptured, off FROM pdpp_replica_door WHERE id = 1",
        )
        .get() as Record<string, unknown> | undefined;
      if (door?.capturing !== 0 || door.uncaptured !== 0 || door.off !== 0)
        throw new ReplicationRefusedError("reenable_refused");
    } else if (enabledWithoutDoor(db)) {
      // Unbaselined replica tables are harmless: the baseline reads every
      // canonical row. A baseline without a door may have missed writes.
      throw new ReplicationRefusedError("reenable_refused");
    }
    db.exec(REPLICATION_DOOR_SCHEMA);
    db.prepare("INSERT OR IGNORE INTO pdpp_replica_door (id) VALUES (1)").run();
  }).immediate();
}

/**
 * The flag-off open's door step: once replication was enabled, an open with
 * it off closes the door for good and drops the fence, so a closed door costs
 * flag-off writes nothing. On a database that never enabled it, this is one
 * read of `sqlite_master` and writes nothing.
 */
export function retireReplication(db: Database): ReplicationDoorStatus {
  if (!hasDoor(db)) return { state: "never" };
  db.transaction(() => db.exec(CLOSE_DOOR)).immediate();
  return { state: "off" };
}

/**
 * Run `write` as a capture or import: canonical writes inside it do not trip
 * the fence. Call it inside the write's transaction. Nested calls leave the
 * guard to the outermost one, which resets it before the transaction
 * commits; a rollback restores it.
 */
export function captureWrites<T>(db: Database, write: () => T): T {
  if (!db.inTransaction)
    throw new Error("a capture guard requires the write transaction");
  let guard = guards.get(db);
  if (!guard) {
    guard = {
      raise: db.prepare(
        "UPDATE pdpp_replica_door SET capturing = 1 WHERE id = 1 AND capturing = 0",
      ),
      lower: db.prepare(
        "UPDATE pdpp_replica_door SET capturing = 0 WHERE id = 1",
      ),
    };
    guards.set(db, guard);
  }
  const outermost = guard.raise.run().changes === 1;
  try {
    return write();
  } finally {
    if (outermost && db.inTransaction) guard.lower.run();
  }
}
const guards = new WeakMap<Database, { raise: Statement; lower: Statement }>();
