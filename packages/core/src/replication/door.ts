/**
 * The one-way door for replication on one device's database.
 *
 * Replication can be turned on once. Turning it off is permanent: a later
 * enabled open is refused, because writes made while it was off were never
 * captured and a peer would never see them. No data is deleted.
 *
 * - `never`: replication has never been enabled on this database.
 * - `on`: enabled, and every replicated write since the first enable was
 *   captured.
 * - `off`: replication was enabled once and this open has it off. The door
 *   is now closed.
 * - `refused`: an enabled open found the door closed. The host shows
 *   `refusal`; the store runs as if the flag were off.
 */
export type ReplicationDoorStatus =
  | { state: "never" | "on" | "off" }
  | { state: "refused"; refusal: ReplicationRefusal };

/**
 * Why an enabled open was refused. `reenable_refused`: replication was
 * turned off after it was on, a write bypassed capture, or the database was
 * enabled by a build that kept no record of its off periods.
 */
export type ReplicationRefusal = "reenable_refused";

/** Thrown by a store asked to replicate behind a closed door. */
export class ReplicationRefusedError extends Error {
  constructor(public readonly reason: ReplicationRefusal) {
    super(reason);
    this.name = "ReplicationRefusedError";
  }
}
