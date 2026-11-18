import type { SqlDriver } from "./driver.js";
import type { GrantObservationPort } from "../policy/data-write.js";

/** Observations use the database's single writer, just like record admission. */
export function createApplicationGrantStore(
  db: SqlDriver,
): GrantObservationPort {
  return {
    async record(observation) {
      await db.batch([
        {
          // A delayed active answer cannot undo a revocation of this revision.
          sql: `DELETE FROM application_grants WHERE grant_id = ?
            AND NOT (revision = ? AND status <> 'active' AND ? = 'active')`,
          params: [
            observation.grantId,
            observation.revision,
            observation.status,
          ],
        },
        {
          sql: `INSERT OR IGNORE INTO application_grants
            (grant_id, revision, status, expires_at, observed_at)
            VALUES (?, ?, ?, ?, ?)`,
          params: [
            observation.grantId,
            observation.revision,
            observation.status,
            observation.expiresAt,
            observation.observedAt,
          ],
        },
      ]);
    },
  };
}
