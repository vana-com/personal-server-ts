import type { ControlState } from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlStatement } from "./driver.js";

/**
 * Owner of one invariant: a `connection_participation` row belongs to one
 * lifetime of a connection. "A later lifetime is a connection this device has
 * not joined", so the row ends with the lifetime, in the same transaction
 * that ends it. Two events end a lifetime:
 *
 * - the purge of a deleted connection (`purge.ts`), which uses
 *   `endParticipation`;
 * - the install of a control row for a new generation (`installControl`),
 *   which covers a device that missed the tombstone and first sees the
 *   recreated connection. It holds for every path that installs a control:
 *   the bootstrap listing and `syncBeforeBegin` (`saveControl`) and apply's
 *   control read (`apply.ts`).
 *
 * Add no other writer of `connections.generation` without going through
 * `installControl`.
 */
export const endParticipation = (connectionId: string): SqlStatement => ({
  sql: "DELETE FROM connection_participation WHERE connection_id = ?",
  params: [connectionId],
});

/**
 * Install a classified control row on an existing `connections` row.
 * Preserves the last active generation and newer controls. Absence is not
 * authority to clear a local-only delete; a fresh active row is. When the
 * install changes the generation, the participation row ends first, under the
 * same fence as the update: a stale, unchanged or absent control keeps it.
 */
export function installControl(
  connectionId: string,
  state: ControlState,
  version: number,
): SqlStatement[] {
  const generation = state.kind === "active" ? state.generation : 1;
  // The fence is shared by both statements. The participation delete runs
  // first because it reads the generation the update replaces.
  const fence = `control_version <= ? AND NOT (control_state = 'deleted' AND ? = 'absent')`;
  const fenceParams = [version, state.kind];
  return [
    {
      sql: `DELETE FROM connection_participation WHERE connection_id = ?
        AND EXISTS (SELECT 1 FROM connections
          WHERE connection_id = ? AND ? = 'active' AND generation <> ? AND ${fence})`,
      params: [
        connectionId,
        connectionId,
        state.kind,
        generation,
        ...fenceParams,
      ],
    },
    {
      sql: `UPDATE connections SET
        generation = CASE WHEN ? = 'active' THEN ? ELSE generation END,
        control_state = ?, control_version = ?
        WHERE connection_id = ? AND ${fence}`,
      params: [
        state.kind,
        generation,
        state.kind,
        version,
        connectionId,
        ...fenceParams,
      ],
    },
  ];
}
