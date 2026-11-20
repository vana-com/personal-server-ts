import { forgetUploadedBlobs } from "./blobs.js";
import type { LocalSyncDeps } from "./deps.js";
import { endParticipation } from "./lifetime.js";
import { withOrigin } from "./merge.js";

// A purge ends the local lifetime even if a later observation restores the
// same registry generation. Retained publishers compare this token in-slot.
const lifetimes = new WeakMap<object, Map<string, object>>();
export function connectionLifetime(db: object, connectionId: string): object {
  let entries = lifetimes.get(db);
  if (!entries) lifetimes.set(db, (entries = new Map()));
  let token = entries.get(connectionId);
  if (!token) entries.set(connectionId, (token = {}));
  return token;
}

/**
 * F.5 step 1: the local purge of one connection, in the connection queue
 * (kind "purge"), in ONE batch with origin `purge`: delete the connection's
 * `records`, `run_rows`, `blob_refs`, `stream_partial` rows and
 * unreferenced `blobs`;
 * set `control_state='deleted'`; set `last_delete_version`; clear
 * `connections.checkpoint`. DELETES USER DATA. Spec: F.5, C.0 step 1.
 *
 * Runs through the connection queue with kind "purge", so it serialises
 * with the connection's other operations. One batch: a failing statement
 * rolls the whole purge back. The batch's origin is `purge`, so the
 * `record_changes` trigger logs every removed record with origin `purge`.
 * `last_delete_version` is the tombstone's control version, per stream in
 * `stream_state`: the fence (C.1) trips a run whose `delete_snapshot` is
 * below it. Blobs survive while any connection still references them; only
 * blobs with no `blob_refs` row left are deleted. `runs` and `run_streams`
 * rows are left alone: the purge removes staged rows, not run history.
 */
export async function purgeConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  deleted: { readonly controlVersion: number },
): Promise<void> {
  await deps.queue.run(connectionId, "purge", async () => {
    const { changes } = await deps.db.batch(
      withOrigin("purge", [
        {
          sql: "DELETE FROM records WHERE connection_id = ?",
          params: [connectionId],
        },
        {
          sql: `DELETE FROM run_rows
   WHERE run_id IN (SELECT run_id FROM runs WHERE connection_id = ?)`,
          params: [connectionId],
        },
        {
          sql: "DELETE FROM blob_refs WHERE connection_id = ?",
          params: [connectionId],
        },
        {
          sql: `DELETE FROM blobs
   WHERE NOT EXISTS (SELECT 1 FROM blob_refs r WHERE r.blob_id = blobs.blob_id)`,
        },
        {
          sql: `UPDATE stream_state SET last_delete_version = ?
   WHERE connection_id = ?`,
          params: [deleted.controlVersion, connectionId],
        },
        {
          sql: `UPDATE connections SET control_state = 'deleted', checkpoint = NULL
   WHERE connection_id = ?`,
          params: [connectionId],
        },
        // The log position and tombstones belong to the lifetime that ended.
        {
          sql: "DELETE FROM log_state WHERE connection_id = ?",
          params: [connectionId],
        },
        {
          sql: "DELETE FROM log_keyed_pending WHERE connection_id = ?",
          params: [connectionId],
        },
        {
          sql: "DELETE FROM log_tombstones WHERE connection_id = ?",
          params: [connectionId],
        },
        // Publish while collecting remembers deletes of the same lifetime.
        {
          sql: "DELETE FROM record_tombstones WHERE connection_id = ?",
          params: [connectionId],
        },
        // A first load in progress ends with the connection's rows.
        {
          sql: "DELETE FROM stream_partial WHERE connection_id = ?",
          params: [connectionId],
        },
        // A later lifetime is a connection this device has not joined.
        endParticipation(connectionId),
      ]),
    );
    // Rotate only after the purge batch commits, before releasing its slot.
    lifetimes.get(deps.db)?.delete(connectionId);
    // The lifetime is over: nothing uploaded for it is known to be there.
    forgetUploadedBlobs(deps.db);
    deps.logger.info(
      {
        connectionId,
        controlVersion: deleted.controlVersion,
        recordsRemoved: changes[1],
        runRowsRemoved: changes[2],
        blobRefsRemoved: changes[3],
        blobsRemoved: changes[4],
      },
      "purge connection",
    );
  });
}
