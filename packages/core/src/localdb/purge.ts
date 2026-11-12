import type { LocalSyncDeps } from "./deps.js";
import { withOrigin } from "./merge.js";

/**
 * F.5 step 1: the local purge of one connection, in the connection queue
 * (kind "purge"), in ONE batch with origin `purge`: delete the connection's
 * `records`, `run_rows`, `head_parts`, `blob_refs`, `publish_spool` rows and
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
          sql: "DELETE FROM head_parts WHERE connection_id = ?",
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
        // A publish copy of the deleted rows. Its transfer sees the rows gone
        // and stops; the commit would refuse it in any case.
        {
          sql: "DELETE FROM publish_spool WHERE connection_id = ?",
          params: [connectionId],
        },
      ]),
    );
    deps.logger.info(
      {
        connectionId,
        controlVersion: deleted.controlVersion,
        recordsRemoved: changes[1],
        runRowsRemoved: changes[2],
        headPartsRemoved: changes[3],
        blobRefsRemoved: changes[4],
        blobsRemoved: changes[5],
      },
      "purge connection",
    );
  });
}
