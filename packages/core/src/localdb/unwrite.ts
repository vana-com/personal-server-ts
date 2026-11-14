import type { LocalSyncDeps } from "./deps.js";
import { dropRunRows, withOrigin } from "./merge.js";

/**
 * C.2 step 3: a run accepted at `end` but now refused is un-written in ONE
 * batch with origin `purge`: delete the stream's rows whose stamp is the
 * run's stamp AND delete the stream's `head_parts`, and record the run's
 * stream decision as `refused`. The caller then applies at once (even at
 * the same version), so rows the refused run overwrote come back from the
 * head and rows that existed only in the refused run are lost.
 * DELETES USER DATA. Spec: C.2 step 3 (must-fix 2).
 *
 * Runs inside the caller's connection-queue turn (publish, C.2); it does
 * not take the queue itself. The run's stamp is (`runs.o`, `run_id`); the
 * run must belong to this connection. The batch's origin is `purge`, so the
 * `record_changes` trigger logs every removed row with origin `purge`.
 */
export async function unwriteRefusedRun(
  deps: LocalSyncDeps,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly runId: string;
    readonly reason: "connector_update_required" | "out_of_order";
  },
): Promise<void> {
  const [run] = await deps.db.query<{
    o: number;
    connection_id: string;
  }>("SELECT o, connection_id FROM runs WHERE run_id = ?", [input.runId]);
  if (!run) {
    throw new Error(`unwrite: unknown run ${input.runId}`);
  }
  if (run.connection_id !== input.connectionId) {
    throw new Error(
      `unwrite: run ${input.runId} belongs to another connection`,
    );
  }
  const { changes } = await deps.db.batch(
    withOrigin("purge", [
      ...dropRunRows(input.connectionId, input.stream, run.o, input.runId),
      {
        sql: `DELETE FROM head_parts WHERE connection_id = ? AND stream = ?`,
        params: [input.connectionId, input.stream],
      },
      {
        sql: `UPDATE run_streams SET decision = 'refused', reason = ?,
   publication_state = 'superseded', publication_reason = ?
 WHERE run_id = ? AND stream = ?`,
        params: [input.reason, input.reason, input.runId, input.stream],
      },
    ]),
  );
  deps.logger.info(
    {
      connectionId: input.connectionId,
      stream: input.stream,
      runId: input.runId,
      reason: input.reason,
      rowsRemoved: changes[1],
      headPartsRemoved: changes[3],
    },
    "unwrite refused run",
  );
}
