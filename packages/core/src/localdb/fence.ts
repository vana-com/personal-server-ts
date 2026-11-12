import type { LocalSyncDeps } from "./deps.js";

/** Where the fence is checked (C.1). */
export type FencePoint = "batch" | "end" | "publish";

/** Why a run is fenced. */
export type FenceTrip =
  | "stream_deleted_after_start"
  | "control_deleted"
  | "generation_moved_by_delete";

/**
 * The per-stream part of the fence, as a pure function of the facts it reads:
 * the run's admitted generation and pinned delete snapshot against the
 * connection's current generation and the stream's last delete version.
 * `undefined` = the run's work is still publishable. A run with no admitted
 * generation yet (`null`) is never tripped by generation. The control-deleted
 * check stays with the callers: it reads the control row, not these facts.
 */
export function streamFenceTrip(facts: {
  readonly runGeneration: number | null;
  readonly deleteSnapshot: number;
  readonly connectionGeneration: number | undefined;
  readonly lastDeleteVersion: number | undefined;
}): Exclude<FenceTrip, "control_deleted"> | undefined {
  if (
    facts.connectionGeneration !== undefined &&
    facts.runGeneration !== null &&
    facts.connectionGeneration > facts.runGeneration
  )
    // A generation can only rise through a delete (control.ts
    // `deletedSinceStart`): a delete followed by a reconnect moved the
    // connection past the generation the run started under. A run that
    // started after the reconnect carries the new generation and is kept.
    return "generation_moved_by_delete";
  if (
    facts.lastDeleteVersion !== undefined &&
    facts.lastDeleteVersion > facts.deleteSnapshot
  )
    // The stream was deleted after the run pinned its snapshot. A row
    // already tombstoned at collection is inside the snapshot, so it does
    // not trip.
    return "stream_deleted_after_start";
  return undefined;
}

/**
 * C.1 per-stream fence. Tripped when `stream_state.last_delete_version >
 * run_streams.delete_snapshot`, or the control row is `deleted`, or its
 * generation moved past the run's generation through a delete. Returns the
 * streams of the run that tripped, with the reason; empty = not fenced.
 * Reads only. Spec: C.1 "Fence, per stream", F.5 #563 carry.
 */
export async function checkRunFence(
  deps: LocalSyncDeps,
  runId: string,
  point: FencePoint,
): Promise<readonly { readonly stream: string; readonly trip: FenceTrip }[]> {
  // The check is the same at every point (C.1: checked at every batch, at
  // end and at publish); `point` only says where the caller is checking.
  void point;
  const runs = await deps.db.query<{
    connection_id: string;
    generation: number | null;
  }>("SELECT connection_id, generation FROM runs WHERE run_id = ?", [runId]);
  const run = runs[0];
  if (run === undefined) return [];
  const streams = await deps.db.query<{
    stream: string;
    delete_snapshot: number;
  }>(
    "SELECT stream, delete_snapshot FROM run_streams WHERE run_id = ? ORDER BY stream",
    [runId],
  );
  if (streams.length === 0) return [];
  const connections = await deps.db.query<{
    control_state: string;
    generation: number;
  }>(
    "SELECT control_state, generation FROM connections WHERE connection_id = ?",
    [run.connection_id],
  );
  const connection = connections[0];
  const states = await deps.db.query<{
    stream: string;
    last_delete_version: number;
  }>(
    "SELECT stream, last_delete_version FROM stream_state WHERE connection_id = ?",
    [run.connection_id],
  );
  const lastDeleteByStream = new Map(
    states.map((s) => [s.stream, s.last_delete_version]),
  );
  const tripped: { stream: string; trip: FenceTrip }[] = [];
  for (const { stream, delete_snapshot } of streams) {
    let trip: FenceTrip | undefined;
    if (connection?.control_state === "deleted") {
      // F.5 step 1 set the control row to `deleted`: the connection's data
      // is gone, so every stream of the run is fenced.
      trip = "control_deleted";
    } else {
      trip = streamFenceTrip({
        runGeneration: run.generation,
        deleteSnapshot: delete_snapshot,
        connectionGeneration: connection?.generation,
        lastDeleteVersion: lastDeleteByStream.get(stream),
      });
    }
    if (trip !== undefined) tripped.push({ stream, trip });
  }
  return tripped;
}
