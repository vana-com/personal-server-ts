import type { LocalSyncDeps } from "./deps.js";

/** Where the fence is checked (C.1). */
export type FencePoint = "batch" | "end" | "publish";

/** Why a run is fenced. */
export type FenceTrip =
  | "stream_deleted_after_start"
  | "control_deleted"
  | "generation_moved_by_delete";

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
  void deps;
  void runId;
  void point;
  throw new Error("PS-2: not built");
}
