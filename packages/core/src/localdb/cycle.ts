import type { ApplyResult } from "./apply.js";
import type { LocalSyncDeps } from "./deps.js";
import type { PublishResult } from "./publish.js";

export interface CycleReport {
  readonly connections: readonly {
    readonly connectionId: string;
    readonly applied: readonly ApplyResult[];
    readonly published: readonly PublishResult[];
    /** Set when this connection's pass threw; other connections still ran. */
    readonly error: string | null;
  }[];
}

/**
 * C.4: one sync cycle. Bootstrap listing (C.0), then per connection in the
 * queue: apply newer heads, then publish. Connections run concurrently, one
 * operation at a time each. Used by the sync-manager timer, `/sync/trigger`
 * and `/sync/file/:id` (trigger = this; file = `syncConnection` for the one
 * connection, then read).
 */
export async function runCycle(deps: LocalSyncDeps): Promise<CycleReport> {
  void deps;
  throw new Error("PS-2: not built");
}

/** One connection: apply, then publish. */
export async function syncConnection(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<CycleReport["connections"][number]> {
  void deps;
  void connectionId;
  throw new Error("PS-2: not built");
}
