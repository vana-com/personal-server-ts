import { applyConnection, type ApplyResult } from "./apply.js";
import { bootstrapConnections } from "./bootstrap.js";
import type { LocalSyncDeps } from "./deps.js";
import { publishConnection, type PublishResult } from "./publish.js";

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
  const connections = await bootstrapConnections(deps);
  return {
    connections: await Promise.all(
      connections.map(({ connectionId }) => syncConnection(deps, connectionId)),
    ),
  };
}

/** One connection: apply, then publish. */
export async function syncConnection(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<CycleReport["connections"][number]> {
  let applied: readonly ApplyResult[] = [];
  let published: readonly PublishResult[] = [];
  let error: string | null = null;
  try {
    // A pass includes publish, so it must not join an apply-only operation.
    await deps.queue.run(connectionId, "publish", async () => {
      // The queue is not reentrant. Siblings may acquire it themselves; this
      // pass already owns this connection until both operations have settled.
      const queuedDeps: LocalSyncDeps = {
        ...deps,
        queue: {
          run(id, kind, operation) {
            return id === connectionId
              ? Promise.resolve().then(operation)
              : deps.queue.run(id, kind, operation);
          },
        },
      };
      applied = await applyConnection(queuedDeps, connectionId);
      published = await publishConnection(queuedDeps, connectionId);
    });
  } catch (cause) {
    error = cause instanceof Error ? cause.message : String(cause);
    // The timer and `/sync/trigger` drop the report. A connection whose
    // publish keeps failing would otherwise stay unpublished with no trace:
    // its run ended as accepted, but nothing it holds becomes readable.
    deps.logger.warn(
      { connectionId, error },
      "Stream sync cycle failed for a connection",
    );
  }
  return { connectionId, applied, published, error };
}
