import { applyConnection, type ApplyResult } from "./apply.js";
import { bootstrapConnections } from "./bootstrap.js";
import type { LocalSyncDeps } from "./deps.js";
import { publishConnection, type PublishResult } from "./publish.js";
import { insideQueue } from "./slot.js";

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
 * C.4: one sync cycle. Bootstrap listing (C.0), then per connection: apply
 * newer heads, then publish. Connections run concurrently, one operation at a
 * time each. Used by the sync-manager timer, `/sync/trigger` and
 * `/sync/file/:id` (trigger = this; file = `syncConnection` for the one
 * connection, then read).
 */
export async function runCycle(deps: LocalSyncDeps): Promise<CycleReport> {
  const connections = await observed(deps, () => bootstrapConnections(deps));
  return {
    connections: await Promise.all(
      connections.map(({ connectionId }) => syncConnection(deps, connectionId)),
    ),
  };
}

/** One operation of the cycle; its committed part is announced even on a throw. */
const observed = <T>(
  deps: LocalSyncDeps,
  work: () => Promise<T>,
): Promise<T> =>
  deps.viewChanges ? deps.viewChanges.observe(deps, work) : work();

/**
 * One connection: apply, then publish.
 *
 * Queue boundaries. Apply holds one "publish" slot, with nested queue calls
 * inline: it merges downloaded rows while it downloads, so its slot cannot
 * be shortened until apply is split the way publish is. Publish does not
 * hold a slot here: `publishConnection` takes the slot for its snapshot and
 * its commit and releases it while it uploads, so a run's begin waits for at
 * most one of those short turns, never for an upload.
 */
export function syncConnection(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<CycleReport["connections"][number]> {
  return observed(deps, () => passOf(deps, connectionId));
}

async function passOf(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<CycleReport["connections"][number]> {
  let applied: readonly ApplyResult[] = [];
  let published: readonly PublishResult[] = [];
  let error: string | null = null;
  try {
    // A pass includes publish, so it must not join an apply-only operation.
    applied = await deps.queue.run(connectionId, "publish", () =>
      applyConnection(insideQueue(deps, connectionId), connectionId),
    );
    published = await publishConnection(deps, connectionId);
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
