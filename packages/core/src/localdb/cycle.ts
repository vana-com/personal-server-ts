import { applyConnection, type ApplyResult } from "./apply.js";
import { bootstrapConnections, knownActiveConnections } from "./bootstrap.js";
import type { LocalSyncDeps } from "./deps.js";
import { publishLog } from "./log-publish.js";
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

/** What a connection's early publish did, before the cycle read the registry. */
export interface EarlyPublish {
  readonly published: readonly PublishResult[];
  readonly error: string | null;
}

/**
 * C.4: one sync cycle. With the log protocol, first publish what the known
 * connections hold (see `publishEarly`). Then the bootstrap listing (C.0), and
 * per connection: apply newer heads, then publish. Connections run
 * concurrently, one operation at a time each. Used by the sync-manager timer,
 * `/sync/trigger` and `/sync/file/:id` (trigger = this; file =
 * `syncConnection` for the one connection, then read).
 */
export async function runCycle(deps: LocalSyncDeps): Promise<CycleReport> {
  const early = deps.logProtocol
    ? await publishEarly(deps)
    : new Map<string, EarlyPublish>();
  const connections = await bootstrapConnections(deps);
  return {
    connections: await Promise.all(
      connections.map(({ connectionId }) =>
        syncConnection(deps, connectionId, early.get(connectionId)),
      ),
    ),
  };
}

/**
 * The log's writer reads nothing from the registry: its commit is a
 * compare-and-set on the log position and on the control row, and a commit
 * that loses applies the winner and starts over (log-publish.ts). So a
 * connection this device already knows to be active publishes its pending
 * changes first, and what the cycle reads from the registry (the listing, the
 * control row, the stream rows) no longer sits between a run's end and its
 * head. Apply then follows as before.
 *
 * Connections run concurrently, as in the rest of the cycle. A registry
 * without the batch route answers `null` and publishes nothing here; a
 * failure is kept for the connection's report and is not tried twice.
 */
async function publishEarly(
  deps: LocalSyncDeps,
): Promise<Map<string, EarlyPublish>> {
  const early = new Map<string, EarlyPublish>();
  await Promise.all(
    (await knownActiveConnections(deps)).map(async ({ connectionId }) => {
      try {
        const published = await publishLog(deps, connectionId);
        if (published !== null)
          early.set(connectionId, { published, error: null });
      } catch (cause) {
        early.set(connectionId, {
          published: [],
          error: cause instanceof Error ? cause.message : String(cause),
        });
      }
    }),
  );
  return early;
}

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
export async function syncConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  early?: EarlyPublish,
): Promise<CycleReport["connections"][number]> {
  let applied: readonly ApplyResult[] = [];
  let published: readonly PublishResult[] = [];
  let error: string | null = null;
  try {
    // A pass includes publish, so it must not join an apply-only operation.
    applied = await deps.queue.run(connectionId, "publish", () =>
      applyConnection(insideQueue(deps, connectionId), connectionId),
    );
    if (early?.error) throw new Error(early.error);
    // With the log flag on, a connection publishes one segment and one commit
    // per batch; `null` means this registry has no batch route, so the
    // per-stream path publishes instead. What apply left to publish goes after
    // what the early publish already sent.
    published = [
      ...(early?.published ?? []),
      ...((deps.logProtocol ? await publishLog(deps, connectionId) : null) ??
        (await publishConnection(deps, connectionId))),
    ];
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
