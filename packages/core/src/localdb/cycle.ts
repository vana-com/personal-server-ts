import { applyConnection } from "./apply.js";
import {
  bootstrapConnections,
  knownActiveConnections,
  newConnectionsWithStreams,
} from "./bootstrap.js";
import type { LocalSyncDeps } from "./deps.js";
import { publishLog } from "./log-publish.js";
import type { PublishResult } from "./publish.js";
import { insideQueue } from "./slot.js";
import { UpdateRequiredError } from "./update-required.js";

export interface CycleReport {
  readonly connections: readonly {
    readonly connectionId: string;
    readonly published: readonly PublishResult[];
    /** Set when this connection's pass threw; other connections still ran. */
    readonly error: string | null;
    /**
     * Set when the connection's log is in a format this build cannot read:
     * nothing was published for it and its pending changes stay pending. Rows
     * applied before the unreadable segment was reached (a snapshot, earlier
     * segments) stay applied (see `UpdateRequiredError`).
     */
    readonly status?: "update_required";
  }[];
}

/** What a connection's early publish did, before the cycle read the registry. */
export interface EarlyPublish {
  readonly published: readonly PublishResult[];
  /** What the early publish threw, kept as thrown so its type survives. */
  readonly error: unknown;
}

/**
 * C.4: one sync cycle. First publish what the known connections hold (see
 * `publishEarly`). Then the bootstrap listing (C.0), and per connection: apply
 * the log, then publish. Connections run
 * concurrently, one operation at a time each. Used by the sync-manager timer,
 * `/sync/trigger` and `/sync/file/:id` (trigger = this; file =
 * `syncConnection` for the one connection, then read).
 */
export async function runCycle(deps: LocalSyncDeps): Promise<CycleReport> {
  const early = await publishEarly(deps);
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
  const active = await knownActiveConnections(deps);
  const fresh = await newConnectionsWithStreams(deps);
  await Promise.all([
    ...active.map(async ({ connectionId }) => {
      try {
        const published = await publishLog(deps, connectionId);
        if (published !== null)
          early.set(connectionId, { published, error: null });
      } catch (cause) {
        early.set(connectionId, { published: [], error: cause });
      }
    }),
    // A new connection's first publish creates its control row, so it does not
    // wait for the cycle's listing and apply, which would find nothing for it.
    // The device's view of it can still be old (another device made the row
    // since): the publish then defers or loses its commit and applies, and the
    // cycle's own pass below publishes it, so a deferral is not reported here.
    ...fresh.map(async ({ connectionId }) => {
      try {
        const published = await publishLog(deps, connectionId);
        if (published !== null)
          early.set(connectionId, {
            published: published.filter((r) => r.outcome !== "deferred"),
            error: null,
          });
      } catch (cause) {
        early.set(connectionId, { published: [], error: cause });
      }
    }),
  ]);
  return early;
}

/**
 * One connection: apply, then publish.
 *
 * Queue boundaries. Apply holds one "publish" slot, with nested queue calls
 * inline: it merges downloaded rows while it downloads, so its slot cannot
 * be shortened until apply is split the way publish is. Publish does not
 * hold a slot here: `publishLog` takes the slot for its snapshot and
 * its commit and releases it while it uploads, so a run's begin waits for at
 * most one of those short turns, never for an upload.
 */
export async function syncConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  early?: EarlyPublish,
): Promise<CycleReport["connections"][number]> {
  let published: readonly PublishResult[] = [];
  let error: string | null = null;
  let status: "update_required" | undefined;
  try {
    // A pass includes publish, so it must not join an apply-only operation.
    await deps.queue.run(connectionId, "publish", () =>
      applyConnection(insideQueue(deps, connectionId), connectionId),
    );
    if (early && early.error !== null) throw early.error;
    // One segment and one commit per batch; `null` means this registry has no
    // batch route, so nothing can be published until it has. What apply left
    // to publish goes after what the early publish already sent.
    const through = await publishLog(deps, connectionId);
    if (through === null)
      throw new Error(
        "stream sync: this registry has no batch route; nothing is published until it has",
      );
    published = [...(early?.published ?? []), ...through];
  } catch (cause) {
    error = cause instanceof Error ? cause.message : String(cause);
    if (cause instanceof UpdateRequiredError) status = "update_required";
    // The timer and `/sync/trigger` drop the report. A connection whose
    // publish keeps failing would otherwise stay unpublished with no trace:
    // its run ended as accepted, but nothing it holds becomes readable.
    deps.logger.warn(
      { connectionId, error },
      "Stream sync cycle failed for a connection",
    );
  }
  return {
    connectionId,
    published,
    error,
    ...(status ? { status } : {}),
  };
}
