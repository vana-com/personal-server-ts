import { applyConnection, type ApplyOutcome } from "./apply.js";
import {
  bootstrapConnections,
  connectionsWithStreams,
  knownActiveConnections,
  newConnectionsWithStreams,
  type OwnerRows,
} from "./bootstrap.js";
import type { ConnectionRow, LocalSyncDeps } from "./deps.js";
import { publishLog } from "./log-publish.js";
import { markedFailedBy } from "./partial-load.js";
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
     * this pass stopped at that refusal. Any acknowledged early publication
     * remains in `published`; this status does not undo it. Rows applied
     * before the unreadable segment was reached (a snapshot, earlier segments)
     * stay applied (see `UpdateRequiredError`).
     */
    readonly status?: "update_required" | "degraded";
    /**
     * Set with `status: "degraded"`: the streams a load of this connection
     * stopped on, each with the reason it stopped (`stream_partial`). The
     * streams the load had not reached were not applied; the rest are as
     * the last complete apply left them. Any acknowledged early publication
     * remains in `published`.
     */
    readonly failedStreams?: readonly FailedStream[];
    /**
     * Set by `runPublish` for a connection the caller awaits whose early
     * publish settled: what the cycle's later pass failed with. `error` stays
     * null, because what the caller saved is published; this says what else
     * went wrong.
     */
    readonly followUpError?: string;
  }[];
}

/** A stream a load of the connection stopped on, and why (`failureCode`). */
export interface FailedStream {
  readonly stream: string;
  readonly reason: string;
}

/** The connections a retry owes while the registry position is unchanged. */
export interface CycleScope {
  readonly connections: readonly string[];
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
export async function runCycle(
  deps: LocalSyncDeps,
  scope?: CycleScope,
  made?: Map<string, EarlyPublish>,
  onApply?: (outcome: ApplyOutcome) => void,
): Promise<CycleReport> {
  if (scope) return runScoped(deps, scope);
  const early = made ?? (await publishEarly(deps, await earlyCandidates(deps)));
  // One listing after early publish, shared by bootstrap and all applies.
  return cycleOver(deps, await deps.registry.listOwnerRows(), early, onApply);
}

/** The cycle's pass over a listing already taken: bootstrap, then each connection. */
async function cycleOver(
  deps: LocalSyncDeps,
  listed: OwnerRows,
  early: Map<string, EarlyPublish>,
  onApply?: (outcome: ApplyOutcome) => void,
): Promise<CycleReport> {
  const connections = await bootstrapConnections(deps, listed);
  return {
    connections: await Promise.all(
      connections.map(({ connectionId }) =>
        syncConnection(
          deps,
          connectionId,
          early.get(connectionId),
          listed,
          onApply,
        ),
      ),
    ),
  };
}

/** Retry only the named connections using one shared owner listing. */
async function runScoped(
  deps: LocalSyncDeps,
  scope: CycleScope,
): Promise<CycleReport> {
  const held = new Set(
    (
      await deps.db.query<{ id: string }>(
        "SELECT connection_id AS id FROM connections",
      )
    ).map((row) => row.id),
  );
  const ids = [...new Set(scope.connections)].filter((id) => held.has(id));
  if (ids.length === 0) return { connections: [] };
  const only = new Set(ids);
  const candidates = await earlyCandidates(deps);
  const early = await publishEarly(deps, {
    active: candidates.active.filter((row) => only.has(row.connectionId)),
    fresh: candidates.fresh.filter((row) => only.has(row.connectionId)),
  });
  const listed = await deps.registry.listOwnerRows();
  return {
    connections: await Promise.all(
      ids.map((id) => syncConnection(deps, id, early.get(id), listed)),
    ),
  };
}

/**
 * What a caller that saved something awaits: the publication of what is
 * pending, ending at the registry commit. It is the cycle's early publish
 * alone. The cycle's listing and apply read the registry for what other
 * devices wrote, and nothing the save wrote waits for them: a commit makes it
 * durable. The sync manager's own cycle (the wake a run's rows raise, the
 * timer) runs the rest.
 *
 * A pass the early publish cannot settle takes the whole cycle, with the early
 * publish's results already in hand: a connection that has an error or any
 * result but published or noop (a deferral, a backoff, a refusal), a fresh
 * connection that deferred (another device made its row), and a connection
 * the early publish does not take (deleted, foreign, or a reconnect), which
 * only the cycle's listing and apply can place.
 */
export async function runPublish(
  deps: LocalSyncDeps,
  /**
   * The connections the caller awaits. When the fallback cycle cannot run
   * (its registry listing rejects), the early publish's report stands if
   * every one of these settled in it: what the caller was acknowledged is
   * not lost to a sibling's failure. Without it the cycle's error is thrown.
   */
  awaited?: readonly string[],
): Promise<CycleReport> {
  const candidates = await earlyCandidates(deps);
  const early = await publishEarly(deps, candidates);
  const fresh = new Set(candidates.fresh.map((c) => c.connectionId));
  // Every connection the early publish takes must have a result: a registry
  // without the batch route throws `RegistryBatchRouteMissingError`, which is
  // kept as the connection's error and leaves no result: nothing is published
  // (the cycle reports it). A fresh
  // connection has streams, so no published result means its deferral was
  // dropped (`publishEarly`); a known connection with no streams has none.
  const isSettled = (connectionId: string): boolean => {
    const e = early.get(connectionId);
    return (
      e !== undefined &&
      e.error === null &&
      (e.published.length > 0 || !fresh.has(connectionId)) &&
      e.published.every(
        (r) => r.outcome === "published" || r.outcome === "noop",
      )
    );
  };
  const earlyReport = (): CycleReport => ({
    connections: [...early].map(([connectionId, e]) => ({
      connectionId,
      published: e.published,
      error:
        e.error === null
          ? null
          : e.error instanceof Error
            ? e.error.message
            : String(e.error),
    })),
  });
  const settled = [...candidates.active, ...candidates.fresh].every(
    ({ connectionId }) => isSettled(connectionId),
  );
  if (!settled || (await hasUnplacedConnections(deps, candidates))) {
    // Only the registry listing is recovered from: the caller's connections
    // settled in the early publish, and the listing is what the fallback
    // needs beyond them. A failure after it (saving controls, purging,
    // apply) is the cycle's own and propagates.
    let listed: OwnerRows;
    try {
      listed = await deps.registry.listOwnerRows();
    } catch (cause) {
      if (awaited && awaited.length > 0 && awaited.every(isSettled))
        return earlyReport();
      throw cause;
    }
    const report = await cycleOver(deps, listed, early);
    // A connection the caller awaits whose early publish settled keeps its
    // receipt: a later pass that fails is reported beside it, not instead.
    const own = new Set(awaited ?? []);
    return {
      connections: report.connections.map((connection) =>
        own.has(connection.connectionId) &&
        isSettled(connection.connectionId) &&
        connection.error !== null
          ? { ...connection, error: null, followUpError: connection.error }
          : connection,
      ),
    };
  }
  return earlyReport();
}

/** The connections the early publish takes: known active, and new with streams. */
interface EarlyCandidates {
  readonly active: readonly ConnectionRow[];
  readonly fresh: readonly ConnectionRow[];
}

async function earlyCandidates(deps: LocalSyncDeps): Promise<EarlyCandidates> {
  return {
    active: await knownActiveConnections(deps),
    fresh: await newConnectionsWithStreams(deps),
  };
}

/**
 * A connection with streams that the early publish takes neither as active nor
 * as new: it waits for the cycle's listing.
 */
async function hasUnplacedConnections(
  deps: LocalSyncDeps,
  { active, fresh }: EarlyCandidates,
): Promise<boolean> {
  const placed = new Set(
    [...active, ...fresh].map(({ connectionId }) => connectionId),
  );
  return (await connectionsWithStreams(deps)).some(
    ({ connectionId }) => !placed.has(connectionId),
  );
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
 * without the batch route throws `RegistryBatchRouteMissingError` and
 * publishes nothing here; a failure, that one included, is kept for the
 * connection's report and is not tried twice.
 */
async function publishEarly(
  deps: LocalSyncDeps,
  { active, fresh }: EarlyCandidates,
): Promise<Map<string, EarlyPublish>> {
  const early = new Map<string, EarlyPublish>();
  await Promise.all([
    ...active.map(async ({ connectionId }) => {
      try {
        const published = await publishLog(deps, connectionId);
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
  /** The cycle's listing of the owner's rows, taken before this call. */
  listed?: OwnerRows,
  onApply?: (outcome: ApplyOutcome) => void,
): Promise<CycleReport["connections"][number]> {
  let published: readonly PublishResult[] = early?.published ?? [];
  let error: string | null = null;
  let status: "update_required" | "degraded" | undefined;
  let failedStreams: readonly FailedStream[] = [];
  try {
    // A pass includes publish, so it must not join an apply-only operation.
    const outcome = await deps.queue.run(connectionId, "publish", () =>
      applyConnection(
        insideQueue(deps, connectionId),
        connectionId,
        listed,
        listed?.find((row) => row.scope === connectionId)?.read,
      ),
    );
    onApply?.(outcome);
    if (early && early.error !== null) throw early.error;
    // One segment and one commit per batch. A registry without the batch
    // route fails it (`RegistryBatchRouteMissingError`): nothing is published
    // until it has one. What apply left to publish goes after what the early
    // publish already sent.
    const through = await publishLog(deps, connectionId);
    published = [...published, ...through];
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
    // Say which streams this attempt's apply stopped on, so one bad object
    // reads as that and not as a connection that failed whole. The apply
    // names them on the error it throws; rows of earlier attempts do not count.
    if (status === undefined) failedStreams = markedFailedBy(cause);
    if (failedStreams.length > 0) status = "degraded";
  }
  return {
    connectionId,
    published,
    error,
    ...(status ? { status } : {}),
    ...(failedStreams.length > 0 ? { failedStreams } : {}),
  };
}
