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
import type { AttemptFailures } from "./partial-load.js";
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
  }[];
  /**
   * A failure of the fallback pass that no connection owns (the registry
   * listing, saving controls or purging). It never changes the result of a
   * scoped caller whose connections settled in the early publish.
   */
  readonly cycleError?: string;
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
  /** A fresh connection's deferral, dropped from `published` (see `publishEarly`). */
  readonly deferred?: boolean;
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

/**
 * The cycle's pass over a listing already taken: bootstrap, then each
 * connection. A connection in `exclude` is left alone: its control row is not
 * saved or purged, it takes no queue slot, and it is neither applied nor
 * published (a caller's connection that its early publish already settled).
 * The listing the applies read stays whole.
 */
async function cycleOver(
  deps: LocalSyncDeps,
  listed: OwnerRows,
  early: Map<string, EarlyPublish>,
  onApply?: (outcome: ApplyOutcome) => void,
  exclude: ReadonlySet<string> = new Set(),
): Promise<CycleReport> {
  const failures = new Map<string, unknown>();
  // A control row's scope is its connection's id (`controlScope`).
  const connections = await bootstrapConnections(
    deps,
    exclude.size === 0
      ? listed
      : listed.filter(({ scope }) => !exclude.has(scope)),
    failures,
  );
  return {
    connections: [
      ...(await Promise.all(
        connections
          .filter(
            ({ connectionId }) =>
              !exclude.has(connectionId) && !failures.has(connectionId),
          )
          .map(({ connectionId }) =>
            syncConnection(
              deps,
              connectionId,
              early.get(connectionId),
              listed,
              onApply,
            ),
          ),
      )),
      ...failedBootstraps(deps, failures, early),
    ],
  };
}

/**
 * A connection whose control save or purge failed is reported against itself,
 * with what the early publish already did, and is not applied or published
 * this pass. The other connections go on.
 */
function failedBootstraps(
  deps: LocalSyncDeps,
  failures: ReadonlyMap<string, unknown>,
  early: ReadonlyMap<string, EarlyPublish>,
): CycleReport["connections"] {
  return [...failures].map(([connectionId, cause]) => {
    const error = errorMessage(cause);
    deps.logger.warn(
      { connectionId, error },
      "Stream sync cycle failed for a connection",
    );
    return {
      connectionId,
      published: early.get(connectionId)?.published ?? [],
      error,
    };
  });
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
   * The connections the caller awaits. Each one that settled in the early
   * publish is final for this call: the fallback pass that follows excludes it
   * (no bootstrap, apply or publish), so nothing it does, and nothing another
   * requested connection needs from it, changes that result. When every
   * requested connection is final, the pass's failures (discovery, listing,
   * a connection's own) are reported, never thrown. Without it every
   * connection is the caller's own.
   */
  awaited?: readonly string[],
): Promise<CycleReport> {
  const candidates = await earlyCandidates(deps);
  const early = await publishEarly(deps, candidates);
  const fresh = new Set(candidates.fresh.map((c) => c.connectionId));
  // Every connection the early publish takes must have a result: a registry
  // without the batch route throws `RegistryBatchRouteMissingError`, which is
  // kept as the connection's error and leaves no result: nothing is published
  // (the cycle reports it). A fresh connection has streams, so no published
  // result means its deferral was dropped (`publishEarly`), and one deferred
  // stream leaves the connection unsettled whatever else it published; a
  // known connection with no streams has none.
  const isSettled = (connectionId: string): boolean => {
    const e = early.get(connectionId);
    return (
      e !== undefined &&
      e.error === null &&
      e.deferred !== true &&
      (e.published.length > 0 || !fresh.has(connectionId)) &&
      e.published.every(
        (r) => r.outcome === "published" || r.outcome === "noop",
      )
    );
  };
  const earlyEntry = (
    connectionId: string,
    e: EarlyPublish,
    unfinished?: string,
  ): CycleReport["connections"][number] => ({
    connectionId,
    published: e.published,
    error:
      e.error !== null
        ? errorMessage(e.error)
        : unfinished !== undefined && !isSettled(connectionId)
          ? unfinished
          : null,
  });
  const settled = [...candidates.active, ...candidates.fresh].every(
    ({ connectionId }) => isSettled(connectionId),
  );
  // What the caller awaits, split by what the early publish did for each: the
  // settled ones are final. Nothing below touches them again, so nothing a
  // sibling does (or another requested connection needs) can change them.
  const final = new Set([...(awaited ?? [])].filter(isSettled));
  const finalEntries = [...early]
    .filter(([id]) => final.has(id))
    .map(([id, e]) => earlyEntry(id, e));
  // Every requested connection is final: the fallback is for siblings only,
  // and its failures are reported, never thrown at this caller.
  const isolated = final.size > 0 && final.size === new Set(awaited).size;

  let unplaced: readonly string[] = [];
  let discoveryError: { readonly cause: unknown } | undefined;
  try {
    unplaced = await unplacedConnections(deps, candidates);
  } catch (cause) {
    if (!isolated) throw cause;
    discoveryError = { cause };
  }
  if (settled && unplaced.length === 0 && discoveryError === undefined)
    return {
      connections: [...early].map(([id, e]) => earlyEntry(id, e)),
    };
  if (!isolated) {
    const cycle = await cycleOver(
      deps,
      await deps.registry.listOwnerRows(),
      early,
      undefined,
      final,
    );
    return { connections: [...finalEntries, ...cycle.connections] };
  }

  // The fallback runs for the rest and reports its failures, never throws.
  const siblings = [...early].filter(([id]) => !final.has(id));
  let cycle: CycleReport["connections"] = [];
  let cycleError: string | undefined;
  try {
    if (discoveryError) throw discoveryError.cause;
    cycle = (
      await cycleOver(
        deps,
        await deps.registry.listOwnerRows(),
        early,
        undefined,
        final,
      )
    ).connections;
  } catch (cause) {
    // Nothing of the pass ran for the siblings: each that did not settle
    // failed with this, and a connection only the pass could place with it.
    cycleError = errorMessage(cause);
    cycle = [
      ...siblings.map(([id, e]) => earlyEntry(id, e, cycleError)),
      ...unplaced
        .filter((id) => !final.has(id))
        .map((connectionId) => ({
          connectionId,
          published: [],
          error: cycleError!,
        })),
    ];
  }
  return {
    connections: [...finalEntries, ...cycle],
    ...(cycleError !== undefined ? { cycleError } : {}),
  };
}

function errorMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
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
 * The connections with streams that the early publish takes neither as active
 * nor as new: they wait for the cycle's listing.
 */
async function unplacedConnections(
  deps: LocalSyncDeps,
  { active, fresh }: EarlyCandidates,
): Promise<readonly string[]> {
  const placed = new Set(
    [...active, ...fresh].map(({ connectionId }) => connectionId),
  );
  return (await connectionsWithStreams(deps))
    .map(({ connectionId }) => connectionId)
    .filter((connectionId) => !placed.has(connectionId));
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
          deferred: published.some((r) => r.outcome === "deferred"),
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
    // The apply attempt's own record of the streams it marks failed.
    const marked: AttemptFailures = new Map();
    let outcome: ApplyOutcome;
    try {
      outcome = await deps.queue.run(connectionId, "publish", () =>
        applyConnection(
          insideQueue({ ...deps, attemptFailures: marked }, connectionId),
          connectionId,
          listed,
          listed?.find((row) => row.scope === connectionId)?.read,
        ),
      );
    } catch (cause) {
      // Only an apply that threw has a failed load to report; an update that
      // is required names no stream.
      if (!(cause instanceof UpdateRequiredError))
        failedStreams = [...marked]
          .map(([stream, reason]) => ({ stream, reason }))
          .sort((a, b) =>
            a.stream < b.stream ? -1 : a.stream > b.stream ? 1 : 0,
          );
      throw cause;
    }
    onApply?.(outcome);
    if (early && early.error !== null) throw early.error;
    // One segment and one commit per batch. A registry without the batch
    // route fails it (`RegistryBatchRouteMissingError`): nothing is published
    // until it has one. What apply left to publish goes after what the early
    // publish already sent.
    const through = await publishLog(deps, connectionId);
    published = [...published, ...through];
  } catch (cause) {
    error = errorMessage(cause);
    if (cause instanceof UpdateRequiredError) status = "update_required";
    // The timer and `/sync/trigger` drop the report. A connection whose
    // publish keeps failing would otherwise stay unpublished with no trace:
    // its run ended as accepted, but nothing it holds becomes readable.
    deps.logger.warn(
      { connectionId, error },
      "Stream sync cycle failed for a connection",
    );
    // Say which streams this attempt's apply stopped on, so one bad object
    // reads as that and not as a connection that failed whole. Rows of
    // earlier attempts do not count.
    if (status === undefined && failedStreams.length > 0) status = "degraded";
  }
  return {
    connectionId,
    published,
    error,
    ...(status ? { status } : {}),
    ...(failedStreams.length > 0 ? { failedStreams } : {}),
  };
}
