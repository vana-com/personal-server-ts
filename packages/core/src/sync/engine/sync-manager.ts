import type { OwnedAccountStorageMode } from "../../api/account-storage-mode.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { SyncStatus, SyncError, SyncBlockedReason } from "../types.js";
import { uploadAll } from "../workers/upload.js";
import { createUploadStateTracker } from "../upload-state.js";
import {
  createMemoryUploadAttemptStore,
  createUploadAttemptLedger,
  type UploadAttemptStore,
} from "../upload-attempts.js";
import { requeueLostDataPoints } from "../workers/lost-data-points.js";
import { downloadAll, downloadScopes } from "../workers/download.js";
import {
  deleteScope,
  retryPendingBlobDeletions,
  type DeleteScopeOptions,
  type DeleteScopeResult,
} from "../workers/delete.js";
import { createDownloadRetryMemory } from "../retry-memory.js";
import { createTombstoneResubmitTracker } from "../tombstone-resubmits.js";
import { changePushBackoffMs } from "./change-push.js";
import type {
  DeleteDataPort,
  PendingBlobDeletionStore,
  TombstoneFinalityPort,
} from "../../ports/index.js";
import type { LegacyWriteSeal } from "../../storage/legacy-write-seal.js";

/**
 * A cheap read of "did anything in the owner's registry change?": one request,
 * whatever the number of rows. The marker is opaque and only compared for
 * equality; `null` is an empty registry; `undefined` is "cannot tell" (the
 * gateway sent nothing to compare). A read that throws is a failed probe.
 *
 * The marker is a HINT, not a proof of "nothing changed". It fingerprints one
 * row, so a change that leaves that row alone (two rows stamped in the same
 * millisecond, a lower row changed under an unchanged top row) is invisible to
 * it. A manager therefore uses it only to start a cycle early. It never uses
 * it to skip a cycle. A failed or "cannot tell" probe never starts a cycle by
 * itself (see `requestPull`). What may skip the timer's cycle is the push's
 * position, which the gateway makes exact (see {@link ChangePush}).
 */
export interface ChangeProbe {
  /**
   * One read. `lifecycle` is the manager's: it aborts on a pause and on a stop,
   * and the read must then end at once (reject, abort its request, clear its
   * timers) whether or not the registry honours the signal.
   */
  read(lifecycle: AbortSignal): Promise<string | null | undefined>;
  /**
   * Period of the timed probe in milliseconds. Signals (`requestPull`) probe
   * at once and do not wait for it. See D4-SYNC-TRIGGERS for how the host
   * derives it from the cost of one idle cycle.
   */
  intervalMs: number;
  /**
   * A server push that tells the manager when to pull. While it is healthy and
   * its position is the one the last clean cycle started under, the timer's
   * cycle and the timed probe are skipped; otherwise nothing differs.
   */
  push?: ChangePush;
}

/**
 * A server push that says where the registry is. Its position is the gateway's
 * exact sequence for the owner: it changes whenever anything a client can see
 * changed. A poke can still be lost, doubled or late, and the marker the probe
 * compares fingerprints one row, so neither decides alone.
 *
 * A poke runs a cycle at once. It does not go through the marker comparison,
 * and it does not wait for the probe: a probe that never answers cannot hold
 * it up. A failed attempt is not a poke.
 *
 * The position lets the manager skip work. A cycle reads the registry after
 * the position it started under, so when the push is healthy and its position
 * is still the one the last clean cycle started under, that cycle already
 * holds everything the registry has, and the timer's cycle and the probe would
 * only repeat it. Both resume the moment the push is not healthy, the position
 * moved, or the last cycle was not clean. Every answer of the held request,
 * an empty one at the end of its wait included, carries the current position.
 * An answer whose position moved also says `changed`, so a wake that was lost
 * on the way is found by the next answer: `onChange` runs a cycle at once.
 * `onPosition` only records the position. A moved position that arrives
 * without `onChange` ends the skip, and the next timer tick or probe runs the
 * cycle.
 *
 * A clean cycle threw nothing, was not blocked and left no work behind (see
 * `reportLeavesWork`). A legacy (unswitched) cycle is never clean: its retries
 * run on the clock, and no position announces them. While the push is healthy
 * and the last cycle was clean, an idle device costs one held request per
 * period. That holds only for what the gateway's position covers: the data
 * rows and the server registration the cycle reads.
 */
export interface ChangePush {
  /**
   * Start a subscription; the returned function ends it. `onPosition(p)` is
   * the registry's position as of an answer; it comes before the `onChange` of
   * the same answer. `onChange` means the registry's sequence moved since the
   * last answer, or the first answer after a failure came back: run a cycle.
   * Both are called on a successful answer only; a failed attempt calls
   * nothing. `onHealth(true)`: the channel answered lately, so positions can be
   * trusted; `onHealth(false)`: it failed or went quiet, so do not rely on one.
   */
  subscribe(handlers: {
    onChange(): void;
    onHealth(healthy: boolean): void;
    onPosition(position: string): void;
  }): () => void;
}

export interface SyncManagerOptions {
  /** Personal Server hosts always supply their owner-bound Account mode. */
  accountStorageMode?: Pick<OwnedAccountStorageMode, "read">;
  localSync?: { cycle(): Promise<unknown> };

  /** Polling interval in milliseconds (default: 60_000 = 1 minute) */
  pollInterval?: number;
  /**
   * Starts a cycle when the registry changed, between the timer's cycles. The
   * timer's cycle is never gated on the marker: a probe that fails or misses a
   * change (see {@link ChangeProbe}) costs at most one poll interval. Only a
   * healthy push whose position has not moved lets the timer skip.
   */
  changeProbe?: ChangeProbe;
  /** Max upload batch size per cycle (default: 50) */
  uploadBatchSize?: number;
  /** Debounce for immediate sync after local ingest (default: 500ms) */
  notifyDebounceMs?: number;
  /** Optional runtime gate. Returning blocked skips upload/download without an error. */
  canSync?: () => Promise<SyncCanRunResult> | SyncCanRunResult;
  /**
   * Remote deletion (gateway tombstone + storage blobs). Without it
   * `deleteScope` is local-only and reports `durable: false`.
   */
  deleteData?: DeleteDataPort | null;
  /**
   * Durable host storage for upload-attempt markers. With it, an upload that
   * kills the process is counted across restarts and host rebuilds, and the
   * entry is quarantined after repeated crashes. Without it the markers live
   * in memory and protect nothing across a restart.
   */
  uploadAttemptStore?: UploadAttemptStore;
  /** Durable retry marker for blob deletions that failed after the tombstone. */
  pendingBlobDeletions?: PendingBlobDeletionStore;
  /**
   * Holds each storage blob delete until the tombstone that covers the key is
   * finalized at the gateway (see `DeleteScopeDeps.tombstoneFinality`).
   */
  tombstoneFinality?: TombstoneFinalityPort;
  /** Select download-only operation for runtimes that cannot sign uploads. */
  transferMode?: "upload-download" | "download-only";
  /** Exact owner scopes to hydrate before the first full download cycle. */
  hydrateScopes?: string[];
  /**
   * Whole-file stream sync (`streamSync.write`, default off). When `write`
   * is true, each upload cycle runs the stream-sync publisher after the
   * legacy upload. When it is false or absent, nothing changes.
   */
  streamSync?: {
    readonly write: boolean;
    readonly publisher: { cycle(): Promise<unknown> };
  } | null;
}

export type SyncCanRunResult =
  { ok: true } | { ok: false; reason: string; message: string };

export interface SyncManager {
  /** Start the background sync loop */
  start(): void;

  /** Stop the background sync loop gracefully */
  stop(): Promise<void>;

  /** Trigger an immediate sync cycle (skips wait) */
  trigger(): Promise<void>;

  /**
   * A signal that remote state may have changed: a tab or window came back, the
   * network returned, a probe period passed. With a `changeProbe`, one cheap
   * registry read decides: a cycle runs only when the registry moved since the
   * last cycle this method ran. Without one, it requests a cycle. Requests
   * coalesce (one probe in flight, one cycle running, one follow-up for any
   * number of requests during it) and never reset the timer. Does nothing
   * while stopped. Rejects when the cycle it ran rejects.
   */
  requestPull(): Promise<void>;

  /** Get current sync status */
  getStatus(): SyncStatus;

  /**
   * Calls `listener` with the new `getStatus()` value after each change of it:
   * a cycle starting or ending, a pass finishing, an error, a blocked or
   * unblocked state, scopes hydrated, the pending count moving, the manager
   * starting or stopping. A change is found by comparing the whole status with
   * the last one delivered at each of those points, so a point that changed
   * nothing is silent, and a subscriber is never told twice for one value.
   *
   * Listeners run after the state change, one at a time and never nested: a
   * change made while they run (for instance by a `trigger` they call) is
   * delivered after they return, once, and only if the value still differs. A
   * listener that throws is logged and skipped. `getStatus` only reads, so a
   * listener that calls it cannot cause an event. No timer is involved.
   *
   * A subscription belongs to the subscriber, not to a run: it works before
   * `start`, and `stop` leaves it registered (the stop itself is delivered as
   * `running: false`), so a manager that starts again is heard again. With no
   * subscriber the manager reads nothing extra; the first subscriber's value is
   * the baseline and is not delivered. Returns the unsubscribe.
   *
   * Do not call `trigger` on every event. Each cycle changes `lastSync`, so
   * each cycle ends with an event that would start the next one, and nothing
   * here bounds that loop: delivery is never nested and coalesces events, but
   * it does not stop a listener that always triggers. Trigger only on a change
   * the listener acts on, such as the first `lastSync`.
   *
   * Disposal: the manager does not close with its host. Unsubscribe before the
   * storage or the stream database the status reads is closed (in Lite,
   * before `closeStreamSync`), because a stop, or a cycle that is still ending,
   * can deliver one more event after the host has begun to close.
   */
  subscribeStatus(listener: (status: SyncStatus) => void): () => void;

  /** Download exact owner scopes without advancing the registry cursor. */
  hydrateScopes(scopes: string[]): Promise<void>;

  /**
   * Owner retry: lift the quarantine of uploads that crashed the process, for
   * one scope or all. The next cycle attempts them again.
   */
  retryQuarantinedUploads(scope?: string): Promise<void>;

  /** Signal that new data has been ingested (next cycle picks it up) */
  notifyNewData(): void;

  /**
   * A run or an import committed its rows: the data is complete, and nothing
   * more is coming that a wait could gather. Starts the cycle now; a cycle in
   * flight runs once more after it. `notifyNewData` instead waits out the
   * debounce, for callers that signal one record at a time.
   */
  notifyRecordsCommitted(): void;

  /**
   * The host says no one is looking (a hidden Web tab). The manager holds no
   * request and no timer until `resume`: it aborts the held push request and
   * clears the push's cooldown, the failure retry, the poll, the probe and the
   * ingest-debounce timers, and forgets the push's health and the failure
   * streak. A cycle already running finishes. Work that came in meanwhile (a
   * follow-up it owes, a local ingest) is remembered, not run. Pulls and
   * signals do nothing while paused; `trigger` still runs. Does nothing when
   * stopped or already paused.
   */
  pause(): void;

  /**
   * The host says someone is looking again. Restarts the timers and starts
   * exactly one push subscription, and runs one cycle if work was owed while
   * paused. A signal that follows (`requestPull`) still does its own probe.
   * Does nothing when stopped or not paused.
   */
  resume(): void;

  /**
   * Durable scope deletion: gateway tombstone, then storage blobs, then the
   * local copy (see workers/delete.ts for why that order is the only safe
   * one). Resolves with a per-step result; a gateway failure leaves the
   * local copy in place and is reported as `steps.gateway.status = "failed"`.
   *
   * `within` is the legacy-write seal's `commit`. When given, the delete runs
   * inside it (and a refusal rejects with `LegacyWriteRefusedError` before
   * anything is sent or removed). It is entered AFTER this manager's mutation
   * queue: a sync cycle holds the queue and asks the seal, so the seal must be
   * the innermost lock or a waiting On deadlocks the two.
   */
  deleteScope(
    scope: string,
    within?: LegacyWriteSeal["commit"],
  ): Promise<DeleteScopeResult>;

  /** Whether the sync manager is currently running */
  readonly running: boolean;
}

const MAX_ERRORS = 10;
const DEFAULT_POLL_INTERVAL_MS = 60_000;

/**
 * The longest delay a host timer holds: it keeps the delay in a signed 32-bit
 * integer of milliseconds, and runs a longer one after 1 ms.
 */
const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

/**
 * A repeating period the host timer runs as written. The timer counts whole
 * milliseconds and runs a delay below 1 after 1 ms, so a period that is not
 * finite or is below 1 would turn the fallback into a busy loop or never run;
 * it takes the default. A period beyond the timer's limit is the longest
 * period the timer holds: the caller asked for a long wait, not a short one.
 */
function timerPeriod(requested: number | undefined): number {
  if (
    typeof requested !== "number" ||
    Number.isNaN(requested) ||
    requested < 1 ||
    requested === Number.POSITIVE_INFINITY
  ) {
    return DEFAULT_POLL_INTERVAL_MS;
  }
  return Math.min(Math.floor(requested), MAX_TIMER_DELAY_MS);
}

/**
 * True when a stream-sync cycle's report says it left work that nothing in the
 * registry announces. The cycle reports per connection and does not throw: a
 * connection that failed, or a stream whose publish backs off or waits on a
 * condition, is tried again only by a later cycle. A position cannot stand in
 * for that cycle, so the pass is not settled and the timer keeps running. A
 * report of another shape says nothing and leaves nothing owed.
 */
function reportLeavesWork(report: unknown): boolean {
  const connections = (report as { connections?: unknown } | null | undefined)
    ?.connections;
  if (!Array.isArray(connections)) return false;
  return connections.some((connection: unknown) => {
    const { error, published } = (connection ?? {}) as {
      error?: unknown;
      published?: unknown;
    };
    if (error !== null && error !== undefined) return true;
    return (
      Array.isArray(published) &&
      published.some((result: { outcome?: unknown } | null) => {
        const outcome = result?.outcome;
        return outcome === "backoff" || outcome === "deferred";
      })
    );
  });
}

export function createSyncManager(
  uploadDeps: UploadWorkerDeps,
  downloadDeps: DownloadWorkerDeps,
  options?: SyncManagerOptions,
): SyncManager {
  const pollInterval = timerPeriod(options?.pollInterval);
  const uploadBatchSize = options?.uploadBatchSize ?? 50;
  const notifyDebounceMs = options?.notifyDebounceMs ?? 500;
  const transferMode = options?.transferMode ?? "upload-download";
  const startupHydrateScopes = [...new Set(options?.hydrateScopes ?? [])];

  let intervalId: ReturnType<typeof setInterval> | null = null;
  let notifyTimerId: ReturnType<typeof setTimeout> | null = null;
  let isRunning = false;
  let lastSync: string | null = null;
  let lastProcessedTimestamp: string | null = null;
  let blocked: SyncBlockedReason | null = null;
  let errors: SyncError[] = [];
  let cycleInFlight: Promise<void> | null = null;
  // The dirty follow-up flag: a request arrived that the running cycle may not
  // have seen. It is owed one more cycle and is dropped only by running one (or
  // by a stop). A pass clears it on entry, so it never re-arms itself.
  let rerunRequested = false;
  // Failed cycles in a row, and the pending retry of the follow-up they owe.
  // `retryTimer` set means cooling down: a pushed change only marks the flag.
  let cycleFailures = 0;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;
  // Pulls: one probe-and-cycle in flight; `pullRequested` is its dirty flag.
  let pullInFlight: Promise<void> | null = null;
  let pullInFlightRun = 0;
  let pullSeq = 0;
  let pullRequested = false;
  // True when a person-driven signal (focus, online) joined the pull in flight.
  let pullSignalled = false;
  // One value per start() and per stop(). A pull remembers the value it began
  // under and does nothing once it differs: a probe answering after stop(), or
  // from before a stop and start, can start no cycle and set no baseline.
  let lifecycle = 0;
  // Ends with the lifecycle value it belongs to: a pause or a stop aborts every
  // request and timer the run before it still holds (the probe's read).
  let lifecycleEnd = new AbortController();
  const nextLifecycle = (why: string): void => {
    lifecycle += 1;
    lifecycleEnd.abort(new Error(`sync manager ${why}`));
    lifecycleEnd = new AbortController();
  };
  // Failed probes in a row, and the earliest time the timed probe tries again.
  let probeFailures = 0;
  let nextTimedProbeAt = 0;
  // The change push (`ChangeProbe.push`): whether it can be trusted now, and
  // how to end the subscription of this run.
  let pushHealthy = false;
  let stopPush: (() => void) | null = null;
  // Positions (see `ChangePush`). `knownPosition` is the push's latest answer.
  // `syncedPosition` is the position the last cleanly finished pass started
  // under; it is undefined while a pass runs or when the last one did not
  // finish clean.
  let knownPosition: string | undefined;
  let syncedPosition: string | undefined;
  // The host paused the manager (no one is looking): no request, no timer.
  // `owedWhilePaused` remembers a local ingest that arrived meanwhile.
  let paused = false;
  let owedWhilePaused = false;
  // The registry marker as of the last cycle a pull ran and finished cleanly.
  // Only `pullIfChanged` moves it, and only to a marker read BEFORE its cycle
  // started, so every change up to it was in the registry when that cycle read.
  // A cycle that does not read its own marker first (a pushed change) leaves it
  // alone: the next probe then runs one conservative follow-up.
  let pulledMarker: string | null | undefined;
  let errorSeq = 0;
  // Status subscribers (`subscribeStatus`). `statusSeen` is the serialized
  // value last delivered or taken as the baseline; null while no one listens.
  const statusListeners = new Set<(status: SyncStatus) => void>();
  let statusSeen: string | null = null;
  let statusDelivering = false;
  let probeIntervalId: ReturnType<typeof setInterval> | null = null;
  let needsFullReconcile = true;
  // Once per boot, then only the scopes whose lookup failed, a few times.
  let lostDataPointRetryScopes: string[] | null = null;
  let lostDataPointAttempts = 0;
  const MAX_LOST_DATA_POINT_ATTEMPTS = 5;
  let needsStartupHydration = startupHydrateScopes.length > 0;
  const hydratedScopes = new Set<string>();
  // One retry memory per manager (= per boot session): a blob that 404s is
  // attempted once per session, not once per cycle; transient storage errors
  // back off exponentially instead of re-firing on every cycle.
  const downloadRetryMemory = createDownloadRetryMemory();
  // Re-submissions of deletes whose tombstone failed (bounded per boot).
  const tombstoneResubmits = createTombstoneResubmitTracker();
  // The pending blob deletions as the last drain left them (see SyncStatus).
  let blobDeletions: SyncStatus["blobDeletions"];
  // Entries too large to upload and failing uploads that back off (per boot).
  const uploadState = uploadDeps.uploadState ?? createUploadStateTracker();
  const dataPointFeed = downloadDeps.dataPointFeed ?? uploadDeps.dataPointFeed;
  const scopeDeletions =
    uploadDeps.scopeDeletions ?? downloadDeps.scopeDeletions;
  const namelessAttempts =
    !uploadDeps.uploadAttempts && !options?.uploadAttemptStore;
  // The upload worker queues guarded cleanup for ciphertext it had to
  // abandon mid-race; it shares the manager's marker store.
  const uploadAttempts =
    uploadDeps.uploadAttempts ??
    createUploadAttemptLedger(
      options?.uploadAttemptStore ?? createMemoryUploadAttemptStore(),
      uploadDeps.serverOwner,
      {
        onDegraded: (message) =>
          pushError({
            fileId: null,
            scope: null,
            message,
            timestamp: new Date().toISOString(),
          }),
      },
    );
  const workerUploadDeps: UploadWorkerDeps = {
    ...uploadDeps,
    uploadState,
    uploadAttempts,
    pendingBlobDeletions:
      uploadDeps.pendingBlobDeletions ?? options?.pendingBlobDeletions,
  };
  const workerDownloadDeps: DownloadWorkerDeps = {
    ...downloadDeps,
    // A mode-aware manager handles On through its cycle above. Its legacy
    // worker is reached only for Off and must not invoke the database hook.
    localSync: options?.accountStorageMode ? undefined : downloadDeps.localSync,
    pendingBlobDeletions:
      downloadDeps.pendingBlobDeletions ?? options?.pendingBlobDeletions,
  };

  // Sync cycles and durable deletes mutate the same local index and the same
  // registry rows. Run them one at a time (FIFO): a delete cannot start while
  // an upload of the same scope is between "blob uploaded" and "row marked
  // synced", and a cycle cannot start until a delete has finished all three
  // steps. A rejected operation never blocks the ones queued behind it.
  let mutationQueue: Promise<unknown> = Promise.resolve();
  function exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const run = mutationQueue.then(operation, operation);
    mutationQueue = run.catch(() => undefined);
    return run;
  }

  async function hydrateScopesExclusive(scopes: string[]): Promise<void> {
    // Resolve scopes individually so an earlier success remains observable if
    // a later scope fails.
    for (const scope of new Set(scopes)) {
      await downloadScopes(workerDownloadDeps, [scope], {
        retryMemory: downloadRetryMemory,
      });
      // "Hydrated" means the remote scope was resolved, including an absent
      // data point or tombstone; it does not guarantee local bytes exist.
      hydratedScopes.add(scope);
      downloadDeps.logger.info({ scope }, "Hydrated requested scope");
      statusMayHaveChanged();
    }
  }

  async function runCycle(): Promise<void> {
    // Prevent concurrent cycles
    if (cycleInFlight) {
      rerunRequested = true;
      return cycleInFlight;
    }

    // One cycle's passes: repeats while a request arrived during a pass.
    const passes = async () => {
      let first = true;
      do {
        // Reaching another pass means the previous one succeeded: the failure
        // streak ends at that boundary, not when the whole cycle returns, or a
        // failure in a pass that follows a success would back off as a repeat.
        if (!first) cycleFailures = 0;
        first = false;
        rerunRequested = false;
        // Sample before anything is read: every change up to this position is
        // in the registry when the pass reads. Nothing is settled until it
        // ends clean.
        const startedUnder = knownPosition;
        const errorsBefore = errorSeq;
        syncedPosition = undefined;
        const settle = () => {
          if (blocked !== null || errorSeq !== errorsBefore) return;
          syncedPosition = startedUnder;
        };
        const canRun = await (options?.canSync?.() ?? { ok: true });
        if (!canRun.ok) {
          blocked = { reason: canRun.reason, message: canRun.message };
          uploadDeps.logger.warn(blocked, "Sync cycle blocked");
          continue;
        }
        blocked = null;
        statusMayHaveChanged();
        // canSync can yield while Account changes. Sample only after it returns.
        if (options?.accountStorageMode) {
          const mode = options.accountStorageMode.read();
          if (mode !== "unswitched") {
            if (mode === "switched" && options.localSync) {
              const report = await options.localSync.cycle();
              lastSync = new Date().toISOString();
              statusMayHaveChanged();
              // Deletion debt is owed work like a backed-off publish: a blob
              // waits on a tombstone's finality, a version-row change no
              // position announces. Nothing is settled while any is left.
              const debt = await drainPendingBlobDeletions("switched");
              if (!reportLeavesWork(report) && !debt.owed) settle();
            } else {
              blocked = {
                reason:
                  mode === "unknown"
                    ? "account_mode_unknown"
                    : "stream_sync_unavailable",
                message: "Waiting for the account or its stream database",
              };
            }
            continue;
          }
        }

        if (needsStartupHydration) {
          try {
            await hydrateScopesExclusive(startupHydrateScopes);
            needsStartupHydration = false;
          } catch (err) {
            downloadDeps.logger.warn(
              { error: (err as Error).message },
              "Scope hydration failed; continuing with full sync",
            );
          }
        }

        // Finish blob deletions whose tombstone landed but whose storage
        // DELETE did not. Cheap when nothing is pending; never blocks sync.
        if (transferMode === "upload-download") {
          if (
            lostDataPointAttempts < MAX_LOST_DATA_POINT_ATTEMPTS &&
            // null: no full pass has completed yet (first cycle, or it threw).
            (lostDataPointRetryScopes === null ||
              lostDataPointRetryScopes.length > 0)
          ) {
            // A registration the gateway accepted and later dropped (failed
            // settle) still reads as synced locally. Full pass once per boot;
            // later cycles retry only scopes whose lookup failed.
            lostDataPointAttempts += 1;
            try {
              const { failed } = await requeueLostDataPoints(
                uploadDeps,
                lostDataPointRetryScopes ?? undefined,
              );
              lostDataPointRetryScopes = failed;
            } catch (err) {
              uploadDeps.logger.warn(
                { error: (err as Error).message },
                "Lost data point check failed; continuing with sync",
              );
            }
          }
          await runUploadCycle();
          statusMayHaveChanged(); // uploads moved, the pending count with them
        }

        try {
          // Download new remote files
          const fullReconcile = needsFullReconcile;
          const downloadResults = await downloadAll(workerDownloadDeps, {
            fullReconcile,
            retryMemory: downloadRetryMemory,
          });
          needsFullReconcile = false;
          downloadDeps.logger.debug(
            { downloaded: downloadResults.length, fullReconcile },
            "Download cycle complete",
          );
        } catch (err) {
          const syncError: SyncError = {
            fileId: null,
            scope: null,
            message: `Download cycle failed: ${(err as Error).message}`,
            timestamp: new Date().toISOString(),
          };
          pushError(syncError);
          downloadDeps.logger.error(
            { error: (err as Error).message },
            "Download cycle failed",
          );
        }

        // Update cached cursor value
        try {
          lastProcessedTimestamp = await downloadDeps.cursor.read();
        } catch {
          // Non-critical: status will show stale value
        }

        lastSync = new Date().toISOString();
        statusMayHaveChanged(); // the cursor and lastSync, at the pass boundary
        // No `settle()`: this pass retries on the clock (a deletion waiting on
        // chain finality, a download in backoff, an upload cap) and no
        // registry position announces that, so the timer keeps running.
      } while (rerunRequested && isRunning && !paused);
    };

    // A failed cycle ends its exclusive operation at once: callers get its
    // error and queued mutations run. A follow-up it still owes (the dirty
    // flag) waits out a cooldown first: see `scheduleRetry`.
    cycleInFlight = exclusive(passes);
    statusMayHaveChanged(); // syncing: true

    try {
      await cycleInFlight;
      cycleFailures = 0;
    } catch (error) {
      cycleFailed();
      throw error;
    } finally {
      cycleInFlight = null;
      statusMayHaveChanged(); // syncing: false, and whatever the cycle moved
    }
  }

  /**
   * A cycle failed. If a request arrived while it ran, one follow-up is owed:
   * run it after a cooldown from the push's back-off schedule (1 s doubling to
   * 30 s over consecutive failures), never at once. Pushes cannot shorten or
   * restart the cooldown: while it runs they only mark the dirty flag, and the
   * one timer runs the follow-up. Without a request nothing retries; the timed
   * cycle is the fallback.
   */
  function cycleFailed(): void {
    const failures = cycleFailures;
    cycleFailures += 1;
    if (!rerunRequested || !isRunning || paused || retryTimer !== null) return;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (!isRunning || paused || !rerunRequested) return;
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });
    }, changePushBackoffMs(failures));
  }

  function clearRetryTimer(): void {
    if (retryTimer !== null) clearTimeout(retryTimer);
    retryTimer = null;
  }

  function deleteScopeDeps() {
    return {
      storage: uploadDeps.storage,
      serverOwner: uploadDeps.serverOwner,
      deleteData: options?.deleteData,
      pendingBlobDeletions: options?.pendingBlobDeletions,
      tombstoneFinality: options?.tombstoneFinality,
      scopeDeletions,
      dataPointFeed,
      logger: uploadDeps.logger,
    };
  }

  /**
   * Durable additions delete their ledger scope through `manager.deleteScope`,
   * which queues behind the running mutation. Inside a cycle that must not be
   * awaited, so it is started and left to run after the cycle.
   */
  function deleteAdditionsAfter(scope: string): void {
    const additions = uploadDeps.additions;
    if (!additions) return;
    // Start only once the running cycle has left the mutation queue: the
    // PS-Lite additions session holds its Web Lock across the ledger delete,
    // and this cycle's uploads need that lock too.
    void mutationQueue
      .then(() => additions.deleteScope(scope))
      .catch((err: unknown) => {
        uploadDeps.logger.warn(
          { scope, error: (err as Error).message },
          "Could not delete the additions ledger of a re-deleted scope",
        );
      });
  }

  /**
   * Finish the storage deletes whose covering tombstone has become final.
   * Both modes call it inside the exclusive pass.
   *
   * `legacy` may re-send a rolled-back tombstone through `deleteScope`, which
   * writes to legacy storage and is sealed once the account has switched.
   * `switched` never does: it only waits for finality and then deletes the
   * blob, and parks a rolled-back scope as a visible failure until the user
   * deletes it again. Either way, a manager that knows the account mode fails
   * closed without a finality port: the worker's permissive no-port release
   * would free a slot a rolled-back tombstone can still hand to another
   * writer, and the mode can change while the drain awaits.
   *
   * Returns whether work is owed that a later pass can do: markers waiting on
   * finality, a failed key, or a retry that threw. Parked and unavailable
   * markers stay queued and show in the status, but are not runnable work.
   */
  async function drainPendingBlobDeletions(
    mode: "legacy" | "switched",
  ): Promise<{ owed: boolean }> {
    try {
      const result = await retryPendingBlobDeletions({
        deleteData: options?.deleteData,
        pendingBlobDeletions: options?.pendingBlobDeletions,
        tombstoneFinality: options?.tombstoneFinality,
        dataPointFeed,
        serverOwner: uploadDeps.serverOwner,
        storage: uploadDeps.storage,
        logger: uploadDeps.logger,
        // The account can switch at any await below, and the legacy write seal
        // does not guard a blob delete. Only a manager that has no account
        // mode at all is fixed to legacy, so only it may release without
        // finality.
        requireFinality: options?.accountStorageMode !== undefined,
        ...(options?.tombstoneFinality && options.deleteData
          ? {
              tombstoneResubmits,
              ...(mode === "legacy"
                ? {
                    // Already inside the mutation queue: call the worker directly.
                    async resubmitDeletion(
                      scope: string,
                      deleteOptions: DeleteScopeOptions,
                    ) {
                      const result = await deleteScope(
                        deleteScopeDeps(),
                        scope,
                        deleteOptions,
                      );
                      if (result.durable) deleteAdditionsAfter(scope);
                      return result;
                    },
                  }
                : {}),
              onDeletionAbandoned(state) {
                pushError({
                  fileId: null,
                  scope: state.scope,
                  message:
                    state.reason === "attempts-exhausted"
                      ? `Deletion of ${state.scope} did not complete: the gateway tombstone failed ${state.attempts + 1} times and the data is live again. Delete it again to retry.`
                      : `Deletion of ${state.scope} did not complete: the gateway tombstone failed and the data is live again. Delete it again to retry.`,
                  timestamp: new Date().toISOString(),
                });
              },
            }
          : {}),
      });
      blobDeletions =
        result.remaining > 0
          ? {
              remaining: result.remaining,
              waiting: result.waiting,
              unavailable: result.unavailable,
            }
          : undefined;
      statusMayHaveChanged();
      return { owed: result.waiting > 0 || result.failed.length > 0 };
    } catch (err) {
      uploadDeps.logger.warn(
        { error: (err as Error).message },
        "Pending blob deletion retry failed",
      );
      return { owed: true };
    }
  }

  async function runUploadCycle(): Promise<void> {
    await drainPendingBlobDeletions("legacy");

    try {
      const uploadResults = await uploadAll(workerUploadDeps, {
        batchSize: uploadBatchSize,
        onError(entry, error) {
          // One notification for the whole upload cycle, from the caller.
          pushError(
            {
              fileId: entry.fileId,
              scope: entry.scope,
              message: `Upload failed for ${entry.path}: ${error.message}`,
              timestamp: new Date().toISOString(),
            },
            false,
          );
        },
      });
      uploadDeps.logger.debug(
        { uploaded: uploadResults.length },
        "Upload cycle complete",
      );
    } catch (err) {
      const syncError: SyncError = {
        fileId: null,
        scope: null,
        message: `Upload cycle failed: ${(err as Error).message}`,
        timestamp: new Date().toISOString(),
      };
      pushError(syncError);
      uploadDeps.logger.error(
        { error: (err as Error).message },
        "Upload cycle failed",
      );
    }

    if (options?.streamSync?.write) {
      try {
        await options.streamSync.publisher.cycle();
      } catch (err) {
        pushError({
          fileId: null,
          scope: null,
          message: `Stream sync publish failed: ${(err as Error).message}`,
          timestamp: new Date().toISOString(),
        });
        uploadDeps.logger.warn(
          { error: (err as Error).message },
          "Stream sync publish failed",
        );
      }
    }
  }

  /**
   * After a failed probe the timed probe waits probe period x 2^failures, capped
   * at the poll interval, so an offline device probes about once a minute and
   * the timer's own cycle stays the fallback. Both numbers are the host's.
   */
  function noteProbeFailure(probe: ChangeProbe): void {
    probeFailures += 1;
    const wait = Math.min(
      probe.intervalMs * 2 ** probeFailures,
      Math.max(pollInterval, probe.intervalMs),
    );
    nextTimedProbeAt = Date.now() + wait;
  }

  async function pullIfChanged(
    probe: ChangeProbe,
    run: number,
    fromSignal: boolean,
    ended: AbortSignal,
  ): Promise<void> {
    let marker: string | null | undefined;
    try {
      marker = await probe.read(ended);
    } catch (err) {
      if (run === lifecycle) noteProbeFailure(probe);
      uploadDeps.logger.debug(
        { error: (err as Error).message },
        "Registry change probe failed; the timer cycle is the fallback",
      );
      return;
    }
    // stop() does not wait for a probe; an answer from an earlier run is void.
    if (run !== lifecycle || !isRunning) return;
    probeFailures = 0;
    nextTimedProbeAt = 0;
    if (marker === undefined && !fromSignal) return; // cannot tell: the timer decides
    if (marker !== undefined && marker === pulledMarker) return;
    const errorsBefore = errorSeq;
    // A cycle already running may have read the registry before the change:
    // `runCycle` makes a joiner wait for a follow-up that starts after this call.
    await runCycle();
    if (
      run === lifecycle &&
      marker !== undefined &&
      blocked === null &&
      errorSeq === errorsBefore
    ) {
      pulledMarker = marker;
    }
  }

  function pull(fromSignal: boolean): Promise<void> {
    if (!isRunning || paused) return Promise.resolve();
    // No probe: a pull is a cycle request, and `runCycle` coalesces those.
    const probe = options?.changeProbe;
    if (!probe) return runCycle();
    const run = lifecycle;
    const ended = lifecycleEnd.signal;
    if (pullInFlight && pullInFlightRun === run) {
      pullRequested = true;
      pullSignalled ||= fromSignal;
      return pullInFlight;
    }
    pullSignalled = fromSignal;
    const seq = ++pullSeq;
    const current = (async () => {
      try {
        do {
          pullRequested = false;
          const signalled = pullSignalled;
          pullSignalled = false;
          await pullIfChanged(probe, run, signalled, ended);
          // A tick that joined a read that then failed waits out the back-off;
          // only a signal (focus, online) is read again at once.
        } while (
          pullRequested &&
          isRunning &&
          run === lifecycle &&
          (pullSignalled || Date.now() >= nextTimedProbeAt)
        );
      } finally {
        // Only the newest pull clears the slot; an older run's may end later.
        if (pullSeq === seq) pullInFlight = null;
      }
    })();
    pullInFlight = current;
    pullInFlightRun = run;
    return current;
  }

  function requestPull(): Promise<void> {
    return pull(true);
  }

  function scheduleNotifiedCycle(delayMs: number = notifyDebounceMs): void {
    if (!isRunning) return;
    if (paused) {
      owedWhilePaused = true;
      return;
    }
    const start = () => {
      notifyTimerId = null;
      if (!isRunning) return;
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });
    };
    if (delayMs === 0) {
      // The cycle starts now and takes whatever a pending timer was waiting for.
      if (notifyTimerId !== null) clearTimeout(notifyTimerId);
      start();
      return;
    }
    if (notifyTimerId !== null) return;
    notifyTimerId = setTimeout(start, delayMs);
  }

  /**
   * Record an error for the status. `notify: false` leaves the notification to
   * the caller, which owes one at the end of its batch: the upload worker
   * reports one error per failed file, and a status read per file would cost
   * a count each.
   */
  function pushError(error: SyncError, notify = true): void {
    errorSeq += 1;
    errors.push(error);
    if (errors.length > MAX_ERRORS) {
      errors = errors.slice(-MAX_ERRORS);
    }
    if (notify) statusMayHaveChanged();
  }

  /**
   * Log a failure of delivery. Anything can be thrown (`null`, a string), and
   * the logger can throw too; neither may leave delivery, or a caller such as
   * `start` would stop before its first cycle.
   */
  function reportQuietly(message: string, thrown: unknown): void {
    try {
      uploadDeps.logger.warn(
        { error: thrown instanceof Error ? thrown.message : String(thrown) },
        message,
      );
    } catch {
      // A failing logger has no one left to tell.
    }
  }

  /**
   * Called at every point where a field of `getStatus()` can change. Reads the
   * status only when someone listens, and tells them only if it differs from
   * what they last had. Not reentrant: a change a listener causes is picked up
   * by the loop below after the listeners return.
   */
  function statusMayHaveChanged(): void {
    if (statusListeners.size === 0) {
      statusSeen = null; // unknown from here: the next subscriber re-baselines
      return;
    }
    if (statusDelivering) return;
    statusDelivering = true;
    try {
      for (;;) {
        let status: SyncStatus;
        let seen: string;
        try {
          status = manager.getStatus();
          seen = JSON.stringify(status);
        } catch (error) {
          reportQuietly("sync status could not be read for subscribers", error);
          return;
        }
        if (seen === statusSeen) return;
        const first = statusSeen === null;
        statusSeen = seen;
        if (first) return; // the baseline, not a change
        for (const listener of [...statusListeners]) {
          try {
            listener(status);
          } catch (error) {
            reportQuietly("a sync status listener threw", error);
          }
        }
      }
    } finally {
      statusDelivering = false;
    }
  }

  /**
   * True when a full cycle or a marker probe would only repeat what the last
   * clean cycle read: the push answers (healthy), nothing runs now, and its
   * position is the one that cycle started under. Each answer of the held
   * request carries the current position, so a change whose wake was lost
   * shows as a position that differs, at the next answer.
   */
  function pushCovers(): boolean {
    return (
      options?.changeProbe?.push !== undefined &&
      pushHealthy &&
      cycleInFlight === null &&
      knownPosition !== undefined &&
      knownPosition === syncedPosition
    );
  }

  function startInterval(): void {
    if (intervalId !== null) return;
    intervalId = setInterval(() => {
      if (pushCovers()) return;
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });
    }, pollInterval);
  }

  function clearIntervalTimer(): void {
    if (intervalId !== null) {
      clearInterval(intervalId);
      intervalId = null;
    }
  }

  function startProbeInterval(): void {
    const probe = options?.changeProbe;
    if (!probe || probeIntervalId !== null) return;
    probeIntervalId = setInterval(() => {
      if (Date.now() < nextTimedProbeAt) return; // backing off after failures
      // The position says nothing moved since the last clean cycle: a marker
      // read would repeat the answer.
      if (pushCovers()) return;
      pull(false).catch(() => {
        // Errors already captured in ring buffer
      });
    }, probe.intervalMs);
  }

  function startChangePush(): void {
    const push = options?.changeProbe?.push;
    if (!push || stopPush !== null) return;
    const run = lifecycle;
    // A cycle the push asks for. It does not wait for the optional probe or
    // join a timed probe read in flight, so a probe that never answers cannot
    // hold it up; `runCycle` still runs one cycle at a time. It reads no marker
    // and publishes none: see `pulledMarker`.
    const cycleNow = () => {
      if (retryTimer !== null) {
        // Cooling down after a failed cycle: the request is owed, and the
        // retry timer runs it. A push neither skips nor restarts the wait.
        rerunRequested = true;
        return;
      }
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });
    };
    stopPush = push.subscribe({
      onChange() {
        if (run !== lifecycle || !isRunning) return;
        cycleNow();
      },
      onHealth(healthy) {
        if (run !== lifecycle) return;
        const wasHealthy = pushHealthy;
        pushHealthy = healthy;
        // While the push was silent its position could not vouch for the
        // registry, and a change committed in that time is not in any
        // position. Read once now rather than wait for the timer, which may
        // have skipped its last tick on the strength of that position.
        if (wasHealthy && !healthy && isRunning) cycleNow();
      },
      onPosition(position) {
        if (run !== lifecycle || !isRunning) return;
        knownPosition = position;
      },
    });
  }

  function stopChangePush(): void {
    stopPush?.();
    stopPush = null;
    pushHealthy = false;
    knownPosition = undefined;
  }

  function clearProbeInterval(): void {
    if (probeIntervalId !== null) {
      clearInterval(probeIntervalId);
      probeIntervalId = null;
    }
  }

  function clearNotifyTimer(): void {
    if (notifyTimerId !== null) {
      clearTimeout(notifyTimerId);
      notifyTimerId = null;
    }
  }

  const manager: SyncManager = {
    get running() {
      return isRunning;
    },

    start() {
      if (isRunning) return; // Idempotent
      isRunning = true;
      paused = false;
      owedWhilePaused = false;
      nextLifecycle("started");
      pulledMarker = undefined;
      cycleFailures = 0;
      probeFailures = 0;
      nextTimedProbeAt = 0;
      knownPosition = undefined;
      syncedPosition = undefined;
      statusMayHaveChanged(); // running: true

      // Crash recovery: run one cycle immediately on start
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });

      startInterval();
      startProbeInterval();
      startChangePush();
    },

    async stop() {
      // Opens the stop's repair window before anything awaits, so a stop that
      // nothing awaits still holds its repair duty.
      const closing = uploadAttempts
        .close(namelessAttempts ? Infinity : undefined)
        .catch((err: unknown) => err);
      clearIntervalTimer();
      clearProbeInterval();
      stopChangePush();
      clearNotifyTimer();
      clearRetryTimer();
      rerunRequested = false;
      isRunning = false;
      paused = false;
      owedWhilePaused = false;
      // Cancel pulls: a probe that answers later finds a new lifecycle value.
      nextLifecycle("stopped");
      statusMayHaveChanged(); // running: false

      // Wait for any in-flight cycle to complete
      if (cycleInFlight) {
        await cycleInFlight;
      }
      // Hand the upload markers to the next manager over this store, once no
      // attempt is still running (a running one keeps its entry excluded).
      // Without a stable store namespace a rebuilt manager gets a fresh,
      // unrelated lock, so only a fully drained stop keeps two managers over
      // the same persistence from overlapping.
      const err = await closing;
      if (err !== undefined) {
        // The ledger keeps the store and retries the repair itself; say so.
        pushError({
          fileId: null,
          scope: null,
          message: `Upload crash protection could not be saved on stop: ${(err as Error).message}`,
          timestamp: new Date().toISOString(),
        });
        uploadDeps.logger.error(
          { error: (err as Error).message },
          "Upload attempt store could not be repaired on stop",
        );
      }
    },

    async trigger() {
      // Clear existing timers, run immediately, restart interval
      clearIntervalTimer();
      clearNotifyTimer();
      await runCycle();
      if (isRunning && !paused) {
        startInterval();
      }
    },

    pause() {
      if (!isRunning || paused) return;
      paused = true;
      // Stale answers (a probe, a poke) of the run before the hide are void.
      nextLifecycle("paused");
      // A debounced ingest still waiting for its timer is owed, not dropped.
      if (notifyTimerId !== null) owedWhilePaused = true;
      clearIntervalTimer();
      clearProbeInterval();
      clearNotifyTimer();
      clearRetryTimer();
      stopChangePush(); // aborts the held request and the push's own timers
      cycleFailures = 0;
      probeFailures = 0;
      nextTimedProbeAt = 0;
    },

    resume() {
      if (!isRunning || !paused) return;
      paused = false;
      startInterval();
      startProbeInterval();
      startChangePush();
      // A follow-up the last cycle owed, or an ingest, waited for this.
      const owed = owedWhilePaused || rerunRequested;
      owedWhilePaused = false;
      if (owed) {
        runCycle().catch(() => {
          // Errors already captured in ring buffer
        });
      }
    },

    requestPull,

    getStatus(): SyncStatus {
      const pendingFiles =
        options?.accountStorageMode &&
        options.accountStorageMode.read() !== "unswitched"
          ? 0
          : (uploadDeps.storage.countUnsynced?.() ??
            uploadDeps.storage.findUnsynced().length);

      return {
        enabled: true,
        running: isRunning,
        syncing: cycleInFlight !== null,
        blocked,
        lastSync,
        lastProcessedTimestamp,
        pendingFiles,
        hydratedScopes: [...hydratedScopes],
        errors: [...errors],
        changeProbeMs: options?.changeProbe?.intervalMs ?? 0,
        deletions: tombstoneResubmits.snapshot(),
        ...(blobDeletions ? { blobDeletions: { ...blobDeletions } } : {}),
        uploads: uploadState.snapshot(),
      };
    },

    subscribeStatus(listener) {
      statusListeners.add(listener);
      // The first subscriber's value is the baseline, not an event.
      if (statusListeners.size === 1) statusMayHaveChanged();
      return () => {
        statusListeners.delete(listener);
        if (statusListeners.size === 0) statusSeen = null;
      };
    },

    hydrateScopes(scopes) {
      return exclusive(async () => {
        const canRun = await (options?.canSync?.() ?? { ok: true });
        if (!canRun.ok) {
          blocked = { reason: canRun.reason, message: canRun.message };
          downloadDeps.logger.warn(blocked, "Scope hydration blocked");
          statusMayHaveChanged();
          return;
        }
        blocked = null;
        statusMayHaveChanged();
        if (options?.accountStorageMode) {
          const mode = options.accountStorageMode.read();
          if (mode !== "unswitched") {
            if (mode === "switched" && options.localSync)
              await options.localSync.cycle();
            else {
              blocked = {
                reason: "account_mode_unknown",
                message: "Waiting for the account or its stream database",
              };
              statusMayHaveChanged();
            }
            return;
          }
        }
        await hydrateScopesExclusive(scopes);
      });
    },

    notifyNewData() {
      uploadDeps.logger.debug("New data notification received");
      statusMayHaveChanged(); // the new data is pending until a cycle takes it
      scheduleNotifiedCycle();
    },

    notifyRecordsCommitted() {
      uploadDeps.logger.debug("Records committed notification received");
      statusMayHaveChanged();
      scheduleNotifiedCycle(0);
    },

    async retryQuarantinedUploads(scope) {
      if (!(await uploadAttempts.recover())) return;
      try {
        for (const path of await uploadAttempts.release(scope))
          uploadState.clear(path);
      } finally {
        // The tracker's snapshot is part of the status, and a release that
        // fails part way has still cleared the paths before it.
        statusMayHaveChanged();
      }
    },

    async deleteScope(scope: string, within?: LegacyWriteSeal["commit"]) {
      const result = await exclusive(async () => {
        // A delete the user asks for starts a fresh set of re-submissions.
        tombstoneResubmits.reset(scope);
        const outcome = within
          ? await within((hold) =>
              deleteScope(deleteScopeDeps(), scope, { hold }),
            )
          : await deleteScope(deleteScopeDeps(), scope);
        // Upload state follows the rows. A failed delete removed nothing, so
        // its entries keep their budget and status; entries the delete did
        // remove are forgotten by comparing with what is still unsynced.
        uploadState.reconcile(uploadDeps.storage.findUnsynced());
        statusMayHaveChanged();
        return outcome;
      });
      if (result.durable && uploadDeps.additions)
        await uploadDeps.additions.deleteScope(scope);
      return result;
    },
  };

  return manager;
}
