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
  type DeleteScopeResult,
} from "../workers/delete.js";
import { createDownloadRetryMemory } from "../retry-memory.js";
import { createTombstoneResubmitTracker } from "../tombstone-resubmits.js";
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
 * it to skip the timer's cycle, and the unconditional timer cycle is what
 * guarantees every change is applied. A failed or "cannot tell" probe never
 * starts a cycle by itself (see `requestPull`).
 */
export interface ChangeProbe {
  read(): Promise<string | null | undefined>;
  /**
   * Period of the timed probe in milliseconds. Signals (`requestPull`) probe
   * at once and do not wait for it. See D4-SYNC-TRIGGERS for how the host
   * derives it from the cost of one idle cycle.
   */
  intervalMs: number;
  /**
   * Whether the timed probe is worth sending now. A hidden Web tab has no one
   * to show a change to and re-probes when it is shown (a signal). Absent: always.
   */
  active?: () => boolean;
}

export interface SyncManagerOptions {
  /** Personal Server hosts always supply their owner-bound Account mode. */
  accountStorageMode?: Pick<OwnedAccountStorageMode, "read">;
  localSync?: { cycle(): Promise<unknown> };

  /** Polling interval in milliseconds (default: 60_000 = 1 minute) */
  pollInterval?: number;
  /**
   * Starts a cycle when the registry changed, between the timer's cycles. The
   * timer stays unconditional and is the completeness guarantee: a probe that
   * fails or misses a change (see {@link ChangeProbe}) costs at most one poll
   * interval, and the timer's cycle is never gated on the marker.
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

export function createSyncManager(
  uploadDeps: UploadWorkerDeps,
  downloadDeps: DownloadWorkerDeps,
  options?: SyncManagerOptions,
): SyncManager {
  const pollInterval = options?.pollInterval ?? 60_000;
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
  let rerunRequested = false;
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
  // Failed probes in a row, and the earliest time the timed probe tries again.
  let probeFailures = 0;
  let nextTimedProbeAt = 0;
  // The registry marker as of the last cycle a pull ran and finished cleanly.
  // Only a pull moves it, and only to a marker read BEFORE its cycle started,
  // so every change up to it was in the registry when that cycle read.
  let pulledMarker: string | null | undefined;
  let errorSeq = 0;
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
    }
  }

  async function runCycle(): Promise<void> {
    // Prevent concurrent cycles
    if (cycleInFlight) {
      rerunRequested = true;
      return cycleInFlight;
    }

    cycleInFlight = exclusive(async () => {
      do {
        rerunRequested = false;
        const canRun = await (options?.canSync?.() ?? { ok: true });
        if (!canRun.ok) {
          blocked = { reason: canRun.reason, message: canRun.message };
          uploadDeps.logger.warn(blocked, "Sync cycle blocked");
          continue;
        }
        blocked = null;
        // canSync can yield while Account changes. Sample only after it returns.
        if (options?.accountStorageMode) {
          const mode = options.accountStorageMode.read();
          if (mode !== "unswitched") {
            if (mode === "switched" && options.localSync) {
              await options.localSync.cycle();
              lastSync = new Date().toISOString();
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
      } while (rerunRequested && isRunning);
    });

    try {
      await cycleInFlight;
    } finally {
      cycleInFlight = null;
    }
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

  async function runUploadCycle(): Promise<void> {
    try {
      await retryPendingBlobDeletions({
        deleteData: options?.deleteData,
        pendingBlobDeletions: options?.pendingBlobDeletions,
        tombstoneFinality: options?.tombstoneFinality,
        dataPointFeed,
        serverOwner: uploadDeps.serverOwner,
        storage: uploadDeps.storage,
        logger: uploadDeps.logger,
        ...(options?.tombstoneFinality && options.deleteData
          ? {
              tombstoneResubmits,
              // Already inside the mutation queue: call the worker directly.
              async resubmitDeletion(scope, resubmit) {
                const result = await deleteScope(
                  deleteScopeDeps(),
                  scope,
                  resubmit,
                );
                if (result.durable) deleteAdditionsAfter(scope);
                return result;
              },
              onDeletionAbandoned(state) {
                pushError({
                  fileId: null,
                  scope: state.scope,
                  message:
                    state.reason === "head-changed"
                      ? `Deletion of ${state.scope} did not complete: the gateway tombstone failed and the data is live again. Delete it again to retry.`
                      : `Deletion of ${state.scope} did not complete: the gateway tombstone failed ${state.attempts + 1} times and the data is live again. Delete it again to retry.`,
                  timestamp: new Date().toISOString(),
                });
              },
            }
          : {}),
      });
    } catch (err) {
      uploadDeps.logger.warn(
        { error: (err as Error).message },
        "Pending blob deletion retry failed",
      );
    }

    try {
      const uploadResults = await uploadAll(workerUploadDeps, {
        batchSize: uploadBatchSize,
        onError(entry, error) {
          pushError({
            fileId: entry.fileId,
            scope: entry.scope,
            message: `Upload failed for ${entry.path}: ${error.message}`,
            timestamp: new Date().toISOString(),
          });
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
  ): Promise<void> {
    let marker: string | null | undefined;
    try {
      marker = await probe.read();
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
    if (!isRunning) return Promise.resolve();
    // No probe: a pull is a cycle request, and `runCycle` coalesces those.
    const probe = options?.changeProbe;
    if (!probe) return runCycle();
    const run = lifecycle;
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
          await pullIfChanged(probe, run, signalled);
        } while (pullRequested && isRunning && run === lifecycle);
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

  function scheduleNotifiedCycle(): void {
    if (!isRunning || notifyTimerId !== null) return;
    notifyTimerId = setTimeout(() => {
      notifyTimerId = null;
      if (!isRunning) return;
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });
    }, notifyDebounceMs);
  }

  function pushError(error: SyncError): void {
    errorSeq += 1;
    errors.push(error);
    if (errors.length > MAX_ERRORS) {
      errors = errors.slice(-MAX_ERRORS);
    }
  }

  function startInterval(): void {
    if (intervalId !== null) return;
    intervalId = setInterval(() => {
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
      if (probe.active && !probe.active()) return;
      if (Date.now() < nextTimedProbeAt) return; // backing off after failures
      pull(false).catch(() => {
        // Errors already captured in ring buffer
      });
    }, probe.intervalMs);
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
      lifecycle += 1;
      pulledMarker = undefined;
      probeFailures = 0;
      nextTimedProbeAt = 0;

      // Crash recovery: run one cycle immediately on start
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });

      startInterval();
      startProbeInterval();
    },

    async stop() {
      // Opens the stop's repair window before anything awaits, so a stop that
      // nothing awaits still holds its repair duty.
      const closing = uploadAttempts
        .close(namelessAttempts ? Infinity : undefined)
        .catch((err: unknown) => err);
      clearIntervalTimer();
      clearProbeInterval();
      clearNotifyTimer();
      isRunning = false;
      // Cancel pulls: a probe that answers later finds a new lifecycle value.
      lifecycle += 1;

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
      if (isRunning) {
        startInterval();
      }
    },

    requestPull,

    getStatus(): SyncStatus {
      const pendingFiles =
        options?.accountStorageMode &&
        options.accountStorageMode.read() !== "unswitched"
          ? 0
          : uploadDeps.storage.findUnsynced().length;

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
        uploads: uploadState.snapshot(),
      };
    },

    hydrateScopes(scopes) {
      return exclusive(async () => {
        const canRun = await (options?.canSync?.() ?? { ok: true });
        if (!canRun.ok) {
          blocked = { reason: canRun.reason, message: canRun.message };
          downloadDeps.logger.warn(blocked, "Scope hydration blocked");
          return;
        }
        blocked = null;
        if (options?.accountStorageMode) {
          const mode = options.accountStorageMode.read();
          if (mode !== "unswitched") {
            if (mode === "switched" && options.localSync)
              await options.localSync.cycle();
            else
              blocked = {
                reason: "account_mode_unknown",
                message: "Waiting for the account or its stream database",
              };
            return;
          }
        }
        await hydrateScopesExclusive(scopes);
      });
    },

    notifyNewData() {
      uploadDeps.logger.debug("New data notification received");
      scheduleNotifiedCycle();
    },

    async retryQuarantinedUploads(scope) {
      if (!(await uploadAttempts.recover())) return;
      for (const path of await uploadAttempts.release(scope))
        uploadState.clear(path);
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
        return outcome;
      });
      if (result.durable && uploadDeps.additions)
        await uploadDeps.additions.deleteScope(scope);
      return result;
    },
  };

  return manager;
}
