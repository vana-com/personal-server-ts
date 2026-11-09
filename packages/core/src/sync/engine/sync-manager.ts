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
import { readTargets } from "../../stream-sync-read/service.js";
import { requeueLostDataPoints } from "../workers/lost-data-points.js";
import { downloadAll, downloadScopes } from "../workers/download.js";
import {
  countsOnlyLogger,
  errorClass,
  retireLegacyScopes,
  type RetireLegacyOption,
} from "../workers/retire-legacy.js";

export type { RetireLegacyOption };
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

export interface SyncManagerOptions {
  /** Polling interval in milliseconds (default: 60_000 = 1 minute) */
  pollInterval?: number;
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
   * Whole-file stream sync (`streamSync.write`, default off). While `write`
   * is true the account has switched: each upload cycle publishes through the
   * stream-sync publisher and does NOT upload or register new legacy files
   * (legacy is read-only history; downloads, reads and deletes stay). Hosts
   * pass `write` as a getter over their config so a switch-off mid-run is
   * seen on the next cycle and legacy uploads resume. When it is false or
   * absent, nothing changes.
   */
  streamSync?: {
    readonly write: boolean;
    readonly publisher: { cycle(): Promise<unknown> };
    /**
     * Whether the stream carries `scope`, so its legacy upload is off while
     * `write` is on. Default: the scope has a read target
     * (`readTargets(scope).length > 0`).
     */
    readonly carries?: (scope: string) => boolean;
  } | null;
  /**
   * Called at the end of every cycle. Returns the retire inputs while the
   * account is switched to stream sync (the host reads its current config), or
   * null while it is not. Absent: legacy files are never retired. Needs
   * `deleteData`: a local-only delete would be undone by the next sync. Its
   * presence also makes every delete-path log counts only.
   */
  retireLegacy?: (() => RetireLegacyOption | null) | null;
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
   */
  deleteScope(scope: string): Promise<DeleteScopeResult>;

  /** Whether the sync manager is currently running */
  readonly running: boolean;
}

const MAX_ERRORS = 10;

/** The stream carries a scope when a stream view can answer a read of it. */
const defaultCarries = (scope: string): boolean =>
  readTargets(scope).length > 0;

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
    onCycleOutcome(outcome) {
      downloadComplete = outcome.complete;
      downloadDeps.onCycleOutcome?.(outcome);
    },
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
                // Requeueing re-registers legacy files with the gateway: not
                // for scopes the stream carries once the writer is on.
                { skipScope: legacyUploadOff },
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

        // Only a pass that reports itself complete may let a retire run.
        downloadComplete = false;
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

        await retireLegacyAfterDownload();

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

  // A host that can retire legacy scopes logs counts only on every delete
  // path (delete, blob retry, re-submission), so no scope name reaches a log.
  const deletionLogger = options?.retireLegacy
    ? countsOnlyLogger(uploadDeps.logger)
    : uploadDeps.logger;
  let downloadComplete = false;
  let legacyWritesAfterSwitch = 0;

  function deleteScopeDeps() {
    return {
      storage: uploadDeps.storage,
      serverOwner: uploadDeps.serverOwner,
      deleteData: options?.deleteData,
      pendingBlobDeletions: options?.pendingBlobDeletions,
      tombstoneFinality: options?.tombstoneFinality,
      scopeDeletions,
      dataPointFeed,
      logger: deletionLogger,
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
   * Whether a legacy upload of `scope` is off: the account has switched
   * (read live from the host) and the stream carries the scope.
   */
  function legacyUploadOff(scope: string): boolean {
    return (
      options?.streamSync?.write === true &&
      (options.streamSync.carries ?? defaultCarries)(scope)
    );
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
        logger: deletionLogger,
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
        // With retiring on, the message could name a scope: class only.
        {
          error: options?.retireLegacy
            ? errorClass(err)
            : (err as Error).message,
        },
        "Pending blob deletion retry failed",
      );
    }

    // Switched account: legacy is read-only history for the scopes the
    // stream carries, so nothing new is uploaded to storage or registered
    // with the gateway for them (the file stays local and the writer
    // publishes it). Scopes the stream does not carry (agent memory, replica
    // scopes) have no other path and still upload.
    try {
      const uploadResults = await uploadAll(workerUploadDeps, {
        batchSize: uploadBatchSize,
        skipEntry: (entry) => legacyUploadOff(entry.scope),
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

    await publishStreamSync();
  }

  async function publishStreamSync(): Promise<void> {
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
   * Inside a cycle, after the import. Reads the host's switch state now, and
   * runs only when this cycle's download pass completed: a failed or partial
   * pass leaves the mirror stale, and a stale mirror must never delete.
   */
  async function retireLegacyAfterDownload(): Promise<void> {
    if (!options?.retireLegacy || !options.deleteData) return;
    const retire = options.retireLegacy();
    if (!retire || !downloadComplete) return;
    try {
      const outcome = await retireLegacyScopes({
        storage: uploadDeps.storage,
        switchedAt: retire.switchedAt,
        coverage: (scope) => retire.coverage(scope),
        viewKeys: (scope) => retire.viewKeys(scope),
        // Turning the switch off mid-pass stops the next delete.
        stillOn: () => options.retireLegacy?.() != null,
        async registeredAt(scope) {
          // No registry to ask is not "the gateway never saw it": fail closed.
          if (!dataPointFeed) throw new Error("no registry to read");
          const row = await dataPointFeed.getDataPoint({
            ownerAddress: uploadDeps.serverOwner,
            scope,
          });
          return row?.addedAt ?? null;
        },
        async deleteScope(scope) {
          const result = await deleteScope(deleteScopeDeps(), scope);
          uploadState.reconcile(uploadDeps.storage.findUnsynced());
          if (result.durable) deleteAdditionsAfter(scope);
          return result;
        },
        logger: deletionLogger,
      });
      legacyWritesAfterSwitch = outcome.legacyWritesAfterSwitch;
    } catch (err) {
      deletionLogger.warn(
        { error: errorClass(err) },
        "Retiring legacy scopes failed; retried next cycle",
      );
    }
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

      // Crash recovery: run one cycle immediately on start
      runCycle().catch(() => {
        // Errors already captured in ring buffer
      });

      startInterval();
    },

    async stop() {
      // Opens the stop's repair window before anything awaits, so a stop that
      // nothing awaits still holds its repair duty.
      const closing = uploadAttempts
        .close(namelessAttempts ? Infinity : undefined)
        .catch((err: unknown) => err);
      clearIntervalTimer();
      clearNotifyTimer();
      isRunning = false;

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

    getStatus(): SyncStatus {
      const pendingFiles = uploadDeps.storage.findUnsynced().length;

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
        deletions: tombstoneResubmits.snapshot(),
        uploads: uploadState.snapshot(),
        streamSync: { legacyWritesAfterSwitch },
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

    async deleteScope(scope: string) {
      const result = await exclusive(async () => {
        // A delete the user asks for starts a fresh set of re-submissions.
        tombstoneResubmits.reset(scope);
        const outcome = await deleteScope(deleteScopeDeps(), scope);
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
