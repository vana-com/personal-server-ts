import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { SyncStatus, SyncError, SyncBlockedReason } from "../types.js";
import { uploadAll } from "../workers/upload.js";
import { downloadAll, downloadScopes } from "../workers/download.js";
import {
  deleteScope,
  retryPendingBlobDeletions,
  type DeleteScopeResult,
} from "../workers/delete.js";
import { createDownloadRetryMemory } from "../retry-memory.js";
import type {
  DeleteDataPort,
  PendingBlobDeletionStore,
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
  /** Durable retry marker for blob deletions that failed after the tombstone. */
  pendingBlobDeletions?: PendingBlobDeletionStore;
  /** Select download-only operation for runtimes that cannot sign uploads. */
  transferMode?: "upload-download" | "download-only";
  /** Exact owner scopes to hydrate before the first full download cycle. */
  hydrateScopes?: string[];
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
  let needsStartupHydration = startupHydrateScopes.length > 0;
  const hydratedScopes = new Set<string>();
  // One retry memory per manager (= per boot session): a blob that 404s is
  // attempted once per session, not once per cycle; transient storage errors
  // back off exponentially instead of re-firing on every cycle.
  const downloadRetryMemory = createDownloadRetryMemory();
  const dataPointFeed = downloadDeps.dataPointFeed ?? uploadDeps.dataPointFeed;
  const scopeDeletions =
    uploadDeps.scopeDeletions ?? downloadDeps.scopeDeletions;
  // The upload worker queues guarded cleanup for ciphertext it had to
  // abandon mid-race; it shares the manager's marker store.
  const workerUploadDeps: UploadWorkerDeps = {
    ...uploadDeps,
    pendingBlobDeletions:
      uploadDeps.pendingBlobDeletions ?? options?.pendingBlobDeletions,
  };
  const workerDownloadDeps: DownloadWorkerDeps = {
    ...downloadDeps,
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
    for (const scope of new Set(scopes)) {
      await downloadScopes(workerDownloadDeps, [scope]);
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
            const syncError: SyncError = {
              fileId: null,
              scope: null,
              message: `Scope hydration failed: ${(err as Error).message}`,
              timestamp: new Date().toISOString(),
            };
            pushError(syncError);
            downloadDeps.logger.error(
              { error: (err as Error).message },
              "Scope hydration failed",
            );
            continue;
          }
        }

        // Finish blob deletions whose tombstone landed but whose storage
        // DELETE did not. Cheap when nothing is pending; never blocks sync.
        if (transferMode === "upload-download") {
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

  async function runUploadCycle(): Promise<void> {
    try {
      await retryPendingBlobDeletions({
        deleteData: options?.deleteData,
        pendingBlobDeletions: options?.pendingBlobDeletions,
        dataPointFeed,
        serverOwner: uploadDeps.serverOwner,
        storage: uploadDeps.storage,
        logger: uploadDeps.logger,
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
      clearIntervalTimer();
      clearNotifyTimer();
      isRunning = false;

      // Wait for any in-flight cycle to complete
      if (cycleInFlight) {
        await cycleInFlight;
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
      };
    },

    hydrateScopes(scopes) {
      return exclusive(() => hydrateScopesExclusive(scopes));
    },

    notifyNewData() {
      uploadDeps.logger.debug("New data notification received");
      scheduleNotifiedCycle();
    },

    deleteScope(scope: string) {
      return exclusive(() =>
        deleteScope(
          {
            storage: uploadDeps.storage,
            serverOwner: uploadDeps.serverOwner,
            deleteData: options?.deleteData,
            pendingBlobDeletions: options?.pendingBlobDeletions,
            scopeDeletions,
            dataPointFeed,
            logger: uploadDeps.logger,
          },
          scope,
        ),
      );
    },
  };

  return manager;
}
