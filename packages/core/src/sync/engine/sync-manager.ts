import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { SyncStatus, SyncError } from "../types.js";
import { uploadAll } from "../workers/upload.js";
import { downloadAll } from "../workers/download.js";

export interface SyncManagerOptions {
  /** Polling interval in milliseconds (default: 60_000 = 1 minute) */
  pollInterval?: number;
  /** Max upload batch size per cycle (default: 50) */
  uploadBatchSize?: number;
  /** Debounce for immediate sync after local ingest (default: 500ms) */
  notifyDebounceMs?: number;
}

export interface SyncManager {
  /** Start the background sync loop */
  start(): void;

  /** Stop the background sync loop gracefully */
  stop(): Promise<void>;

  /** Trigger an immediate sync cycle (skips wait) */
  trigger(): Promise<void>;

  /** Get current sync status */
  getStatus(): SyncStatus;

  /** Signal that new data has been ingested (next cycle picks it up) */
  notifyNewData(): void;

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

  let intervalId: ReturnType<typeof setInterval> | null = null;
  let notifyTimerId: ReturnType<typeof setTimeout> | null = null;
  let isRunning = false;
  let lastSync: string | null = null;
  let lastProcessedTimestamp: string | null = null;
  let errors: SyncError[] = [];
  let cycleInFlight: Promise<void> | null = null;
  let rerunRequested = false;

  async function runCycle(): Promise<void> {
    // Prevent concurrent cycles
    if (cycleInFlight) {
      rerunRequested = true;
      return cycleInFlight;
    }

    cycleInFlight = (async () => {
      do {
        rerunRequested = false;

        try {
          // Upload unsynced local files
          const uploadResults = await uploadAll(uploadDeps, {
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

        try {
          // Download new remote files
          const downloadResults = await downloadAll(downloadDeps);
          downloadDeps.logger.debug(
            { downloaded: downloadResults.length },
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
    })();

    try {
      await cycleInFlight;
    } finally {
      cycleInFlight = null;
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
        lastSync,
        lastProcessedTimestamp,
        pendingFiles,
        errors: [...errors],
      };
    },

    notifyNewData() {
      uploadDeps.logger.debug("New data notification received");
      scheduleNotifiedCycle();
    },
  };

  return manager;
}
