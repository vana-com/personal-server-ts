export type { SyncStatus, SyncError } from "./types.js";
export type { SyncCursor } from "./cursor.js";
export {
  classifySyncFailure,
  inferPayloadKind,
  type ClassifiedSyncFailure,
  type ClassifySyncFailureInput,
  type SyncDownloadFailureTelemetryEvent,
  type SyncFailureDisposition,
  type SyncFailureStage,
  type SyncFileIssue,
  type SyncPayloadKind,
} from "./issues.js";
export {
  createSyncManager,
  type SyncManager,
  type SyncManagerOptions,
} from "./engine/sync-manager.js";
export type {
  DownloadDiagnosticsHook,
  DownloadWorkerDeps,
} from "./workers/download.js";
export {
  deleteScope,
  retryPendingBlobDeletions,
  type DeleteScopeDeps,
  type DeleteScopeResult,
  type DeleteScopeStep,
  type DeleteStepStatus,
  type RetryPendingBlobDeletionsResult,
} from "./workers/delete.js";
export {
  createGatewayDataPointFeed,
  feedFromGatewayClient,
  type GatewayDataPointFeedOptions,
} from "./data-point-feed.js";
export {
  createGatewayDeleteDataPort,
  type GatewayDeleteDataPortOptions,
} from "./delete-data-port.js";
export {
  createMemoryPendingBlobDeletionStore,
  createPendingBlobDeletionStore,
  type PendingBlobDeletionKv,
} from "./pending-blob-deletions.js";
export { computeDataPointId } from "./data-point-id.js";
export {
  TOMBSTONE_DATA_HASH,
  TOMBSTONE_METADATA_HASH,
  isTombstoneRecord,
} from "./tombstone.js";
