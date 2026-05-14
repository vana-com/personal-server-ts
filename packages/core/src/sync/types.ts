/** Sync engine status for GET /v1/sync/status */
export interface SyncStatus {
  enabled: boolean;
  /** Background sync manager lifecycle state. */
  running: boolean;
  /** True while an upload/download cycle is actively in progress. */
  syncing: boolean;
  /** Present when sync is enabled but intentionally blocked by runtime state. */
  blocked?: SyncBlockedReason | null;
  lastSync: string | null; // ISO 8601
  lastProcessedTimestamp: string | null;
  pendingFiles: number;
  errors: SyncError[];
}

export interface SyncBlockedReason {
  reason: string;
  message: string;
}

export interface SyncError {
  fileId: string | null;
  scope: string | null;
  message: string;
  timestamp: string;
}
