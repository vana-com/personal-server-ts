/** Sync engine status for GET /v1/sync/status */
export interface SyncStatus {
  enabled: boolean;
  running: boolean;
  lastSync: string | null; // ISO 8601
  lastProcessedTimestamp: string | null;
  pendingFiles: number;
  errors: SyncError[];
}

export interface SyncError {
  fileId: string | null;
  scope: string | null;
  message: string;
  timestamp: string;
}
