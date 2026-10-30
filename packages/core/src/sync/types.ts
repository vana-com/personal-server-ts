import type { TombstoneResubmitSnapshot } from "./tombstone-resubmits.js";
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
  /** Exact scopes hydrated independently of the registry cursor. */
  hydratedScopes: string[];
  errors: SyncError[];
  /**
   * Deletes whose gateway tombstone failed and rolled back (the data is live
   * again). `retrying`: re-submitted automatically, a new tombstone is due or
   * settling. `failed`: every allowed re-submission failed; the user must
   * delete the scope again. Both lists are empty when nothing is owed.
   */
  deletions?: TombstoneResubmitSnapshot;
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
