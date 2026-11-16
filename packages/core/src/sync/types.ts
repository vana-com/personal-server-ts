import type { TombstoneResubmitSnapshot } from "./tombstone-resubmits.js";
import type { UploadStateSnapshot } from "./upload-state.js";
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
   * Period of the registry change probe in milliseconds; 0 when the server has
   * none. A client that wants to start a pull when its window returns
   * (`POST /trigger?when=changed`) may do so only when this is above 0: an
   * older server lacks the field and answers that request with a full cycle.
   * The probe period is also the least time between such requests that can
   * find a new marker.
   */
  changeProbeMs?: number;
  /**
   * Deletes whose gateway tombstone failed and rolled back (the data is live
   * again). `retrying`: re-submitted automatically, a new tombstone is due or
   * settling. `failed`: every allowed re-submission failed; the user must
   * delete the scope again. Both lists are empty when nothing is owed.
   */
  deletions?: TombstoneResubmitSnapshot;
  /**
   * Storage deletes queued behind a tombstone, as of the last drain, whatever
   * the transport can do about them: `remaining` markers in all. `waiting` of
   * them a later pass finishes by itself (finality pending, or a key to
   * retry). The rest are parked behind a rolled-back scope, which stays until
   * the user deletes it again (see `deletions.failed`), or cannot run because
   * `unavailable` names a missing port. Absent until a drain has run.
   */
  blobDeletions?: {
    remaining: number;
    waiting: number;
    unavailable: "delete-port" | "finality-port" | null;
  };
  /**
   * Local entries that are too large to upload (kept locally, not synced),
   * and failing uploads that are backing off or have stopped. Each list is
   * empty when nothing is owed.
   */
  uploads?: UploadStateSnapshot;
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
