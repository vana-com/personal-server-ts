import type {
  IndexEntry,
  IndexListOptions,
  NewIndexEntry,
  ScopeSummary,
} from "./types.js";

export interface IndexManager {
  insert(entry: NewIndexEntry): IndexEntry;
  findByPath(path: string): IndexEntry | undefined;
  findByScope(options: IndexListOptions): IndexEntry[];
  findLatestByScope(scope: string): IndexEntry | undefined;
  countByScope(scope: string): number;
  deleteByPath(path: string): boolean;
  /**
   * Delete a row by path ONLY if it is still unsynced (`dataPointId` null).
   * Atomic guard so a row that raced to synced after selection keeps its
   * metadata. Returns true only when an unsynced row was actually removed.
   */
  deleteUnsyncedByPath(path: string): boolean;
  listDistinctScopes(options?: {
    scopePrefix?: string;
    limit?: number;
    offset?: number;
  }): { scopes: ScopeSummary[]; total: number };
  findClosestByScope(scope: string, at: string): IndexEntry | undefined;
  findByFileId(fileId: string): IndexEntry | undefined;
  /** Find an index entry by its DPv2 data-point id (download dedup). */
  findByDataPointId(dataPointId: string): IndexEntry | undefined;
  /**
   * Find all index entries where dataPointId is null (not yet synced /
   * registered on-chain). Returns entries ordered by created_at ASC (oldest
   * first).
   */
  findUnsynced(options?: { limit?: number }): IndexEntry[];
  /**
   * Update the fileId for an index entry (after successful upload + on-chain registration).
   * @returns true if row was updated, false if path not found
   */
  updateFileId(path: string, fileId: string): boolean;
  /**
   * Returns the highest stored `version` for a scope, or 0 if none. Used by
   * `insert` to derive the next expectedVersion for DPv2 AddData.
   */
  findLatestVersionByScope(scope: string): number;
  /**
   * Update the dataPointId for an index entry (after successful DPv2
   * registerDataPoint). Sync-worker step that runs alongside fileId update.
   * @returns true if row was updated, false if path not found
   */
  updateDataPointId(path: string, dataPointId: string): boolean;
  /**
   * Update the DPv2 `version` for an index entry. Used by the upload worker
   * when a registration is rebased onto the registry's live version after a
   * stale-expectedVersion conflict (the blob key embeds the version, so the
   * local row must follow).
   * @returns true if row was updated, false if path not found
   */
  updateVersion(path: string, version: number): boolean;
  /** Deletes all index entries for a scope. Returns count of deleted rows. */
  deleteByScope(scope: string): number;
  close(): void;
}
