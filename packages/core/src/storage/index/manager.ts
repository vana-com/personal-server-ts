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
  listDistinctScopes(options?: {
    scopePrefix?: string;
    limit?: number;
    offset?: number;
  }): { scopes: ScopeSummary[]; total: number };
  findClosestByScope(scope: string, at: string): IndexEntry | undefined;
  findByFileId(fileId: string): IndexEntry | undefined;
  /**
   * Find all index entries where fileId is null (not yet synced to storage backend).
   * Returns entries ordered by created_at ASC (oldest first).
   */
  findUnsynced(options?: { limit?: number }): IndexEntry[];
  /**
   * Update the fileId for an index entry (after successful upload + on-chain registration).
   * @returns true if row was updated, false if path not found
   */
  updateFileId(path: string, fileId: string): boolean;
  /** Deletes all index entries for a scope. Returns count of deleted rows. */
  deleteByScope(scope: string): number;
  close(): void;
}
