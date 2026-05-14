export interface IndexEntry {
  id: number;
  fileId: string | null; // null until synced on-chain (Phase 4)
  schemaId: string | null; // null for legacy/local-only entries without schema metadata
  path: string; // relative path from dataDir
  scope: string;
  collectedAt: string; // ISO 8601
  createdAt: string; // ISO 8601
  sizeBytes: number;
}

export type NewIndexEntry = Omit<
  IndexEntry,
  "id" | "createdAt" | "schemaId"
> & {
  schemaId?: string | null;
};

export interface IndexListOptions {
  scope?: string;
  limit?: number;
  offset?: number;
}

export interface ScopeSummary {
  scope: string;
  latestCollectedAt: string;
  versionCount: number;
}
