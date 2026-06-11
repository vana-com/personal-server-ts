export interface IndexEntry {
  id: number;
  fileId: string | null; // null until synced on-chain (Phase 4)
  schemaId: string | null; // null for legacy/local-only entries without schema metadata
  path: string; // relative path from dataDir
  scope: string;
  collectedAt: string; // ISO 8601
  createdAt: string; // ISO 8601
  sizeBytes: number;
  // DPv2 monotonic per-scope version; advances on every ingest. Matches the
  // `expectedVersion` field signed in AddData EIP-712 + the `version` field
  // of any RECORD_DATA_ACCESS attestation we sign over this entry.
  version: number;
  // DPv2 data-point id assigned by the gateway after registerDataPoint
  // succeeds. Null until the sync worker has registered this entry on-chain.
  dataPointId: string | null;
}

export type NewIndexEntry = Omit<
  IndexEntry,
  "id" | "createdAt" | "schemaId" | "version" | "dataPointId"
> & {
  schemaId?: string | null;
  // Optional at the contract boundary: when omitted, the IndexManager
  // computes `max(version) + 1` for the scope inside `insert`. Ingest
  // callers don't have to thread version state through their flow.
  version?: number;
  dataPointId?: string | null;
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
  /**
   * Whether bounded block reads for the latest local version are ready.
   * Existing data can appear in the index before the block sidecar finishes
   * indexing; MCP reads require the sidecar.
   */
  dataStatus?: "ready" | "indexing";
  /** Size in bytes of the latest local version. */
  sizeBytes?: number;
}
