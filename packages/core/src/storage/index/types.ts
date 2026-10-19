export interface IndexEntry {
  id: number;
  fileId: string | null; // null until synced on-chain (Phase 4)
  schemaId: string | null; // null for legacy/local-only entries without schema metadata
  path: string; // relative path from dataDir
  scope: string;
  collectedAt: string; // ISO 8601
  createdAt: string; // ISO 8601
  sizeBytes: number;
  // DPv2 sync version. This may be rebased to the registry version by
  // updateVersion and is used in AddData expectedVersion / sync attestations.
  version: number;
  // Immutable local CAS revision for legacy /v1/data writes. It advances on
  // every local ingest for a scope and survives row deletion. Older in-memory
  // fixtures may omit it, so API callers fall back to `version` defensively.
  casRevision?: number;
  // DPv2 data-point id assigned by the gateway after registerDataPoint
  // succeeds. Null until the sync worker has registered this entry on-chain.
  dataPointId: string | null;
  // Causal deletion marker for unsynced entries. The gateway tombstone
  // version this replica knew about when the entry was ingested: the entry
  // is a deliberate re-add on top of that deletion and survives it. Null (or
  // absent, for rows from before this column) means the entry was ingested
  // without knowledge of any tombstone, so any tombstone covers it. Never a
  // wall-clock comparison: clocks differ across replicas, versions do not.
  afterTombstoneVersion?: number | null;
  /** Server-stamped origin of a legacy cache version. Null for older/manual writes. */
  producer?: "pdpp-projector" | "pdpp-import-projection" | null;
  /** JSON provenance stored outside the grantee-visible data object. */
  producerProvenance?: string | null;
}

export type NewIndexEntry = Omit<
  IndexEntry,
  "id" | "createdAt" | "schemaId" | "version" | "casRevision" | "dataPointId"
> & {
  schemaId?: string | null;
  // Optional sync version. When omitted, the IndexManager uses the allocated
  // local CAS revision as the initial DPv2 expectedVersion.
  version?: number;
  // Optional only for migration/import tests. Normal inserts allocate this from
  // the durable per-scope CAS revision ledger.
  casRevision?: number;
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
