import type {
  Builder,
  DataFileEnvelope,
  DataPointListResult,
  DataPointRecord,
  GatewayGrantResponse,
  ListDataPointsOptions,
  Schema,
  ServerInfo,
} from "@opendatalabs/vana-sdk/browser";
import type { WriteResult } from "../storage/hierarchy/index.js";
import type {
  DataBlockManifest,
  DataScopeBlock,
  ReadScopeBlocksResponse,
} from "../storage/blocks/index.js";
import type {
  IndexEntry,
  NewIndexEntry,
  ScopeSummary,
} from "../storage/index/types.js";

export interface ProtocolGatewayPort {
  getBuilder(address: string): Promise<Builder | null>;
  getGrant(grantId: string): Promise<GatewayGrantResponse | null>;
  getSchemaForScope(scope: string): Promise<Schema | null>;
  getServer(address: string): Promise<ServerInfo | null>;
  getDataPoint(dataPointId: string): Promise<DataPointRecord | null>;
  listDataPointsByOwner(
    owner: string,
    cursor: string | null,
    options?: ListDataPointsOptions,
  ): Promise<DataPointListResult>;
}

export interface GrantVerifierPort {
  getGrant(grantId: string): Promise<GatewayGrantResponse | null>;
}

export interface AuthSessionVerifierPort {
  getBuilder(address: string): Promise<Builder | null>;
}

export interface FileRegistrySyncRegistryPort {
  getDataPoint(dataPointId: string): Promise<DataPointRecord | null>;
  listDataPointsByOwner(
    owner: string,
    cursor: string | null,
    options?: ListDataPointsOptions,
  ): Promise<DataPointListResult>;
}

export interface PlatformCryptoPort {
  randomBytes(length: number): Uint8Array;
}

export interface RuntimeStoragePort {
  kind: "node-fs-sqlite" | "browser-indexeddb-opfs" | "custom";
}

export interface DataStorageListOptions {
  limit?: number;
  offset?: number;
}

export interface DataStorageScopeListOptions extends DataStorageListOptions {
  scopePrefix?: string;
}

export interface DataStorageEntryLookup {
  scope: string;
  fileId?: string;
  at?: string;
}

export interface DataStorageEnvelopePreview {
  text: string;
  truncated: boolean;
}

export interface DataStoragePort extends RuntimeStoragePort {
  listScopes(options: DataStorageScopeListOptions): {
    scopes: ScopeSummary[];
    total: number;
  };
  listVersions(scope: string, options: DataStorageListOptions): IndexEntry[];
  countVersions(scope: string): number;
  findEntry(lookup: DataStorageEntryLookup): IndexEntry | undefined;
  findByFileId(fileId: string): IndexEntry | undefined;
  /** Dedup lookup for the download worker: find an entry by its DPv2 data-point id. */
  findByDataPointId(dataPointId: string): IndexEntry | undefined;
  findUnsynced(options?: { limit?: number }): IndexEntry[];
  readEnvelope(scope: string, collectedAt: string): Promise<DataFileEnvelope>;
  readEnvelopePreview?(
    scope: string,
    collectedAt: string,
    options: { maxBytes: number },
  ): Promise<DataStorageEnvelopePreview>;
  readScopeBlocks?(
    scope: string,
    collectedAt: string,
    options: {
      cursor?: string;
      maxBytes: number;
      /**
       * Block-addressed read: return only these blocks, in this order. When
       * set, `cursor` is ignored and no `nextCursor` is produced; `maxBytes`
       * still applies and any ids it cuts off are reported as warnings.
       */
      blockIds?: readonly string[];
    },
  ): Promise<ReadScopeBlocksResponse>;
  /**
   * Read a scope's block manifest (table of contents) without reading any block
   * values. Returns null when the scope has no manifest yet.
   */
  readBlockManifest?(
    scope: string,
    collectedAt: string,
  ): Promise<DataBlockManifest | null>;
  hasScopeBlocks?(
    scope: string,
    collectedAt: string,
  ): boolean | Promise<boolean>;
  canReadScopeBlocks?(
    scope: string,
    collectedAt: string,
  ): boolean | Promise<boolean>;
  writeEnvelope(envelope: DataFileEnvelope): Promise<WriteResult>;
  writeBlockManifest?(
    scope: string,
    collectedAt: string,
    manifest: DataBlockManifest,
    blocks: DataScopeBlock[],
  ): Promise<void>;
  insertEntry(entry: NewIndexEntry): IndexEntry | Promise<IndexEntry>;
  updateFileId(path: string, fileId: string): boolean | Promise<boolean>;
  /** Highest stored DPv2 `version` for a scope; 0 if none. */
  findLatestVersionByScope(scope: string): number | Promise<number>;
  /** Stamps the DPv2 dataPointId on an entry after registerDataPoint. */
  updateDataPointId(
    path: string,
    dataPointId: string,
  ): boolean | Promise<boolean>;
  /**
   * Rewrites the DPv2 `version` on an entry. Used when the upload worker
   * rebases a registration onto the registry's live version after a
   * stale-expectedVersion conflict — the blob key embeds the version, so
   * the local row must follow the registered one.
   */
  updateEntryVersion(path: string, version: number): boolean | Promise<boolean>;
  deleteScope(scope: string): Promise<number>;
  /**
   * Delete a single version (index entry + its local blob) by its gateway fileId.
   * Returns true if a local copy existed and was removed, false if none was present (no-op).
   * Used by sync delete-reconciliation to drop a copy the gateway reports as deleted.
   */
  deleteByFileId(fileId: string): Promise<boolean>;
  /**
   * Delete a single version (index entry + its local blob + block sidecars)
   * by its DPv2 identity (scope, collectedAt). Returns true if a local copy
   * existed and was removed, false if none was present (no-op). Used by sync
   * deletion reconciliation to drop the exact versions a gateway tombstone
   * covers while leaving a newer local re-ingest in place.
   */
  deleteVersion(scope: string, collectedAt: string): Promise<boolean>;
  /**
   * Drop a single unsynced index entry by path, WITHOUT touching any blob.
   * Used by the upload worker to evict an orphaned row whose local payload
   * file is already gone (e.g. a manual `data/<scope>` deletion): the row can
   * never upload, so retrying it head-blocks the scope forever. Returns true
   * if a row was removed. No-op-safe when the path is unknown.
   */
  dropUnsyncedEntry?(path: string): boolean | Promise<boolean>;
}

export interface RuntimeAvailabilityPort {
  isAvailable(): boolean | Promise<boolean>;
}

/**
 * A gateway data-point row as seen by sync, including the deletion marker the
 * plain SDK `DataPointRecord` does not model. `deletedAt` is null while the
 * point is live and an ISO timestamp once the owner has tombstoned it.
 */
export interface DataPointFeedRecord extends DataPointRecord {
  deletedAt: string | null;
}

export interface DataPointFeedListOptions extends ListDataPointsOptions {
  /**
   * Ask the gateway to include tombstoned rows (with `deletedAt` set). Sync
   * always passes true: deletions must reach every replica or the local copy
   * would be re-uploaded and resurrect the point.
   */
  includeDeleted?: boolean;
}

export interface DataPointFeedListResult {
  dataPoints: DataPointFeedRecord[];
  cursor: string | null;
}

/**
 * Deletion-aware view of the gateway data-point registry. Mirrors the SDK
 * `GatewayClient` listing/lookup shape but surfaces `deletedAt`, which the
 * SDK client (3.14) neither requests (`includeDeleted`) nor types.
 */
export interface DataPointFeedPort {
  listDataPointsByOwner(
    owner: string,
    cursor: string | null,
    options?: DataPointFeedListOptions,
  ): Promise<DataPointFeedListResult>;
  /**
   * Current registry row for (owner, scope), deleted or not. Null when the
   * point was never registered. A tombstoned point comes back with
   * `deletedAt` set (never as a thrown 410).
   */
  getDataPoint(input: {
    ownerAddress: string;
    scope: string;
  }): Promise<DataPointFeedRecord | null>;
}

export type TombstoneOutcome =
  | {
      status: "tombstoned";
      dataPointId: string;
      /** The tombstone's own version (previous current + 1). */
      version: string;
      deletedAt: string | null;
    }
  | {
      status: "already-deleted";
      dataPointId: string;
      /**
       * The winning tombstone's registry version as the gateway reports it
       * (possibly higher than the version this replica attempted), or null
       * when the gateway did not say. Null means the covered key range is
       * unknown, so callers defer enumeration rather than guess.
       */
      version: string | null;
      deletedAt: string | null;
    }
  | {
      /** The gateway has no row for (owner, scope): nothing to tombstone. */
      status: "not-registered";
      dataPointId: string;
    };

export interface DeleteBlobVersionsOutcome {
  /** Versions whose blob existed and was deleted. */
  deleted: string[];
  /** Versions with no blob in storage (404): nothing to do, counts as done. */
  missing: string[];
  /** Versions whose delete failed (rate limit, 5xx, network); retry later. */
  failed: Array<{ version: string; error: string }>;
}

/**
 * Remote side of durable deletion. `tombstone` is the durable fact (an
 * owner-signed AddData with the tombstone commitments, recorded by the
 * gateway); `deleteBlobVersions` removes the ciphertext of exactly the given
 * versions, one exact-key delete per version, never a scope-wide prefix: a
 * re-add registered after the tombstone lives under a higher version key and
 * is untouched by construction. Callers MUST run tombstone first: a blob
 * delete without a tombstone leaves a live registry row every replica would
 * 404 on and then wedge.
 */
export interface DeleteDataPort {
  tombstone(scope: string): Promise<TombstoneOutcome>;
  deleteBlobVersions(
    scope: string,
    versions: string[],
  ): Promise<DeleteBlobVersionsOutcome>;
}

/**
 * Blob deletion work still to do after a tombstone landed, in one of three
 * shapes:
 *   - an exact key: `{ scope, version }`;
 *   - a contiguous version range `{ scope, version: null, range }` (both
 *     bounds inclusive, decimal strings): the registry versions a tombstone
 *     covers, kept as bounds so a large tombstone version never has to be
 *     materialised key by key; passes take keys from the head and advance
 *     `from`;
 *   - an unexpanded marker `{ scope, version: null }` (no range): the gateway
 *     did not report the tombstone's version, so the covered range is not
 *     known yet; the retry expands it once the registry answers.
 */
export interface PendingBlobDeletion {
  scope: string;
  version: string | null;
  range?: { from: string; to: string };
}

/**
 * Durable retry marker for blob deletions that could not complete AFTER the
 * gateway tombstone landed (storage failure, rate limit, or a batch larger
 * than one pass may send). The tombstone already makes the deletion stick;
 * this only exists so later sync cycles finish removing the ciphertext, key
 * by key.
 */
export interface PendingBlobDeletionStore {
  list(): Promise<PendingBlobDeletion[]>;
  add(keys: PendingBlobDeletion[]): Promise<void>;
  remove(keys: PendingBlobDeletion[]): Promise<void>;
}

// FeeVerifier was the pre-X402 hook that gated reads on grant.paymentStatus
// via a side-channel call to the gateway. Replaced by the X402 layer on
// GET /v1/data/:scope (see packages/core/src/payment/x402.ts), which
// forwards the builder's signed payment to gateway.payForOperation as part
// of the read response cycle. Reads no longer block on prior paymentStatus.
