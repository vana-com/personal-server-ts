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

export interface SchemaResolverPort {
  getSchemaForScope(scope: string): Promise<Schema | null>;
}

/** Result of registering (or idempotently resolving) a schema for a scope. */
export interface RegisteredSchema {
  schemaId: string;
  definitionUrl: string;
}

/**
 * Registers a permissive "no-schema" schema for scopes that carry unstructured
 * data (e.g. binary blobs). Idempotent on scope at the gateway: registering an
 * already-registered scope returns its existing schemaId.
 */
export interface SchemaRegistrarPort {
  registerNoSchema(scope: string): Promise<RegisteredSchema>;
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
    options: { cursor?: string; maxBytes: number },
  ): Promise<ReadScopeBlocksResponse>;
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
}

export interface RuntimeAvailabilityPort {
  isAvailable(): boolean | Promise<boolean>;
}

// FeeVerifier was the pre-X402 hook that gated reads on grant.paymentStatus
// via a side-channel call to the gateway. Replaced by the X402 layer on
// GET /v1/data/:scope (see packages/core/src/payment/x402.ts), which
// forwards the builder's signed payment to gateway.payForOperation as part
// of the read response cycle. Reads no longer block on prior paymentStatus.
