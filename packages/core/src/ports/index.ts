import type {
  Builder,
  DataFileEnvelope,
  FileListResult,
  FileRecord,
  GatewayGrantResponse,
  Schema,
  ServerInfo,
} from "@opendatalabs/vana-sdk/browser";
import type { WriteResult } from "../storage/hierarchy/index.js";
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
  getFile(fileId: string): Promise<FileRecord | null>;
  listFilesSince(owner: string, cursor: string | null): Promise<FileListResult>;
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

export interface FileRegistrySyncRegistryPort {
  getFile(fileId: string): Promise<FileRecord | null>;
  listFilesSince(owner: string, cursor: string | null): Promise<FileListResult>;
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

export interface DataStoragePort extends RuntimeStoragePort {
  listScopes(options: DataStorageScopeListOptions): {
    scopes: ScopeSummary[];
    total: number;
  };
  listVersions(scope: string, options: DataStorageListOptions): IndexEntry[];
  countVersions(scope: string): number;
  findEntry(lookup: DataStorageEntryLookup): IndexEntry | undefined;
  findByFileId(fileId: string): IndexEntry | undefined;
  findUnsynced(options?: { limit?: number }): IndexEntry[];
  readEnvelope(scope: string, collectedAt: string): Promise<DataFileEnvelope>;
  writeEnvelope(envelope: DataFileEnvelope): Promise<WriteResult>;
  insertEntry(entry: NewIndexEntry): IndexEntry | Promise<IndexEntry>;
  updateFileId(path: string, fileId: string): boolean | Promise<boolean>;
  /** Highest stored DPv2 `version` for a scope; 0 if none. */
  findLatestVersionByScope(scope: string): number | Promise<number>;
  /** Stamps the DPv2 dataPointId on an entry after registerDataPoint. */
  updateDataPointId(
    path: string,
    dataPointId: string,
  ): boolean | Promise<boolean>;
  deleteScope(scope: string): Promise<number>;
}

export interface RuntimeAvailabilityPort {
  isAvailable(): boolean | Promise<boolean>;
}

// FeeVerifier was the pre-X402 hook that gated reads on grant.paymentStatus
// via a side-channel call to the gateway. Replaced by the X402 layer on
// GET /v1/data/:scope (see packages/core/src/payment/x402.ts), which
// forwards the builder's signed payment to gateway.payForOperation as part
// of the read response cycle. Reads no longer block on prior paymentStatus.
