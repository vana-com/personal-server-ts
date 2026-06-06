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
  writeEnvelope(envelope: DataFileEnvelope): Promise<WriteResult>;
  writeBlockManifest?(
    scope: string,
    collectedAt: string,
    manifest: DataBlockManifest,
    blocks: DataScopeBlock[],
  ): Promise<void>;
  insertEntry(entry: NewIndexEntry): IndexEntry | Promise<IndexEntry>;
  updateFileId(path: string, fileId: string): boolean | Promise<boolean>;
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

export interface FeeVerificationInput {
  grantId: string;
  builderAddress: `0x${string}`;
  requestedScope: string;
}

export type FeeVerificationResult =
  | { ok: true }
  | { ok: false; reason?: string };

export interface FeeVerifierPort {
  verifyDataReadFee(
    input: FeeVerificationInput,
  ): Promise<FeeVerificationResult>;
}

export const allowAllFeeVerifier: FeeVerifierPort = {
  async verifyDataReadFee() {
    return { ok: true };
  },
};
