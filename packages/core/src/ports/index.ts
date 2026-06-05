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
  writeEnvelope(envelope: DataFileEnvelope): Promise<WriteResult>;
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
