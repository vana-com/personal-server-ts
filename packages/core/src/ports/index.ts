import type { Builder, Schema, ServerInfo } from "../gateway/client.js";
import type { GatewayGrantResponse } from "../grants/types.js";
import type { FileListResult, FileRecord } from "../sync/types.js";

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
