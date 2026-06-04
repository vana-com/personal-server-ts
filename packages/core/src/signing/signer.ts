/**
 * ServerSigner — signs EIP-712 messages for gateway write operations.
 * Uses the ServerAccount's derived key for all signatures.
 */

import type { ServerAccount } from "../keys/server-account.js";
import type { GatewayConfig } from "../schemas/server-config.js";
import {
  fileRegistrationDomain,
  fileDeletionDomain,
  grantRegistrationDomain,
  grantRevocationDomain,
  FILE_REGISTRATION_TYPES,
  FILE_DELETION_TYPES,
  GRANT_REGISTRATION_TYPES,
  GRANT_REVOCATION_TYPES,
  type FileRegistrationMessage,
  type FileDeletionMessage,
  type GrantRegistrationMessage,
  type GrantRevocationMessage,
} from "@opendatalabs/vana-sdk/browser";

export interface ServerSigner {
  signFileRegistration(msg: FileRegistrationMessage): Promise<`0x${string}`>;
  signFileDeletion(msg: FileDeletionMessage): Promise<`0x${string}`>;
  signGrantRegistration(msg: GrantRegistrationMessage): Promise<`0x${string}`>;
  signGrantRevocation(msg: GrantRevocationMessage): Promise<`0x${string}`>;
}

export function createServerSigner(
  account: ServerAccount,
  gatewayConfig: GatewayConfig,
): ServerSigner {
  return {
    async signFileRegistration(
      msg: FileRegistrationMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: fileRegistrationDomain(gatewayConfig),
        types: FILE_REGISTRATION_TYPES,
        primaryType: "FileRegistration",
        message: msg as unknown as Record<string, unknown>,
      });
    },

    async signFileDeletion(msg: FileDeletionMessage): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: fileDeletionDomain(gatewayConfig),
        types: FILE_DELETION_TYPES,
        primaryType: "FileDeletion",
        message: msg as unknown as Record<string, unknown>,
      });
    },

    async signGrantRegistration(
      msg: GrantRegistrationMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: grantRegistrationDomain(gatewayConfig),
        types: GRANT_REGISTRATION_TYPES,
        primaryType: "GrantRegistration",
        message: {
          ...msg,
          fileIds: msg.fileIds.map((id: bigint) => id),
        } as unknown as Record<string, unknown>,
      });
    },

    async signGrantRevocation(
      msg: GrantRevocationMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: grantRevocationDomain(gatewayConfig),
        types: GRANT_REVOCATION_TYPES,
        primaryType: "GrantRevocation",
        message: msg as unknown as Record<string, unknown>,
      });
    },
  };
}
