/**
 * ServerSigner — signs EIP-712 messages for gateway write operations.
 * Uses the ServerAccount's derived key for all signatures.
 */

import type { ServerAccount } from "../keys/server-account.js";
import type { GatewayConfig } from "../schemas/server-config.js";
import {
  fileRegistrationDomain,
  grantRegistrationDomain,
  grantRevocationDomain,
  dataRegistryDomain,
  FILE_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  GRANT_REVOCATION_TYPES,
  ADD_DATA_TYPES,
  type FileRegistrationMessage,
  type GrantRegistrationMessage,
  type GrantRevocationMessage,
  type AddDataMessage,
} from "@opendatalabs/vana-sdk/browser";

export interface ServerSigner {
  signFileRegistration(msg: FileRegistrationMessage): Promise<`0x${string}`>;
  signGrantRegistration(msg: GrantRegistrationMessage): Promise<`0x${string}`>;
  signGrantRevocation(msg: GrantRevocationMessage): Promise<`0x${string}`>;
  /**
   * DPv2 AddData attestation: registers (scope, dataHash, metadataHash) at
   * the supplied expectedVersion on behalf of `ownerAddress`. The signer is
   * the personal server's account; the on-chain contract validates that this
   * server is a registered trusted server of the owner.
   */
  signAddData(msg: AddDataMessage): Promise<`0x${string}`>;
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

    async signGrantRegistration(
      msg: GrantRegistrationMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: grantRegistrationDomain(gatewayConfig),
        types: GRANT_REGISTRATION_TYPES,
        primaryType: "GrantRegistration",
        // Canary GrantRegistrationMessage is structured:
        //   {grantorAddress, granteeId, scopes, grantVersion, expiresAt}
        // No JSON `grant` blob, no `fileIds`. The legacy mapping that
        // converted bigint fileIds is gone with the field itself.
        message: msg as unknown as Record<string, unknown>,
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

    async signAddData(msg: AddDataMessage): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: dataRegistryDomain(gatewayConfig),
        types: ADD_DATA_TYPES,
        primaryType: "AddData",
        message: msg as unknown as Record<string, unknown>,
      });
    },
  };
}
