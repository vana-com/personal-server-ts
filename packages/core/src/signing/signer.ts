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

/**
 * EIP-712 typed-data for schema registration (gateway POST /v1/schemas).
 *
 * Not provided by the SDK — schema registration is signed against the Data
 * Refiner Registry contract (distinct from the file/server/grant contracts),
 * so we define the domain + types here. Domain name/version match the rest of
 * the Data Portability protocol ("Vana Data Portability" / "1").
 */
export const SCHEMA_REGISTRATION_TYPES: Record<
  string,
  Array<{ name: string; type: string }>
> = {
  SchemaRegistration: [
    { name: "ownerAddress", type: "address" },
    { name: "name", type: "string" },
    { name: "definitionUrl", type: "string" },
    { name: "scope", type: "string" },
    { name: "dialect", type: "string" },
  ],
};

export interface SchemaRegistrationMessage {
  ownerAddress: `0x${string}`;
  name: string;
  definitionUrl: string;
  scope: string;
  dialect: string;
}

export interface ServerSigner {
  /** Address that signs (the server account). Schema registration requires
   * the EIP-712 signer to equal the registered ownerAddress. */
  readonly address: `0x${string}`;
  signFileRegistration(msg: FileRegistrationMessage): Promise<`0x${string}`>;
  signFileDeletion(msg: FileDeletionMessage): Promise<`0x${string}`>;
  signGrantRegistration(msg: GrantRegistrationMessage): Promise<`0x${string}`>;
  signGrantRevocation(msg: GrantRevocationMessage): Promise<`0x${string}`>;
  signSchemaRegistration(
    msg: SchemaRegistrationMessage,
  ): Promise<`0x${string}`>;
}

export function createServerSigner(
  account: ServerAccount,
  gatewayConfig: GatewayConfig,
): ServerSigner {
  return {
    address: account.address,

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

    async signSchemaRegistration(
      msg: SchemaRegistrationMessage,
    ): Promise<`0x${string}`> {
      const verifyingContract = gatewayConfig.contracts.dataRefinerRegistry;
      if (!verifyingContract) {
        throw new Error(
          "Cannot sign schema registration: gateway.contracts.dataRefinerRegistry is not configured (set GATEWAY_DATA_REFINER_REGISTRY)",
        );
      }
      return account.signTypedData({
        domain: {
          name: "Vana Data Portability",
          version: "1",
          chainId: gatewayConfig.chainId,
          verifyingContract: verifyingContract as `0x${string}`,
        },
        types: SCHEMA_REGISTRATION_TYPES,
        primaryType: "SchemaRegistration",
        message: msg as unknown as Record<string, unknown>,
      });
    },
  };
}
