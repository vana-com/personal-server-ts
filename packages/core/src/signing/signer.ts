/**
 * ServerSigner — signs EIP-712 messages for gateway write operations.
 * Uses the ServerAccount's derived key for all signatures.
 */

import type { ServerAccount } from "../keys/server-account.js";
import type { GatewayConfig } from "../schemas/server-config.js";
import {
  grantRegistrationDomain,
  grantRevocationDomain,
  dataRegistryDomain,
  GRANT_REGISTRATION_TYPES,
  GRANT_REVOCATION_TYPES,
  ADD_DATA_TYPES,
  RECORD_DATA_ACCESS_TYPES,
  type GrantRegistrationMessage,
  type GrantRevocationMessage,
  type AddDataMessage,
  type RecordDataAccessMessage,
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
  signGrantRegistration(msg: GrantRegistrationMessage): Promise<`0x${string}`>;
  signGrantRevocation(msg: GrantRevocationMessage): Promise<`0x${string}`>;
  /**
   * DPv2 AddData attestation: registers (scope, dataHash, metadataHash) at
   * the supplied expectedVersion on behalf of `ownerAddress`. The signer is
   * the personal server's account; the on-chain contract validates that this
   * server is a registered trusted server of the owner.
   */
  signAddData(msg: AddDataMessage): Promise<`0x${string}`>;
  /**
   * RECORD_DATA_ACCESS attestation: a server-signed delivery receipt that a
   * specific (scope, version) was served to `accessor`. Emitted on every
   * successful GET /v1/data/:scope; builders attach it to the AccessRecord
   * on their next gateway.payForOperation call so the gateway can settle
   * it on-chain via DataRegistryV2.recordDataAccess.
   *
   * recordId is a per-event bytes32 the contract pins to prevent replay.
   */
  signRecordDataAccess(msg: RecordDataAccessMessage): Promise<`0x${string}`>;
  /** SchemaRegistration EIP-712 for the gateway's POST /v1/schemas (binary /
   * "no schema" auto-registration). Signed against the Data Refiner Registry. */
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

    async signRecordDataAccess(
      msg: RecordDataAccessMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: dataRegistryDomain(gatewayConfig),
        types: RECORD_DATA_ACCESS_TYPES,
        primaryType: "RecordDataAccess",
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
