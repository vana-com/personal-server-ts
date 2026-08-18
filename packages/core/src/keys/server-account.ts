import type { TypedDataDomain } from "viem";

export interface SignTypedDataParams {
  domain: TypedDataDomain;
  // vana-sdk 3.14.0 declares its EIP-712 TYPES consts (GRANT_REGISTRATION_TYPES
  // etc.) as `readonly` tuples. Accept readonly field arrays so those consts can
  // be passed directly; the signer only ever reads the schema, never mutates it.
  types: Record<string, readonly { name: string; type: string }[]>;
  primaryType: string;
  message: Record<string, unknown>;
}

export interface ServerAccount {
  address: `0x${string}`;
  /** Uncompressed public key (65 bytes, 0x04 prefix). */
  publicKey: `0x${string}`;
  signTypedData(params: SignTypedDataParams): Promise<`0x${string}`>;
  /** Sign a personal message (EIP-191). */
  signMessage(message: string): Promise<`0x${string}`>;
}

export interface KeyFileData {
  address: string;
  publicKey: string;
  privateKey: string;
}
