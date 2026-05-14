import type { TypedDataDomain } from "viem";

export interface SignTypedDataParams {
  domain: TypedDataDomain;
  types: Record<string, Array<{ name: string; type: string }>>;
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
