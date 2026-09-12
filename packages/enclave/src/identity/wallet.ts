/**
 * Enclave wallet: the dstack-derived key at walletPath(userPsId, epoch), used
 * as the secp256k1 private key directly. RAW bytes on purpose: the SDK's
 * `toViemAccountSecure` SHA-256-hashes the key first, which would make the
 * wallet differ from the key the agent itself signs with for this path. Using
 * the raw scalar keeps the public key in signatureChain[0] equal to this
 * wallet's, so a verifier can tie the address to the attested app.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { privateKeyToAccount, publicKeyToAddress } from "viem/accounts";
import { toHex, type TypedDataDomain } from "viem";
import type { DstackClient } from "../dstack/client.js";
import { WALLET_PURPOSE, walletPath, type UserPsId } from "./paths.js";

// Mirrors packages/server/src/keys/server-account.ts. Kept structural rather
// than imported so the server never depends on this package or vice versa.
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
  signMessage(message: string): Promise<`0x${string}`>;
}

/** Public half plus derivation evidence. Safe to persist and to show the owner. */
export interface EnclaveIdentity {
  address: `0x${string}`;
  publicKey: `0x${string}`;
  epoch: number;
  /** dstack signature chain for the wallet key; see DerivedKey. */
  signatureChain: Uint8Array[];
}

export interface EnclaveKey {
  key: Uint8Array;
  address: `0x${string}`;
  publicKey: `0x${string}`;
  signatureChain: Uint8Array[];
}

/** Full account, same shape packages/server persists in key.json plus signers. */
export interface EnclaveAccount extends ServerAccount {
  privateKey: `0x${string}`;
}

type ViemAccount = ReturnType<typeof privateKeyToAccount>;

export async function deriveEnclaveAccount(
  client: DstackClient,
  id: UserPsId,
  epoch: number,
): Promise<EnclaveAccount> {
  const { key } = await deriveEnclaveKey(client, id, epoch);
  const privateKey = toHex(key);

  try {
    const account = privateKeyToAccount(privateKey);
    return {
      address: account.address,
      publicKey: account.publicKey,
      privateKey,
      signTypedData: (params) => signTypedData(account, params),
      signMessage: (message) => account.signMessage({ message }),
    };
  } finally {
    key.fill(0);
  }
}

/**
 * Identity before registration: address and public key, nothing else kept.
 * The derived key buffer is zero-filled after computing its public values.
 */
export async function deriveEnclaveIdentity(
  client: DstackClient,
  id: UserPsId,
  epoch: number,
): Promise<EnclaveIdentity> {
  const { key, address, publicKey, signatureChain } = await deriveEnclaveKey(
    client,
    id,
    epoch,
  );
  key.fill(0);

  return {
    address,
    publicKey,
    epoch,
    signatureChain,
  };
}

export async function deriveEnclaveKey(
  client: DstackClient,
  id: UserPsId,
  epoch: number,
): Promise<EnclaveKey> {
  const { key, signatureChain } = await client.deriveKey(
    walletPath(id, epoch),
    WALLET_PURPOSE,
  );
  const publicKey = toHex(secp256k1.getPublicKey(key, false));

  return {
    key,
    address: publicKeyToAddress(publicKey),
    publicKey,
    signatureChain,
  };
}

function signTypedData(
  account: ViemAccount,
  params: SignTypedDataParams,
): Promise<`0x${string}`> {
  return account.signTypedData({
    domain: params.domain as Parameters<
      typeof account.signTypedData
    >[0]["domain"],
    types: params.types as Parameters<typeof account.signTypedData>[0]["types"],
    primaryType: params.primaryType,
    message: params.message,
  });
}
