/**
 * Test wallet utilities for Web3Signed auth testing.
 * Provides deterministic wallets and header builders for integration tests.
 */

import { privateKeyToAccount } from "viem/accounts";
import type { PrivateKeyAccount } from "viem";
import { buildWeb3SignedHeader as sdkBuildWeb3SignedHeader } from "@opendatalabs/vana-sdk/node";

export interface TestWallet {
  address: `0x${string}`;
  privateKey: `0x${string}`;
  signMessage(message: string): Promise<`0x${string}`>;
  signTypedData(params: {
    domain: Record<string, unknown>;
    types: Record<string, Array<{ name: string; type: string }>>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<`0x${string}`>;
}

/**
 * Create a deterministic test wallet from a seed index.
 * Seed 0 produces a fixed private key, seed N produces key = padded hex(N+1).
 */
export function createTestWallet(seed: number = 0): TestWallet {
  // Derive a deterministic private key from the seed.
  // Pad the (seed + 1) value to 32 bytes hex.
  const keyValue = (seed + 1).toString(16).padStart(64, "0");
  const privateKey = `0x${keyValue}` as `0x${string}`;
  const account: PrivateKeyAccount = privateKeyToAccount(privateKey);

  return {
    address: account.address,
    privateKey,
    async signMessage(message: string): Promise<`0x${string}`> {
      return account.signMessage({ message });
    },
    async signTypedData(params): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: params.domain as Parameters<
          typeof account.signTypedData
        >[0]["domain"],
        types: params.types as Parameters<
          typeof account.signTypedData
        >[0]["types"],
        primaryType: params.primaryType,
        message: params.message,
      });
    },
  };
}

/**
 * Build a valid Web3Signed Authorization header value.
 * Format: "Web3Signed {base64url(payload)}.{signature}"
 *
 * The payload is JSON with sorted keys, signed via EIP-191.
 */
export async function buildWeb3SignedHeader(params: {
  wallet: TestWallet;
  aud: string;
  method: string;
  uri: string;
  bodyHash?: string;
  iat?: number;
  exp?: number;
  grantId?: string;
}): Promise<string> {
  return sdkBuildWeb3SignedHeader({
    signMessage: (message: string) => params.wallet.signMessage(message),
    aud: params.aud,
    method: params.method,
    uri: params.uri,
    bodyHash: params.bodyHash,
    iat: params.iat,
    exp: params.exp,
    grantId: params.grantId,
  });
}
