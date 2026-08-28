/**
 * Test wallet utilities for Web3Signed auth testing.
 * Provides deterministic wallets and header builders for integration tests.
 */

import { privateKeyToAccount } from "viem/accounts";
import type { PrivateKeyAccount } from "viem";
import { buildWeb3SignedHeader as sdkBuildWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";

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
  body?: Uint8Array;
  iat?: number;
  exp?: number;
  grantId?: string;
  /**
   * Optional `nonce` claim. The SDK's builder has no parameter for it yet,
   * so a proof that carries one is assembled here (same wire rules: JSON
   * with sorted keys, base64url, EIP-191 over the encoded payload).
   */
  nonce?: unknown;
}): Promise<string> {
  if (params.nonce !== undefined) {
    return buildWeb3SignedHeaderWithClaims(params, { nonce: params.nonce });
  }
  return sdkBuildWeb3SignedHeader({
    signMessage: (message: string) => params.wallet.signMessage(message),
    aud: params.aud,
    method: params.method,
    uri: params.uri,
    bodyHash: params.bodyHash,
    body: params.body,
    iat: params.iat,
    exp: params.exp,
    grantId: params.grantId,
  });
}

/** Base64url without padding, matching the SDK's encoder. */
function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCodePoint(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Sign a Web3Signed payload with extra claims the SDK builder cannot emit.
 * Same serialization as the SDK: sorted keys, compact JSON, base64url,
 * EIP-191 over the encoded string.
 */
async function buildWeb3SignedHeaderWithClaims(
  params: {
    wallet: TestWallet;
    aud: string;
    method: string;
    uri: string;
    bodyHash?: string;
    body?: Uint8Array;
    iat?: number;
    exp?: number;
    grantId?: string;
  },
  extra: Record<string, unknown>,
): Promise<string> {
  const base = await sdkBuildWeb3SignedHeader({
    signMessage: (message: string) => params.wallet.signMessage(message),
    aud: params.aud,
    method: params.method,
    uri: params.uri,
    bodyHash: params.bodyHash,
    body: params.body,
    iat: params.iat,
    exp: params.exp,
    grantId: params.grantId,
  });
  const payloadBase64 = base.slice("Web3Signed ".length).split(".")[0] ?? "";
  const padded = payloadBase64
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(payloadBase64.length + ((4 - (payloadBase64.length % 4)) % 4), "=");
  const decoded = new TextDecoder().decode(
    Uint8Array.from(atob(padded), (char) => char.charCodeAt(0)),
  );
  const claims = { ...JSON.parse(decoded), ...extra } as Record<
    string,
    unknown
  >;
  const sorted = Object.keys(claims)
    .sort()
    .reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = claims[key];
      return acc;
    }, {});
  const encoded = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(sorted)),
  );
  return `Web3Signed ${encoded}.${await params.wallet.signMessage(encoded)}`;
}
