import {
  deriveMasterKey as sdkDeriveMasterKey,
  deriveScopeKey as sdkDeriveScopeKey,
  recoverServerOwner as sdkRecoverServerOwner,
} from "@opendatalabs/vana-sdk/node";

/**
 * Extracts master key material from EIP-191 signature over "vana-master-key-v1".
 * The raw signature bytes ARE the master key material (spec §2.3).
 * @param signature - 0x-prefixed hex string (65 bytes = 130 hex chars + 0x)
 * @returns 65-byte Uint8Array
 */
export function deriveMasterKey(signature: `0x${string}`): Uint8Array {
  return sdkDeriveMasterKey(signature);
}

/**
 * Recovers the server owner address from a master key signature.
 * Uses EIP-191 recovery over the canonical message "vana-master-key-v1".
 */
export async function recoverServerOwner(
  masterKeySignature: `0x${string}`,
): Promise<`0x${string}`> {
  return sdkRecoverServerOwner(masterKeySignature);
}

/**
 * Derives a scope-specific 32-byte key via HKDF-SHA256.
 * salt = "vana", info = "scope:{scope}" (spec §2.3).
 */
export function deriveScopeKey(
  masterKey: Uint8Array,
  scope: string,
): Uint8Array {
  return sdkDeriveScopeKey(masterKey, scope);
}
