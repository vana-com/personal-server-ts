import { encryptWithPassword as sdkEncryptWithPassword } from "@opendatalabs/vana-sdk/node";

/**
 * Encrypt plaintext using OpenPGP password-based encryption.
 * Produces the same binary format as vana-sdk.
 *
 * @param plaintext - data to encrypt (typically JSON.stringify of envelope)
 * @param password - hex-encoded scope key from deriveScopeKey()
 * @returns OpenPGP encrypted binary (Uint8Array)
 */
export async function encryptWithPassword(
  plaintext: Uint8Array,
  password: string,
): Promise<Uint8Array> {
  return sdkEncryptWithPassword(plaintext, password);
}
