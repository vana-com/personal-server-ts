/**
 * Hashing is a port: the core never imports a crypto module. Hosts without
 * Web Crypto inject their own SHA-256.
 */

import { HashUnavailableError } from "./errors.js";

/** SHA-256 of the exact bytes, as the 32-byte digest. */
export type Sha256 = (data: Uint8Array) => Promise<Uint8Array>;

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

export async function sha256Hex(
  sha256: Sha256,
  data: Uint8Array,
): Promise<string> {
  return toHex(await sha256(data));
}

/** The default port: Web Crypto, present in Node 22, browsers and most WebViews. */
export const webCryptoSha256: Sha256 = async (data) => {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new HashUnavailableError();
  const copy = new Uint8Array(data.length);
  copy.set(data);
  return new Uint8Array(await subtle.digest("SHA-256", copy));
};

export const SHA256_HEX = /^[0-9a-f]{64}$/;
