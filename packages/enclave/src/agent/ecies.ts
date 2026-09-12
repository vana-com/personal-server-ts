/** Decrypts the eccrypto format from vana-sdk src/crypto/ecies/interface.ts. */

import {
  createDecipheriv,
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";

const IV_BYTES = 16;
const PUBLIC_KEY_BYTES = 65;
const MAC_BYTES = 32;
const BLOCK_BYTES = 16;
const UNCOMPRESSED_PREFIX = 0x04;
const ENC_KEY_BYTES = 32;
const CIPHER = "aes-256-cbc";

export function decryptEcies(
  privateKey: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  const minimumBytes = IV_BYTES + PUBLIC_KEY_BYTES + BLOCK_BYTES + MAC_BYTES;
  if (payload.length < minimumBytes) {
    throw new Error("ECIES payload is too short");
  }

  const publicKeyStart = IV_BYTES;
  const ciphertextStart = publicKeyStart + PUBLIC_KEY_BYTES;
  const macStart = payload.length - MAC_BYTES;
  const iv = payload.subarray(0, IV_BYTES);
  const publicKey = payload.subarray(publicKeyStart, ciphertextStart);
  const ciphertext = payload.subarray(ciphertextStart, macStart);
  const mac = payload.subarray(macStart);

  if (
    publicKey[0] !== UNCOMPRESSED_PREFIX ||
    ciphertext.length === 0 ||
    ciphertext.length % BLOCK_BYTES !== 0
  ) {
    throw new Error("ECIES payload has an invalid shape");
  }

  const sharedPoint = secp256k1.getSharedSecret(privateKey, publicKey, false);
  const shared = sharedPoint.subarray(1, 1 + ENC_KEY_BYTES);
  const keyMaterial = createHash("sha512").update(shared).digest();
  const encKey = keyMaterial.subarray(0, ENC_KEY_BYTES);
  const macKey = keyMaterial.subarray(ENC_KEY_BYTES);

  try {
    const authenticated = payload.subarray(0, macStart);
    const expectedMac = createHmac("sha256", macKey)
      .update(authenticated)
      .digest();

    if (!timingSafeEqual(mac, expectedMac)) {
      throw new Error("ECIES authentication failed");
    }

    const decipher = createDecipheriv(CIPHER, encKey, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    sharedPoint.fill(0);
    keyMaterial.fill(0);
  }
}
