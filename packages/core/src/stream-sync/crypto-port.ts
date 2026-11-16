/**
 * The byte-level primitives a part publish spends its CPU on: SHA-256 of a
 * part, ChaCha20-Poly1305 over 64 KiB chunks, and the Keccak-256 that names a
 * log segment (a reader hashes every byte of every segment it applies). Core runs everywhere, so it
 * ships the pure-JS noble implementation (`nobleStreamCrypto`); a host with a
 * native implementation passes its own. Both must give the same bytes for the
 * same inputs, so a blob sealed by one opens with the other and a part hash
 * does not depend on the host. HKDF and the framing stay in `stream-aead.ts`:
 * they run once per part and are not worth a port.
 *
 * This module imports no `node:` module, so a browser bundle can use it.
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { sha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";

export interface StreamCryptoPort {
  sha256(data: Uint8Array): Uint8Array;
  /** Keccak-256 (Ethereum's, not SHA3-256) of the exact bytes. */
  keccak256(data: Uint8Array): Uint8Array;
  /** ChaCha20-Poly1305 (RFC 8439), no associated data: `ciphertext || 16-byte tag`. */
  seal(key: Uint8Array, nonce: Uint8Array, plain: Uint8Array): Uint8Array;
  /** The inverse of `seal`. Throws when the tag does not verify. */
  open(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array): Uint8Array;
}

export const nobleStreamCrypto: StreamCryptoPort = {
  sha256: (data) => sha256(data),
  keccak256: (data) => keccak_256(data),
  seal: (key, nonce, plain) => chacha20poly1305(key, nonce).encrypt(plain),
  open: (key, nonce, sealed) => chacha20poly1305(key, nonce).decrypt(sealed),
};

/**
 * The Keccak-256 every log hash goes through (`digestSegment`, `verifySegment`,
 * the control hashes): the host's port, else noble. This is the one place a
 * module of `localdb/` gets its keccak, so a host's native one reaches every
 * caller (`keccak-port-boundary.test.ts` holds the others out).
 */
export const keccakOf =
  (port: StreamCryptoPort | undefined) =>
  async (bytes: Uint8Array): Promise<Uint8Array> =>
    (port ?? nobleStreamCrypto).keccak256(bytes);
