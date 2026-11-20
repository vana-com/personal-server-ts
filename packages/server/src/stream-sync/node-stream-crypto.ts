/**
 * The Node host's `StreamCryptoPort`: OpenSSL SHA-256, Keccak-256 and
 * ChaCha20-Poly1305 through `node:crypto`, about ten times (SHA-256) and
 * thirty times (Keccak-256) faster than the pure-JS default on the same bytes. Same inputs give the same outputs as the noble port, so a
 * blob sealed here opens anywhere and a part hash is the same (the test next
 * to this file holds both).
 */

import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import {
  nobleStreamCrypto,
  type StreamCryptoPort,
} from "@opendatalabs/personal-server-ts-core/stream-sync";

const TAG_BYTES = 16;

/** Keccak-256 of "abc" (Ethereum's padding, not SHA3-256's `3a985da7…`). */
const KECCAK_ABC =
  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";

const opensslKeccak256 = (data: Uint8Array): Uint8Array =>
  createHash("keccak-256").update(data).digest();

/**
 * OpenSSL gained `keccak-256` in 3.2, so a Node built on an older OpenSSL has
 * none (or, if a build ever aliased the name to SHA3, a different digest).
 * The port uses it only after it has produced the known digest here; otherwise
 * it keeps noble, which is slower and gives the same bytes.
 */
function nativeKeccak256OrNoble(): StreamCryptoPort["keccak256"] {
  try {
    const digest = Buffer.from(
      opensslKeccak256(new TextEncoder().encode("abc")),
    ).toString("hex");
    if (digest === KECCAK_ABC) return opensslKeccak256;
  } catch {
    // No such digest in this OpenSSL.
  }
  return nobleStreamCrypto.keccak256;
}

export const nodeStreamCrypto: StreamCryptoPort = {
  sha256: (data) => createHash("sha256").update(data).digest(),
  keccak256: nativeKeccak256OrNoble(),
  seal(key, nonce, plain) {
    const cipher = createCipheriv("chacha20-poly1305", key, nonce, {
      authTagLength: TAG_BYTES,
    });
    const body = cipher.update(plain);
    cipher.final();
    const out = new Uint8Array(body.length + TAG_BYTES);
    out.set(body);
    out.set(cipher.getAuthTag(), body.length);
    return out;
  },
  open(key, nonce, sealed) {
    if (sealed.length < TAG_BYTES) throw new Error("sealed chunk is short");
    const split = sealed.length - TAG_BYTES;
    const decipher = createDecipheriv("chacha20-poly1305", key, nonce, {
      authTagLength: TAG_BYTES,
    });
    decipher.setAuthTag(sealed.subarray(split));
    const plain = decipher.update(sealed.subarray(0, split));
    decipher.final(); // throws when the tag does not verify
    return plain;
  },
};
