/**
 * The Node host's `StreamCryptoPort`: OpenSSL SHA-256 and ChaCha20-Poly1305
 * through `node:crypto`, about ten times faster than the pure-JS default on
 * the same bytes. Same inputs give the same outputs as the noble port, so a
 * blob sealed here opens anywhere and a part hash is the same (the test next
 * to this file holds both).
 */

import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import type { StreamCryptoPort } from "@opendatalabs/personal-server-ts-core/stream-sync";

const TAG_BYTES = 16;

export const nodeStreamCrypto: StreamCryptoPort = {
  sha256: (data) => createHash("sha256").update(data).digest(),
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
