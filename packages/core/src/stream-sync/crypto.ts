/**
 * Default crypto ports: Keccak-256, SHA-256 and HMAC from @noble/hashes (the
 * same in Node and browsers), the namespace key `K_ns` and per-object
 * encryption with the per-scope key, as the legacy upload path does.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  decryptWithPassword,
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import {
  NAMESPACE_KEY_LABEL,
  type HashPorts,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { streamMasterKey } from "../keys/owner-master-key.js";
import type { StreamSyncKeyPorts } from "./ports.js";

export const streamSyncHashes: HashPorts = {
  sha256: async (data) => nobleSha256(data),
  keccak256: async (data) => keccak_256(data),
};

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Key ports bound to the stream-sync master key of the owner signature.
 *
 * The ports take the signature, not a master key: the stream-sync master key
 * is the signature in one normal form (`streamMasterKey`), so
 * every encoding of one signature gives the same `ns`, `keyCheck`, head and
 * part keys. Legacy scope keys keep the raw signature and do not use this.
 *
 * `deriveScopeKey` is HKDF over the name; it does not validate the scope, so
 * physical names are safe here.
 */
export function createStreamSyncKeyPorts(
  ownerSignature: Uint8Array | string,
): StreamSyncKeyPorts {
  const masterKey = streamMasterKey(ownerSignature);
  const kNs = deriveScopeKey(masterKey, NAMESPACE_KEY_LABEL);
  const password = (scope: string) => hex(deriveScopeKey(masterKey, scope));
  return {
    async namespaceHmac(message) {
      return hmac(nobleSha256, kNs, message);
    },
    async encrypt(scope, clear) {
      return encryptWithPassword(clear, password(scope));
    },
    async decrypt(scope, cipher) {
      return decryptWithPassword(cipher, password(scope));
    },
  };
}
