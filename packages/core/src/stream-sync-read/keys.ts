/**
 * Default host adapters of the read side: hashes from @noble/hashes (Node
 * and browsers alike), owner-key operations bound to the master key, and
 * blob reads from a Personal Server `StorageAdapter`.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  decryptWithPassword,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/browser";
import {
  deriveKeyCheck,
  NAMESPACE_KEY_LABEL,
  type HashPorts,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StorageAdapter } from "../storage/adapters/interface.js";
import type { StreamSyncBlobReader, StreamSyncReadKeys } from "./ports.js";

export const streamSyncReadHashes: HashPorts = {
  sha256: async (data) => nobleSha256(data),
  keccak256: async (data) => keccak_256(data),
};

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * `deriveScopeKey` is HKDF over the name and does not validate it, so
 * physical names are safe here.
 */
export async function createStreamSyncReadKeys(
  masterKey: Uint8Array,
): Promise<StreamSyncReadKeys> {
  const kNs = deriveScopeKey(masterKey, NAMESPACE_KEY_LABEL);
  const keyCheck = await deriveKeyCheck(async (message) =>
    hmac(nobleSha256, kNs, message),
  );
  return {
    hashes: streamSyncReadHashes,
    keyCheck,
    async decrypt(scope, cipher) {
      return decryptWithPassword(cipher, hex(deriveScopeKey(masterKey, scope)));
    },
  };
}

export function createStorageBlobReader(
  storage: StorageAdapter,
): StreamSyncBlobReader {
  return {
    async get(key) {
      const url = storage.urlForKey(key);
      try {
        return await storage.download(url);
      } catch (error) {
        if (!(await storage.exists(url))) return null;
        throw error;
      }
    },
  };
}
