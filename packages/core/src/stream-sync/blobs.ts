/**
 * Stream-sync blobs on a Personal Server `StorageAdapter`.
 *
 * Blob names are content addressed by the hash of the clear bytes, and
 * encryption is randomized, so a second upload of the same name carries
 * different ciphertext for the same clear bytes. The stored copy is kept.
 */

import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../storage/adapters/interface.js";
import type { StreamSyncBlobs } from "./ports.js";

export function createStorageStreamSyncBlobs(
  storage: StorageAdapter,
): StreamSyncBlobs {
  return {
    async put(key, bytes) {
      try {
        await storage.upload(key, bytes);
      } catch (error) {
        if (error instanceof StoredBlobConflictError) return;
        throw error;
      }
    },
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
