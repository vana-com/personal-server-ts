/**
 * Stream-sync blobs on a Personal Server `StorageAdapter`.
 *
 * Blob names are content addressed by the hash of the clear bytes, and
 * encryption is randomized, so a second upload of the same name carries
 * different ciphertext for the same clear bytes. The stored copy is kept.
 *
 * Every call goes through one shared concurrency limit and retries transient
 * failures (see `storage-retry.ts`), because a sync cycle reads many blobs at
 * once and the storage service answers a burst with HTTP 500. The retry is
 * safe: a read changes nothing, and a repeated upload keeps the stored copy.
 */

import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../storage/adapters/interface.js";
import { isDefinitiveNotFound } from "../storage/adapters/sdk.js";
import type { StreamSyncBlobs } from "./ports.js";
import {
  DEFAULT_STORAGE_ACCESS_POLICY,
  createConcurrencyLimit,
  createStorageAccess,
  isTransientStorageError,
  type StorageAccessPolicy,
} from "./storage-retry.js";

export function createStorageStreamSyncBlobs(
  storage: StorageAdapter,
  policy: Partial<StorageAccessPolicy> = {},
): StreamSyncBlobs {
  const resolved = { ...DEFAULT_STORAGE_ACCESS_POLICY, ...policy };
  const guarded = createStorageAccess(resolved);
  // Outside `guarded`: an upload waiting for its turn holds no `maxConcurrent`
  // slot, so reads are not queued behind uploads, and its retries stay inside
  // its turn.
  const onePut = createConcurrencyLimit(
    resolved.maxConcurrentPuts,
    "maxConcurrentPuts",
  );
  return {
    put: (key, bytes, beforeAttempt) =>
      onePut(() =>
        guarded(async () => {
          try {
            await storage.upload(key, bytes);
          } catch (error) {
            if (error instanceof StoredBlobConflictError) return;
            throw error;
          }
        }, beforeAttempt),
      ),
    get: (key) =>
      guarded(async () => {
        const url = storage.urlForKey(key);
        try {
          return await storage.download(url);
        } catch (error) {
          // A transient failure is retried, never read as "absent".
          if (isTransientStorageError(error)) throw error;
          if (isDefinitiveNotFound(error)) return null;
          if (!(await storage.exists(url))) return null;
          throw error;
        }
      }),
  };
}
