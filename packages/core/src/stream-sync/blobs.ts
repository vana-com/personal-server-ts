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
import { mark } from "../localdb/timing.js";
import type { StreamSyncBlobs } from "./ports.js";
import {
  DEFAULT_STORAGE_ACCESS_POLICY,
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
  return {
    put: (key, bytes) =>
      guarded(async () => {
        try {
          await storage.upload(key, bytes);
        } catch (error) {
          if (error instanceof StoredBlobConflictError) return;
          throw error;
        }
      }),
    get: (key) =>
      guarded(async () => {
        const url = storage.urlForKey(key);
        const startedAt = Date.now();
        const kind = /\/h-[^/]*$/.test(key)
          ? "head"
          : /\/g\d+-p-[^/]*$/.test(key)
            ? "part"
            : "other";
        try {
          const bytes = await storage.download(url);
          mark("storage.get.ok", { kind, ms: Date.now() - startedAt });
          return bytes;
        } catch (error) {
          mark("storage.get.failed", {
            kind,
            ms: Date.now() - startedAt,
            error: (error instanceof Error
              ? error.message
              : String(error)
            ).slice(0, 80),
          });
          // A transient failure is retried, never read as "absent".
          if (isTransientStorageError(error)) throw error;
          if (isDefinitiveNotFound(error)) return null;
          if (!(await storage.exists(url))) return null;
          throw error;
        }
      }),
  };
}
