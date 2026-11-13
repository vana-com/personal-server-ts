/**
 * Stream-sync blobs on a Personal Server `StorageAdapter`.
 *
 * Blob names are content addressed by the hash of the clear bytes, and
 * encryption is randomized, so a second upload of the same name carries
 * different ciphertext for the same clear bytes. The stored copy is kept.
 *
 * Every call goes through one shared send gate (a quota and an in-flight
 * window, adjusted by the storage service's answers) and retries transient
 * failures, honouring Retry-After (see `send-gate.ts`, `storage-retry.ts`).
 * The retry is safe: a read changes nothing, and a repeated upload keeps the
 * stored copy.
 */

import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../storage/adapters/interface.js";
import { isDefinitiveNotFound } from "../storage/adapters/sdk.js";
import type { StreamSyncBlobs } from "./ports.js";
import {
  DEFAULT_STORAGE_ACCESS_POLICY,
  createStorageAccess,
  isTransientStorageError,
  type SendGovernor,
  type StorageAccessPolicy,
} from "./storage-retry.js";

/**
 * One governor per adapter instance: an adapter is one store, so every blob
 * wrapper made on it shares one gate, one quota and one byte budget. The
 * first wrapper's policy builds the governor; a later wrapper's is ignored.
 */
const governors = new WeakMap<StorageAdapter, SendGovernor>();

function governorFor(
  storage: StorageAdapter,
  policy: StorageAccessPolicy,
): SendGovernor {
  let governor = governors.get(storage);
  if (!governor) {
    governor = createStorageAccess(policy);
    // The quota the service publishes, if it publishes one, paces the gate.
    // The adapter replays one it already saw.
    governor.follow(storage);
    governors.set(storage, governor);
  }
  return governor;
}

export function createStorageStreamSyncBlobs(
  storage: StorageAdapter,
  policy: Partial<StorageAccessPolicy> = {},
): StreamSyncBlobs {
  const governor = governorFor(storage, {
    ...DEFAULT_STORAGE_ACCESS_POLICY,
    ...policy,
  });
  const probe = (key: string) =>
    governor.run({ kind: "head" }, (signal) =>
      storage.exists(storage.urlForKey(key), signal),
    );
  return {
    governor,
    put: (key, bytes, beforeAttempt) =>
      governor.run({ kind: "put", beforeAttempt }, async (signal) => {
        try {
          await storage.upload(key, bytes, signal);
        } catch (error) {
          if (error instanceof StoredBlobConflictError) return;
          throw error;
        }
      }),
    // A HEAD probe through the same retry and limiter as `get`. The adapter
    // answers "absent" only for a definitive not-found.
    exists: probe,
    get: async (key) => {
      const url = storage.urlForKey(key);
      const read = await governor.run({ kind: "get" }, async (signal) => {
        try {
          return {
            kind: "bytes" as const,
            bytes: await storage.download(url, signal),
          };
        } catch (error) {
          // A transient failure is retried, never read as "absent".
          if (isTransientStorageError(error)) throw error;
          return { kind: "failure" as const, failure: error };
        }
      });
      if (read.kind === "bytes") return read.bytes;
      if (isDefinitiveNotFound(read.failure)) return null;
      // The GET's slot is free by now: the probe asks for its own, so a probe
      // never waits for a slot while holding one.
      if (!(await probe(key))) return null;
      throw read.failure;
    },
  };
}
