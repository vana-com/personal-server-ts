import type { ByteBudget } from "../../additions/budget.js";
/**
 * Abstract storage backend adapter.
 * All methods operate on encrypted binary blobs.
 * Keys are opaque strings (e.g., "{scope}/{collectedAt}").
 */
export interface StorageAdapter {
  /**
   * Upload an encrypted blob to the storage backend.
   *
   * A key names one data version, so a backend that can refuse to replace
   * stored bytes (vana-storage keys are write-once) must do so: re-sending
   * identical bytes succeeds, and different bytes throw
   * {@link StoredBlobConflictError} with the stored bytes left unchanged.
   * @param key - unique storage key / path
   * @param data - encrypted binary data
   * @returns URL where the blob is accessible
   */
  upload(key: string, data: Uint8Array): Promise<string>;

  /**
   * Resolve the canonical URL for a storage key WITHOUT uploading.
   *
   * The personal server owns the key layout (`{scope}/{version}`), so the
   * download worker can reconstruct a blob's URL from a DataPointRecord —
   * which carries `scope` + `expectedVersion` but no URL — and fetch it
   * via {@link download}. Must be the inverse of {@link upload}'s keying:
   * `download(urlForKey(key))` returns what `upload(key, data)` stored.
   */
  urlForKey(key: string): string;

  /**
   * Download an encrypted blob from the storage backend.
   * @param url - storage URL returned by upload()
   * @returns encrypted binary data
   * @throws if blob not found
   */
  download(url: string): Promise<Uint8Array>;

  /** Optional bounded transport. Absence means budgeted recovery is unavailable. */
  downloadBounded?(url: string, budget: ByteBudget): Promise<Uint8Array>;

  /**
   * Delete an encrypted blob from the storage backend.
   * @param url - storage URL
   * @returns true if deleted, false if not found
   */
  delete(url: string): Promise<boolean>;

  /**
   * Check if a blob exists in the storage backend.
   * @param url - storage URL
   * @returns true if blob exists
   */
  exists(url: string): Promise<boolean>;

  /**
   * Bulk delete all blobs for a scope.
   * Optional — not all backends support bulk delete.
   * @param scope - scope identifier (dot notation)
   * @returns count of blobs deleted
   */
  deleteScope?(scope: string): Promise<number>;

  /**
   * Delete all blobs for the owner.
   * Optional — not all backends support bulk delete.
   * @returns count of blobs deleted
   */
  deleteAll?(): Promise<number>;
}

/** An adapter whose every read stops at a caller's byte budget. */
export type BoundedStorageAdapter = StorageAdapter &
  Required<Pick<StorageAdapter, "downloadBounded">>;

/**
 * The upload key already holds different bytes, which the backend kept.
 * Callers decide whether those bytes are theirs (same plaintext, different
 * ciphertext) or another writer's.
 */
export class StoredBlobConflictError extends Error {
  constructor(readonly key: string) {
    super(`Storage key ${key} already holds different bytes`);
    this.name = "StoredBlobConflictError";
  }
}
