import type { ByteBudget } from "../../additions/budget.js";
import type { QuotaPolicies } from "./rate-limit-policy.js";
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
   * @param signal - cancels the transfer; the call settles once it stops
   * @returns URL where the blob is accessible
   */
  upload(key: string, data: Uint8Array, signal?: AbortSignal): Promise<string>;

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
   * @param signal - cancels the transfer; the call settles once it stops
   * @returns encrypted binary data
   * @throws if blob not found
   */
  download(url: string, signal?: AbortSignal): Promise<Uint8Array>;

  /**
   * Optional. Reports the request quotas the backend publishes in its
   * `RateLimit-Policy` response header, whenever a response carries a new one.
   * Absence means the backend publishes none, and callers pace nothing to it.
   * @returns a function that ends the subscription
   */
  onRateLimitPolicy?(listener: (policies: QuotaPolicies) => void): () => void;

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
   * @param signal - cancels the probe; the call settles once it stops
   * @returns true if blob exists
   */
  exists(url: string, signal?: AbortSignal): Promise<boolean>;

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

/**
 * The user's OAuth authorization for an external storage provider (e.g. Google
 * Drive, Dropbox) was revoked, expired without refresh, or never granted.
 * Callers must surface a reconnect prompt rather than retrying blindly.
 */
export class StorageAuthRevokedError extends Error {
  readonly code = "STORAGE_AUTH_REVOKED";
  readonly status = 401;

  constructor(
    readonly provider: string,
    message = `${provider} access was revoked or is unavailable`,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "StorageAuthRevokedError";
  }
}

/**
 * The user's external storage quota is full (e.g. Google Drive
 * `storageQuotaExceeded`). Non-retryable until the user frees space or switches
 * storage providers.
 */
export class StorageQuotaExceededError extends Error {
  readonly code = "STORAGE_QUOTA_EXCEEDED";
  readonly status = 403;

  constructor(
    readonly provider: string,
    message = `${provider} storage is full`,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "StorageQuotaExceededError";
  }
}

export type ExternalOAuthStorageProvider = "gdrive" | "dropbox";

export interface StorageAccessTokenRequest {
  provider: ExternalOAuthStorageProvider;
  forceRefresh?: boolean;
  signal?: AbortSignal;
}

/**
 * Host-owned access-token broker for OAuth storage backends.
 * Refresh tokens stay strictly in the host (Desktop OS Keychain or Web server
 * session) and never enter the Personal Server runtime or config files.
 */
export interface StorageCredentialProvider {
  getAccessToken(request: StorageAccessTokenRequest): Promise<string>;
  /**
   * Optional host notification fired whenever the storage provider rejects
   * credentials after refresh (e.g. Google OAuth `invalid_grant` / 401 / 403
   * revoked), even if a background sync worker catches the per-file error.
   */
  onAuthRevoked?: (
    provider: ExternalOAuthStorageProvider,
    reason: string,
  ) => void;
  /**
   * Optional host notification fired whenever the external storage provider
   * reports quota exhaustion (e.g. Google Drive `storageQuotaExceeded`).
   */
  onQuotaExceeded?: (
    provider: ExternalOAuthStorageProvider,
    reason: string,
  ) => void;
}
