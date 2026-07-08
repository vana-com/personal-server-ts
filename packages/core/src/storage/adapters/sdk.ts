import type { StorageAdapter } from "./interface.js";

export interface SdkStorageProvider {
  upload(
    file: Blob,
    filename?: string,
  ): Promise<{ url: string; size?: number; contentType?: string }>;
  download(url: string): Promise<Blob>;
  delete(url: string): Promise<boolean>;
}
export type SdkStorageProviderFactory = () => SdkStorageProvider;

export interface SdkStorageAdapterOptions {
  /**
   * Reconstruct a blob URL from a storage key without uploading. The personal
   * server owns the key layout, so the download worker can resolve a URL from
   * a DataPointRecord's (scope, version). Supplied by the concrete backend
   * (e.g. vana.ts knows endpoint + owner). Defaults to identity so in-memory
   * test backends that treat the key itself as the URL keep working.
   */
  urlForKey?: (key: string) => string;
}

export function createSdkStorageAdapter(
  providerOrFactory: SdkStorageProvider | SdkStorageProviderFactory,
  options?: SdkStorageAdapterOptions,
): StorageAdapter {
  let cachedProvider: SdkStorageProvider | undefined;
  const urlForKey = options?.urlForKey ?? ((key: string) => key);

  function provider(): SdkStorageProvider {
    if (typeof providerOrFactory === "function") {
      cachedProvider ??= providerOrFactory();
      return cachedProvider;
    }
    return providerOrFactory;
  }

  return {
    async upload(key, data) {
      const result = await provider().upload(
        new Blob([copyBytes(data)], { type: "application/octet-stream" }),
        key,
      );
      return result.url;
    },

    urlForKey,

    async download(storageUrl) {
      const blob = await provider().download(storageUrl);
      return new Uint8Array(await blob.arrayBuffer());
    },

    async delete(storageUrl) {
      return provider().delete(storageUrl);
    },

    async exists(storageUrl) {
      // The SDK provider interface has no HEAD/metadata call, so existence is
      // probed with a full download (follow-up: add a HEAD to the vana
      // provider). Only a definitive not-found may report "absent" — a
      // transient error (network, 5xx, auth blip) must throw instead, so the
      // caller retries next cycle rather than acting on a false "missing"
      // (e.g. the upload worker's blob heal overwriting a blob that is
      // actually there).
      try {
        await provider().download(storageUrl);
        return true;
      } catch (err) {
        if (isDefinitiveNotFound(err)) {
          return false;
        }
        throw err;
      }
    },
  };
}

// Mirrors the stable message shape of the SDK storage providers'
// download failures ("vana-storage download failed: 404 Not Found",
// "R2 download failed: 404 ..."): the status is only in the message, no
// numeric property. Providers with other message shapes (ipfs, pinata,
// dropbox) won't match and so surface as errors — safe, never a false
// "missing".
function isDefinitiveNotFound(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /download failed: (404|410)\b/.test(message);
}

function copyBytes(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}
