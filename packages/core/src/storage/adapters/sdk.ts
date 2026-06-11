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
      try {
        await provider().download(storageUrl);
        return true;
      } catch {
        return false;
      }
    },
  };
}

function copyBytes(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}
