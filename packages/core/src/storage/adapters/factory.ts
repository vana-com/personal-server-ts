import type { ServerConfig } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type {
  BoundedStorageAdapter,
  StorageCredentialProvider,
} from "./interface.js";
import { createGoogleDriveStorageAdapter } from "./gdrive.js";
import { createVanaSyncStorageAdapter } from "./vana.js";
import { isDefinitiveNotFound } from "./sdk.js";

export interface CreateSyncStorageAdapterParams {
  config: ServerConfig;
  serverOwner: `0x${string}`;
  serverAccount: Pick<ServerAccount, "address" | "signMessage">;
  reads?: "signed" | "public";
  audience?: string;
  fetch?: typeof fetch;
  /** Host-owned short-lived access-token broker for OAuth storage backends. */
  storageCredentials?: StorageCredentialProvider;
  /**
   * When true and backend is an external provider (e.g. `gdrive`), a definitive
   * 404 on download falls back to reading from Vana Hosted Storage so data
   * uploaded before switching backends remains readable without 404 quarantine.
   */
  fallbackReadToVana?: boolean;
}

/**
 * Single storage adapter factory for PS Node and PS Lite.
 * Selects the adapter from `config.storage.backend` without hardcoding Vana
 * Hosted Storage across call sites.
 */
export function createSyncStorageAdapter(
  params: CreateSyncStorageAdapterParams,
): BoundedStorageAdapter {
  const backend = params.config.storage.backend;

  if (backend === "gdrive") {
    const gdriveConfig = params.config.storage.config.gdrive;
    if (!gdriveConfig?.folderId) {
      throw new Error(
        "Google Drive storage backend requires storage.config.gdrive.folderId",
      );
    }
    if (!params.storageCredentials) {
      throw new Error(
        "Google Drive storage backend requires a host storageCredentials provider",
      );
    }
    const primary = createGoogleDriveStorageAdapter({
      folderId: gdriveConfig.folderId,
      credentials: params.storageCredentials,
      apiBaseUrl: gdriveConfig.apiBaseUrl,
      fetch: params.fetch,
    });
    if (!params.fallbackReadToVana) {
      return primary;
    }
    const vanaFallback = createVanaSyncStorageAdapter({
      config: params.config,
      serverOwner: params.serverOwner,
      serverAccount: params.serverAccount,
      reads: params.reads,
      audience: params.audience,
      fetch: params.fetch,
    });
    return withVanaReadFallback(primary, vanaFallback, gdriveConfig.folderId);
  }

  return createVanaSyncStorageAdapter({
    config: params.config,
    serverOwner: params.serverOwner,
    serverAccount: params.serverAccount,
    reads: params.reads,
    audience: params.audience,
    fetch: params.fetch,
  });
}

function withVanaReadFallback(
  primary: BoundedStorageAdapter,
  fallback: BoundedStorageAdapter,
  folderId: string,
): BoundedStorageAdapter {
  const gdrivePrefix = `gdrive://${folderId}/`;
  const keyFromPrimaryUrl = (url: string): string | null => {
    if (!url.startsWith(gdrivePrefix)) return null;
    const rest = url.slice(gdrivePrefix.length);
    if (!rest) return null;
    return rest
      .split("/")
      .map((segment) => decodeURIComponent(segment))
      .join("/");
  };

  return {
    ...primary,
    async download(url, signal) {
      try {
        return await primary.download(url, signal);
      } catch (err) {
        if (!isDefinitiveNotFound(err)) throw err;
        const key = keyFromPrimaryUrl(url);
        if (!key) throw err;
        return fallback.download(fallback.urlForKey(key), signal);
      }
    },
    async downloadBounded(url, budget) {
      try {
        return await primary.downloadBounded(url, budget);
      } catch (err) {
        if (!isDefinitiveNotFound(err)) throw err;
        const key = keyFromPrimaryUrl(url);
        if (!key) throw err;
        return fallback.downloadBounded(fallback.urlForKey(key), budget);
      }
    },
  };
}
