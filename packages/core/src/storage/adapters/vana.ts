import { createVanaStorageProvider } from "@opendatalabs/vana-sdk/browser";
import { StorageError } from "@opendatalabs/vana-sdk/storage/index";
import { ServerSigningUnavailableError } from "../../errors/catalog.js";
import type { ServerConfig } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type { StorageAdapter } from "./interface.js";
import { createSdkStorageAdapter } from "./sdk.js";

// Default endpoint baked into the SDK's vana-storage provider; mirrored here
// so urlForKey resolves to the same host the provider uploads to when no
// explicit apiUrl is configured.
const DEFAULT_VANA_STORAGE_ENDPOINT = "https://storage.vana.org";
const GET_METHOD = "GET";
const PUBLIC_READS = "public";
const DOWNLOAD_ERROR = "DOWNLOAD_ERROR";
const DOWNLOAD_FAILED = "DOWNLOAD_FAILED";
const VANA_STORAGE = "vana-storage";

/** Storage base URL the sync adapter targets (config override or SDK default). */
export function resolveVanaStorageEndpoint(config: ServerConfig): string {
  return (
    config.storage.config.vana?.apiUrl ?? DEFAULT_VANA_STORAGE_ENDPOINT
  ).replace(/\/+$/, "");
}

export function createVanaSyncStorageAdapter(params: {
  config: ServerConfig;
  serverOwner: `0x${string}`;
  serverAccount: ServerAccount;
  reads?: "signed" | "public";
}): StorageAdapter {
  const endpoint = resolveVanaStorageEndpoint(params.config);
  // The SDK's vana-storage provider lowercases the owner before building the
  // blob path (and its URL validator compares against the lowercased form),
  // so urlForKey MUST lowercase too or the reconstructed download URL won't
  // match the uploaded blob's key.
  // serverOwner is already a 0x-hex address; lowercasing preserves that, but
  // .toLowerCase() widens to string. vana-sdk 3.14.0 types the provider's
  // ownerAddress as `0x${string}`, so re-narrow to the known-hex form.
  const owner = params.serverOwner.toLowerCase() as `0x${string}`;
  // Storage blob paths are scoped by the protocol chain id so data for the same
  // owner/scope/version never collides across networks. The chain id is the
  // gateway's — it is never inferred from the storage host (apiUrl), which
  // selects the product host independently.
  const chainId = params.config.gateway.chainId;

  // enclave sandbox --> public blob GET ----------> vana-storage
  // desktop/cloud ---> signed PUT / GET / DELETE -> vana-storage
  if (params.reads === PUBLIC_READS) {
    // TODO(decision): blob reads stay public (architecture, resolved 2026-09-02); revisit if storage adds read auth.
    return createPublicReadAdapter({ endpoint, chainId, owner });
  }

  return createSdkStorageAdapter(
    createVanaStorageProvider({
      endpoint: params.config.storage.config.vana?.apiUrl,
      chainId,
      ownerAddress: owner,
      signer: {
        address: params.serverAccount.address,
        signMessage: (message: string) =>
          params.serverAccount.signMessage(message),
      },
    }),
    {
      // Mirror the provider's keying: PUT/GET target
      // `${endpoint}/v1/chains/${chainId}/blobs/${owner}/${encodeURIComponent-per-segment(key)}`.
      // The download worker hands us `{scope}/{version}` and we rebuild the
      // exact URL the provider's pathFromUrl() validator accepts.
      urlForKey: (key) => {
        const subpath = key
          .split("/")
          .map((segment) => encodeURIComponent(segment))
          .join("/");
        return `${endpoint}/v1/chains/${chainId}/blobs/${owner}/${subpath}`;
      },
    },
  );
}

function createPublicReadAdapter(options: {
  endpoint: string;
  chainId: number;
  owner: `0x${string}`;
}): StorageAdapter {
  const blobPrefix = `${options.endpoint}/v1/chains/${options.chainId}/blobs/${options.owner}/`;

  function invalidBlobUrl(): StorageError {
    return new StorageError(
      "Public blob URL does not match the configured storage namespace",
      DOWNLOAD_FAILED,
      VANA_STORAGE,
    );
  }

  return createSdkStorageAdapter(
    {
      async upload() {
        throw new ServerSigningUnavailableError();
      },

      async download(storageUrl) {
        let requestUrl: string;
        try {
          requestUrl = new URL(storageUrl).href;
        } catch {
          throw invalidBlobUrl();
        }
        if (!requestUrl.startsWith(blobPrefix)) {
          throw invalidBlobUrl();
        }

        let response: Response;
        try {
          response = await fetch(requestUrl, { method: GET_METHOD });
        } catch (cause) {
          throw new StorageError(
            "vana-storage public download network error",
            DOWNLOAD_ERROR,
            VANA_STORAGE,
            { cause: cause instanceof Error ? cause : undefined },
          );
        }
        if (!response.ok) {
          throw new StorageError(
            `vana-storage download failed: ${response.status} ${response.statusText}`,
            DOWNLOAD_FAILED,
            VANA_STORAGE,
          );
        }

        return response.blob();
      },

      async delete() {
        throw new ServerSigningUnavailableError();
      },
    },
    {
      urlForKey(key) {
        const subpath = key
          .split("/")
          .map((segment) => encodeURIComponent(segment))
          .join("/");
        return `${blobPrefix}${subpath}`;
      },
    },
  );
}
