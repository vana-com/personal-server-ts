import { readBoundedResponse } from "../../additions/budget.js";
import { createVanaStorageProvider } from "@opendatalabs/vana-sdk/browser";
import { StorageError } from "@opendatalabs/vana-sdk/storage/index";
import { ServerSigningUnavailableError } from "../../errors/catalog.js";
import type { ServerConfig } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type { BoundedStorageAdapter, StorageAdapter } from "./interface.js";
import { createAudienceVanaAdapter } from "./vana-audience.js";
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
const ENCODED_PATH_SEPARATOR_PATTERN = /%(?:2f|5c)/i;

/** Storage base URL the sync adapter targets (config override or SDK default). */
export function resolveVanaStorageEndpoint(config: ServerConfig): string {
  return (
    config.storage.config.vana?.apiUrl ?? DEFAULT_VANA_STORAGE_ENDPOINT
  ).replace(/\/+$/, "");
}

export function createVanaSyncStorageAdapter(params: {
  config: ServerConfig;
  serverOwner: `0x${string}`;
  serverAccount: Pick<ServerAccount, "address" | "signMessage">;
  reads?: "signed" | "public";
  /** Authentication origin, independently of a preview routing endpoint. */
  audience?: string;
}): BoundedStorageAdapter {
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
  const downloadBounded = boundedBlobDownload(
    `${endpoint}/v1/chains/${chainId}/blobs/${owner}/`,
  );
  if (params.reads === PUBLIC_READS) {
    // TODO(decision): blob reads stay public (architecture, resolved 2026-09-02); revisit if storage adds read auth.
    return {
      ...createPublicReadAdapter({ endpoint, chainId, owner }),
      downloadBounded,
    };
  }

  const adapter =
    params.audience && params.audience !== endpoint
      ? createAudienceVanaAdapter({
          endpoint,
          audience: params.audience,
          chainId,
          owner,
          signer: params.serverAccount,
        })
      : createSdkStorageAdapter(
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
  return { ...adapter, downloadBounded };
}

/**
 * Blob GET is public by the existing storage contract, so signed and public
 * adapters read the canonical URL directly. The read never enters SDK blob
 * buffering: it stops on `Content-Length` or cancels the stream at the budget.
 */
function boundedBlobDownload(
  prefix: string,
): BoundedStorageAdapter["downloadBounded"] {
  return async (url, budget) => {
    const parsed = new URL(url);
    if (
      !parsed.href.startsWith(prefix) ||
      ENCODED_PATH_SEPARATOR_PATTERN.test(parsed.pathname)
    )
      throw new Error("Blob URL does not match configured namespace");
    budget.charge();
    const response = await fetch(parsed.href, {
      signal: budget.signal,
      cache: "no-store",
      redirect: "error",
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Blob download failed (${response.status})`);
    }
    return readBoundedResponse(response, budget);
  };
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
          const parsed = new URL(storageUrl);
          if (ENCODED_PATH_SEPARATOR_PATTERN.test(parsed.pathname)) {
            throw invalidBlobUrl();
          }
          requestUrl = parsed.href;
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
