import { readBoundedResponse } from "../../additions/budget.js";
import { createVanaStorageProvider } from "@opendatalabs/vana-sdk/browser";
import { StorageError } from "@opendatalabs/vana-sdk/storage/index";
import { ServerSigningUnavailableError } from "../../errors/catalog.js";
import type { ServerConfig } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type { BoundedStorageAdapter, StorageAdapter } from "./interface.js";
import { createAudienceVanaAdapter } from "./vana-audience.js";
import { createSdkStorageAdapter, type SdkStorageProvider } from "./sdk.js";
import {
  settleFailure,
  throttleAwareFetch,
  throttleError,
} from "./throttle.js";
import {
  createRateLimitPolicyFeed,
  type RateLimitPolicyFeed,
} from "./rate-limit-policy.js";
import { parseRetryAfterHeader } from "../../stream-sync/storage-retry.js";

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
  const blobPrefix = `${endpoint}/v1/chains/${chainId}/blobs/${owner}/`;
  const feed = createRateLimitPolicyFeed();
  const downloadBounded = boundedBlobDownload(blobPrefix, feed.fetch);
  if (params.reads === PUBLIC_READS) {
    // TODO(decision): blob reads stay public (architecture, resolved 2026-09-02); revisit if storage adds read auth.
    return {
      ...createPublicReadAdapter({ endpoint, chainId, owner, feed }),
      exists: headProbe(blobPrefix, feed.fetch),
      downloadBounded,
      onRateLimitPolicy: feed.subscribe,
    };
  }

  const sdkProvider = (signal?: AbortSignal) =>
    createVanaStorageProvider({
      endpoint: params.config.storage.config.vana?.apiUrl,
      chainId,
      ownerAddress: owner,
      signer: {
        address: params.serverAccount.address,
        signMessage: (message: string) =>
          params.serverAccount.signMessage(message),
      },
      // Always set: a 429 or 503 must reach the send governor, not the SDK's
      // own retry loop (see `throttleAwareFetch`).
      fetchImpl: throttleAwareFetch((input, init) =>
        feed.fetch(input, { ...init, ...(signal ? { signal } : {}) }),
      ),
    });
  const adapter =
    params.audience && params.audience !== endpoint
      ? createAudienceVanaAdapter({
          endpoint,
          audience: params.audience,
          chainId,
          owner,
          signer: params.serverAccount,
          feed,
        })
      : createSdkStorageAdapter(sdkProvider(), {
          // The provider's transport is its `fetchImpl`; a provider built
          // per signal sends every request of one call under that signal.
          providerFor: (signal) => sdkProvider(signal),
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
        });
  return {
    ...adapter,
    exists: headProbe(blobPrefix, feed.fetch),
    downloadBounded,
    onRateLimitPolicy: feed.subscribe,
  };
}

/**
 * Existence by an HTTP HEAD on the blob URL: the body is never read. Storage
 * serves blob HEAD publicly, like GET, so the probe carries no authorization.
 * Only a 200 answers "present" and only a 404 "absent"; every other status
 * (204, 202, redirects included) throws, so the caller's
 * retry policy applies and a refusal is never read as a missing blob.
 */
function headProbe(
  prefix: string,
  fetchFn: typeof fetch,
): StorageAdapter["exists"] {
  return async (url, signal) => {
    const parsed = new URL(url);
    if (
      !parsed.href.startsWith(prefix) ||
      ENCODED_PATH_SEPARATOR_PATTERN.test(parsed.pathname)
    )
      throw new Error("Blob URL does not match configured namespace");
    const response = await fetchFn(parsed.href, {
      method: "HEAD",
      cache: "no-store",
      redirect: "error",
      ...(signal ? { signal } : {}),
    });
    await response.body?.cancel();
    if (response.status === 200) return true;
    if (response.status === 404) return false;
    if (response.status === 429 || response.status === 503) {
      throw Object.assign(new Error(`Blob probe failed (${response.status})`), {
        status: response.status,
        retryAfterMs: parseRetryAfterHeader(
          response.headers.get("retry-after"),
          Date.now(),
        ),
      });
    }
    throw Object.assign(new Error(`Blob probe failed (${response.status})`), {
      status: response.status,
    });
  };
}

/**
 * Blob GET is public by the existing storage contract, so signed and public
 * adapters read the canonical URL directly. The read never enters SDK blob
 * buffering: it stops on `Content-Length` or cancels the stream at the budget.
 */
function boundedBlobDownload(
  prefix: string,
  fetchFn: typeof fetch,
): BoundedStorageAdapter["downloadBounded"] {
  return async (url, budget) => {
    const parsed = new URL(url);
    if (
      !parsed.href.startsWith(prefix) ||
      ENCODED_PATH_SEPARATOR_PATTERN.test(parsed.pathname)
    )
      throw new Error("Blob URL does not match configured namespace");
    budget.charge();
    const response = await fetchFn(parsed.href, {
      signal: budget.signal,
      cache: "no-store",
      redirect: "error",
    });
    if (!response.ok) {
      const retryAfterMs = await settleFailure(response);
      throw Object.assign(
        new Error(`Blob download failed (${response.status})`),
        {
          status: response.status,
          ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
        },
      );
    }
    return readBoundedResponse(response, budget);
  };
}

function createPublicReadAdapter(options: {
  endpoint: string;
  chainId: number;
  owner: `0x${string}`;
  feed: RateLimitPolicyFeed;
}): StorageAdapter {
  const blobPrefix = `${options.endpoint}/v1/chains/${options.chainId}/blobs/${options.owner}/`;

  function invalidBlobUrl(): StorageError {
    return new StorageError(
      "Public blob URL does not match the configured storage namespace",
      DOWNLOAD_FAILED,
      VANA_STORAGE,
    );
  }

  const provider = (signal?: AbortSignal): SdkStorageProvider => ({
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
        response = await options.feed.fetch(requestUrl, {
          method: GET_METHOD,
          ...(signal ? { signal } : {}),
        });
      } catch (cause) {
        throw new StorageError(
          "vana-storage public download network error",
          DOWNLOAD_ERROR,
          VANA_STORAGE,
          { cause: cause instanceof Error ? cause : undefined },
        );
      }
      if (response.status === 429 || response.status === 503) {
        throw await throttleError(response);
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
  });

  return createSdkStorageAdapter(provider(), {
    providerFor: (signal) => provider(signal),
    urlForKey(key) {
      const subpath = key
        .split("/")
        .map((segment) => encodeURIComponent(segment))
        .join("/");
      return `${blobPrefix}${subpath}`;
    },
  });
}
