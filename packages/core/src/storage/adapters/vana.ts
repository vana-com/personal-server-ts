import { createVanaStorageProvider } from "@opendatalabs/vana-sdk/browser";
import type { ServerConfig } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type { StorageAdapter } from "./interface.js";
import { createSdkStorageAdapter } from "./sdk.js";

// Default endpoint baked into the SDK's vana-storage provider; mirrored here
// so urlForKey resolves to the same host the provider uploads to when no
// explicit apiUrl is configured.
const DEFAULT_VANA_STORAGE_ENDPOINT = "https://storage.vana.org";

export function createVanaSyncStorageAdapter(params: {
  config: ServerConfig;
  serverOwner: `0x${string}`;
  serverAccount: ServerAccount;
}): StorageAdapter {
  const endpoint = (
    params.config.storage.config.vana?.apiUrl ?? DEFAULT_VANA_STORAGE_ENDPOINT
  ).replace(/\/+$/, "");
  // The SDK's vana-storage provider lowercases the owner before building the
  // blob path (and its URL validator compares against the lowercased form),
  // so urlForKey MUST lowercase too or the reconstructed download URL won't
  // match the uploaded blob's key.
  const owner = params.serverOwner.toLowerCase();
  // Storage blob paths are scoped by the protocol chain id so data for the same
  // owner/scope/version never collides across networks. The chain id is the
  // gateway's — it is never inferred from the storage host (apiUrl), which
  // selects the product host independently.
  const chainId = params.config.gateway.chainId;

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
