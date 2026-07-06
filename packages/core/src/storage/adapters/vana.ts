import { createVanaStorageProvider } from "@opendatalabs/vana-sdk/browser";
import type {
  ServerConfig,
  ProtocolNetwork,
} from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type { StorageAdapter } from "./interface.js";
import { createSdkStorageAdapter } from "./sdk.js";

// Default endpoint baked into the SDK's vana-storage provider; mirrored here
// so urlForKey resolves to the same host the provider uploads to when no
// explicit apiUrl is configured.
const DEFAULT_VANA_STORAGE_ENDPOINT = "https://storage.vana.org";
const LEGACY_BLOB_PATH_PREFIX = "/v1/blobs";

// Well-known Vana protocol chain ids. The storage network scopes blob paths
// and is orthogonal to the product storage host (apiUrl), so it is resolved
// from explicit config or the protocol chain id — never from the hostname.
const CHAIN_ID_TO_NETWORK: Record<number, ProtocolNetwork> = {
  1480: "mainnet",
  14800: "moksha",
};

/**
 * Resolve the protocol network that scopes storage blob paths.
 *
 * Precedence:
 *  1. explicit `storage.config.vana.network` wins;
 *  2. otherwise the gateway chain id (14800 → moksha, 1480 → mainnet);
 *  3. otherwise `undefined`, preserving legacy `/v1/blobs/...` behavior.
 *
 * The network is deliberately independent of the storage host: it is never
 * inferred from `apiUrl`.
 */
export function resolveStorageNetwork(
  config: ServerConfig,
): ProtocolNetwork | undefined {
  return (
    config.storage.config.vana?.network ??
    CHAIN_ID_TO_NETWORK[config.gateway.chainId]
  );
}

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
  const network = resolveStorageNetwork(params.config);
  // Mirror the SDK's blobPathPrefix: network-scoped when a network is resolved,
  // legacy otherwise. Kept in lockstep with the provider so urlForKey rebuilds
  // the exact path the provider's pathFromUrl() validator accepts.
  const blobPathPrefix = network
    ? `/v1/networks/${network}/blobs`
    : LEGACY_BLOB_PATH_PREFIX;

  return createSdkStorageAdapter(
    createVanaStorageProvider({
      endpoint: params.config.storage.config.vana?.apiUrl,
      network,
      ownerAddress: owner,
      signer: {
        address: params.serverAccount.address,
        signMessage: (message: string) =>
          params.serverAccount.signMessage(message),
      },
    }),
    {
      // Mirror the provider's keying: PUT/GET target
      // `${endpoint}${blobPathPrefix}/${owner}/${encodeURIComponent-per-segment(key)}`.
      // The download worker hands us `{scope}/{version}` and we rebuild the
      // exact URL the provider's pathFromUrl() validator accepts.
      urlForKey: (key) => {
        const subpath = key
          .split("/")
          .map((segment) => encodeURIComponent(segment))
          .join("/");
        return `${endpoint}${blobPathPrefix}/${owner}/${subpath}`;
      },
    },
  );
}
