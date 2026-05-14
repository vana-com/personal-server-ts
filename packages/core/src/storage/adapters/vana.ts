import { createVanaStorageProvider } from "@opendatalabs/vana-sdk/browser";
import type { ServerConfig } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type { StorageAdapter } from "./interface.js";
import { createSdkStorageAdapter } from "./sdk.js";

export function createVanaSyncStorageAdapter(params: {
  config: ServerConfig;
  serverOwner: `0x${string}`;
  serverAccount: ServerAccount;
}): StorageAdapter {
  return createSdkStorageAdapter(
    createVanaStorageProvider({
      endpoint: params.config.storage.config.vana?.apiUrl,
      ownerAddress: params.serverOwner,
      signer: {
        address: params.serverAccount.address,
        signMessage: (message: string) =>
          params.serverAccount.signMessage(message),
      },
    }),
  );
}
