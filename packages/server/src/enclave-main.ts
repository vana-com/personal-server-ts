import { createPublicOnlyAccount } from "@opendatalabs/personal-server-ts-core/keys";
import { isAddress, isHex, type Address, type Hex } from "viem";
import { createServer } from "./bootstrap.js";
import { loadConfig } from "./config/index.js";
import { listenHttpServer } from "./listen.js";

const REQUIRED_ENV = [
  "VANA_MASTER_KEY_SIGNATURE",
  "PS_ACCESS_TOKEN",
  "PS_SERVER_ADDRESS",
  "PS_SERVER_PUBLIC_KEY",
] as const;
const SYNC_DISABLED = "false";

export interface EnclaveEnv {
  ownerSignature: Hex;
  accessToken: string;
  serverAddress: Address;
  serverPublicKey: Hex;
}

export function readEnclaveEnv(env: NodeJS.ProcessEnv): EnclaveEnv {
  if (env.VANA_OWNER_PRIVATE_KEY) {
    throw new Error("VANA_OWNER_PRIVATE_KEY is forbidden in enclave profile");
  }

  for (const key of REQUIRED_ENV) {
    if (!env[key]) {
      throw new Error(`${key} is required in enclave profile`);
    }
  }

  const ownerSignature = env.VANA_MASTER_KEY_SIGNATURE as string;
  const accessToken = env.PS_ACCESS_TOKEN as string;
  const serverAddress = env.PS_SERVER_ADDRESS as string;
  const serverPublicKey = env.PS_SERVER_PUBLIC_KEY as string;

  // Drop the master signature before config and application code can inspect env.
  delete env.VANA_MASTER_KEY_SIGNATURE;

  if (!isHex(ownerSignature)) {
    throw new Error("VANA_MASTER_KEY_SIGNATURE must be hex encoded");
  }
  if (!isAddress(serverAddress)) {
    throw new Error("PS_SERVER_ADDRESS must be an address");
  }
  if (!isHex(serverPublicKey)) {
    throw new Error("PS_SERVER_PUBLIC_KEY must be hex encoded");
  }

  return {
    ownerSignature,
    accessToken,
    serverAddress,
    serverPublicKey,
  };
}

export async function runEnclaveMain(): Promise<void> {
  const enclaveEnv = readEnclaveEnv(process.env);
  const rootPath = process.env.PERSONAL_SERVER_ROOT_PATH;
  const config = await loadConfig({ rootPath });
  config.sync.enabled = process.env.SYNC_ENABLED !== SYNC_DISABLED;
  config.devUi.enabled = false;
  config.tunnel.enabled = false;

  const serverAccount = createPublicOnlyAccount({
    address: enclaveEnv.serverAddress,
    publicKey: enclaveEnv.serverPublicKey,
  });
  const context = await createServer(config, {
    rootPath,
    ownerSignature: enclaveEnv.ownerSignature,
    serverAccount,
    profile: "enclave",
  });
  const server = await listenHttpServer({
    fetch: context.app.fetch,
    port: config.server.port,
    onListening: (info) => {
      context.logger.info({ port: info.port }, "Enclave server started");
    },
  });

  void context.startBackgroundServices();

  const shutdown = (signal: string) => {
    context.logger.info({ signal }, "Shutdown signal received");
    server.close(() => {
      void context.cleanup();
    });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
