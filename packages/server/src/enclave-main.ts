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
  "ENCLAVE_AGENT_URL",
] as const;
const SYNC_DISABLED = "false";
const MAINNET_CHAIN_ID = 1_480;
const MOKSHA_CHAIN_ID = 14_800;
const DEFAULT_STORAGE_API_URLS = {
  [MAINNET_CHAIN_ID]: "https://storage.vana.org",
  [MOKSHA_CHAIN_ID]: "https://storage-dev.vana.org",
} as const;
const CONTRACT_ENV = {
  DATA_REGISTRY_CONTRACT: "dataRegistry",
  DATA_PORTABILITY_SERVER_CONTRACT: "dataPortabilityServer",
  DATA_PORTABILITY_GRANTEES_CONTRACT: "dataPortabilityGrantees",
  DATA_PORTABILITY_PERMISSIONS_CONTRACT: "dataPortabilityPermissions",
} as const;

export interface EnclaveEnv {
  ownerSignature: Hex;
  accessToken: string;
  serverAddress: Address;
  serverPublicKey: Hex;
  agentUrl: string;
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
  const agentUrl = env.ENCLAVE_AGENT_URL as string;

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
  assertHttpUrl(agentUrl, "ENCLAVE_AGENT_URL");

  return {
    ownerSignature,
    accessToken,
    serverAddress,
    serverPublicKey,
    agentUrl,
  };
}

export async function runEnclaveMain(): Promise<void> {
  const enclaveEnv = readEnclaveEnv(process.env);
  const rootPath = process.env.PERSONAL_SERVER_ROOT_PATH;
  const config = await loadConfig({ rootPath });
  const chainId = readChainId(process.env.CHAIN_ID);
  config.gateway.chainId = chainId;
  for (const [envName, contractName] of Object.entries(CONTRACT_ENV)) {
    const address = process.env[envName];
    if (!address) {
      continue;
    }
    if (!isAddress(address)) {
      throw new Error(`${envName} must be an address`);
    }
    config.gateway.contracts[contractName] = address;
  }
  if (process.env.GATEWAY_URL) {
    config.gateway.url = process.env.GATEWAY_URL;
  }
  const storageApiUrlValue =
    process.env.STORAGE_API_URL ?? DEFAULT_STORAGE_API_URLS[chainId];
  if (storageApiUrlValue) {
    let storageApiUrl: URL;
    try {
      storageApiUrl = new URL(storageApiUrlValue);
    } catch {
      throw new Error("STORAGE_API_URL must be a valid absolute https URL");
    }
    if (storageApiUrl.protocol !== "https:") {
      throw new Error("STORAGE_API_URL must be a valid absolute https URL");
    }
    config.storage.config.vana = {
      ...config.storage.config.vana,
      apiUrl: storageApiUrlValue,
    };
  }
  // Preview-testing hook; production fetch behaviour is unchanged when unset.
  if (process.env.VERCEL_PROTECTION_BYPASS) {
    installGatewayBypass(
      config.gateway.url,
      process.env.VERCEL_PROTECTION_BYPASS,
    );
  }
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
    jobResultUpload: {
      storageEndpoint: storageApiUrlValue,
      agentEndpoint: enclaveEnv.agentUrl,
      accessToken: enclaveEnv.accessToken,
      chainId,
    },
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

function assertHttpUrl(value: string, name: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be a valid absolute http(s) URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`${name} must be a valid absolute http(s) URL`);
  }
}

function readChainId(value: string | undefined): 1480 | 14800 {
  const chainId = value === undefined ? MOKSHA_CHAIN_ID : Number(value);
  if (chainId !== MAINNET_CHAIN_ID && chainId !== MOKSHA_CHAIN_ID) {
    throw new Error("CHAIN_ID must be 1480 or 14800");
  }

  return chainId;
}

function installGatewayBypass(gatewayUrl: string, secret: string): void {
  const gatewayOrigin = new URL(gatewayUrl).origin;
  const requestFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const requestUrl = new URL(
      input instanceof Request ? input.url : input.toString(),
    );
    if (requestUrl.origin !== gatewayOrigin) {
      return requestFetch(input, init);
    }

    const headers = new Headers(
      input instanceof Request ? input.headers : undefined,
    );
    new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
    headers.set("x-vercel-protection-bypass", secret);

    return requestFetch(input, { ...init, headers });
  };
}
