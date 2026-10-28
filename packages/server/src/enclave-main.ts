import { createHash } from "node:crypto";
import {
  recoverServerOwner,
  createGatewayClient,
} from "@opendatalabs/vana-sdk/node";
import { createVanaSyncStorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import type { CreateServerOptions } from "./bootstrap.js";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import { createPublicOnlyAccount } from "@opendatalabs/personal-server-ts-core/keys";
import {
  isAddress,
  isHex,
  keccak256,
  stringToHex,
  type Address,
  type Hex,
} from "viem";
import { createServer } from "./bootstrap.js";
import { createAccessReporter } from "./jobs/access-reporter.js";
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
  // Enclave only: MCP reads become enclave-signed access records. Other
  // profiles have no agent to sign them, so they report nothing.
  const accessReporter = createAccessReporter({
    agentEndpoint: enclaveEnv.agentUrl,
    accessToken: enclaveEnv.accessToken,
    chainId,
  });
  const context = await createServer(config, {
    rootPath,
    hydrateScopes: readHydrateScopes(process.env.PS_HYDRATE_SCOPES),
    ownerSignature: enclaveEnv.ownerSignature,
    ...(await createEnclaveAdditionsPorts(config, enclaveEnv)),
    serverAccount,
    profile: "enclave",
    readFulfillmentReporter: accessReporter,
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
      void accessReporter.stop().then(() => context.cleanup());
    });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

function readHydrateScopes(value: string | undefined): string[] | undefined {
  if (!value) {
    return undefined;
  }

  const scopes = [
    ...new Set(value.split(",").map((scope) => scope.trim())),
  ].filter(Boolean);

  return scopes.length > 0 ? scopes : undefined;
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

/** Sandbox adapter: all signing stays behind the node's closed additions RPC. */
export async function createEnclaveAdditionsPorts(
  config: ServerConfig,
  env: EnclaveEnv,
): Promise<
  Pick<CreateServerOptions, "additionsInventorySigner" | "additionsWriter">
> {
  const ownerAddress = await recoverServerOwner(env.ownerSignature);
  const sources = new Map<string, string>();
  const sourceFor = (scope: string) =>
    scope.startsWith("vana.system.additions.")
      ? scope.slice("vana.system.additions.".length)
      : sources.get(scope);
  async function rpc(body: Record<string, unknown>) {
    const response = await fetch(
      `${env.agentUrl.replace(/\/+$/, "")}/agent/v1/additions/sign`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...body,
          owner: ownerAddress,
          chainId: config.gateway.chainId,
        }),
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Additions signing refused (${response.status})`);
    }
    const result: unknown = await response.json();
    if (typeof result !== "object" || result === null)
      throw new Error("Invalid additions signing result");
    return result;
  }
  const additionsInventorySigner: NonNullable<
    CreateServerOptions["additionsInventorySigner"]
  > = {
    async signRequest(params) {
      if (
        params.aud !== new URL(config.gateway.url).origin ||
        params.method !== "GET" ||
        params.body ||
        params.grantId !== undefined
      )
        throw new Error("Only inventory signing is supported");
      const uri = new URL(params.uri, params.aud);
      if (
        uri.origin !== params.aud ||
        !/^\/v1\/data\/0x[0-9a-f]{64}\/versions$/.test(uri.pathname) ||
        uri.hash ||
        uri.searchParams.get("user") !== ownerAddress.toLowerCase() ||
        [...uri.searchParams.keys()].join(",") !== "user,scope,after,limit"
      )
        throw new Error("Only canonical inventory signing is supported");
      const source = uri.searchParams.get("scope");
      if (source && !source.startsWith("vana.system."))
        sources.set(
          `vana.system.additions-hash.${keccak256(stringToHex(source)).slice(2)}`,
          source,
        );
      const result = await rpc({
        kind: "inventory",
        scope: uri.searchParams.get("scope"),
        after: uri.searchParams.get("after"),
        limit: uri.searchParams.get("limit"),
      });
      if (
        !("authorization" in result) ||
        typeof result.authorization !== "string"
      )
        throw new Error("Invalid inventory authorization");
      return result.authorization;
    },
  };
  // This account only resolves public storage URLs. Its signing functions stay
  // unavailable; upload authorization uses the dedicated RPC below.
  const publicStorage = createVanaSyncStorageAdapter({
    config,
    serverOwner: ownerAddress,
    serverAccount: createPublicOnlyAccount({
      address: env.serverAddress,
      publicKey: env.serverPublicKey,
    }),
    reads: "public",
  });
  const storageEndpoint = (
    config.storage.config.vana?.apiUrl ?? "https://storage.vana.org"
  ).replace(/\/+$/, "");
  const keyUrl = (address: string, key: string) =>
    `${storageEndpoint}/v1/chains/${config.gateway.chainId}/blobs/${address.toLowerCase()}/${key.split("/").map(encodeURIComponent).join("/")}`;
  const storageAdapter: NonNullable<
    CreateServerOptions["additionsWriter"]
  >["storageAdapter"] = {
    urlForKey(key) {
      return keyUrl(ownerAddress, key);
    },
    async upload(key, data) {
      const parts = key.split("/");
      if (parts.length !== 2) throw new Error("Invalid checkpoint key");
      const result = await rpc({
        kind: "upload",
        sourceScope: sourceFor(parts[0] ?? ""),
        scope: parts[0],
        version: parts[1],
        bodyHash: `sha256:${createHash("sha256").update(data).digest("hex")}`,
      });
      if (
        !("authorization" in result) ||
        typeof result.authorization !== "string"
      )
        throw new Error("Invalid upload authorization");
      const url = keyUrl(ownerAddress, key);
      const response = await fetch(url, {
        method: "PUT",
        headers: {
          Authorization: result.authorization,
          "Content-Type": "application/octet-stream",
        },
        body: new Uint8Array(data),
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
      });
      await response.body?.cancel();
      if (!response.ok)
        throw new Error(`Checkpoint upload failed (${response.status})`);
      return url;
    },
    async download(url) {
      return publicStorage.download(url);
    },
    async downloadBounded(url, budget) {
      return publicStorage.downloadBounded(url, budget);
    },
    async exists(url) {
      return publicStorage.exists(url);
    },
    async delete() {
      throw new Error("Checkpoint deletion is not authorized");
    },
  };
  return {
    additionsInventorySigner,
    additionsWriter: {
      storageAdapter,
      gateway: createGatewayClient(config.gateway.url),
      signer: {
        async signAddData(message) {
          if (message.ownerAddress.toLowerCase() !== ownerAddress.toLowerCase())
            throw new Error("Checkpoint owner mismatch");
          const result = await rpc({
            kind: "register",
            sourceScope: sourceFor(message.scope),
            scope: message.scope,
            version: String(message.expectedVersion),
            dataHash: message.dataHash,
            metadataHash: message.metadataHash,
          });
          if (!("signature" in result) || !isHex(result.signature))
            throw new Error("Invalid checkpoint signature");
          return result.signature;
        },
      },
    },
  };
}
