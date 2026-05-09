import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  createGatewayClient,
  recoverServerOwner,
} from "@opendatalabs/vana-sdk/browser";
import {
  createIndexedDbPsLitePersistence,
  createPersistentPsLiteStorage,
  type PsLiteDataFileStore,
} from "./storage.js";
import {
  createIndexedDbPsLiteAccessLogStore,
  createIndexedDbPsLiteStateStore,
  createIndexedDbPsLiteTokenStore,
  loadOrCreatePsLiteConfig,
  loadOrCreatePsLiteServerIdentity,
  savePsLiteConfig,
  type PsLiteStateStore,
  type PsLiteUnlockedServerIdentity,
} from "./state.js";
import {
  createWeb3SignedPsLiteAuth,
  createPsLiteRuntime,
  type PsLiteRuntime,
  type PsLiteRuntimeOptions,
} from "./runtime.js";
import { createPsLiteSyncManager } from "./sync.js";

export interface IndexedDbPsLiteRuntimeOptions extends Omit<
  PsLiteRuntimeOptions,
  | "accessLogReader"
  | "accessLogWriter"
  | "config"
  | "identity"
  | "saveConfig"
  | "stateCapabilities"
  | "storage"
  | "tokenStore"
> {
  ownerSignature: `0x${string}`;
  dbName?: string;
  stateStoreName?: string;
  storageDbName?: string;
  storageStoreName?: string;
  storageKey?: string;
  configDefaults?: Partial<ServerConfig>;
  dataFileStore?: PsLiteDataFileStore;
}

export interface IndexedDbPsLiteRuntime {
  runtime: PsLiteRuntime;
  config: ServerConfig;
  identity: PsLiteUnlockedServerIdentity;
  stateStore: PsLiteStateStore;
  storage: DataStoragePort;
  tokenStore: PsLiteRuntimeOptions["tokenStore"];
  accessLogStore: AccessLogReader & AccessLogWriter;
  syncManager: PsLiteRuntimeOptions["syncManager"];
}

export async function createIndexedDbPsLiteRuntime(
  options: IndexedDbPsLiteRuntimeOptions,
): Promise<IndexedDbPsLiteRuntime> {
  const dbName = options.dbName ?? "personal-server-lite";
  const stateStore = createIndexedDbPsLiteStateStore({
    dbName,
    storeName: options.stateStoreName ?? "state",
  });
  const config = await loadOrCreatePsLiteConfig(
    stateStore,
    options.configDefaults,
  );
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: options.ownerSignature,
  });
  const tokenStore = createIndexedDbPsLiteTokenStore({
    dbName,
    storeName: "tokens",
  });
  const accessLogStore = createIndexedDbPsLiteAccessLogStore({
    dbName,
    storeName: "accessLogs",
  });
  const storage = await createPersistentPsLiteStorage(
    { kind: "indexeddb" },
    createIndexedDbPsLitePersistence({
      dbName: options.storageDbName ?? `${dbName}-storage`,
      storeName: options.storageStoreName ?? "state",
      key: options.storageKey ?? "data-storage-v1",
    }),
    options.dataFileStore,
  );
  const gateway = options.gateway ?? createGatewayClient(config.gateway.url);
  const serverOwner = await recoverServerOwner(options.ownerSignature);
  const serverSigner =
    options.serverSigner ??
    createServerSigner(identity.account, {
      chainId: config.gateway.chainId,
      contracts: config.gateway.contracts,
    });
  let syncManager = options.syncManager ?? null;
  if (!syncManager && config.sync.enabled) {
    syncManager = (
      await createPsLiteSyncManager({
        config,
        stateStore,
        storage,
        ownerSignature: options.ownerSignature,
        serverAccount: identity.account,
        gateway,
      })
    ).syncManager;
  }
  let runtimeRef: PsLiteRuntime | null = null;
  const auth =
    options.auth ??
    createWeb3SignedPsLiteAuth({
      origin: () => config.server.origin,
      ownerAddress: serverOwner,
      accessToken: options.accessToken,
      tokenStore,
      dataReadPolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
        runtimeAvailability: {
          isAvailable: () =>
            runtimeRef?.isAvailable() ?? Boolean(options.active),
        },
      },
    });
  const runtime = createPsLiteRuntime({
    ...options,
    auth,
    storage,
    config,
    identity: {
      address: identity.account.address,
      publicKey: identity.account.publicKey,
    },
    gateway,
    serverOwner,
    serverSigner,
    syncManager,
    saveConfig: async (nextConfig) => {
      const saved = await savePsLiteConfig(stateStore, nextConfig);
      Object.assign(config, saved);
    },
    stateCapabilities: { config: "indexeddb" },
    tokenStore,
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
  });
  runtimeRef = runtime;

  return {
    runtime,
    config,
    identity,
    stateStore,
    storage,
    tokenStore,
    accessLogStore,
    syncManager,
  };
}
