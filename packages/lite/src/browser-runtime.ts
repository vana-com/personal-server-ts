import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
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
  createPsLiteRuntime,
  type PsLiteRuntime,
  type PsLiteRuntimeOptions,
} from "./runtime.js";

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
  const runtime = createPsLiteRuntime({
    ...options,
    storage,
    config,
    identity: {
      address: identity.account.address,
      publicKey: identity.account.publicKey,
    },
    saveConfig: async (nextConfig) => {
      const saved = await savePsLiteConfig(stateStore, nextConfig);
      Object.assign(config, saved);
    },
    stateCapabilities: { config: "indexeddb" },
    tokenStore,
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
  });

  return {
    runtime,
    config,
    identity,
    stateStore,
    storage,
    tokenStore,
    accessLogStore,
  };
}
