import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { Logger } from "@opendatalabs/personal-server-ts-core/logger";
import type { InferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";
import {
  createRequestSigner,
  createServerSigner,
} from "@opendatalabs/personal-server-ts-core/signing";
import { createGatewayLineageClient } from "@opendatalabs/personal-server-ts-core/lineage";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type {
  DataPointFeedPort,
  DataStoragePort,
} from "@opendatalabs/personal-server-ts-core/ports";
import { createGatewayClient } from "@opendatalabs/vana-sdk/browser";
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
import {
  createPsLiteDerivativeCompute,
  createPsLiteQuestionStore,
} from "./derivatives.js";
import { resolvePsLiteOwner } from "./owner-binding.js";
import { DiagnosticsRecorder } from "./diagnostics.js";
import {
  assertCompletePsLitePersistenceBundle,
  type PsLitePersistenceBundle,
} from "./persistence.js";

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
  ownerAddress?: `0x${string}`;
  /**
   * Inference provider for the derivative compute layer. Defaults to the
   * OpenAI-compatible fetch client on `config.inference`; tests inject a
   * fake. Pass `derivatives` (the runtime option) to bypass this wiring.
   */
  inferenceProvider?: InferenceProvider;
  ownerSignature: `0x${string}`;
  dbName?: string;
  stateStoreName?: string;
  storageDbName?: string;
  storageStoreName?: string;
  storageKey?: string;
  runtimeOrigin?: string;
  configDefaults?: Partial<ServerConfig>;
  dataFileStore?: PsLiteDataFileStore;
  logger?: Logger;
  /**
   * Deletion-aware gateway feed for the sync workers. Defaults to a REST
   * feed on the configured gateway URL; inject with a mock `gateway` in tests.
   */
  dataPointFeed?: DataPointFeedPort;
  /**
   * Inject host-owned persistence ports (Mobile native SQLite/filesystem) in
   * place of the browser IndexedDB defaults, without giving up this factory's
   * identity/config/sync/auth/signer composition. This is all-or-nothing:
   * either omit it for the default Web IndexedDB/OPFS path, or provide every
   * port for a host-owned persistence implementation.
   */
  persistence?: PsLitePersistenceBundle;
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
  /** The compute layer; hosts call `scheduler.stop()` on teardown. */
  derivatives: PsLiteRuntimeOptions["derivatives"];
}

export async function createIndexedDbPsLiteRuntime(
  options: IndexedDbPsLiteRuntimeOptions,
): Promise<IndexedDbPsLiteRuntime> {
  const dbName = options.dbName ?? "personal-server-lite";
  const injected = options.persistence;
  if (injected !== undefined) assertCompletePsLitePersistenceBundle(injected);
  // No bundle preserves the Web IndexedDB/OPFS path. A supplied bundle has
  // already been validated as complete, so hosts never silently mix native and
  // browser persistence. Config, identity, and sync remain generic over state.
  const stateStore =
    injected?.state ??
    createIndexedDbPsLiteStateStore({
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
  const tokenStore =
    injected?.tokens ??
    createIndexedDbPsLiteTokenStore({
      dbName,
      storeName: "tokens",
    });
  const accessLogStore =
    injected?.accessLog ??
    createIndexedDbPsLiteAccessLogStore({
      dbName,
      storeName: "accessLogs",
    });
  const storage =
    injected?.storage ??
    (await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createIndexedDbPsLitePersistence({
        dbName: options.storageDbName ?? `${dbName}-storage`,
        storeName: options.storageStoreName ?? "state",
        key: options.storageKey ?? "data-storage-v1",
      }),
      options.dataFileStore,
    ));
  const gateway = options.gateway ?? createGatewayClient(config.gateway.url);
  const serverOwner = await resolvePsLiteOwner({
    ownerAddress: options.ownerAddress,
    ownerSignature: options.ownerSignature,
  });
  const serverSigner =
    options.serverSigner ??
    createServerSigner(identity.account, {
      chainId: config.gateway.chainId,
      contracts: config.gateway.contracts,
    });
  // Create (or reuse) a shared diagnostics recorder before the sync manager so
  // both share the same recorder instance and events appear in /v1/diagnostics.
  const diagnostics = options.diagnostics ?? new DiagnosticsRecorder();
  // Derivative data: lineage reads are signed with the server key and
  // derivatives are registered with their lineage (see core/lineage).
  const lineageGateway = createGatewayLineageClient({
    gatewayUrl: config.gateway.url,
    requestSigner: createRequestSigner(identity.account),
  });
  let syncManager = options.syncManager ?? null;
  let scopeDeletions = options.scopeDeletions;
  // Derivative compute: built before sync so downloads can mark questions
  // stale; it reaches the sync manager lazily to upload its results.
  const derivatives =
    options.derivatives ??
    createPsLiteDerivativeCompute({
      config,
      storage,
      store: await createPsLiteQuestionStore(stateStore),
      serverOwner,
      syncManager: () => syncManager,
      scopeDeletions: () => scopeDeletions,
      writePolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
      },
      provider: options.inferenceProvider,
      logger: options.logger,
    });
  if (!syncManager && config.sync.enabled) {
    const sync = await createPsLiteSyncManager({
      config,
      stateStore,
      storage,
      ownerSignature: options.ownerSignature,
      ownerAddress: options.ownerAddress,
      serverAccount: identity.account,
      gateway,
      dataPointFeed: options.dataPointFeed,
      scopeDeletions,
      diagnostics,
      logger: options.logger,
      lineageGateway,
      onDataPointIndexed: (event) =>
        derivatives.scheduler.markSourceChanged(event.scope),
    });
    syncManager = sync.syncManager;
    scopeDeletions = sync.scopeDeletions;
  }
  let runtimeRef: PsLiteRuntime | null = null;
  const auth =
    options.auth ??
    createWeb3SignedPsLiteAuth({
      origin: () => options.runtimeOrigin ?? config.server.origin,
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
    scopeDeletions,
    diagnostics,
    lineageGateway,
    derivatives,
    saveConfig: async (nextConfig) => {
      const saved = await savePsLiteConfig(stateStore, nextConfig);
      Object.assign(config, saved);
    },
    stateCapabilities: { config: injected?.state ? "custom" : "indexeddb" },
    tokenStore,
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    // A complete host bundle owns both MCP records too. Direct options remain
    // available only on the default Web path for backwards compatibility.
    mcpConnectionStore: injected?.mcpConnections ?? options.mcpConnectionStore,
    mcpOAuthAuthorizationStore:
      injected?.mcpOAuthAuthorizations ?? options.mcpOAuthAuthorizationStore,
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
    derivatives,
  };
}
