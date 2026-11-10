import { accountStorageModeFor } from "@opendatalabs/personal-server-ts-core/api";
import { accountStorageModeOf } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import type { ReplicationDoorStatus } from "@opendatalabs/personal-server-ts-core/replication/door";
import { resolveLiteReplication } from "./replication-door.js";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import { createReplicationNetworkPorts } from "@opendatalabs/personal-server-ts-core/replication/host-ports";
import {
  createGatewayDataPointFeed,
  withCancellableRegistration,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { RunIntake } from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createLiteReplication,
  liteVanaReplicaObjects,
  type LiteReplication,
} from "./replication-host.js";
import type {
  LiteReplicaObjectTransfers,
  LiteReplicaPersistence,
  ReplicationBootConfig,
} from "./replication-ports.js";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createImportWaker,
  createMemoryModeRecordStore,
  createModeAuthority,
  type ImportRunner,
  type ImportWaker,
  type ModeAuthority,
  type ModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  createLegacyWriteSeal,
  type LegacyWriteSeal,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import { createIndexedDbModeRecordStore } from "./account-mode-store.js";
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
import { legacyMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createInMemoryWriteProofReplayStore,
  createInMemoryWriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
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
import {
  createPsLiteSyncManager,
  type PsLiteOwnerSyncSigner,
  type PsLiteSyncOptions,
} from "./sync.js";
import {
  createPsLiteDerivativeCompute,
  createPsLiteQuestionStore,
  psLiteInferenceConfigured,
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
  /** Host-owned local database, shared by stream intake and reads. */
  localDb?: PsLiteSyncOptions["localDb"];
  localDbDeviceId?: PsLiteSyncOptions["localDbDeviceId"];
  olderVersionReads?: PsLiteSyncOptions["olderVersionReads"];
  /**
   * Where the account-mode module keeps its per-owner records. Default: its
   * own IndexedDB database next to the data store's. A host with another
   * durable place (a native bundle) injects a store.
   */
  accountModeStore?: ModeRecordStore;
  /**
   * The host's legacy importer. The runtime runs it when the Account says On
   * and once at boot when the owner is already switched; what is owed and when
   * it is done is the importer's own record. Without one no import starts.
   */
  legacyImporter?: ImportRunner;
  /**
   * Inference provider for the derivative compute layer. Defaults to the
   * OpenAI-compatible fetch client on `config.inference`; tests inject a
   * fake. Pass `derivatives` (the runtime option) to bypass this wiring.
   */
  inferenceProvider?: InferenceProvider;
  ownerSignature: `0x${string}`;
  ownerSyncSigner?: PsLiteOwnerSyncSigner;
  additionsWorkerFactory?: PsLiteSyncOptions["additionsWorkerFactory"];
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
   * Artifact digest -> stream declarations, filled by the host after it
   * verified each artifact. The run intake trusts only this table; with none
   * given, every digest answers `unknown_artifact`. Admission follows Account mode.
   */
  streamSyncDeclarations?: PsLiteSyncOptions["streamSyncDeclarations"];
  streamSyncRegistry?: PsLiteSyncOptions["streamSyncRegistry"];
  streamSyncBlobs?: PsLiteSyncOptions["streamSyncBlobs"];
  /** Stream names per connector from verified manifests; see `PsLiteSyncOptions`. */
  streamSyncDeclaredStreams: PsLiteSyncOptions["streamSyncDeclaredStreams"];
  /** Retained manifest documents for the delete fence; see `PsLiteSyncOptions`. */
  streamSyncRetainedManifests?: PsLiteSyncOptions["streamSyncRetainedManifests"];
  /**
   * The host's replication ports (host contract §4): native persistence
   * with replica support and native object transfers. With the door on and
   * `config.enabled`, this factory builds replication over them and passes
   * its runtime as `replication`; otherwise it builds none of it.
   */
  replicaHost?: {
    config: ReplicationBootConfig;
    persistence: LiteReplicaPersistence;
    transfers: LiteReplicaObjectTransfers;
    /** The retained declarations the host's canonical store serves. */
    declarations: readonly DeclarationSnapshot[];
    /** The host cannot rule out that this database is a copy (§3.2). */
    rotateWriterIdentity?: boolean;
  };
  /**
   * Inject host-owned persistence ports (Mobile native SQLite/filesystem) in
   * place of the browser IndexedDB defaults, without giving up this factory's
   * identity/config/sync/auth/signer composition. This is all-or-nothing:
   * either omit it for the default Web IndexedDB/OPFS path, or provide every
   * port for a host-owned persistence implementation.
   *
   * A host may supply storageFactory to construct storage using the runtime seal.
   */
  persistence?: Omit<PsLitePersistenceBundle, "storage"> &
    Partial<Pick<PsLitePersistenceBundle, "storage">>;
  /** Constructs host storage with the runtime's account-mode seal. */
  storageFactory?: (
    seal: LegacyWriteSeal,
  ) => DataStoragePort | Promise<DataStoragePort>;
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
  /** Database facade when a host driver is supplied and available. */
  localSync?: LocalSync | null;
  /** Lazily open the database after Account mode is known. */
  getLocalSync?(): Promise<LocalSync>;
  /** Stop the sync manager before releasing its owner/network database. */
  closeStreamSync?(): Promise<void>;
  /**
   * The database run intake for host code; admission follows Account mode.
   */
  streamSyncIntake: RunIntake | null;
  /** The compute layer; hosts call `scheduler.stop()` on teardown. */
  derivatives: PsLiteRuntimeOptions["derivatives"];
  /** This boot's replication door, from `resolveLiteReplication`. */
  replication: ReplicationDoorStatus;
  /** Replication built over `replicaHost`, when the host passed it. */
  replicationHost?: LiteReplication;
  /**
   * The account-mode module. Web code gives it the Account's answer with
   * `submitEvidence` before it starts the first collection. On teardown call
   * `importWaker.stop()` first, then close the storage, then `close()`.
   */
  accountModeAuthority: ModeAuthority;
  /** Wakes the host's importer; present when the host passed `legacyImporter`. */
  importWaker?: ImportWaker;
}

export async function createIndexedDbPsLiteRuntime(
  options: IndexedDbPsLiteRuntimeOptions,
): Promise<IndexedDbPsLiteRuntime> {
  const dbName = options.dbName ?? "personal-server-lite";
  const injected = options.persistence;
  if (injected !== undefined)
    assertCompletePsLitePersistenceBundle(
      injected,
      Boolean(options.storageFactory),
    );
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
  const replication = await resolveLiteReplication(
    stateStore,
    config.replication.enabled,
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
  const serverOwner = await resolvePsLiteOwner({
    ownerAddress: options.ownerAddress,
    ownerSignature: options.ownerSignature,
  });
  // One mode, from one place: the account-mode module. Its records live in
  // their own IndexedDB database, never in the data store. Boot does not wait
  // for the Account: before the first answer reads stay legacy and legacy
  // writes pause. A host that injects its own persistence has not offered
  // browser IndexedDB, so without an `accountModeStore` the records are in
  // memory and the Account's answer at the next launch restores them.
  let importWaker: ImportWaker | undefined;
  const accountModeAuthority = createModeAuthority({
    store:
      options.accountModeStore ??
      (options.persistence
        ? createMemoryModeRecordStore()
        : createIndexedDbModeRecordStore(`${dbName}-account-mode`)),
    // An answer that leaves the owner On wakes the import.
    onOn: () => void importWaker?.wake(),
    onWarning: (message, detail) => console.warn(message, detail),
  });
  await accountModeAuthority.ready;
  if (options.legacyImporter && serverOwner) {
    importWaker = createImportWaker({
      authority: accountModeAuthority,
      owner: serverOwner,
      importer: options.legacyImporter,
      onWarning: (message, detail) => console.warn(message, detail),
    });
  }
  // The one seal over that module. The storage makes a legacy version durable
  // only inside it, so the lock that answers an On is the lock every legacy
  // write holds. A runtime without an owner gets a seal that answers unknown.
  const legacyWriteSeal = createLegacyWriteSeal({
    authority: accountModeAuthority,
    owner: serverOwner,
  });
  const storageFactory =
    options.storageFactory ??
    (injected?.storage
      ? () => injected.storage!
      : (seal: LegacyWriteSeal) =>
          createPersistentPsLiteStorage(
            { kind: "indexeddb" },
            createIndexedDbPsLitePersistence({
              dbName: options.storageDbName ?? `${dbName}-storage`,
              storeName: options.storageStoreName ?? "state",
              key: options.storageKey ?? "data-storage-v1",
            }),
            options.dataFileStore,
            seal,
          ));
  const storage = await storageFactory(legacyWriteSeal);
  const gateway =
    options.gateway ??
    withCancellableRegistration(
      createGatewayClient(config.gateway.url),
      config.gateway.url,
    );
  const serverSigner =
    options.serverSigner ??
    createServerSigner(identity.account, {
      chainId: config.gateway.chainId,
      contracts: config.gateway.contracts,
    });
  // Create (or reuse) a shared diagnostics recorder before the sync manager so
  // both share the same recorder instance and events appear in /v1/diagnostics.
  const diagnostics = options.diagnostics ?? new DiagnosticsRecorder();
  // The one browser request signer: the identity key that registered this
  // server with the gateway signs the lineage reads and the inference relay
  // calls with the same Web3Signed scheme.
  const requestSigner = createRequestSigner(identity.account);
  // Derivative data: lineage reads are signed with the server key and
  // derivatives are registered with their lineage (see core/lineage).
  const lineageGateway = createGatewayLineageClient({
    gatewayUrl: config.gateway.url,
    requestSigner,
  });
  let syncManager = options.syncManager ?? null;
  let dataPointFeed = options.dataPointFeed;
  let scopeDeletions = options.scopeDeletions;
  let additions = options.additions;
  let streamSyncRead = options.streamSyncRead;
  let streamSyncIntake: RunIntake | null = null;
  let syncRuntime:
    Awaited<ReturnType<typeof createPsLiteSyncManager>> | undefined;
  let closeStreamSync = async () => {};
  let runtimeRef: PsLiteRuntime | null = null;
  // Derivative compute: built before sync so downloads can mark questions
  // stale; it reaches the sync manager lazily to upload its results.
  // Without a relay URL (or an injected provider) the layer stays off and
  // /v1/derivatives answers 503: the browser never calls a provider
  // directly with no key.
  let derivatives = options.derivatives ?? null;
  if (
    derivatives === null &&
    options.derivatives === undefined &&
    (options.inferenceProvider || psLiteInferenceConfigured(config))
  ) {
    derivatives = createPsLiteDerivativeCompute({
      config,
      // Derivatives read sources the way apps do: projected legacy bodies.
      storage: withLegacyProjection(storage),
      store: await createPsLiteQuestionStore(stateStore),
      serverOwner,
      syncManager: () => syncManager,
      scopeDeletions: () => scopeDeletions,
      writePolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
      },
      runtimeAvailability: {
        isAvailable: () => runtimeRef?.isAvailable() ?? Boolean(options.active),
      },
      provider: options.inferenceProvider,
      // The relay forwards only requests signed as the owner's server.
      requestSigner,
      logger: options.logger,
    });
  } else if (derivatives === null && options.derivatives === undefined) {
    options.logger?.warn(
      { baseUrl: config.inference.baseUrl },
      "Derivative compute disabled: inference.baseUrl is the direct-provider default; point it at the Vana inference relay",
    );
  }
  if (!syncManager && (config.sync.enabled || options.localDb)) {
    const sync = await createPsLiteSyncManager({
      config,
      autoStartSync: config.sync.enabled,
      localDb: options.localDb,
      localDbDeviceId: options.localDbDeviceId,
      olderVersionReads: options.olderVersionReads,
      stateStore,
      storage,
      ownerSignature: options.ownerSignature,
      accountStorageMode: accountStorageModeFor(
        accountStorageModeOf(accountModeAuthority),
        serverOwner,
      ),
      ownerAddress: options.ownerAddress,
      ownerSyncSigner: options.ownerSyncSigner,
      additionsWorkerFactory: options.additionsWorkerFactory,
      serverAccount: identity.account,
      gateway,
      dataPointFeed: options.dataPointFeed,
      scopeDeletions,
      streamSyncDeclarations: options.streamSyncDeclarations,
      streamSyncRegistry: options.streamSyncRegistry,
      streamSyncBlobs: options.streamSyncBlobs,
      streamSyncDeclaredStreams: options.streamSyncDeclaredStreams,
      streamSyncRetainedManifests: options.streamSyncRetainedManifests,
      diagnostics,
      logger: options.logger,
      lineageGateway,
      onDataPointIndexed: (event) =>
        derivatives?.scheduler.markSourceChanged(event.scope, {
          lineageSources: event.lineageSources,
        }),
    });
    additions = sync.additions ?? additions;
    syncManager = sync.syncManager;
    scopeDeletions = sync.scopeDeletions;
    dataPointFeed = sync.dataPointFeed;
    syncRuntime = sync;
    closeStreamSync = sync.closeStreamSync;
    streamSyncRead = sync.streamSyncRead;
    streamSyncIntake = sync.streamSyncIntake;
  }
  const replicationHost = options.replicaHost
    ? await createLiteReplication({
        ...options.replicaHost,
        door: replication,
        serverAccount: identity.account,
        objects: liteVanaReplicaObjects({
          config,
          owner: serverOwner,
          signer: identity.account,
        }),
        network: (owner, objectStorage) =>
          createReplicationNetworkPorts({
            config,
            owner,
            masterKey: legacyMasterKey(options.ownerSignature),
            storage: objectStorage,
            gateway,
            feed:
              dataPointFeed ??
              createGatewayDataPointFeed({ gatewayUrl: config.gateway.url }),
            // The registered server key, as on Node; never the owner signer.
            signer: createServerSigner(identity.account, {
              chainId: config.gateway.chainId,
              contracts: config.gateway.contracts,
            }),
          }),
        onError: (error) =>
          options.logger?.warn({ err: error }, "Replication step failed"),
      })
    : undefined;
  const runtimeAvailability = {
    isAvailable: () => runtimeRef?.isAvailable() ?? Boolean(options.active),
  };
  // Delegated builder writes. One session store is wired into the handshake
  // route AND the auth adapter (the route mints what the adapter redeems),
  // and one replay guard covers the handshake proof and every per-write
  // proof — the same single-store discipline as createApp in the Node build.
  // A caller that brings its OWN auth adapter owns this wiring, so we do not
  // mount a handshake for a store that adapter has never heard of.
  const writeProofReplayStore =
    options.writeProofReplayStore ?? createInMemoryWriteProofReplayStore();
  const writeSessionStore =
    options.writeSessionStore ??
    (options.auth ? undefined : createInMemoryWriteSessionStore());
  // One audience for the whole delegated-write flow: the handshake proof and
  // every per-write proof are verified against the same origin.
  const serverOrigin =
    options.serverOrigin ??
    (() => options.runtimeOrigin ?? config.server.origin);
  const auth =
    options.auth ??
    createWeb3SignedPsLiteAuth({
      origin: serverOrigin,
      ownerAddress: serverOwner,
      accessToken: options.accessToken,
      tokenStore,
      dataReadPolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
        grantLister: gateway,
        runtimeAvailability,
      },
      ...(writeSessionStore
        ? {
            writeSessions: {
              store: writeSessionStore,
              replayStore: writeProofReplayStore,
              policyPorts: {
                authSessionVerifier: gateway,
                grantVerifier: gateway,
                runtimeAvailability,
              },
            },
          }
        : {}),
    });
  const runtime = createPsLiteRuntime({
    ...options,
    accountModeAuthority,
    replication: replicationHost?.runtime ?? options.replication,
    auth,
    serverOrigin,
    writeSessionStore,
    writeProofReplayStore,
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
    additions,
    scopeDeletions,
    streamSyncRead,
    localSync: syncRuntime?.getLocalSync,
    history: syncRuntime
      ? {
          additions: async (input) =>
            (await syncRuntime!.getLocalSync()).history.additions(input),
          versions: async (input) =>
            (await syncRuntime!.getLocalSync()).history.versions(input),
          lineage: async (input) =>
            (await syncRuntime!.getLocalSync()).history.lineage(input),
        }
      : undefined,
    streamSyncConnectionDelete: syncRuntime
      ? {
          requestConnectionDelete: async (connector) =>
            (await syncRuntime!.getLocalSync()).deleter.requestConnectionDelete(
              connector,
            ),
        }
      : null,
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
  // An import owed from a saved On needs no new answer from the Account.
  void importWaker?.wake();

  return {
    runtime,
    config,
    identity,
    stateStore,
    storage,
    tokenStore,
    accessLogStore,
    syncManager,
    get localSync() {
      return syncRuntime?.localSync ?? null;
    },
    getLocalSync: syncRuntime?.getLocalSync,
    closeStreamSync,
    streamSyncIntake,
    derivatives,
    replication,
    replicationHost,
    accountModeAuthority,
    importWaker,
  };
}
