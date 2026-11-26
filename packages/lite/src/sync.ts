import type { PsLiteStoragePort } from "./storage.js";
import { createLegacyRetireRemote } from "@opendatalabs/personal-server-ts-core/localdb";
import { createPsLiteSeedStaging } from "./seed-staging.js";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
  legacyScopesOfConnector,
  legacyStreamsOfScope,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import type {
  OwnedAccountStorageMode,
  StreamSyncReadPort,
} from "@opendatalabs/personal-server-ts-core/api";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  connectionQueue,
  createLocalSync,
  createLocalSeed,
  createSeedIntake,
  createViewChanges,
  inventoryVersionLister,
  legacyHeadFrom,
  modeOfAccount,
  pendingBlobsFrom,
  type LocalSyncDeps,
  type LogErasurePorts,
  type SeedIntake,
  type LocalSync,
  type SqlDriver,
  type ViewChangeRecorder,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openLiteLocalDb, type LiteLocalDbOptions } from "./localdb-port.js";
import {
  type ResolveArtifact,
  type RunIntake,
  type StreamSyncRegistry,
  type StreamSyncBlobs,
  createGatewayStreamSyncRegistry,
  createStorageStreamSyncBlobs,
  createStreamSyncKeyPorts,
  streamSyncNetwork,
  streamSyncFlagsOn,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { wasmStreamCrypto } from "./wasm-stream-crypto.js";
import { LITE_PART_TARGET_BYTES } from "./stream-sync-budget.js";
import {
  createVersionInventoryClient,
  type DurableAdditionsService,
} from "@opendatalabs/personal-server-ts-core/additions";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { Logger } from "@opendatalabs/personal-server-ts-core/logger";
import {
  createSyncManager,
  type SyncManager,
} from "@opendatalabs/personal-server-ts-core/sync/manager";
import {
  createGatewayDataPointFeed,
  createGatewayDeleteDataPort,
  createRegistryChangeProbe,
  createInventoryTombstoneFinality,
  createPendingBlobDeletionStore,
  createScopeDeletionTracker,
  normalizePendingBlobDeletionPlanned,
  normalizePendingBlobDeletions,
  type PendingBlobDeletionPlanned,
  type ScopeDeletionTracker,
  type UploadAttemptStore,
} from "@opendatalabs/personal-server-ts-core/sync";
import type {
  DataPointFeedPort,
  PendingBlobDeletion,
  PendingBlobDeletionStore,
} from "@opendatalabs/personal-server-ts-core/ports";
import {
  createVanaSyncStorageAdapter,
  resolveVanaStorageEndpoint,
} from "@opendatalabs/personal-server-ts-core/storage/adapters";
import {
  createServerSigner,
  type ServerSigner,
} from "@opendatalabs/personal-server-ts-core/signing";
import type { RequestSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { ServerAccount } from "@opendatalabs/personal-server-ts-core/keys";
import {
  buildWeb3SignedHeader,
  createGatewayClient,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import { legacyMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import { eraseLegacyScopesOf } from "@opendatalabs/personal-server-ts-core/legacy-projection";
import {
  withCancellableRegistration,
  type DownloadDiagnosticsHook,
  type DownloadWorkerDeps,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { LineageGatewayPort } from "@opendatalabs/personal-server-ts-core/lineage";
import type { PsLiteStateStore } from "./state.js";
import { resolvePsLiteOwner } from "./owner-binding.js";
import {
  createPsLiteAdditionsSession,
  type AdditionsWorkerPort,
} from "./additions-session.js";
import {
  createPsLiteAdditionsTransport,
  type PsLiteBoundedOwnerSigner,
} from "./additions-transport.js";
import type { DiagnosticsRecorder } from "./diagnostics.js";

const SYNC_CURSOR_KEY = "sync-cursor-v1";
const PENDING_BLOB_DELETIONS_KEY = "pending-blob-deletions-v1";
const UPLOAD_ATTEMPTS_KEY = "upload-attempts-v1";

interface PsLitePendingBlobDeletionsState {
  /** Exact (scope, version) keys; `scopes` is the pre-key format. */
  keys?: PendingBlobDeletion[];
  scopes?: string[];
  /** Per-scope planned-through watermark (see the core marker store). */
  planned?: PendingBlobDeletionPlanned;
}

interface PsLiteSyncCursorState {
  lastProcessedTimestamp: string | null;
}

interface SyncCursor {
  read(): Promise<string | null>;
  write(timestamp: string): Promise<void>;
}

/** Owner-authorized sync capability. Hosts mediate signing; no owner key enters Lite. */
export interface PsLiteOwnerSyncSigner
  extends
    Partial<PsLiteBoundedOwnerSigner>,
    Pick<ServerSigner, "address" | "signAddData" | "signLineageAttestation"> {
  signMessage(message: string): Promise<`0x${string}`>;
}

export interface PsLiteSyncOptions {
  /** Host registration gate: while closed, switched sync only pulls owner data. */
  registrationReady?: () => boolean;
  accountStorageMode?: OwnedAccountStorageMode;
  config: ServerConfig;
  /** Host-owned SQLite database; a missing driver makes switched sync unavailable. */
  localDb?: LiteLocalDbOptions;
  /** Stable host device identity; defaults to this server account. */
  localDbDeviceId?: string;
  /**
   * Resolves a run's `artifactDigest` to declarations the host verified
   * (run-intake contract v2 §6). Without it every run answers
   * `unknown_artifact`.
   */
  streamSyncDeclarations?: ResolveArtifact;
  /**
   * Verified manifests retained for seed-descriptor admission. Seed profiles
   * and primary keys must match one of these documents. Default: none.
   */
  streamSyncRetainedManifests?: () => readonly string[];
  /**
   * The stream-sync registry. Default: the gateway client at `config.gateway.url`.
   * A host or test that has no gateway passes its own registry (for example
   * `createMemoryStreamSyncRegistry()`).
   */
  streamSyncRegistry?: StreamSyncRegistry;
  /** Host transport for encrypted parts, heads and run blobs. */
  streamSyncBlobs?: StreamSyncBlobs;
  /** Publish while collecting, default off. See `LocalSyncDeps.publishWhileCollecting`. */
  streamSyncPublishWhileCollecting?: boolean;
  /**
   * Serve a first load's applied parts while it fills. Default: the config key
   * `streamSync.progressiveFirstLoad`, off. An explicit option wins. See
   * `LocalSyncDeps.progressiveFirstLoad`.
   */
  streamSyncProgressiveFirstLoad?: boolean;
  /**
   * The design flags to turn on, as one comma list of names (see
   * `STREAM_SYNC_DESIGN_FLAGS`). A host passes the list as it got it and holds
   * no flag table. A flag's own option above wins.
   */
  streamSyncFlags?: string;
  stateStore: PsLiteStateStore;
  storage: DataStoragePort & Pick<PsLiteStoragePort, "retirementRows">;
  ownerAddress?: `0x${string}`;
  ownerSignature: `0x${string}`;
  serverAccount: ServerAccount;
  /** Uses owner authority for Storage and AddData, without server registration. */
  ownerSyncSigner?: PsLiteOwnerSyncSigner;
  additionsWorkerFactory?: () => AdditionsWorkerPort;
  /** Background recovery deadline, including lock wait. Defaults to 10 seconds;
   * hosted owner signing may use up to two minutes. */
  additionsTimeBudgetMs?: number;
  /** Summary recovery work allowance, default 8 MiB, maximum 256 MiB.
   * Upload hints and bounded deletion retain their 8 MiB allowance. */
  additionsByteBudget?: number;
  /** Metrics-only hosts can use the bounded coordinator without starting sync. */
  autoStartSync?: boolean;
  /** Storage authentication origin, independent of its routing endpoint. */
  storageAudience?: string;
  /**
   * Gateway client. The default SDK client is wrapped so the upload deadline
   * closes its in-flight registry write. A client supplied here is used as
   * given: it is cancellable only if it declares so (see
   * `withCancellableRegistration`); otherwise a hung registry write runs on
   * past the deadline and its entry waits for it.
   */
  gateway?: GatewayClient;
  /**
   * Names the backing store of `stateStore` for upload crash protection when
   * the store does not name itself. Without either, that protection is kept
   * in memory and does not survive a restart.
   */
  uploadAttemptNamespace?: string;
  /**
   * Deletion-aware gateway feed. Defaults to a REST feed on the configured
   * gateway URL; inject alongside a mock `gateway` in tests.
   */
  dataPointFeed?: DataPointFeedPort;
  /**
   * Read-side tombstone memory shared with the runtime's data API. Built
   * here by default so the sync workers and the reads see the same state.
   */
  scopeDeletions?: ScopeDeletionTracker;
  diagnostics?: DiagnosticsRecorder;
  logger?: Logger;
  /** Registers derivatives (envelopes carrying `$lineage`) with their lineage. */
  lineageGateway?: Pick<LineageGatewayPort, "registerDataPoint">;
  /** Post-index download hook (marks derivative questions stale). */
  onDataPointIndexed?: DownloadWorkerDeps["onDataPointIndexed"];
}

function createBrowserLogger(logger?: Logger): Logger {
  const fallback: Logger = {
    info: console.info.bind(console),
    error: console.error.bind(console),
    warn: console.warn.bind(console),
    debug: console.debug.bind(console),
  };
  if (!logger) {
    return fallback;
  }
  return {
    debug: logger.debug?.bind(logger) ?? fallback.debug,
    info: logger.info?.bind(logger) ?? fallback.info,
    warn: logger.warn?.bind(logger) ?? fallback.warn,
    error: logger.error?.bind(logger) ?? fallback.error,
  };
}

export function createPsLiteSyncCursor(
  stateStore: PsLiteStateStore,
): SyncCursor {
  return {
    async read() {
      const state =
        await stateStore.get<PsLiteSyncCursorState>(SYNC_CURSOR_KEY);
      return state?.lastProcessedTimestamp ?? null;
    },
    async write(timestamp) {
      await stateStore.set<PsLiteSyncCursorState>(SYNC_CURSOR_KEY, {
        lastProcessedTimestamp: timestamp,
      });
    },
  };
}

const MAX_CORRUPT_COPIES = 3;
const CORRUPT_INDEX_KEY = "upload-attempts-v1.corrupt-index";

/**
 * Upload-attempt markers in the same durable state store as the sync cursor,
 * so a WebView or manager rebuild keeps the interrupted-attempt count. The
 * single-owner lock is named by the backing store (`namespace`, from the
 * store or the host), never by the wrapper object: managers over the same
 * store exclude each other, managers over different stores do not. Browser
 * locks are shared by every tab of the origin; a runtime without them
 * excludes only within this JS realm.
 */
export function createPsLiteUploadAttemptStore(
  stateStore: PsLiteStateStore,
  options: { namespace?: string } = {},
): UploadAttemptStore {
  const namespace = options.namespace ?? stateStore.namespace;
  if (!namespace)
    throw new Error(
      "Upload attempt markers need a namespace: the host must name the backing store",
    );
  return {
    namespace: `${namespace}/${UPLOAD_ATTEMPTS_KEY}`,
    crossRealmLock: true,
    read() {
      return stateStore.get<unknown>(UPLOAD_ATTEMPTS_KEY);
    },
    async write(envelope) {
      await stateStore.set(UPLOAD_ATTEMPTS_KEY, envelope);
    },
    async preserveCorrupt(value, stamp) {
      const kept = [
        ...((await stateStore.get<string[]>(CORRUPT_INDEX_KEY)) ?? []),
        stamp,
      ];
      await stateStore.set(`${UPLOAD_ATTEMPTS_KEY}.corrupt-${stamp}`, value);
      await stateStore.set(CORRUPT_INDEX_KEY, kept.slice(-MAX_CORRUPT_COPIES));
      for (const old of kept.slice(0, -MAX_CORRUPT_COPIES))
        await stateStore.delete(`${UPLOAD_ATTEMPTS_KEY}.corrupt-${old}`);
    },
  };
}

export function createPsLitePendingBlobDeletionStore(
  stateStore: PsLiteStateStore,
): PendingBlobDeletionStore {
  return createPendingBlobDeletionStore({
    async read() {
      const state = await stateStore.get<PsLitePendingBlobDeletionsState>(
        PENDING_BLOB_DELETIONS_KEY,
      );
      if (!state) return null;
      return {
        keys: normalizePendingBlobDeletions(state.keys ?? state.scopes),
        planned: normalizePendingBlobDeletionPlanned(state.planned),
      };
    },
    async write(keys, planned) {
      await stateStore.set<PsLitePendingBlobDeletionsState>(
        PENDING_BLOB_DELETIONS_KEY,
        { keys, planned },
      );
    },
  });
}

function buildDownloadDiagnosticsHook(
  recorder: DiagnosticsRecorder,
): DownloadDiagnosticsHook {
  return {
    onDownloadStart(fileId) {
      recorder.beginOperation("downloading", undefined, fileId);
      recorder.push({ phase: "downloading", fileId });
    },
    onDownloadEnd(fileId, scope) {
      recorder.endOperation();
      recorder.push({ phase: "downloading", fileId, scope });
    },
    onDownloadError(fileId, detail) {
      recorder.endOperation();
      recorder.push({ phase: "downloading", fileId, error: true, detail });
    },
    onDecryptStart(fileId, scope) {
      recorder.beginOperation("decrypting", scope, fileId);
      recorder.push({ phase: "decrypting", fileId, scope });
    },
    onDecryptEnd(fileId, scope) {
      recorder.endOperation();
      recorder.push({ phase: "decrypting", fileId, scope });
    },
    onDecryptError(fileId, scope, detail) {
      recorder.endOperation();
      recorder.push({
        phase: "decrypting",
        fileId,
        scope,
        error: true,
        detail,
      });
    },
    onIndexStart(fileId, scope) {
      recorder.beginOperation("indexing", scope, fileId);
      recorder.push({ phase: "indexing", fileId, scope });
    },
    onIndexEnd(fileId, scope) {
      recorder.endOperation();
      recorder.push({ phase: "indexing", fileId, scope });
      recorder.setScopeReadyAfterIndex(scope);
    },
    onIndexError(fileId, scope, detail) {
      recorder.endOperation();
      recorder.push({ phase: "indexing", fileId, scope, error: true, detail });
    },
    onManifestBuildStart(fileId, scope) {
      recorder.push({ phase: "buildingManifest", fileId, scope });
    },
    onManifestBuildEnd(fileId, scope) {
      recorder.push({ phase: "buildingManifest", fileId, scope });
      recorder.setScopeManifestBuilt(scope);
    },
    onManifestBuildError(fileId, scope, detail) {
      recorder.push({
        phase: "buildingManifest",
        fileId,
        scope,
        error: true,
        detail,
      });
    },
    onRepair(scope, detail) {
      recorder.recordRepair(scope);
      recorder.push({ phase: "repairingManifest", scope, detail });
    },
  };
}

export async function createPsLiteSyncManager(
  options: PsLiteSyncOptions,
): Promise<{
  syncManager: SyncManager;
  /** Database-backed facade, or null when the host cannot open it. */
  localSync?: LocalSync | null;
  /** Changes of the local view; see `IndexedDbPsLiteRuntime.subscribeViewChanges`. */
  viewChanges: ViewChangeRecorder;
  additions?: DurableAdditionsService;
  serverOwner: `0x${string}`;
  dataPointFeed: DataPointFeedPort;
  scopeDeletions: ScopeDeletionTracker;
  /** Releases the owner/network database after the manager has stopped. */
  closeStreamSync(): Promise<void>;
  /** In-process database intake, admitted only after Account says On. */
  streamSyncIntake: RunIntake | null;
  streamSyncSeed: SeedIntake | null;
  streamSyncRead?: StreamSyncReadPort;
  getLocalSync(): Promise<LocalSync>;
}> {
  const additionsTimeBudgetMs = options.additionsTimeBudgetMs ?? 10_000;
  const additionsByteBudget = options.additionsByteBudget ?? 8 * 1024 * 1024;
  if (
    !Number.isSafeInteger(additionsByteBudget) ||
    additionsByteBudget < 1 ||
    additionsByteBudget > 256 * 1024 * 1024
  ) {
    throw new RangeError(
      "Additions recovery allowance must be 1..268435456 bytes",
    );
  }
  if (
    !Number.isSafeInteger(additionsTimeBudgetMs) ||
    additionsTimeBudgetMs < 1 ||
    additionsTimeBudgetMs > 120_000
  ) {
    throw new RangeError("Additions recovery deadline must be 1..120000 ms");
  }
  const serverOwner = await resolvePsLiteOwner({
    ownerAddress: options.ownerAddress,
    ownerSignature: options.ownerSignature,
  });
  const syncAccount = options.ownerSyncSigner ?? options.serverAccount;
  if (
    options.ownerSyncSigner &&
    syncAccount.address.toLowerCase() !== serverOwner.toLowerCase()
  ) {
    throw new Error("Owner sync signer must match the verified data owner");
  }
  const masterKey = legacyMasterKey(options.ownerSignature);
  const gateway =
    options.gateway ??
    withCancellableRegistration(
      createGatewayClient(options.config.gateway.url),
      options.config.gateway.url,
    );
  const uploadAttemptNamespace =
    options.uploadAttemptNamespace ?? options.stateStore.namespace;
  const storageAdapter = createVanaSyncStorageAdapter({
    config: options.config,
    serverOwner,
    serverAccount: syncAccount,
    audience: options.storageAudience,
  });
  const signer =
    options.ownerSyncSigner ??
    createServerSigner(options.serverAccount, {
      chainId: options.config.gateway.chainId,
      contracts: options.config.gateway.contracts,
    });
  const ownerSigner = options.ownerSyncSigner;
  const ownerRequestSigner: RequestSigner | undefined = ownerSigner
    ? {
        signRequest: (params) =>
          buildWeb3SignedHeader({
            ...params,
            signMessage: (message: string) => ownerSigner.signMessage(message),
          }),
      }
    : undefined;
  const boundedSigner =
    ownerSigner?.signMessageBounded && ownerSigner.signAddDataBounded
      ? {
          signMessageBounded: ownerSigner.signMessageBounded.bind(ownerSigner),
          signAddDataBounded: ownerSigner.signAddDataBounded.bind(ownerSigner),
        }
      : undefined;
  const additions =
    ownerSigner && boundedSigner && options.stateStore.bounded
      ? createPsLiteAdditionsSession({
          init: {
            ownerAddress: serverOwner.toLowerCase() as `0x${string}`,
            network: `vana:${options.config.gateway.chainId}:${new URL(options.config.gateway.url).origin}`,
            gatewayUrl: options.config.gateway.url,
            storageEndpoint: resolveVanaStorageEndpoint(options.config),
            masterKey,
            byteBudget: additionsByteBudget,
            timeBudgetMs: additionsTimeBudgetMs,
            diagnostics: Boolean(options.diagnostics),
          },
          diagnostics: options.diagnostics,
          transport: createPsLiteAdditionsTransport({
            config: options.config,
            ownerAddress: serverOwner,
            stateStore: options.stateStore,
            masterKey,
            ownerSigner: boundedSigner,
            storageAudience: options.storageAudience,
          }),
          workerFactory: options.additionsWorkerFactory,
          deleteSystemScope: async (scope) => {
            const result = await syncManager.deleteScope(scope);
            if (!result.durable || result.steps.gateway.status === "failed")
              throw new Error("System scope deletion was not durable");
          },
        })
      : undefined;
  const cursor = createPsLiteSyncCursor(options.stateStore);
  const logger = createBrowserLogger(options.logger);
  if (!uploadAttemptNamespace)
    logger.warn(
      {},
      "State store names no backing store; upload crash protection is kept in memory",
    );
  const dataPointFeed =
    options.dataPointFeed ??
    createGatewayDataPointFeed({
      gatewayUrl: options.config.gateway.url,
      ownerRequestSigner,
    });
  const scopeDeletions =
    options.scopeDeletions ??
    createScopeDeletionTracker({ feed: dataPointFeed, serverOwner, logger });
  // Durable deletion: same AddData signer as uploads, same Web3Signed
  // account as the storage provider.
  const deleteData = createGatewayDeleteDataPort({
    gatewayUrl: options.config.gateway.url,
    dataPointFeed,
    serverOwner,
    signer,
    storage: {
      endpoint: resolveVanaStorageEndpoint(options.config),
      audience: options.storageAudience,
      chainId: options.config.gateway.chainId,
      signMessage: (message) => syncAccount.signMessage(message),
    },
  });
  const pendingBlobDeletions = createPsLitePendingBlobDeletionStore(
    options.stateStore,
  );
  // Blob deletes wait for the covering tombstone to be finalized. The
  // inventory accepts the owner or a registered server of the owner: the
  // same account that signs storage requests.
  const versionInventory = createVersionInventoryClient({
    gatewayUrl: options.config.gateway.url,
    ownerAddress: serverOwner,
    ownerSigner: ownerRequestSigner ?? {
      signRequest: (params) =>
        buildWeb3SignedHeader({
          ...params,
          signMessage: (message: string) => syncAccount.signMessage(message),
        }),
    },
  });
  const tombstoneFinality = createInventoryTombstoneFinality(versionInventory);
  // A deleted connection's log objects leave storage through the same signed
  // delete port and finality as everything else this runtime deletes: a Web or
  // phone delete erases them here, with no Desktop needed.
  const logErasurePorts: LogErasurePorts = {
    versions: inventoryVersionLister(versionInventory),
    finality: tombstoneFinality,
    objects: deleteData,
  };
  const downloadDiagnostics = options.diagnostics
    ? buildDownloadDiagnosticsHook(options.diagnostics)
    : undefined;
  // Account mode selects the database or the explicit legacy sync path.
  const streamSyncNet = streamSyncNetwork(options.config.gateway);
  const mode = options.accountStorageMode ?? {
    owner: serverOwner,
    read: () => "unknown" as const,
  };
  // Only this host's registration observations may authorize retirement.
  let registrationConfirmed = false;
  async function checkRegistration(): Promise<boolean> {
    registrationConfirmed = false;
    const serverInfo = await gateway.getServer(options.serverAccount.address);
    registrationConfirmed = Boolean(serverInfo?.id);
    return registrationConfirmed;
  }
  const retirementWriteReady = () =>
    registrationConfirmed &&
    (options.registrationReady === undefined ||
      options.registrationReady() === true);
  let localDb: SqlDriver | null = null;
  let localSync: LocalSync | null = null;
  // Built before the database opens, so a subscriber never waits for it.
  const viewChanges = createViewChanges();
  let localSyncDeps: LocalSyncDeps | null = null;
  async function closeDatabase() {
    if (localSync) await localSync.close();
    else await localDb?.close();
  }

  // Which design flags are on: the host's list. A browser has no environment.
  const designFlags = streamSyncFlagsOn(options.streamSyncFlags);
  // One registry client for the cycle's reads and the change probe.
  const streamSyncRegistry: StreamSyncRegistry =
    options.streamSyncRegistry ??
    createGatewayStreamSyncRegistry({
      gatewayUrl: options.config.gateway.url,
      ownerAddress: serverOwner,
    });
  // A hidden tab has no one to show a change to: the runtime pauses the
  // manager (`startVisibilityPause`), which holds no request and no timer
  // until it is shown again. Where the document says nothing (a worker), the
  // probe runs.
  const changeProbe = options.localDb
    ? createRegistryChangeProbe(streamSyncRegistry, {
        intervalMs: options.config.streamSync.changeProbeMs,
        push: { enabled: options.config.streamSync.changePush },
      })
    : undefined;

  let syncManager!: ReturnType<typeof createSyncManager>;
  try {
    let closed = false;
    let opening: Promise<LocalSync | null> | undefined;
    async function openDatabase(): Promise<LocalSync | null> {
      if (!options.localDb) return null;
      // Every write the sync engine makes goes through the driver this
      // returns, so the recorder sees each commit (and starts a new baseline
      // per open). The shared open path attaches it.
      localDb = await openLiteLocalDb(
        options.localDb,
        {
          owner: serverOwner,
          network: streamSyncNet,
          deviceId: options.localDbDeviceId ?? options.serverAccount.address,
        },
        { viewChanges: { recorder: viewChanges, logger } },
      );
      if (localDb) {
        localSyncDeps = {
          db: localDb,
          queue: connectionQueue(),
          ownerAddress: serverOwner.toLowerCase() as `0x${string}`,
          registry: streamSyncRegistry,
          blobs:
            options.streamSyncBlobs ??
            createStorageStreamSyncBlobs(storageAdapter),
          keys: createStreamSyncKeyPorts(options.ownerSignature),
          // A reader hashes every segment it applies; noble's Keccak is the
          // largest CPU cost of a first load on a browser's main thread.
          streamCrypto: await wasmStreamCrypto(),
          signer,
          logger,
          now: Date.now,
          newOp: () => globalThis.crypto.randomUUID(),
          recordsCommitted: () => syncManager?.notifyRecordsCommitted(),
          progressiveFirstLoad:
            options.streamSyncProgressiveFirstLoad ??
            (designFlags.progressiveFirstLoad ||
              options.config.streamSync.progressiveFirstLoad),
          partTargetBytes: LITE_PART_TARGET_BYTES,
          ...((options.streamSyncPublishWhileCollecting ??
          designFlags.publishWhileCollecting)
            ? { publishWhileCollecting: true }
            : {}),
        };
        localSync = createLocalSync(localSyncDeps, {
          aliasScopes: () => LEGACY_SCOPE_BINDINGS.keys(),
          aliasTargets: legacyAliasScopes,
          // A held registration confers no write authority, whoever asks:
          // the worker reads this before every host call.
          legacyWriteReady: retirementWriteReady,
          resolveArtifact: options.streamSyncDeclarations ?? (() => null),
          eraseLegacy: (connector) =>
            eraseLegacyScopesOf(connector, options.storage),
          erasure: () => logErasurePorts,
          // Standalone retirement owns its transport, receipts and row leaves.
          legacyRetire: () => {
            const rows = options.storage.retirementRows;
            if (!rows) return undefined;
            return {
              scopesOf: legacyScopesOfConnector,
              streamsOf: legacyStreamsOfScope,
              mode: modeOfAccount(() => mode.read()),
              head: legacyHeadFrom(dataPointFeed, serverOwner),
              finality: tombstoneFinality,
              versions: logErasurePorts.versions,
              rows,
              ...createLegacyRetireRemote({
                gatewayUrl: options.config.gateway.url,
                dataPointFeed,
                serverOwner,
                signer,
                storage: {
                  endpoint: resolveVanaStorageEndpoint(options.config),
                  audience: options.storageAudience,
                  chainId: options.config.gateway.chainId,
                  signMessage: (message) => syncAccount.signMessage(message),
                },
              }),
            };
          },
          // Ordinary connector DELETE retains the scope-delete worker.
          legacyDelete: () => ({
            scopesOf: legacyScopesOfConnector,
            mode: modeOfAccount(() => mode.read()),
            head: legacyHeadFrom(dataPointFeed, serverOwner),
            retire: (scope, head) =>
              syncManager.deleteScope(scope, undefined, { fence: { head } }),
            pendingBlobs: pendingBlobsFrom(pendingBlobDeletions),
            finality: tombstoneFinality,
            versions: logErasurePorts.versions,
            objects: deleteData,
          }),
        });
        // An open legacy retirement resumes when the runtime opens, not only
        // in a full sync cycle. It sends deletes at the gateway, so it needs
        // the write authority a registered runtime has: a read-only
        // registration waits for the cycle that runs once it is admitted.
        if (retirementWriteReady())
          void localSync.legacyRetirer.resume().catch((error: unknown) =>
            logger.warn(
              {
                error: error instanceof Error ? error.message : String(error),
              },
              "Could not resume the legacy retirement at open",
            ),
          );
      }
      return localSync;
    }
    function requireDatabaseMode() {
      if (closed)
        throw new ProtocolError(
          503,
          "STREAM_READ_UNAVAILABLE",
          "Stream sync is unavailable",
        );
      const state = mode.read();
      if (state === "unknown")
        throw new ProtocolError(
          503,
          "ACCOUNT_MODE_UNKNOWN",
          "Waiting for the account storage mode",
        );
      if (state !== "switched")
        throw new ProtocolError(
          409,
          "STREAM_SYNC_NOT_ENABLED",
          "Stream sync is not enabled for this account",
        );
    }
    async function getLocalSync(): Promise<LocalSync> {
      requireDatabaseMode();
      if (localSync) return localSync;
      opening ??= openDatabase().finally(() => {
        opening = undefined;
      });
      const sync = await opening;
      if (!sync)
        throw new ProtocolError(
          503,
          "STREAM_READ_UNAVAILABLE",
          "The stream database is unavailable",
        );
      requireDatabaseMode();
      return sync;
    }
    if (mode.read() === "switched") {
      // A host callback cannot substitute for this runtime's own write check.
      if (options.registrationReady?.() === true) {
        if (options.ownerSyncSigner) registrationConfirmed = true;
        else {
          try {
            await checkRegistration();
          } catch (error) {
            logger.warn(
              { error: String(error) },
              "Could not verify server registration before retirement",
            );
          }
        }
      }
      await openDatabase();
    }
    const streamSyncSeed = createSeedIntake(
      createLocalSeed({
        getDeps: async () => {
          await getLocalSync();
          return localSyncDeps!;
        },
        manifests: options.streamSyncRetainedManifests ?? (() => []),
        staging: createPsLiteSeedStaging(
          options.stateStore,
          serverOwner,
          streamSyncNet,
        ),
      }),
    );
    const streamSyncIntake: RunIntake = {
      begin: async (...args) => (await getLocalSync()).intake.begin(...args),
      batch: async (...args) => (await getLocalSync()).intake.batch(...args),
      end: async (...args) => (await getLocalSync()).intake.end(...args),
      abort: async (...args) => (await getLocalSync()).intake.abort(...args),
      publicationStatus: async (...args) =>
        (await getLocalSync()).intake.publicationStatus(...args),
      checkpoint: async (connector) =>
        (await (await getLocalSync()).intake.checkpoint?.(connector)) ?? null,
    };
    syncManager = createSyncManager(
      {
        additions,
        storage: options.storage,
        storageAdapter,
        gateway,
        signer,
        masterKey,
        serverOwner,
        logger: logger as never,
        lineageGateway: options.lineageGateway,
        dataPointFeed,
        scopeDeletions,
      },
      {
        storage: options.storage,
        storageAdapter,
        gateway,
        cursor,
        masterKey,
        serverOwner,
        logger: logger as never,
        diagnostics: downloadDiagnostics,
        dataPointFeed,
        scopeDeletions,
        onDataPointIndexed: options.onDataPointIndexed,
        localSync: { apply: async () => (await getLocalSync()).apply() },
      },
      {
        accountStorageMode: mode,
        localSync: {
          hasPendingPublication: async () =>
            (await getLocalSync()).hasPendingPublication(),
          cycle: async (scope) => {
            const sync = await getLocalSync();
            if (options.registrationReady && !options.registrationReady()) {
              // Binding was verified above; registry and encrypted blob reads
              // confer no server publication authority. No pending writes leave.
              await sync.apply();
              return { connections: [] };
            }
            return sync.cycle(scope);
          },
          applyDelta: async (delta) => (await getLocalSync()).applyDelta(delta),
        },
        ...(changeProbe && { changeProbe }),
        deleteData,
        pendingBlobDeletions,
        uploadAttemptStore: uploadAttemptNamespace
          ? createPsLiteUploadAttemptStore(options.stateStore, {
              namespace: uploadAttemptNamespace,
            })
          : undefined,
        tombstoneFinality,
        async canSync() {
          registrationConfirmed = false;
          if (options.ownerSyncSigner) {
            registrationConfirmed = true;
            return { ok: true };
          }
          if (
            options.registrationReady &&
            !options.registrationReady() &&
            mode.read() !== "unswitched"
          )
            return { ok: true };
          try {
            if (await checkRegistration()) return { ok: true };
            return {
              ok: false,
              reason: "unregistered",
              message: "Register this Personal Server before syncing.",
            };
          } catch (err) {
            logger.warn(
              { error: err instanceof Error ? err.message : String(err) },
              "Could not verify server registration for sync",
            );
            return {
              ok: false,
              reason: "registration_check_failed",
              message: "Could not verify server registration before syncing.",
            };
          }
        },
      },
    );
    if (options.autoStartSync !== false) syncManager.start();
    return {
      syncManager,
      get localSync() {
        return localSync;
      },
      viewChanges,
      getLocalSync,
      additions,
      serverOwner,
      dataPointFeed,
      scopeDeletions,
      closeStreamSync: async () => {
        closed = true;
        await opening;
        await closeDatabase();
      },
      streamSyncIntake,
      streamSyncSeed,
      streamSyncRead: {
        resolve: async (input) =>
          (await getLocalSync()).resolver.resolve(input),
        listScopes: async (input) =>
          (await getLocalSync()).listing.listScopes(input),
      },
    };
  } catch (error) {
    try {
      await closeDatabase();
    } catch (closeError) {
      logger.warn(
        {
          error:
            closeError instanceof Error
              ? closeError.message
              : String(closeError),
        },
        "Could not release stream sync storage after a failed start",
      );
    }
    throw error;
  }
}
