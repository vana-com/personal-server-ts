import { createPsLiteSeedStaging } from "./seed-staging.js";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
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
  type LocalSyncDeps,
  type SeedIntake,
  type LocalSync,
  type SqlDriver,
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
} from "@opendatalabs/personal-server-ts-core/stream-sync";
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
  accountStorageMode?: OwnedAccountStorageMode;
  config: ServerConfig;
  /** Host-owned SQLite database; a missing driver makes switched sync unavailable. */
  localDb?: LiteLocalDbOptions;
  /** Stable host device identity; defaults to this server account. */
  localDbDeviceId?: string;
  /** Whether the local database may fetch historical versions. */
  olderVersionReads?: () => boolean;
  /**
   * Resolves a run's `artifactDigest` to declarations the host verified
   * (run-intake contract v2 §6). Without it every run answers
   * `unknown_artifact`.
   */
  streamSyncDeclarations?: ResolveArtifact;
  /**
   * The stream names a connector declares, from the manifests the host
   * verified (`manifestStreamLister` over the same documents the host passes
   * to `streamSyncDeclarations`). A connection delete posts a delete head on
   * each declared stream that has no registry row. Required: a host that omits
   * it lets a stale record of a rowless stream publish after a delete.
   * A connector with registry rows and no declared names is not deleted
   * (`ConnectorNotVerifiedError`).
   */
  streamSyncDeclaredStreams: (connector: string) => readonly string[];
  /**
   * Verified manifests retained for seed-descriptor admission and deletion.
   * Seed profiles and primary keys must match one of these documents. A connection
   * delete also fences the streams these declare, so a host that passes no
   * `streamSyncDeclaredStreams` names for a connector with rows still deletes
   * it. Default: none.
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
  stateStore: PsLiteStateStore;
  storage: DataStoragePort;
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
  const tombstoneFinality = createInventoryTombstoneFinality(
    createVersionInventoryClient({
      gatewayUrl: options.config.gateway.url,
      ownerAddress: serverOwner,
      ownerSigner: ownerRequestSigner ?? {
        signRequest: (params) =>
          buildWeb3SignedHeader({
            ...params,
            signMessage: (message: string) => syncAccount.signMessage(message),
          }),
      },
    }),
  );
  const downloadDiagnostics = options.diagnostics
    ? buildDownloadDiagnosticsHook(options.diagnostics)
    : undefined;
  // Account mode selects the database or the explicit legacy sync path.
  const streamSyncNet = streamSyncNetwork(options.config.gateway);
  const mode = options.accountStorageMode ?? {
    owner: serverOwner,
    read: () => "unknown" as const,
  };
  let localDb: SqlDriver | null = null;
  let localSync: LocalSync | null = null;
  let localSyncDeps: LocalSyncDeps | null = null;
  async function closeDatabase() {
    if (localSync) await localSync.close();
    else await localDb?.close();
  }

  let syncManager!: ReturnType<typeof createSyncManager>;
  try {
    let closed = false;
    let opening: Promise<LocalSync | null> | undefined;
    async function openDatabase(): Promise<LocalSync | null> {
      if (!options.localDb) return null;
      localDb = await openLiteLocalDb(options.localDb, {
        owner: serverOwner,
        network: streamSyncNet,
        deviceId: options.localDbDeviceId ?? options.serverAccount.address,
      });
      if (localDb) {
        localSyncDeps = {
          db: localDb,
          queue: connectionQueue(),
          ownerAddress: serverOwner.toLowerCase() as `0x${string}`,
          registry:
            options.streamSyncRegistry ??
            createGatewayStreamSyncRegistry({
              gatewayUrl: options.config.gateway.url,
              ownerAddress: serverOwner,
            }),
          blobs:
            options.streamSyncBlobs ??
            createStorageStreamSyncBlobs(storageAdapter),
          keys: createStreamSyncKeyPorts(options.ownerSignature),
          signer,
          logger,
          now: Date.now,
          newOp: () => globalThis.crypto.randomUUID(),
          partTargetBytes: LITE_PART_TARGET_BYTES,
        };
        localSync = createLocalSync(localSyncDeps, {
          aliasScopes: () => LEGACY_SCOPE_BINDINGS.keys(),
          aliasTargets: legacyAliasScopes,
          resolveArtifact: options.streamSyncDeclarations ?? (() => null),
          declaredStreams: options.streamSyncDeclaredStreams,
          retainedManifests: options.streamSyncRetainedManifests,
          eraseLegacy: (connector) =>
            eraseLegacyScopesOf(connector, options.storage),
          olderVersionReads:
            options.olderVersionReads ??
            (() => options.config.olderVersionReads),
        });
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
    if (mode.read() === "switched") await openDatabase();
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
        localSync: { cycle: async () => (await getLocalSync()).cycle() },
        deleteData,
        pendingBlobDeletions,
        uploadAttemptStore: uploadAttemptNamespace
          ? createPsLiteUploadAttemptStore(options.stateStore, {
              namespace: uploadAttemptNamespace,
            })
          : undefined,
        tombstoneFinality,
        async canSync() {
          if (options.ownerSyncSigner) return { ok: true };
          try {
            const serverInfo = await gateway.getServer(
              options.serverAccount.address,
            );
            if (serverInfo?.id) return { ok: true };
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
        olderVersions: {
          read: async (...args) =>
            (await getLocalSync()).olderVersions.read(...args),
          list: async (...args) =>
            (await getLocalSync()).olderVersions.list(...args),
          counts: () =>
            localSync?.olderVersions.counts() ?? {
              served: 0,
              gone: 0,
              off: 0,
            },
        },
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
