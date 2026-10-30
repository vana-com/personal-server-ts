import { type DurableAdditionsService } from "@opendatalabs/personal-server-ts-core/additions";
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
  createPendingBlobDeletionStore,
  createScopeDeletionTracker,
  normalizePendingBlobDeletionPlanned,
  normalizePendingBlobDeletions,
  type PendingBlobDeletionPlanned,
  type ScopeDeletionTracker,
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
  deriveMasterKey,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type {
  DownloadDiagnosticsHook,
  DownloadWorkerDeps,
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
  config: ServerConfig;
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
  /** Summary recovery work allowance, default 8 MiB, maximum 32 MiB.
   * Upload hints and bounded deletion retain their 8 MiB allowance. */
  additionsByteBudget?: number;
  /** Metrics-only hosts can use the bounded coordinator without starting sync. */
  autoStartSync?: boolean;
  /** Storage authentication origin, independent of its routing endpoint. */
  storageAudience?: string;
  gateway?: GatewayClient;
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
  additions?: DurableAdditionsService;
  serverOwner: `0x${string}`;
  dataPointFeed: DataPointFeedPort;
  scopeDeletions: ScopeDeletionTracker;
}> {
  const additionsTimeBudgetMs = options.additionsTimeBudgetMs ?? 10_000;
  const additionsByteBudget = options.additionsByteBudget ?? 8 * 1024 * 1024;
  if (
    !Number.isSafeInteger(additionsByteBudget) ||
    additionsByteBudget < 1 ||
    additionsByteBudget > 32 * 1024 * 1024
  ) {
    throw new RangeError(
      "Additions recovery allowance must be 1..33554432 bytes",
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
  const masterKey = deriveMasterKey(options.ownerSignature);
  const gateway =
    options.gateway ?? createGatewayClient(options.config.gateway.url);
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
            ownerAddress: serverOwner,
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
  const downloadDiagnostics = options.diagnostics
    ? buildDownloadDiagnosticsHook(options.diagnostics)
    : undefined;
  const syncManager = createSyncManager(
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
    },
    {
      deleteData,
      pendingBlobDeletions,
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
  return { syncManager, additions, serverOwner, dataPointFeed, scopeDeletions };
}
