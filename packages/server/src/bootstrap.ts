import { mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { PersonalServerReadFulfillmentReporter } from "@opendatalabs/personal-server-ts-core/api";
import { DEFAULT_ROOT_PATH, resolveRootPath } from "./config/index.js";
import { createLogger, type Logger } from "./logger/index.js";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "./storage/index-manager.js";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { createGatewayClient } from "@opendatalabs/vana-sdk/node";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { createAccessLogWriter } from "./logging/access-log.js";
import { createAccessLogReader } from "./logging/access-reader.js";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import {
  deriveMasterKey,
  recoverServerOwner,
} from "@opendatalabs/vana-sdk/node";
import { loadOrCreateServerAccount } from "./keys/server-account.js";
import type { ServerAccount } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createRequestSigner,
  createServerSigner,
} from "@opendatalabs/personal-server-ts-core/signing";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import {
  createGatewayLineageClient,
  type LineageGatewayPort,
} from "@opendatalabs/personal-server-ts-core/lineage";
import { createSyncCursor } from "./sync-cursor.js";
import {
  createGatewayDataPointFeed,
  createGatewayDeleteDataPort,
  createScopeDeletionTracker,
  createSyncManager,
  type SyncManager,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { DataPointFeedPort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  createVanaSyncStorageAdapter,
  resolveVanaStorageEndpoint,
} from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { createFilePendingBlobDeletionStore } from "./pending-blob-deletions.js";
import type { Hono } from "hono";
import { createApp, type IdentityInfo } from "./app.js";
import { generateDevToken } from "./dev-token.js";
import { migrateLocalState } from "./migrations/local-state.js";
import { createTokenStore, type TokenStore } from "./token-store.js";
import { TunnelManager, ensureFrpcBinary } from "./tunnel/index.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";
import { createSqliteQuestionStore } from "./storage/question-store.js";
import {
  computeQuestion,
  createOpenAiCompatibleInferenceProvider,
  createPhalaE2eeEncryption,
  createRecomputeScheduler,
  type InferenceProvider,
  type RecomputeScheduler,
} from "@opendatalabs/personal-server-ts-core/derivatives";

export interface ServerContext {
  app: Hono;
  logger: Logger;
  config: ServerConfig;
  startedAt: Date;
  indexManager: IndexManager;
  gatewayClient: GatewayClient;
  accessLogReader: AccessLogReader;
  serverAccount?: ServerAccount;
  serverSigner?: ServerSigner;
  syncManager: SyncManager | null;
  tunnelManager?: TunnelManager;
  tunnelUrl?: string;
  isServerRegistered: () => boolean;
  localApprovalPort?: number;
  getLocalApprovalOrigin: () => string | undefined;
  setLocalApprovalOrigin: (origin?: string) => void;
  devToken?: string;
  startBackgroundServices: () => Promise<void>;
  cleanup: () => Promise<void>;
}

export interface CreateServerOptions {
  rootPath?: string;
  /**
   * Inference provider for the derivative compute layer. Defaults to the
   * OpenAI-compatible client on `config.inference` (env overrides:
   * INFERENCE_BASE_URL, INFERENCE_MODEL, INFERENCE_API_KEY,
   * INFERENCE_E2EE, INFERENCE_REQUEST_FIELDS). Tests inject a fake.
   */
  inferenceProvider?: InferenceProvider;
  /** @deprecated Use rootPath instead. */
  serverDir?: string;
  dataDir?: string;
  ownerSignature?: `0x${string}`;
  gatewayClient?: GatewayClient;
  /**
   * Deletion-aware gateway feed (`includeDeleted=true` listings + tombstone
   * lookups). Defaults to a REST feed on `config.gateway.url`; inject with a
   * mock gateway in tests.
   */
  dataPointFeed?: DataPointFeedPort;
  readFulfillmentReporter?: PersonalServerReadFulfillmentReporter;
  /**
   * MCP OAuth approval page URL (or a lazy getter for it). When set, the MCP
   * OAuth router advertises discovery metadata and redirects authorization
   * requests to this page for owner approval; when absent, MCP OAuth
   * endpoints report MCP_OAUTH_NOT_CONFIGURED. Hosts that render their own
   * approval surface (e.g. the desktop app) pass it here.
   */
  mcpOAuthApprovalUrl?: string | (() => string);
}

const DEFAULT_LOCAL_APPROVAL_PORT = 34127;

/**
 * `INFERENCE_REQUEST_FIELDS` — extra top-level fields on every chat request.
 *
 * Unset leaves `config.inference.requestFields` (the Phala routing hint) in
 * place, so default behaviour is unchanged. `none` or `{}` sends no extra
 * fields, which is what a non-Phala provider wants. Anything else must be a
 * JSON object; a malformed value throws at boot rather than silently sending
 * the wrong body — the request bytes are what the signature covers.
 */
export function parseRequestFields(
  raw: string | undefined,
  fallback: Record<string, unknown>,
): Record<string, unknown> {
  if (raw === undefined) return fallback;
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed.toLowerCase() === "none") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error(
      "INFERENCE_REQUEST_FIELDS must be a JSON object, `none`, or unset",
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(
      "INFERENCE_REQUEST_FIELDS must be a JSON object, `none`, or unset",
    );
  }
  return parsed as Record<string, unknown>;
}

function resolveLocalApprovalPort(serverPort: number): number {
  const raw = process.env.LOCAL_AUTH_PORT;
  if (raw !== undefined) {
    const parsed = Number(raw);
    if (
      Number.isInteger(parsed) &&
      parsed >= 1 &&
      parsed <= 65535 &&
      parsed !== serverPort
    ) {
      return parsed;
    }
  }

  const adjacentPort = serverPort + 1;
  if (adjacentPort <= 65535) {
    return adjacentPort;
  }

  return DEFAULT_LOCAL_APPROVAL_PORT;
}

export async function createServer(
  config: ServerConfig,
  options?: CreateServerOptions,
): Promise<ServerContext> {
  const logger = createLogger(config.logging);
  const startedAt = new Date();

  const storageRoot = resolveRootPath(
    options?.rootPath ?? options?.serverDir ?? DEFAULT_ROOT_PATH,
  );
  const dataDir = options?.dataDir ?? join(storageRoot, "data");
  const indexPath = join(storageRoot, "index.db");
  const configPath = join(storageRoot, "config.json");
  const syncCursorPath = join(storageRoot, "sync-cursor.json");
  const pendingBlobDeletionsPath = join(
    storageRoot,
    "pending-blob-deletions.json",
  );
  const tokensPath = join(storageRoot, "tokens.json");

  await mkdir(storageRoot, { recursive: true });
  await mkdir(dataDir, { recursive: true });

  const db = initializeDatabase(indexPath);
  await migrateLocalState({
    storageRoot,
    dataDir,
    configPath,
    syncCursorPath,
    tokensPath,
    db,
    logger,
  });
  const indexManager = createIndexManager(db);
  const hierarchyOptions: HierarchyManagerOptions = { dataDir };
  const dataStorage = createNodeDataStorage({ indexManager, hierarchyOptions });

  const gatewayClient =
    options?.gatewayClient ?? createGatewayClient(config.gateway.url);

  // X402 payment enforcement on data reads. When config.payment.enabled is
  // true, GET /v1/data/:scope requires builders to supply a signed X-PAYMENT
  // header on every read; the server forwards to gateway.payForOperation.
  // See packages/core/src/payment/x402.ts. Off-by-default for development
  // and test setups where signing payment per read is friction.
  if (config.payment.enabled) {
    logger.info("X402 payment enforcement enabled on data reads");
  }

  // Derive server owner from VANA_MASTER_KEY_SIGNATURE env var
  const masterKeySignature =
    options?.ownerSignature ??
    (process.env.VANA_MASTER_KEY_SIGNATURE as `0x${string}` | undefined);
  const ownerPrivateKey = process.env.VANA_OWNER_PRIVATE_KEY as
    `0x${string}` | undefined;
  const ownerTunnelSigner = ownerPrivateKey
    ? privateKeyToAccount(
        ownerPrivateKey.startsWith("0x")
          ? ownerPrivateKey
          : (`0x${ownerPrivateKey}` as `0x${string}`),
      )
    : null;
  let serverOwner: `0x${string}` | undefined;

  let serverAccount: ServerAccount | undefined;
  let serverSigner: ServerSigner | undefined;
  let identity: IdentityInfo | undefined;

  if (masterKeySignature) {
    const recoveredServerOwner = await recoverServerOwner(masterKeySignature);
    serverOwner = recoveredServerOwner;
    deriveMasterKey(masterKeySignature); // validate signature format
    logger.info({ owner: serverOwner }, "Server owner derived from master key");
    if (
      ownerTunnelSigner &&
      ownerTunnelSigner.address.toLowerCase() !==
        recoveredServerOwner.toLowerCase()
    ) {
      throw new Error(
        "VANA_OWNER_PRIVATE_KEY does not match VANA_MASTER_KEY_SIGNATURE owner",
      );
    }

    // Load or create server keypair from disk
    const keyPath = join(storageRoot, "key.json");
    serverAccount = loadOrCreateServerAccount(keyPath);
    logger.info(
      { owner: serverOwner, serverAddress: serverAccount.address },
      "Server signing account loaded",
    );

    serverSigner = createServerSigner(serverAccount, {
      chainId: config.gateway.chainId,
      contracts: config.gateway.contracts,
    });

    // Identity starts with serverId=null; background services will populate it
    identity = {
      address: serverAccount.address,
      publicKey: serverAccount.publicKey,
      serverId: null,
    };
  } else {
    logger.warn(
      "VANA_MASTER_KEY_SIGNATURE not set — owner-restricted endpoints will return 500",
    );
  }

  // Resolve PS_ACCESS_TOKEN for cloud control-plane / bootstrap auth.
  // This is not the per-login CLI session token returned to users.
  let accessToken: string | undefined = process.env.PS_ACCESS_TOKEN;
  if (!accessToken && process.env.CLOUD_MODE === "true") {
    try {
      const metadataRes = await fetch(
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ps-access-token",
        {
          headers: { "Metadata-Flavor": "Google" },
          signal: AbortSignal.timeout(2000),
        },
      );
      if (metadataRes.ok) {
        const token = (await metadataRes.text()).trim();
        if (token.length > 0) {
          accessToken = token;
          logger.info("PS control-plane token loaded from instance metadata");
        }
      }
    } catch {
      logger.debug(
        "Could not read PS control-plane token from instance metadata",
      );
    }
  }
  if (accessToken) {
    logger.info(
      "PS_ACCESS_TOKEN configured — control-plane bearer auth enabled",
    );
  }

  // Download frpc binary eagerly (auth-independent) so it's ready when the user signs in
  let frpcBinaryPath = "";
  if (config.tunnel.enabled) {
    try {
      frpcBinaryPath = await ensureFrpcBinary(storageRoot, {
        log: (msg) => logger.info(msg),
      });
    } catch (err) {
      logger.warn({ err }, "Failed to download frpc binary - tunnel disabled");
    }
  }

  // Derivative data: the gateway lineage client signs lineage reads with the
  // server key (the gateway treats a registered server as the owner's) and
  // registers derivatives with their lineage. Needs the server account.
  // The one server-key request signer: lineage reads, and the inference
  // relay calls below, authenticate to the gateway with the same scheme.
  const requestSigner = serverAccount
    ? createRequestSigner(serverAccount)
    : undefined;
  const lineageGateway: LineageGatewayPort | undefined = requestSigner
    ? createGatewayLineageClient({
        gatewayUrl: config.gateway.url,
        requestSigner,
      })
    : undefined;

  // --- Sync engine setup ---
  let syncManager: SyncManager | null = null;
  // Deletion-aware registry view. Independent of sync: the data route uses
  // it to answer 410 for scopes the owner deleted even when sync is off.
  const dataPointFeed =
    options?.dataPointFeed ??
    createGatewayDataPointFeed({ gatewayUrl: config.gateway.url });
  // Read-side memory of tombstones, shared by the sync workers (which feed
  // it) and the data route (which consults it on every read).
  const scopeDeletions = createScopeDeletionTracker({
    feed: dataPointFeed,
    serverOwner,
    logger,
  });

  // --- Derivative compute (question -> derivative) ---
  // The scheduler exists before the sync manager so downloads can mark
  // questions stale; it reaches the sync manager lazily to upload results.
  const questionStore = createSqliteQuestionStore(db);
  const inferenceBaseUrl =
    process.env.INFERENCE_BASE_URL ?? config.inference.baseUrl;
  // E2EE to the Phala gateway is on unless config or INFERENCE_E2EE=false
  // turns it off (local development against a provider without ACI).
  const inferenceE2ee =
    process.env.INFERENCE_E2EE !== undefined
      ? process.env.INFERENCE_E2EE !== "false"
      : config.inference.e2ee;
  // Local development only: production relays hold the provider key. A key
  // means the base URL is a provider, not the relay, so nothing is signed.
  const inferenceApiKey = process.env.INFERENCE_API_KEY;
  // Extra body fields on every chat-completions request. Defaults to the
  // Vana / Phala routing hint; set INFERENCE_REQUEST_FIELDS to `none` (or
  // `{}`) when pointing baseUrl at a provider where the hint is meaningless.
  const inferenceRequestFields = parseRequestFields(
    process.env.INFERENCE_REQUEST_FIELDS,
    config.inference.requestFields,
  );
  // The Vana inference relay only forwards requests signed by the owner or
  // by one of the owner's active registered servers; this is the same
  // server-key signer the lineage reads use.
  const inferenceSigner = inferenceApiKey ? undefined : requestSigner;
  const inferenceProvider =
    options?.inferenceProvider ??
    createOpenAiCompatibleInferenceProvider({
      baseUrl: inferenceBaseUrl,
      model: process.env.INFERENCE_MODEL ?? config.inference.model,
      apiKey: inferenceApiKey,
      requestSigner: inferenceSigner,
      requestFields: inferenceRequestFields,
      encryption: inferenceE2ee
        ? createPhalaE2eeEncryption({
            baseUrl: inferenceBaseUrl,
            requestSigner: inferenceSigner,
            logger,
          })
        : undefined,
    });
  if (!inferenceE2ee) {
    logger.warn(
      { baseUrl: inferenceBaseUrl },
      "Inference E2EE is disabled: prompts and answers travel as plaintext over TLS",
    );
  }
  const derivativeScheduler: RecomputeScheduler = createRecomputeScheduler({
    store: questionStore,
    debounceMs: config.inference.recomputeDebounceMs,
    serverOwner,
    logger,
    compute: (questionId) =>
      computeQuestion(questionId, {
        // A -> B -> C: a question reading this derived scope recomputes.
        onDerivedWritten: (event) =>
          derivativeScheduler.markSourceChanged(event.scope, {
            lineageSources: event.lineageSources,
          }),
        storage: dataStorage,
        store: questionStore,
        provider: inferenceProvider,
        serverOwner,
        maxSourceItems: config.inference.maxSourceItems,
        syncManager: {
          notifyNewData: () => syncManager?.notifyNewData(),
        },
        scopeDeletions,
        writePolicyPorts: {
          authSessionVerifier: gatewayClient,
          grantVerifier: gatewayClient,
        },
        logger,
      }),
  });
  const derivativeCompute = {
    store: questionStore,
    scheduler: derivativeScheduler,
  };

  if (
    config.sync.enabled &&
    masterKeySignature &&
    serverOwner &&
    serverAccount &&
    serverSigner
  ) {
    const masterKey = deriveMasterKey(masterKeySignature);

    const storageAdapter = createVanaSyncStorageAdapter({
      config,
      serverOwner,
      serverAccount,
    });

    const cursor = createSyncCursor(syncCursorPath, {
      legacyConfigPath: configPath,
    });

    const uploadDeps = {
      storage: dataStorage,
      storageAdapter,
      gateway: gatewayClient,
      signer: serverSigner,
      masterKey,
      serverOwner,
      logger,
      lineageGateway,
      dataPointFeed,
      scopeDeletions,
    };

    const downloadDeps = {
      storage: dataStorage,
      storageAdapter,
      gateway: gatewayClient,
      cursor,
      masterKey,
      serverOwner,
      logger,
      dataPointFeed,
      scopeDeletions,
      onDataPointIndexed: (event: {
        scope: string;
        lineageSources?: string[];
      }) =>
        derivativeScheduler.markSourceChanged(event.scope, {
          lineageSources: event.lineageSources,
        }),
    };

    // Durable deletion: gateway tombstone signed with the same server
    // account + AddData signer uploads use, storage DELETE authorised with
    // the same Web3Signed signer the storage provider uploads with.
    const deleteData = createGatewayDeleteDataPort({
      gatewayUrl: config.gateway.url,
      dataPointFeed,
      serverOwner,
      signer: serverSigner,
      storage: {
        endpoint: resolveVanaStorageEndpoint(config),
        chainId: config.gateway.chainId,
        signMessage: (message) => serverAccount.signMessage(message),
      },
    });
    const pendingBlobDeletions = createFilePendingBlobDeletionStore(
      pendingBlobDeletionsPath,
    );

    syncManager = createSyncManager(uploadDeps, downloadDeps, {
      deleteData,
      pendingBlobDeletions,
      async canSync() {
        try {
          const serverInfo = await gatewayClient.getServer(
            serverAccount.address,
          );
          identity!.serverId = serverInfo?.id ?? null;
          if (serverInfo?.id) return { ok: true };
          return {
            ok: false,
            reason: "unregistered",
            message: "Register this Personal Server before syncing.",
          };
        } catch (err) {
          logger.warn({ err }, "Could not verify server registration for sync");
          return {
            ok: false,
            reason: "registration_check_failed",
            message: "Could not verify server registration before syncing.",
          };
        }
      },
    });
    syncManager.start();
    logger.info("Sync engine started");
  } else if (config.sync.enabled) {
    logger.warn(
      "Sync enabled in config but VANA_MASTER_KEY_SIGNATURE not set — sync disabled",
    );
  }

  const logsDir = join(storageRoot, "logs");
  await mkdir(logsDir, { recursive: true });
  const accessLogWriter = createAccessLogWriter(logsDir);
  const accessLogReader = createAccessLogReader(logsDir);

  // Generate ephemeral dev token when devUi is enabled
  const devToken = config.devUi.enabled ? generateDevToken() : undefined;

  // Token store for /auth/device flow (self-hosted CLI auth)
  const tokenStore: TokenStore = createTokenStore(tokensPath, logger);
  const cloudMode = process.env.CLOUD_MODE === "true";
  const localApprovalPort = cloudMode
    ? undefined
    : resolveLocalApprovalPort(config.server.port);

  // Mutable origin — starts with config value, updated when tunnel connects
  let effectiveOrigin = config.server.origin;
  let effectiveLocalApprovalOrigin: string | undefined;

  // Mutable tunnelManager — set when tunnel starts in background
  let tunnelManager: TunnelManager | undefined;

  // Registration can land after boot (desktop signing exchange or the
  // /ui/api registration route); the tunnel connect is gated on it, so the
  // route needs a way to trigger the deferred connect. Assigned inside
  // startBackgroundServices once the tunnel is reserved.
  let notifyServerRegistered: (serverId: string | null) => void = () => {};
  let registrationPollTimer: ReturnType<typeof setTimeout> | null = null;
  // Set by cleanup(). A poll iteration that is mid-flight when cleanup runs
  // holds no timer handle, so clearing the timer alone cannot stop it — and
  // a reserved-but-never-connected TunnelManager would happily spawn frpc
  // from an orphaned poll after shutdown. Every deferred path checks this.
  let backgroundClosed = false;
  const clearRegistrationPoll = () => {
    if (registrationPollTimer) {
      clearTimeout(registrationPollTimer);
      registrationPollTimer = null;
    }
  };

  const app = createApp({
    logger,
    version: pkg.version,
    startedAt,
    indexManager,
    hierarchyOptions,
    serverOrigin: () => effectiveOrigin,
    localApprovalOrigin: () => effectiveLocalApprovalOrigin,
    serverOwner,
    identity,
    gateway: gatewayClient,
    gatewayConfig: config.gateway,
    paymentEnabled: config.payment.enabled,
    gatewayUrl: config.gateway.url,
    lineageGateway,
    derivativeCompute,
    config,
    accessLogWriter,
    accessLogReader,
    readFulfillmentReporter: options?.readFulfillmentReporter,
    dataStorage,
    scopeDeletions,
    cloudMode,
    devToken,
    ownerSignature: masterKeySignature,
    ownerPrivateKey,
    accessToken,
    tokenStore,
    configPath,
    syncManager,
    serverSigner,
    getTunnelStatus: () => tunnelManager?.getStatus() ?? null,
    mcpOAuthApprovalUrl: options?.mcpOAuthApprovalUrl,
    onServerRegistered: (serverId) => notifyServerRegistered(serverId),
  });

  const cleanup = async () => {
    backgroundClosed = true;
    clearRegistrationPoll();
    derivativeScheduler.stop();
    if (tunnelManager) {
      await tunnelManager.stop();
    }
    if (syncManager) {
      await syncManager.stop();
    }
    indexManager.close();
  };

  const context: ServerContext = {
    app,
    logger,
    config,
    startedAt,
    indexManager,
    gatewayClient,
    accessLogReader,
    serverAccount,
    serverSigner,
    syncManager,
    tunnelManager,
    tunnelUrl: undefined,
    isServerRegistered: () => Boolean(identity?.serverId),
    localApprovalPort,
    getLocalApprovalOrigin: () => effectiveLocalApprovalOrigin,
    setLocalApprovalOrigin: (origin?: string) => {
      effectiveLocalApprovalOrigin = origin;
    },
    devToken,
    startBackgroundServices: async () => {
      // --- Gateway registration check (slow: HTTP call) ---
      if (serverAccount && identity) {
        try {
          const serverInfo = await gatewayClient.getServer(
            serverAccount.address,
          );
          identity.serverId = serverInfo?.id ?? null;
        } catch {
          // Gateway unreachable — assume not registered
        }

        if (identity.serverId) {
          logger.info(
            "Server registered with gateway — signing delegation active",
          );
        } else {
          logger.warn(
            {
              serverAddress: serverAccount.address,
              publicKey: serverAccount.publicKey,
            },
            "Server not registered. Register personal server with the gateway to enable delegation.",
          );
        }
      }

      // --- Tunnel setup (slow: subprocess wait) ---
      if (
        config.tunnel.enabled &&
        serverOwner &&
        serverAccount &&
        frpcBinaryPath
      ) {
        tunnelManager = new TunnelManager(storageRoot);
        context.tunnelManager = tunnelManager;

        const runId = randomUUID();

        let tunnelConnectStarted = false;
        const connectTunnel = async () => {
          const manager = tunnelManager;
          if (!manager || tunnelConnectStarted || backgroundClosed) {
            return;
          }
          tunnelConnectStarted = true;
          try {
            const url = await manager.connect();
            const tunnelStatus = manager.getStatus();
            if (tunnelStatus.status === "connected") {
              logger.info({ tunnelUrl: url }, "Tunnel established");
            } else {
              logger.warn(
                { tunnelUrl: url, warning: tunnelStatus.warning },
                "Tunnel URL reserved; waiting for tunnel connection",
              );
            }
          } catch (err) {
            logger.warn(
              { err },
              "Tunnel failed to connect - server running in local-only mode",
            );
            tunnelManager = undefined;
            context.tunnelManager = undefined;
            // Local-only mode must keep the local audience/URL: leaving the
            // public URL as effectiveOrigin would reject local Web3Signed
            // callers against an origin that will never route.
            effectiveOrigin = config.server.origin;
            context.tunnelUrl = undefined;
          }
        };

        // Poll fallback for registrations the route callback can't see
        // (e.g. desktop registers with the gateway directly and the sidecar
        // only observes it via a gateway lookup).
        const scheduleRegistrationPoll = () => {
          const pollStartedAt = Date.now();
          const poll = async () => {
            registrationPollTimer = null;
            if (backgroundClosed) {
              return;
            }
            try {
              const serverInfo = await gatewayClient.getServer(
                serverAccount.address,
              );
              if (serverInfo?.id) {
                if (identity) {
                  identity.serverId = serverInfo.id;
                }
                logger.info("Server registration detected — starting tunnel");
                await connectTunnel();
                return;
              }
            } catch {
              // Gateway unreachable — keep polling.
            }
            if (backgroundClosed) {
              return;
            }
            const interval =
              Date.now() - pollStartedAt < 2 * 60_000 ? 5_000 : 30_000;
            registrationPollTimer = setTimeout(() => void poll(), interval);
            registrationPollTimer.unref?.();
          };
          registrationPollTimer = setTimeout(() => void poll(), 5_000);
          registrationPollTimer.unref?.();
        };

        notifyServerRegistered = (serverId) => {
          if (backgroundClosed) {
            return;
          }
          if (serverId) {
            if (identity) {
              identity.serverId = serverId;
            }
            // Only a confirmed serverId stops the poll: on a null result the
            // poll keeps running so identity/health converge once the
            // gateway lookup sees the registration.
            clearRegistrationPoll();
          }
          void connectTunnel();
        };

        try {
          // Reserve the public URL without dialing the relay: the URL is
          // what registration needs, and dialing before the registration
          // lands poisons the relay's delegation cache (BUI-611).
          const url = tunnelManager.reserve(
            {
              walletAddress: serverAccount.address,
              ownerAddress: serverOwner,
              serverKeypair: serverAccount,
              tunnelSigner: ownerTunnelSigner
                ? {
                    signMessage: (message) =>
                      ownerTunnelSigner.signMessage({ message }),
                  }
                : undefined,
              runId,
              serverAddr: config.tunnel.serverAddr,
              serverPort: config.tunnel.serverPort,
              localPort: config.server.port,
            },
            frpcBinaryPath,
          );
          context.tunnelUrl = url;
          // The public URL is the audience clients sign against, so adopt it
          // as the effective origin as soon as it's known (matches the
          // unity-surfaces #583 sidecar patch).
          effectiveOrigin = url;

          if (identity?.serverId) {
            await connectTunnel();
          } else {
            logger.info(
              { tunnelUrl: url },
              "Tunnel start deferred until server registration — register to enable routing",
            );
            scheduleRegistrationPoll();
          }
        } catch (err) {
          logger.warn(
            { err },
            "Tunnel failed to start - server running in local-only mode",
          );
          tunnelManager = undefined;
          context.tunnelManager = undefined;
        }
      } else if (config.tunnel.enabled && !frpcBinaryPath) {
        logger.warn("frpc binary not available — tunnel disabled");
      } else if (config.tunnel.enabled) {
        logger.warn(
          "Tunnel enabled in config but VANA_MASTER_KEY_SIGNATURE not set — tunnel disabled",
        );
      }
    },
    cleanup,
  };

  return context;
}
