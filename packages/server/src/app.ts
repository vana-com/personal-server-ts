import { Hono } from "hono";
import { cors } from "hono/cors";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import { healthRoute, type HealthDeps } from "./routes/health.js";
import { dataRoutes } from "./routes/data.js";
import { grantsRoutes } from "./routes/grants.js";
import { accessLogsRoutes } from "./routes/access-logs.js";
import { syncRoutes } from "./routes/sync.js";
import {
  mcpActivityRoutes,
  mcpConnectionsRoutes,
  mcpOAuthRoutes,
  mcpStreamableHttpRoutes,
} from "./routes/mcp.js";
import {
  McpActivityRecorder,
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
  type McpConnectionStore,
  type McpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { uiConfigRoutes } from "./routes/ui-config.js";
import { uiRegistrationRoutes } from "./routes/ui-registration.js";
import { uiRoute } from "./routes/ui.js";
import {
  authDeviceRoutes,
  createDeviceSessionLookup,
} from "./routes/auth-device.js";
import { oauthTokenRoutes } from "./routes/oauth-token.js";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { TokenStore } from "./token-store.js";
import type { Logger } from "pino";

export interface IdentityInfo {
  address: `0x${string}`;
  publicKey: `0x${string}`;
  serverId: string | null;
}

export interface AppDeps {
  logger: Logger;
  version: string;
  startedAt: Date;
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
  serverOrigin: string | (() => string);
  localApprovalOrigin?: string | (() => string | undefined);
  serverOwner?: `0x${string}`;
  identity?: IdentityInfo;
  gateway: GatewayClient;
  gatewayConfig?: DataPortabilityGatewayConfig & { url?: string };
  config?: ServerConfig;
  accessLogWriter: AccessLogWriter;
  accessLogReader: AccessLogReader;
  cloudMode?: boolean;
  devToken?: string;
  ownerSignature?: `0x${string}`;
  ownerPrivateKey?: `0x${string}`;
  accessToken?: string;
  configPath?: string;
  syncManager?: SyncManager | null;
  serverSigner?: ServerSigner;
  tokenStore?: TokenStore;
  runtimeAvailability?: RuntimeAvailabilityPort;
  dataStorage?: DataStoragePort;
  /**
   * Gateway base URL — wired into the data route so the GET handler can
   * forward validated X-PAYMENTs to POST /v1/escrow/pay via direct fetch.
   */
  gatewayUrl?: string;
  /**
   * When true, GET /v1/data/:scope enforces X402 payment on every read.
   * Off-by-default to keep dev / test setups frictionless.
   */
  paymentEnabled?: boolean;
  getTunnelStatus?: HealthDeps["getTunnelStatus"];
  /**
   * MCP connection store shared between the `/mcp/:token` Streamable HTTP
   * endpoint and the owner `/v1/mcp/connections` management surface. Defaults
   * to an in-memory store so the routes are wired up out of the box; pass an
   * IndexedDB-backed (or persistent) store for production.
   */
  mcpConnectionStore?: McpConnectionStore;
  mcpOAuthAuthorizationStore?: McpOAuthAuthorizationStore;
  mcpOAuthApprovalUrl?: string | (() => string);
  mcpActivityRecorder?: McpActivityRecorder;
}

export function createApp(deps: AppDeps): Hono {
  const app = new Hono();

  // CORS — allow all origins for browser-based clients
  app.use(
    "*",
    cors({
      origin: "*",
      allowHeaders: ["Content-Type", "Authorization"],
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      maxAge: 86400,
    }),
  );

  // Mount health route
  app.route(
    "/",
    healthRoute({
      version: deps.version,
      startedAt: deps.startedAt,
      serverOrigin: deps.serverOrigin,
      serverOwner: deps.serverOwner,
      identity: deps.identity,
      gateway: deps.gateway,
      gatewayConfig: deps.gatewayConfig,
      logger: deps.logger,
      getTunnelStatus: deps.getTunnelStatus,
      runtimeAvailability: deps.runtimeAvailability,
    }),
  );

  // Mount data routes (ingest + read + delete)
  app.route(
    "/v1/data",
    dataRoutes({
      indexManager: deps.indexManager,
      hierarchyOptions: deps.hierarchyOptions,
      logger: deps.logger,
      serverOrigin: deps.serverOrigin,
      serverOwner: deps.serverOwner,
      gateway: deps.gateway,
      accessLogWriter: deps.accessLogWriter,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      syncManager: deps.syncManager ?? null,
      runtimeAvailability: deps.runtimeAvailability,
      dataStorage: deps.dataStorage,
      // Powers the RECORD_DATA_ACCESS attestation embedded in X402 challenges.
      serverSigner: deps.serverSigner,
      serverAddress: deps.identity?.address,
      // Required for X402: gatewayConfig provides the EIP-712 domain for
      // payment signature recovery; gatewayUrl is the forward target for
      // POST /v1/escrow/pay (direct fetch — bypasses the SDK client to
      // preserve the gateway's structured error bodies).
      gatewayConfig: deps.gatewayConfig,
      gatewayUrl:
        deps.gatewayUrl ?? deps.config?.gateway.url ?? deps.gatewayConfig?.url,
      paymentEnabled: deps.paymentEnabled,
      mountPath: "/v1/data",
    }),
  );

  // Mount grants routes (POST /verify is public, GET / and POST / need owner auth)
  app.route(
    "/v1/grants",
    grantsRoutes({
      logger: deps.logger,
      gateway: deps.gateway,
      gatewayConfig: deps.gatewayConfig,
      serverOwner: deps.serverOwner,
      serverOrigin: deps.serverOrigin,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      serverSigner: deps.serverSigner,
      mountPath: "/v1/grants",
    }),
  );

  // Mount access-logs routes (all owner auth)
  app.route(
    "/v1/access-logs",
    accessLogsRoutes({
      logger: deps.logger,
      accessLogReader: deps.accessLogReader,
      serverOrigin: deps.serverOrigin,
      serverOwner: deps.serverOwner,
      gateway: deps.gateway,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      mountPath: "/v1/access-logs",
    }),
  );

  // Mount sync routes (all owner auth)
  app.route(
    "/v1/sync",
    syncRoutes({
      logger: deps.logger,
      serverOrigin: deps.serverOrigin,
      serverOwner: deps.serverOwner,
      gateway: deps.gateway,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      syncManager: deps.syncManager ?? null,
      mountPath: "/v1/sync",
    }),
  );

  // MCP — Phase 1 / 260604-PLAN-vana-mcp-personal-server.md.
  // Owner endpoints + Claude-facing Streamable HTTP endpoint share a single
  // connection store so the management API and the data path agree on which
  // connections exist.
  const mcpConnectionStore =
    deps.mcpConnectionStore ?? createInMemoryMcpConnectionStore();
  const mcpOAuthAuthorizationStore =
    deps.mcpOAuthAuthorizationStore ??
    createInMemoryMcpOAuthAuthorizationStore();
  const mcpActivityRecorder =
    deps.mcpActivityRecorder ?? new McpActivityRecorder();
  const mcpRouteDeps = {
    logger: deps.logger,
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    serverSigner: deps.serverSigner,
    gateway: deps.gateway,
    gatewayConfig: deps.gatewayConfig,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    accessLogWriter: deps.accessLogWriter,
    indexManager: deps.indexManager,
    hierarchyOptions: deps.hierarchyOptions,
    dataStorage: deps.dataStorage,
    feeVerifier: deps.feeVerifier,
    runtimeAvailability: deps.runtimeAvailability,
    connectionStore: mcpConnectionStore,
    oauthAuthorizationStore: mcpOAuthAuthorizationStore,
    oauthApprovalUrl: deps.mcpOAuthApprovalUrl,
    activityRecorder: mcpActivityRecorder,
  };

  app.route("/", mcpOAuthRoutes(mcpRouteDeps));
  app.route("/v1/mcp/connections", mcpConnectionsRoutes(mcpRouteDeps));
  app.route("/v1/mcp/activity", mcpActivityRoutes(mcpRouteDeps));
  app.route("/mcp", mcpStreamableHttpRoutes(mcpRouteDeps));

  // Mount login flow v2 routes (self-hosted CLI auth, no auth required)
  if (deps.tokenStore) {
    app.route(
      "/auth/device",
      authDeviceRoutes({
        logger: deps.logger,
        serverOrigin: deps.serverOrigin,
        localApprovalOrigin: deps.localApprovalOrigin,
        serverOwner: deps.serverOwner,
        tokenStore: deps.tokenStore,
        devToken: deps.devToken,
        accessToken: deps.accessToken,
        allowInteractiveLogin: !deps.cloudMode,
      }),
    );

    // RFC 6749 token endpoint. Replaces ad-hoc `/auth/device/token` semantics
    // with a standard OAuth2 surface that supports both the cloud
    // control-plane `client_credentials` grant and the CLI device-code grant.
    app.route(
      "/oauth/token",
      oauthTokenRoutes({
        logger: deps.logger,
        tokenStore: deps.tokenStore,
        controlPlaneSecret: deps.accessToken,
        deviceSessions: createDeviceSessionLookup(),
      }),
    );
  }

  // Mount dev UI routes when dev token is available
  if (deps.devToken) {
    app.route(
      "/ui",
      uiRoute({
        devToken: deps.devToken,
        psLiteBootstrap: deps.ownerSignature
          ? {
              ownerSignature: deps.ownerSignature,
              config: deps.config,
            }
          : null,
      }),
    );

    if (deps.configPath) {
      app.route(
        "/ui/api",
        uiConfigRoutes({
          devToken: deps.devToken,
          configPath: deps.configPath,
        }),
      );
    }
    app.route(
      "/ui/api",
      uiRegistrationRoutes({
        devToken: deps.devToken,
        ownerPrivateKey: deps.ownerPrivateKey,
      }),
    );
  }

  // Global error handler
  app.onError((err, c) => {
    if (err instanceof ProtocolError) {
      deps.logger.warn({ err }, err.message);
      return c.json(err.toJSON(), err.code as 401 | 403 | 413 | 503);
    }

    deps.logger.error({ err }, "Unhandled error");
    return c.json(
      {
        error: {
          code: 500,
          errorCode: "INTERNAL_ERROR",
          message: "Internal server error",
        },
      },
      500,
    );
  });

  // 404 fallback
  app.notFound((c) => {
    return c.json(
      {
        error: {
          code: 404,
          errorCode: "NOT_FOUND",
          message: "Not found",
        },
      },
      404,
    );
  });

  return app;
}
