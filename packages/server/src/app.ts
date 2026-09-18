import { randomUUID } from "node:crypto";
import { Hono } from "hono";
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
import type { PersonalServerReadFulfillmentReporter } from "@opendatalabs/personal-server-ts-core/api";
import { healthRoute, type HealthDeps } from "./routes/health.js";
import { corsMiddleware } from "./middleware/cors.js";
import { requireLoopbackListener } from "./middleware/local-listener.js";
import { dataRoutes } from "./routes/data.js";
import { writeSessionRoutes } from "./routes/write-session.js";
import {
  createInMemoryWriteProofReplayStore,
  createInMemoryWriteSessionStore,
  type WriteProofReplayStore,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import { derivativesRoutes } from "./routes/derivatives.js";
import { grantsRoutes } from "./routes/grants.js";
import { accessLogsRoutes } from "./routes/access-logs.js";
import { syncRoutes } from "./routes/sync.js";
import {
  executeMcpConnectionRequest,
  mcpActivityRoutes,
  mcpConnectionsRoutes,
  mcpOAuthRoutes,
  mcpStreamableHttpRoutes,
} from "./routes/mcp.js";
import { enclaveMcpRoutes } from "./routes/enclave-mcp.js";
import { enclaveFleetRoutes } from "./routes/enclave-fleet.js";
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
import { pdppAuthRoutes, type PdppAuthRouteDeps } from "./routes/pdpp-auth.js";
import { pdppDeclarationRoutes } from "./routes/pdpp-declarations.js";
import type { MutableDeclarationRegistry } from "./pdpp/declaration-registry.js";
import type {
  PdppImporter,
  ScopeDeletionTracker,
  SyncManager,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { LineageGatewayPort } from "@opendatalabs/personal-server-ts-core/lineage";
import type {
  QuestionStore,
  RecomputeScheduler,
} from "@opendatalabs/personal-server-ts-core/derivatives";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { TokenStore } from "./token-store.js";
import type { Logger } from "pino";
import { enclaveJobRoutes } from "./routes/enclave-jobs.js";
import type { JobRequestEnvelope } from "@opendatalabs/vana-sdk/protocol/jobs";
import type { JobExecuteResponse } from "./jobs/types.js";
import { pdppRecordsRoutes } from "./routes/pdpp-records.js";
import { pdppBlobsRoutes } from "./routes/pdpp-blobs.js";
import { pdppWellKnownRoutes } from "./routes/pdpp-well-known.js";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type {
  PdppRecordStore,
  StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

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
  readFulfillmentReporter?: PersonalServerReadFulfillmentReporter;
  cloudMode?: boolean;
  devToken?: string;
  /**
   * Port of the loopback-only auth listener. The dev UI subtree is served
   * only to connections that arrived on it (never via the tunnel).
   */
  localApprovalPort?: number;
  /** Main server port; a loopback-port collision disables the dev UI. */
  serverPort?: number;
  ownerSignature?: `0x${string}`;
  ownerPrivateKey?: `0x${string}`;
  accessToken?: string;
  configPath?: string;
  syncManager?: SyncManager | null;
  /** Read-side tombstone memory; reads of a deleted scope answer 410. */
  scopeDeletions?: ScopeDeletionTracker;
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
  /** Derivative data: gateway lineage access for the data routes. */
  lineageGateway?: LineageGatewayPort;
  /**
   * Derivative compute layer (docs/derivative-data-api.md, "Compute").
   * Absent = /v1/derivatives answers 503 and writes trigger no recompute.
   */
  derivativeCompute?: {
    store: QuestionStore;
    scheduler: RecomputeScheduler;
  } | null;
  /**
   * PDPP record importer for locally-ingested envelopes. The bootstrap passes
   * the same stable delegate it gives the sync download worker, so both
   * arrival routes — gateway sync and local owner-authenticated POST —
   * import through one importer into one store. Absent = no PDPP mounted,
   * and `$pdpp` envelopes are stored and indexed exactly as before.
   */
  pdppImporter?: PdppImporter;
  getTunnelStatus?: HealthDeps["getTunnelStatus"];
  /**
   * Invoked when the /ui/api registration route confirms the server is
   * registered with the gateway (fresh or pre-existing), so a
   * registration-gated tunnel can start immediately instead of waiting for
   * the bootstrap's gateway poll (BUI-611).
   */
  onServerRegistered?: (serverId: string | null) => void;
  /**
   * MCP connection store shared between the `/mcp/:token` Streamable HTTP
   * endpoint and the owner `/v1/mcp/connections` management surface. Defaults
   * to an in-memory store so the routes are wired up out of the box; pass an
   * IndexedDB-backed (or persistent) store for production.
   */
  mcpConnectionStore?: McpConnectionStore;
  mcpOAuthAuthorizationStore?: McpOAuthAuthorizationStore;
  mcpOAuthApprovalUrl?: string | (() => string);
  /**
   * PDPP Core v0.1 Authorization Server. Absent = the `/pdpp/v1` surface is
   * not mounted, and existing OAuth/MCP behavior is unchanged. This is a
   * separate authority from `tokenStore`: PDPP tokens are grant-bound and
   * live in their own store (spec §8 forbids a second grant authority behind
   * one enforcement path).
   */
  pdppAuth?: PdppAuthRouteDeps;
  /**
   * Operator-authenticated declaration submission. Absent (or with no
   * operator token) leaves the route unmounted and the declaration set
   * exactly as config made it — the pre-existing behavior.
   */
  pdppDeclarations?: {
    registry: MutableDeclarationRegistry;
    supportedConnectors: string[];
    /** Absent = the route is not mounted at all. */
    operatorToken?: string;
  };
  mcpActivityRecorder?: McpActivityRecorder;
  mcpHydrateScopes?: (scopes: string[]) => Promise<void>;
  /**
   * Write API session store shared between POST /v1/write/session (which
   * mints tokens) and the ingest endpoint (which redeems them). Defaults to
   * an in-memory store, mirroring the MCP connection store default.
   */
  writeSessionStore?: WriteSessionStore;
  /**
   * Replay guard for per-write proofs on delegated ingest. Defaults to an
   * in-memory store (api-auth); hosts may supply a shared one.
   */
  writeProofReplayStore?: WriteProofReplayStore;
  profile?: "standard" | "enclave";
  jobWorker?: (envelope: JobRequestEnvelope) => Promise<JobExecuteResponse>;
  /**
   * PDPP §4/§8 record model + Resource Server query surface. Absent = the
   * PDPP routes are not mounted; existing deployments are unaffected. When
   * present, all three must be present together (record store, token
   * resolution, and stream declarations are mutually required).
   */
  pdpp?: {
    store: PdppRecordStore;
    auth: PdppAuthorizationService;
    declarations: StreamDeclarationRegistry;
    instancesForSubject?: (subjectId: string) => string[];
    readBlobBytes?: (
      blobId: string,
    ) => Promise<Uint8Array<ArrayBuffer> | undefined>;
    /** This resource server's own identifier, RFC 9728 `resource` member. */
    resource: string;
    authorizationServers?: string[];
  };
}

export function createApp(deps: AppDeps): Hono {
  const app = new Hono();

  // One store for mint (POST /v1/write/session) and redeem (data ingest and
  // derivative question registration), and one replay guard for the proofs
  // both redeeming routes verify.
  const writeSessionStore =
    deps.writeSessionStore ?? createInMemoryWriteSessionStore();
  const writeProofReplayStore =
    deps.writeProofReplayStore ?? createInMemoryWriteProofReplayStore();

  // CORS — allow all origins for browser-based clients. Registered first so
  // OPTIONS preflights are answered before any route or auth code runs
  // (route sub-apps only register their real methods).
  // Dev UI gate — registered BEFORE the permissive global CORS so a
  // cross-origin preflight for /ui/* is refused rather than answered with
  // `Access-Control-Allow-Origin: *`. The whole /ui subtree is served only to
  // connections on the loopback auth listener: the tunnel forwards the main
  // server port, so without this gate the page (and the dev token it
  // carries, which is a full owner/policy bypass) is reachable by anyone who
  // knows the public tunnel URL.
  const uiLoopbackOnly = requireLoopbackListener({
    localApprovalPort: deps.localApprovalPort,
    serverPort: deps.serverPort,
  });
  app.use("/ui", uiLoopbackOnly);
  app.use("/ui/*", uiLoopbackOnly);

  app.use("*", corsMiddleware());

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

  // PDPP §4 record model + §8 Resource Server query surface. Independent of
  // the legacy DPP fileId/scope routes above; mounted only when a pdpp deps
  // bundle is supplied.
  if (deps.pdpp) {
    app.route(
      "/v1",
      pdppRecordsRoutes({
        store: deps.pdpp.store,
        auth: deps.pdpp.auth,
        declarations: deps.pdpp.declarations,
        instancesForSubject: deps.pdpp.instancesForSubject,
        // An `api_error` on the resource surface is a server fault and must
        // leave a correlatable line behind; the route never reaches the
        // global onError below, because it maps its own errors.
        logger: deps.logger,
        // PDPP reads land in the SAME owner access feed as legacy
        // `/v1/data/{scope}` reads. Adopting PDPP must not make an owner's
        // access history less complete than it was before.
        //
        // The legacy entry shape is per-scope and per-builder, so the PDPP
        // fields map on rather than extend it: `grantId` is the PDPP grant,
        // `builder` is the PDPP client, and `scope` carries the stream. A
        // denied or failed read is recorded too, which the legacy middleware
        // cannot do — it only fires on 2xx.
        accessLog: {
          record: async (entry) => {
            await deps.accessLogWriter.write({
              logId: randomUUID(),
              grantId: entry.grantId,
              builder: entry.clientId,
              action: "read",
              scope: entry.stream,
              timestamp: new Date().toISOString(),
              ipAddress: entry.ipAddress,
              userAgent: entry.userAgent,
              ...(entry.outcome !== "completed" && {
                outcome: entry.outcome,
              }),
            } as Parameters<typeof deps.accessLogWriter.write>[0]);
          },
        },
      }),
    );
    app.route(
      "/v1/blobs",
      pdppBlobsRoutes({
        store: deps.pdpp.store,
        auth: deps.pdpp.auth,
        declarations: deps.pdpp.declarations,
        instancesForSubject: deps.pdpp.instancesForSubject,
        readBlobBytes: deps.pdpp.readBlobBytes,
      }),
    );
    app.route(
      "/.well-known",
      pdppWellKnownRoutes({
        resource: deps.pdpp.resource,
        coreQueryBase: "/v1",
        authorizationServers: deps.pdpp.authorizationServers,
      }),
    );
  }

  if (deps.profile === "enclave" && deps.jobWorker && deps.accessToken) {
    app.route(
      "/enclave/v1/jobs",
      enclaveJobRoutes({
        accessToken: deps.accessToken,
        executeJob: deps.jobWorker,
      }),
    );
  }

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
      readFulfillmentReporter: deps.readFulfillmentReporter,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      syncManager: deps.syncManager ?? null,
      scopeDeletions: deps.scopeDeletions,
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
      lineageGateway: deps.lineageGateway,
      writeSessionStore,
      writeProofReplayStore,
      // A new local version of a scope marks every question that reads it
      // stale; the recompute waits for a reader.
      onDataWritten: deps.derivativeCompute
        ? (event) =>
            deps.derivativeCompute?.scheduler.markSourceChanged(event.scope, {
              lineageSources: event.lineageSources,
            })
        : undefined,
      // And an authorized read of a derived scope is that reader.
      onDataRead: deps.derivativeCompute
        ? (event) => deps.derivativeCompute?.scheduler.markDemand(event.scope)
        : undefined,
      // The same stable importer delegate the sync download worker holds, so
      // a local owner-authenticated ingest of a `$pdpp` envelope reaches the
      // record store the resource server reads — see the importer's note in
      // core's data API. Undefined when the deployment mounted no PDPP.
      pdppImporter: deps.pdppImporter,
      mountPath: "/v1/data",
    }),
  );

  // Derivative compute: question registration + readiness for builders.
  app.route(
    "/v1/derivatives",
    derivativesRoutes({
      logger: deps.logger,
      serverOrigin: deps.serverOrigin,
      serverOwner: deps.serverOwner,
      gateway: deps.gateway,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      dataStorage: deps.dataStorage,
      runtimeAvailability: deps.runtimeAvailability,
      writeSessionStore,
      writeProofReplayStore,
      compute: deps.derivativeCompute ?? null,
      mountPath: "/v1/derivatives",
    }),
  );

  // Mount the Write API session handshake (delegated builder writes).
  app.route(
    "/v1/write",
    writeSessionRoutes({
      logger: deps.logger,
      serverOrigin: deps.serverOrigin,
      serverOwner: deps.serverOwner,
      gateway: deps.gateway,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      sessionStore: writeSessionStore,
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
    serverAddress: deps.identity?.address,
    serverSigner: deps.serverSigner,
    gateway: deps.gateway,
    gatewayConfig: deps.gatewayConfig,
    paymentEnabled: deps.paymentEnabled,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    accessLogWriter: deps.accessLogWriter,
    readFulfillmentReporter: deps.readFulfillmentReporter,
    indexManager: deps.indexManager,
    hierarchyOptions: deps.hierarchyOptions,
    dataStorage: deps.dataStorage,
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
  if (deps.profile === "enclave" && deps.accessToken && deps.serverOwner) {
    app.route(
      "/enclave/v1/fleet",
      enclaveFleetRoutes({
        accessToken: deps.accessToken,
        hydrate: async (scopes) => {
          if (!deps.mcpHydrateScopes)
            throw new Error("Scoped hydration unavailable");
          await deps.mcpHydrateScopes(scopes);
        },
        observe: async (scope) => {
          const storage = deps.dataStorage;
          const entry = storage?.findEntry({ scope });
          const ready =
            entry && storage?.hasScopeBlocks
              ? await storage.hasScopeBlocks(scope, entry.collectedAt)
              : false;
          return { dataVersion: entry?.version ?? null, ready };
        },
      }),
    );
    app.route(
      "/enclave/v1/mcp",
      enclaveMcpRoutes({
        accessToken: deps.accessToken,
        serverOwner: deps.serverOwner,
        execute: async (request, connection) => {
          await deps.mcpHydrateScopes?.([
            ...new Set(connection.grants.flatMap((grant) => grant.scopes)),
          ]);
          return executeMcpConnectionRequest(request, connection, mcpRouteDeps);
        },
      }),
    );
  }

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

  // PDPP Core v0.1 Authorization Server (spec §6–§8). Mounted only when the
  // deployment supplies a PDPP auth store, so servers that do not speak PDPP
  // are byte-for-byte unchanged.
  if (deps.pdppAuth) {
    app.route("/pdpp/v1", pdppAuthRoutes(deps.pdppAuth));

    // Declaration submission (§5 acceptance). Mounted at `/pdpp`, NOT under
    // `/pdpp/v1`: it is an operator surface rather than part of the versioned
    // client-facing AS contract, and the separation keeps the "must not be
    // client-reachable" property visible in the path itself. Only mounted
    // when an operator credential exists — the route refuses everything
    // without one, so mounting it would be surface with no capability.
    if (deps.pdppDeclarations?.operatorToken) {
      app.route(
        "/pdpp",
        pdppDeclarationRoutes({
          logger: deps.logger,
          registry: deps.pdppDeclarations.registry,
          supportedConnectors: deps.pdppDeclarations.supportedConnectors,
          operatorToken: deps.pdppDeclarations.operatorToken,
        }),
      );
    }
  }

  // Mount dev UI routes when dev token is available. The /ui subtree is
  // already gated to the loopback auth listener above.
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
        onRegistered: deps.onServerRegistered,
      }),
    );
  }

  // Global error handler
  app.onError((err, c) => {
    if (err instanceof ProtocolError) {
      deps.logger.warn({ err }, err.message);
      return c.json(err.toJSON(), err.code as 401 | 403 | 413 | 503);
    }

    // The last-resort handler. Anything reaching it escaped a route's own
    // mapping, so carry the same correlation fields the route handlers now
    // emit — an operator should never have to tell two 500s apart by
    // timestamp alone. The id goes out on the response too, so a user's bug
    // report names the line in the log.
    const requestId = randomUUID();
    deps.logger.error(
      {
        requestId,
        route: `${c.req.method} ${new URL(c.req.url).pathname}`,
        errorCode: "INTERNAL_ERROR",
        err,
      },
      "Unhandled error",
    );
    c.header("Request-Id", requestId);
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
