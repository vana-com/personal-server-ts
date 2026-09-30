import { Hono, type Context } from "hono";
import {
  handlePersonalServerDataRequest,
  type PersonalServerApiDispatchOptions,
  type PersonalServerReadFulfillmentReporter,
} from "@opendatalabs/personal-server-ts-core/api";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type {
  PdppImporter,
  ScopeDeletionTracker,
  SyncManager,
} from "@opendatalabs/personal-server-ts-core/sync";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { TokenStore } from "../token-store.js";
import type {
  WriteProofReplayStore,
  WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import type { LineageGatewayPort } from "@opendatalabs/personal-server-ts-core/lineage";
import type { Logger } from "pino";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  ContentTooLargeError,
  ProtocolError,
} from "@opendatalabs/personal-server-ts-core/errors";
import { cacheRequestBodyBytes } from "@opendatalabs/personal-server-ts-core/auth";
import {
  createBodyLimit,
  DATA_INGEST_MAX_SIZE,
} from "../middleware/body-limit.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { createServerApiAuth } from "../api-auth.js";
import { parseDataScopeContract } from "@opendatalabs/personal-server-ts-core/contracts";
import {
  abortScopeImport,
  beginScopeImport,
  finalizeScopeImport,
  putScopeImportChunk,
  ScopeImportError,
  type ScopeImportDeps,
  SCOPE_IMPORT_CHUNK_BYTES,
} from "./chunked-scope-import.js";

export interface DataRouteDeps {
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  /**
   * Required for the X402 flow on GET /v1/data/:scope. Provides the EIP-712
   * domain (escrowPaymentDomain + dataRegistryDomain) the server uses to
   * recover X-PAYMENT signatures and the embedded accessRecord signatures.
   */
  gatewayConfig?: DataPortabilityGatewayConfig;
  /**
   * Gateway base URL. Used by the X402 forward path — the handler `fetch`es
   * POST /v1/escrow/pay directly so it can inspect the gateway's structured
   * error body (the SDK's gateway.payForOperation discards it).
   */
  gatewayUrl?: string;
  /**
   * When true, GET /v1/data/:scope enforces the X402 challenge / X-PAYMENT
   * cycle on every read. Off-by-default so dev / test setups don't require
   * builder-side payment signing.
   */
  paymentEnabled?: boolean;
  accessLogWriter: AccessLogWriter;
  readFulfillmentReporter?: PersonalServerReadFulfillmentReporter;
  syncManager?: SyncManager | null;
  /** Read-side tombstone memory; reads of a deleted scope answer 410. */
  scopeDeletions?: ScopeDeletionTracker;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  dataStorage?: DataStoragePort;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /**
   * Write API sessions (POST /v1/write/session). When present, the ingest
   * endpoint accepts write-session bearer tokens for delegated builder
   * writes; absent = owner-only ingest, unchanged.
   */
  writeSessionStore?: WriteSessionStore;
  /** Replay guard for per-write proofs; defaults to in-memory (api-auth). */
  writeProofReplayStore?: WriteProofReplayStore;
  pdppOwnerBearer?: {
    auth: PdppAuthorizationService;
    configuredMethods: Map<string, string[]>;
    ownerSubjectId?: string;
    instancesForSubject?: (subjectId: string) => string[];
    instancesForSource?: (subjectId: string, sourceId: string) => string[];
  };
  /**
   * Powers the RECORD_DATA_ACCESS attestation embedded in 402 challenges.
   * When supplied alongside serverOwner + paymentEnabled, every challenge
   * carries a server-signed accessRecord. Required for the on-chain
   * recordDataAccess to be scheduled by gateway.settle later.
   */
  serverSigner?: ServerSigner;
  /**
   * Personal server's own EOA address. Needed by the X402 verifier so it
   * can confirm that the accessRecord echoed back in X-PAYMENT was signed
   * by this server (not forged by a malicious builder).
   */
  serverAddress?: `0x${string}`;
  /**
   * Gateway access for derivative data: lineage source lookups on write, the
   * signed lineage read and the cascade delete walk. Absent = lineage writes
   * can only cite local scopes; lineage read / cascade answer 503 / 501.
   */
  lineageGateway?: LineageGatewayPort;
  /** Post-commit write hook (marks derivative questions stale). */
  onDataWritten?: (event: {
    scope: string;
    collectedAt: string;
    lineageSources?: string[];
  }) => void;
  /** Post-auth read hook (runs a stale derivative question on demand). */
  onDataRead?: (event: { scope: string }) => void;
  /**
   * The deployment's PDPP importer, so an owner-authenticated local ingest
   * reaches the record store the resource server reads — the same importer
   * and the same delegate the sync download worker is given at boot.
   */
  pdppImporter?: PdppImporter;
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
}

export function dataRoutes(deps: DataRouteDeps): Hono {
  const app = new Hono();

  const dataStorage =
    deps.dataStorage ??
    createNodeDataStorage({
      indexManager: deps.indexManager,
      hierarchyOptions: deps.hierarchyOptions,
    });
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    dataStorage,
    runtimeAvailability: deps.runtimeAvailability,
    writeSessionStore: deps.writeSessionStore,
    writeProofReplayStore: deps.writeProofReplayStore,
    pdppOwnerBearer: deps.pdppOwnerBearer,
  });

  const importDeps: ScopeImportDeps = {
    hierarchyOptions: deps.hierarchyOptions,
    indexManager: deps.indexManager,
    serverOwner: deps.serverOwner,
    authorizeOwner: (request, scope) =>
      auth.authorizeOwnerScope({ request, scope }),
    syncManager: deps.syncManager,
    onDataWritten: deps.onDataWritten,
    afterTombstoneVersion: async (scope) => {
      if (!deps.scopeDeletions) return null;
      const verdict = await deps.scopeDeletions.resolve(scope);
      if (!verdict.deleted || verdict.version === null) return null;
      const version = Number(verdict.version);
      return Number.isSafeInteger(version) ? version : null;
    },
  };

  const importRoute = async (
    c: Context,
    action: () => Promise<unknown>,
    status = 200,
  ) => {
    try {
      return c.body(JSON.stringify(await action()), status as 200, {
        "content-type": "application/json",
      });
    } catch (error) {
      if (error instanceof ScopeImportError) {
        return c.body(
          JSON.stringify({ error: error.code, message: error.message }),
          error.status as 400,
          { "content-type": "application/json" },
        );
      }
      if (error instanceof ProtocolError) {
        return c.body(
          JSON.stringify({ error: error.errorCode, message: error.message }),
          error.code as 400,
          { "content-type": "application/json" },
        );
      }
      const caught = error as {
        status?: number;
        code?: string;
        message?: string;
      };
      if (caught.status && caught.code) {
        return c.body(
          JSON.stringify({ error: caught.code, message: caught.message }),
          caught.status as 500,
          { "content-type": "application/json" },
        );
      }
      return c.body(
        JSON.stringify({
          error: "IMPORT_FAILED",
          message: "Scope import failed",
        }),
        500,
        { "content-type": "application/json" },
      );
    }
  };

  app.post("/:scope/imports", createBodyLimit(4096), (c) =>
    importRoute(
      c,
      async () => {
        const parsedScope = parseDataScopeContract(c.req.param("scope"));
        if (!parsedScope.ok) {
          throw new ScopeImportError(
            400,
            "INVALID_SCOPE",
            parsedScope.body.message,
          );
        }
        let body: unknown;
        try {
          body = await c.req.json();
        } catch {
          throw new ScopeImportError(
            400,
            "INVALID_BODY",
            "Request body must be valid JSON",
          );
        }
        return beginScopeImport(importDeps, c.req.raw, parsedScope.scope, body);
      },
      201,
    ),
  );
  app.put(
    "/:scope/imports/:id/chunks/:index",
    async (c, next) => {
      try {
        await cacheRequestBodyBytes(c.req.raw, SCOPE_IMPORT_CHUNK_BYTES, true);
      } catch (error) {
        if (error instanceof ContentTooLargeError) {
          return c.json(
            {
              error: "CONTENT_TOO_LARGE",
              message: `Request body exceeds maximum size of ${SCOPE_IMPORT_CHUNK_BYTES} bytes`,
            },
            413,
          );
        }
        throw error;
      }
      await next();
    },
    (c) =>
      importRoute(c, () =>
        putScopeImportChunk(
          importDeps,
          c.req.raw,
          c.req.param("scope"),
          c.req.param("id"),
          Number(c.req.param("index")),
        ),
      ),
  );
  app.post("/:scope/imports/:id/finalize", (c) =>
    importRoute(
      c,
      () =>
        finalizeScopeImport(
          importDeps,
          c.req.raw,
          c.req.param("scope"),
          c.req.param("id"),
        ),
      201,
    ),
  );
  app.delete("/:scope/imports/:id", (c) =>
    importRoute(c, () =>
      abortScopeImport(
        importDeps,
        c.req.raw,
        c.req.param("scope"),
        c.req.param("id"),
      ),
    ),
  );

  const legacyWriteBodyLimit = createBodyLimit(DATA_INGEST_MAX_SIZE);
  app.use("/:scope", (c, next) => {
    if (c.req.path.split("/").includes("imports")) return next();
    return legacyWriteBodyLimit(c, next);
  });
  app.all("*", (c) =>
    handlePersonalServerDataRequest(
      c.req.raw,
      {
        storage: dataStorage,
        auth,
        accessLogWriter: deps.accessLogWriter,
        readFulfillmentReporter: deps.readFulfillmentReporter,
        syncManager: deps.syncManager ?? null,
        scopeDeletions: deps.scopeDeletions,
        runtimeAvailability: deps.runtimeAvailability,
        serverSigner: deps.serverSigner,
        serverOwner: deps.serverOwner,
        serverAddress: deps.serverAddress,
        gateway: deps.gateway,
        gatewayConfig: deps.gatewayConfig,
        gatewayUrl: deps.gatewayUrl,
        paymentEnabled: deps.paymentEnabled,
        lineageGateway: deps.lineageGateway,
        onDataWritten: deps.onDataWritten,
        onDataRead: deps.onDataRead,
        pdppImporter: deps.pdppImporter,
        // Network identifier for the 402 challenge body. We use the chain
        // id as the convention since the gateway is chain-scoped; clients
        // dispatch on the (scheme, chainId) pair, not the human name.
        network: deps.gatewayConfig
          ? `vana:${deps.gatewayConfig.chainId}`
          : undefined,
        logger: deps.logger,
      },
      { basePath: deps.mountPath },
    ),
  );

  return app;
}
