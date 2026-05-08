import { Hono } from "hono";
import {
  deleteDataScopeContract,
  ingestDataContract,
  listDataScopesContract,
  listDataVersionsContract,
  parseDataScopeContract,
  readDataContract,
} from "@opendatalabs/personal-server-ts-core/contracts";
import { generateCollectedAt } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { GatewayClient } from "@opendatalabs/personal-server-ts-core/gateway";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type {
  FeeVerifierPort,
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { TokenStore } from "../token-store.js";
import type { Logger } from "pino";
import {
  createBodyLimit,
  DATA_INGEST_MAX_SIZE,
} from "../middleware/body-limit.js";
import { createWeb3AuthMiddleware } from "../middleware/web3-auth.js";
import { createBuilderCheckMiddleware } from "../middleware/builder-check.js";
import { createDataReadPolicyMiddleware } from "../middleware/data-read-policy.js";
import { createAccessLogMiddleware } from "../middleware/access-log.js";
import { createOwnerCheckMiddleware } from "../middleware/owner-check.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";

export interface DataRouteDeps {
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  accessLogWriter: AccessLogWriter;
  syncManager?: SyncManager | null;
  devToken?: string;
  tokenStore?: TokenStore;
  feeVerifier?: FeeVerifierPort;
  dataStorage?: DataStoragePort;
  runtimeAvailability?: RuntimeAvailabilityPort;
}

export function dataRoutes(deps: DataRouteDeps): Hono {
  const app = new Hono();

  // Create middleware instances
  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: deps.serverOrigin,
    devToken: deps.devToken,
    tokenStore: deps.tokenStore,
    serverOwner: deps.serverOwner,
  });
  const builderCheck = createBuilderCheckMiddleware(
    deps.gateway,
    deps.serverOwner,
  );
  const dataReadPolicy = createDataReadPolicyMiddleware({
    gateway: deps.gateway,
    feeVerifier: deps.feeVerifier,
    runtimeAvailability: deps.runtimeAvailability,
  });
  const accessLog = createAccessLogMiddleware(deps.accessLogWriter);
  const ownerCheck = createOwnerCheckMiddleware(deps.serverOwner);
  const dataStorage =
    deps.dataStorage ??
    createNodeDataStorage({
      indexManager: deps.indexManager,
      hierarchyOptions: deps.hierarchyOptions,
    });

  // GET /v1/data/:scope/versions — list versions for a scope (requires auth + builder, no grant)
  app.get("/:scope/versions", web3Auth, builderCheck, async (c) => {
    const limit = c.req.query("limit")
      ? parseInt(c.req.query("limit")!, 10)
      : 20;
    const offset = c.req.query("offset")
      ? parseInt(c.req.query("offset")!, 10)
      : 0;

    const result = listDataVersionsContract({
      storage: dataStorage,
      scopeParam: c.req.param("scope"),
      limit,
      offset,
    });
    if (!result.ok) return c.json(result.body, result.status);
    return c.json(result.response);
  });

  // GET /v1/data — list distinct scopes (requires auth + builder, no grant)
  app.get("/", web3Auth, builderCheck, async (c) => {
    const scopePrefix = c.req.query("scopePrefix");
    const limit = c.req.query("limit")
      ? parseInt(c.req.query("limit")!, 10)
      : 20;
    const offset = c.req.query("offset")
      ? parseInt(c.req.query("offset")!, 10)
      : 0;

    const result = listDataScopesContract({
      storage: dataStorage,
      scopePrefix: scopePrefix || undefined,
      limit,
      offset,
    });

    return c.json(result.response);
  });

  // GET /v1/data/:scope — read a data file (requires auth + grant)
  app.get("/:scope", web3Auth, dataReadPolicy, accessLog, async (c) => {
    const result = await readDataContract({
      storage: dataStorage,
      scopeParam: c.req.param("scope"),
      fileId: c.req.query("fileId"),
      at: c.req.query("at"),
    });
    if (!result.ok) return c.json(result.body, result.status);
    return c.json(result.envelope);
  });

  app.use("/:scope", createBodyLimit(DATA_INGEST_MAX_SIZE));

  app.post("/:scope", web3Auth, ownerCheck, async (c) => {
    const scopeParam = c.req.param("scope");
    const scopeResult = parseDataScopeContract(scopeParam);
    if (!scopeResult.ok) return c.json(scopeResult.body, scopeResult.status);
    const { scope } = scopeResult;

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        {
          error: "INVALID_BODY",
          message: "Request body must be valid JSON",
        },
        400,
      );
    }

    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return c.json(
        {
          error: "INVALID_BODY",
          message: "Request body must be a JSON object",
        },
        400,
      );
    }

    // 3. Look up schema via Gateway (strict: reject if not found)
    let schemaUrl: string | undefined;
    try {
      const schema = await deps.gateway.getSchemaForScope(scope);
      if (!schema) {
        return c.json(
          {
            error: "NO_SCHEMA",
            message: `No schema registered for scope: ${scope}`,
          },
          400,
        );
      }
      schemaUrl = schema.definitionUrl;
    } catch (err) {
      deps.logger.error({ err, scope }, "Gateway schema lookup failed");
      return c.json(
        {
          error: "GATEWAY_ERROR",
          message: "Failed to look up schema for scope",
        },
        502,
      );
    }

    const collectedAt = generateCollectedAt();
    const status: "stored" | "syncing" = deps.syncManager
      ? "syncing"
      : "stored";
    const ingest = await ingestDataContract({
      storage: dataStorage,
      scopeParam,
      body,
      collectedAt,
      status,
      schemaUrl,
    });
    if (!ingest.ok) return c.json(ingest.body, ingest.status);

    deps.logger.info(
      { scope, collectedAt, path: ingest.writeResult.relativePath },
      "Data file ingested",
    );

    if (deps.syncManager) {
      deps.syncManager.notifyNewData();
    }

    return c.json(ingest.response, 201);
  });

  // DELETE /v1/data/:scope — delete all versions for a scope (owner auth required)
  app.delete("/:scope", web3Auth, ownerCheck, async (c) => {
    const result = await deleteDataScopeContract({
      storage: dataStorage,
      scopeParam: c.req.param("scope"),
    });
    if (!result.ok) return c.json(result.body, result.status);

    deps.logger.info(
      { scope: c.req.param("scope"), deletedCount: result.deletedCount },
      "Scope deleted",
    );
    return c.body(null, 204);
  });

  return app;
}
