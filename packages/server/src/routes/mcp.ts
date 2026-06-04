/**
 * MCP routes — both the Claude-facing `/mcp/:token` Streamable HTTP endpoint
 * and the owner-only `/v1/mcp/connections` management surface.
 *
 * §1–§3 of `260604-PLAN-vana-mcp-personal-server.md`.
 *
 * Owner endpoints reuse `createServerApiAuth().authorizeOwner` so the same
 * auth surface that gates `/v1/grants` gates connection management. The
 * Claude-facing endpoint uses the connection token as a capability — there
 * is no Web3Signed payload from Claude; the token resolves to a connection
 * and we then sign reads ourselves with the per-connection grantee.
 *
 * NOTE on Phase-1 storage: this route accepts an `McpConnectionStore` from
 * the caller. The in-memory implementation in `core/src/mcp/store.ts` is
 * fine for tests and the first server-side smoke; for Web PS Lite an
 * IndexedDB-backed adapter is the natural production path (Phase-2 §4
 * "encrypt grantee private keys at rest" applies there).
 */

import { Hono } from "hono";
import type { Context } from "hono";
import type { Logger } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  approveMcpConnection,
  buildMcpUrl,
  createMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpDataReadClient,
  handleMcpStreamableHttpRequest,
  hashConnectionToken,
  listMcpConnectionViews,
  loadMcpGranteeAccount,
  McpConnectionNotFoundError,
  McpConnectionStateError,
  revokeMcpConnection,
  toMcpConnectionView,
  type McpConnectionGrant,
  type McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type {
  PersonalServerDataApiDeps,
  PersonalServerApiAuthPort,
} from "@opendatalabs/personal-server-ts-core/api";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { createServerApiAuth } from "../api-auth.js";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type {
  DataStoragePort,
  FeeVerifierPort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { TokenStore } from "../token-store.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";

export interface McpRouteDeps {
  logger: Logger;
  /**
   * `serverOrigin` used both as the Web3Signed `aud` for the per-connection
   * grantee's self-issued read requests AND as the base URL printed back to
   * the user when they create a connection ("paste this into Claude").
   * Caller may pass a thunk if the public origin depends on relay state.
   */
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  accessLogWriter: AccessLogWriter;
  indexManager?: IndexManager;
  hierarchyOptions?: HierarchyManagerOptions;
  dataStorage?: DataStoragePort;
  feeVerifier?: FeeVerifierPort;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /** Per-process connection store. Defaults to in-memory. */
  connectionStore?: McpConnectionStore;
}

function resolveOrigin(origin: string | (() => string)): string {
  return typeof origin === "function" ? origin() : origin;
}

function jsonError(status: number, errorCode: string, message: string) {
  return {
    error: { code: status, errorCode, message },
  };
}

function buildDataApiDeps(deps: McpRouteDeps): PersonalServerDataApiDeps {
  const dataStorage =
    deps.dataStorage ??
    (deps.indexManager && deps.hierarchyOptions
      ? createNodeDataStorage({
          indexManager: deps.indexManager,
          hierarchyOptions: deps.hierarchyOptions,
        })
      : undefined);
  if (!dataStorage) {
    throw new Error(
      "mcpRoutes requires either `dataStorage` or `{ indexManager, hierarchyOptions }` to build the read path",
    );
  }

  const auth: PersonalServerApiAuthPort = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    dataStorage,
    feeVerifier: deps.feeVerifier,
    runtimeAvailability: deps.runtimeAvailability,
  });

  return {
    storage: dataStorage,
    auth,
    schemaResolver: deps.gateway,
    accessLogWriter: deps.accessLogWriter,
    runtimeAvailability: deps.runtimeAvailability,
    feeVerifier: deps.feeVerifier,
    logger: deps.logger,
  };
}

/**
 * Hono sub-app for the owner-only `/v1/mcp/connections` endpoints.
 * Mount under `/v1/mcp/connections` in `app.ts`.
 */
export function mcpConnectionsRoutes(deps: McpRouteDeps): Hono {
  const app = new Hono();
  const store = deps.connectionStore ?? createInMemoryMcpConnectionStore();

  const ownerAuth: PersonalServerApiAuthPort = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  async function requireOwner(c: Context): Promise<Response | null> {
    try {
      await ownerAuth.authorizeOwner(c.req.raw);
      return null;
    } catch (err) {
      if (err instanceof ProtocolError) {
        return c.json(err.toJSON(), err.code as 401 | 403);
      }
      throw err;
    }
  }

  app.post("/", async (c) => {
    const err = await requireOwner(c);
    if (err) return err;
    let body: { displayName?: string } = {};
    try {
      body = (await c.req.json()) as { displayName?: string };
    } catch {
      body = {};
    }
    const created = await createMcpConnection(
      { displayName: body.displayName },
      { store, publicOrigin: resolveOrigin(deps.serverOrigin) },
    );
    return c.json(created, 201);
  });

  app.get("/", async (c) => {
    const err = await requireOwner(c);
    if (err) return err;
    const records = await listMcpConnectionViews(store);
    return c.json({ connections: records });
  });

  app.post("/:id/approve", async (c) => {
    const err = await requireOwner(c);
    if (err) return err;
    const id = c.req.param("id");
    let body: { grants?: McpConnectionGrant[] } = {};
    try {
      body = (await c.req.json()) as { grants?: McpConnectionGrant[] };
    } catch {
      return c.json(jsonError(400, "INVALID_BODY", "Body must be JSON"), 400);
    }
    if (!Array.isArray(body.grants) || body.grants.length === 0) {
      return c.json(
        jsonError(
          400,
          "GRANTS_REQUIRED",
          "Approve requires at least one grant — mint grants in the consent flow first",
        ),
        400,
      );
    }
    try {
      const updated = await approveMcpConnection(
        { connectionId: id, grants: body.grants },
        { store },
      );
      return c.json(toMcpConnectionView(updated));
    } catch (caught) {
      if (caught instanceof McpConnectionNotFoundError) {
        return c.json(jsonError(404, "NOT_FOUND", caught.message), 404);
      }
      if (caught instanceof McpConnectionStateError) {
        return c.json(jsonError(409, "INVALID_STATE", caught.message), 409);
      }
      throw caught;
    }
  });

  app.delete("/:id", async (c) => {
    const err = await requireOwner(c);
    if (err) return err;
    const id = c.req.param("id");
    try {
      const updated = await revokeMcpConnection(id, { store });
      return c.json(toMcpConnectionView(updated));
    } catch (caught) {
      if (caught instanceof McpConnectionNotFoundError) {
        return c.json(jsonError(404, "NOT_FOUND", caught.message), 404);
      }
      throw caught;
    }
  });

  return app;
}

/**
 * Hono sub-app for the Claude-facing Streamable HTTP endpoint.
 * Mount under `/mcp` in `app.ts`; the route matches `/mcp/:connectionToken`.
 *
 * NOTE: this MUST receive the SAME `connectionStore` instance you pass to
 * `mcpConnectionsRoutes` — otherwise the management API creates connections
 * that the Claude endpoint can never see.
 */
export function mcpStreamableHttpRoutes(deps: McpRouteDeps): Hono {
  const app = new Hono();
  const store = deps.connectionStore ?? createInMemoryMcpConnectionStore();
  if (!deps.connectionStore) {
    deps.logger.warn(
      "mcpStreamableHttpRoutes: no connectionStore passed; using a fresh in-memory store. The management routes will not see these connections unless they share the same store.",
    );
  }

  app.all("/:connectionToken", async (c) => {
    const rawToken = c.req.param("connectionToken");
    const tokenHash = await hashConnectionToken(rawToken);
    const record = await store.getByTokenHash(tokenHash);
    if (!record) {
      // Unknown / pending / revoked token. Don't leak which.
      return c.json(
        jsonError(401, "INVALID_TOKEN", "Unknown or revoked MCP connection"),
        401,
      );
    }
    let dataApiDeps: PersonalServerDataApiDeps;
    try {
      dataApiDeps = buildDataApiDeps(deps);
    } catch (caught) {
      deps.logger.error({ err: caught }, "mcp route data deps failed");
      return c.json(
        jsonError(500, "SERVER_NOT_CONFIGURED", String(caught)),
        500,
      );
    }
    const granteeAccount = loadMcpGranteeAccount({
      address: record.granteeAddress,
      publicKey: record.granteePublicKey,
      encryptedPrivateKey: record.encryptedGranteePrivateKey,
    });
    const readClient = createMcpDataReadClient({
      serverOrigin: resolveOrigin(deps.serverOrigin),
      granteeAccount,
      dataApiDeps,
    });
    const response = await handleMcpStreamableHttpRequest(c.req.raw, {
      connection: record,
      readClient,
    });
    await store.update(record.id, {
      lastUsedAt: new Date().toISOString(),
    });
    return response;
  });

  return app;
}

export { buildMcpUrl };
