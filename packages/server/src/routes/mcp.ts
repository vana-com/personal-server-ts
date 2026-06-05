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
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import {
  approveMcpOAuthAuthorization,
  approveMcpOAuthAuthorizationWithScopes,
  approveMcpConnection,
  buildMcpProtectedResourceMetadataUrl,
  buildMcpUrl,
  buildStableMcpUrl,
  createInMemoryMcpOAuthAuthorizationStore,
  createMcpConnection,
  createMcpOAuthAuthorization,
  createInMemoryMcpConnectionStore,
  createMcpDataReadClient,
  handleMcpStreamableHttpRequest,
  hashConnectionToken,
  listMcpConnectionViews,
  loadMcpGranteeAccount,
  McpActivityRecorder,
  McpConnectionNotFoundError,
  McpConnectionStateError,
  McpOAuthAuthorizationError,
  redeemMcpOAuthAuthorizationCode,
  toMcpOAuthAuthorizationView,
  revokeMcpConnection,
  toMcpConnectionView,
  type McpConnectionGrant,
  type McpConnectionStore,
  type McpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type {
  PersonalServerDataApiDeps,
  PersonalServerApiAuthPort,
} from "@opendatalabs/personal-server-ts-core/api";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { createServerApiAuth } from "../api-auth.js";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
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
  serverSigner?: Pick<ServerSigner, "signGrantRegistration">;
  gateway: GatewayClient;
  gatewayConfig?: (DataPortabilityGatewayConfig & { url?: string }) | null;
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
  /**
   * OAuth authorization store shared by `/mcp/oauth/authorize`,
   * `/mcp/oauth/token`, and the owner approval endpoint.
   */
  oauthAuthorizationStore?: McpOAuthAuthorizationStore;
  /** Activity recorder for live MCP call visibility. */
  activityRecorder?: McpActivityRecorder;
  /**
   * Vana Web approval surface. `/mcp/oauth/authorize` redirects owners here
   * with `mcp_authorization` and `ps_origin` query params.
   */
  oauthApprovalUrl?: string | (() => string);
}

function resolveOrigin(origin: string | (() => string)): string {
  return typeof origin === "function" ? origin() : origin;
}

function jsonError(status: number, errorCode: string, message: string) {
  return {
    error: { code: status, errorCode, message },
  };
}

function bearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return null;
  const token = authorization.slice("Bearer ".length).trim();
  return token.length > 0 ? token : null;
}

function mcpUnauthorized(
  origin: string,
  message = "MCP authorization required",
) {
  return new Response(
    JSON.stringify(jsonError(401, "MCP_AUTH_REQUIRED", message)),
    {
      status: 401,
      headers: {
        "content-type": "application/json",
        "www-authenticate": `Bearer resource_metadata="${buildMcpProtectedResourceMetadataUrl(origin)}", scope="vana:read"`,
      },
    },
  );
}

function authorizationServerMetadata(origin: string) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/mcp/oauth/authorize`,
    token_endpoint: `${origin}/mcp/oauth/token`,
    registration_endpoint: `${origin}/mcp/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["vana:read"],
  };
}

function protectedResourceMetadata(origin: string) {
  return {
    resource: buildStableMcpUrl(origin),
    authorization_servers: [origin],
    bearer_methods_supported: ["header"],
    scopes_supported: ["vana:read"],
    resource_name: "Vana Personal Server MCP",
  };
}

function resolveApprovalUrl(deps: McpRouteDeps): string | null {
  const value = deps.oauthApprovalUrl;
  if (!value) return null;
  return typeof value === "function" ? value() : value;
}

function redirectWithOAuthError(
  redirectUri: string,
  error: string,
  description: string,
  state: string | null,
): Response {
  try {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    url.searchParams.set("error_description", description);
    if (state) url.searchParams.set("state", state);
    return Response.redirect(url.toString(), 302);
  } catch {
    return new Response(
      JSON.stringify({
        error,
        error_description: description,
        ...(state ? { state } : {}),
      }),
      {
        status: 400,
        headers: { "content-type": "application/json" },
      },
    );
  }
}

async function parseFormBody(request: Request): Promise<URLSearchParams> {
  const text = await request.text();
  return new URLSearchParams(text);
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
 * Top-level MCP OAuth/discovery routes.
 *
 * Mount at `/` so the well-known documents are served from the PS origin and
 * Claude can discover auth for the stable `/mcp` resource.
 */
export function mcpOAuthRoutes(deps: McpRouteDeps): Hono {
  const app = new Hono();
  const connectionStore =
    deps.connectionStore ?? createInMemoryMcpConnectionStore();
  const authorizationStore =
    deps.oauthAuthorizationStore ?? createInMemoryMcpOAuthAuthorizationStore();

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

  app.get("/.well-known/oauth-protected-resource/mcp", (c) =>
    resolveApprovalUrl(deps)
      ? c.json(protectedResourceMetadata(resolveOrigin(deps.serverOrigin)))
      : c.json(
          jsonError(
            404,
            "MCP_OAUTH_NOT_CONFIGURED",
            "MCP OAuth is not configured",
          ),
          404,
        ),
  );

  app.get("/.well-known/oauth-authorization-server", (c) =>
    resolveApprovalUrl(deps)
      ? c.json(authorizationServerMetadata(resolveOrigin(deps.serverOrigin)))
      : c.json(
          jsonError(
            404,
            "MCP_OAUTH_NOT_CONFIGURED",
            "MCP OAuth is not configured",
          ),
          404,
        ),
  );

  app.post("/mcp/oauth/register", async (c) => {
    if (!resolveApprovalUrl(deps)) {
      return c.json(
        jsonError(
          404,
          "MCP_OAUTH_NOT_CONFIGURED",
          "MCP OAuth is not configured",
        ),
        404,
      );
    }
    let body: { client_name?: string; redirect_uris?: string[] } = {};
    try {
      body = (await c.req.json()) as typeof body;
    } catch {
      body = {};
    }
    return c.json(
      {
        client_id: `mcp-client-${crypto.randomUUID()}`,
        client_name: body.client_name ?? "Claude",
        redirect_uris: Array.isArray(body.redirect_uris)
          ? body.redirect_uris
          : [],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
      },
      201,
    );
  });

  app.get("/mcp/oauth/authorize", async (c) => {
    if (!resolveApprovalUrl(deps)) {
      return c.json(
        jsonError(
          404,
          "MCP_OAUTH_NOT_CONFIGURED",
          "MCP OAuth is not configured",
        ),
        404,
      );
    }
    const origin = resolveOrigin(deps.serverOrigin);
    const url = new URL(c.req.url);
    const responseType = url.searchParams.get("response_type");
    const clientId = url.searchParams.get("client_id") ?? "";
    const redirectUri = url.searchParams.get("redirect_uri") ?? "";
    const codeChallenge = url.searchParams.get("code_challenge") ?? "";
    const codeChallengeMethod =
      url.searchParams.get("code_challenge_method") ?? "";
    const state = url.searchParams.get("state");
    const scope = url.searchParams.get("scope") ?? "vana:read";

    if (responseType !== "code") {
      return redirectWithOAuthError(
        redirectUri,
        "unsupported_response_type",
        "Only response_type=code is supported",
        state,
      );
    }

    try {
      const created = await createMcpOAuthAuthorization(
        {
          clientId,
          redirectUri,
          codeChallenge,
          codeChallengeMethod,
          scope,
          ...(state ? { state } : {}),
        },
        {
          connectionStore,
          authorizationStore,
          publicOrigin: origin,
        },
      );
      const approvalUrl = resolveApprovalUrl(deps);
      if (!approvalUrl) {
        return c.json(
          jsonError(
            500,
            "MCP_APPROVAL_URL_MISSING",
            "MCP OAuth approval URL is not configured",
          ),
          500,
        );
      }
      const approve = new URL(approvalUrl);
      approve.searchParams.set("mcp_authorization", created.authorizationId);
      approve.searchParams.set("ps_origin", origin);
      return c.redirect(approve.toString(), 302);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return redirectWithOAuthError(
        redirectUri,
        err instanceof McpOAuthAuthorizationError
          ? err.code
          : "invalid_request",
        message,
        state,
      );
    }
  });

  app.post("/mcp/oauth/token", async (c) => {
    if (!resolveApprovalUrl(deps)) {
      return c.json(
        jsonError(
          404,
          "MCP_OAUTH_NOT_CONFIGURED",
          "MCP OAuth is not configured",
        ),
        404,
      );
    }
    const body = await parseFormBody(c.req.raw);
    if (body.get("grant_type") !== "authorization_code") {
      return c.json(
        {
          error: "unsupported_grant_type",
          error_description: "Only authorization_code is supported",
        },
        400,
      );
    }
    try {
      const token = await redeemMcpOAuthAuthorizationCode(
        {
          authorizationCode: body.get("code") ?? "",
          codeVerifier: body.get("code_verifier") ?? "",
          clientId: body.get("client_id") ?? "",
          redirectUri: body.get("redirect_uri") ?? "",
        },
        { authorizationStore, connectionStore },
      );
      return c.json({
        access_token: token.accessToken,
        token_type: "Bearer",
        ...(token.scope ? { scope: token.scope } : {}),
      });
    } catch (err) {
      return c.json(
        {
          error:
            err instanceof McpOAuthAuthorizationError
              ? err.code
              : "invalid_grant",
          error_description: err instanceof Error ? err.message : String(err),
        },
        400,
      );
    }
  });

  app.get("/v1/mcp/oauth/authorizations/:id", async (c) => {
    const err = await requireOwner(c);
    if (err) return err;
    const record = await authorizationStore.getById(c.req.param("id"));
    if (!record) {
      return c.json(
        jsonError(404, "NOT_FOUND", "Authorization not found"),
        404,
      );
    }
    return c.json(toMcpOAuthAuthorizationView(record));
  });

  app.post("/v1/mcp/oauth/authorizations/:id/approve", async (c) => {
    const err = await requireOwner(c);
    if (err) return err;
    let body: {
      expiresAt?: number;
      grants?: McpConnectionGrant[];
      nonce?: number;
      scopes?: string[];
    } = {};
    try {
      body = (await c.req.json()) as typeof body;
    } catch {
      return c.json(jsonError(400, "INVALID_BODY", "Body must be JSON"), 400);
    }
    if (Array.isArray(body.scopes) && body.scopes.length > 0) {
      if (!deps.gatewayConfig?.url) {
        return c.json(
          jsonError(
            500,
            "SERVER_NOT_CONFIGURED",
            "Gateway config is not configured",
          ),
          500,
        );
      }
      try {
        const approved = await approveMcpOAuthAuthorizationWithScopes(
          {
            authorizationId: c.req.param("id"),
            scopes: body.scopes,
            ...(body.expiresAt !== undefined
              ? { expiresAt: body.expiresAt }
              : {}),
            ...(body.nonce !== undefined ? { nonce: body.nonce } : {}),
          },
          {
            connectionStore,
            authorizationStore,
            gateway: deps.gateway,
            gatewayConfig: deps.gatewayConfig,
            gatewayUrl: deps.gatewayConfig.url,
            serverOwner: deps.serverOwner,
            serverSigner: deps.serverSigner,
          },
        );
        return c.json({ redirectTo: approved.redirectTo });
      } catch (err) {
        if (err instanceof McpOAuthAuthorizationError) {
          return c.json(
            jsonError(err.status, err.code, err.message),
            err.status as 400 | 404 | 500,
          );
        }
        throw err;
      }
    }
    if (!Array.isArray(body.grants) || body.grants.length === 0) {
      return c.json(
        jsonError(400, "GRANTS_REQUIRED", "Approve requires grants or scopes"),
        400,
      );
    }
    try {
      const approved = await approveMcpOAuthAuthorization(
        { authorizationId: c.req.param("id"), grants: body.grants },
        { connectionStore, authorizationStore },
      );
      return c.json({ redirectTo: approved.redirectTo });
    } catch (err) {
      if (err instanceof McpOAuthAuthorizationError) {
        return c.json(
          jsonError(err.status, err.code, err.message),
          err.status as 400 | 404 | 500,
        );
      }
      throw err;
    }
  });

  return app;
}

/**
 * Hono sub-app for the Claude-facing Streamable HTTP endpoint.
 * Mount under `/mcp` in `app.ts`; stable `/mcp` accepts OAuth bearer tokens
 * and legacy `/mcp/:connectionToken` still accepts token-in-path calls.
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

  async function handleToken(
    c: Context,
    rawToken: string | null,
    options: { oauthChallenge: boolean },
  ) {
    if (!rawToken) {
      if (!options.oauthChallenge) {
        return c.json(
          jsonError(401, "INVALID_TOKEN", "Missing MCP connection token"),
          401,
        );
      }
      return mcpUnauthorized(resolveOrigin(deps.serverOrigin));
    }
    const tokenHash = await hashConnectionToken(rawToken);
    const record = await store.getByTokenHash(tokenHash);
    if (!record) {
      if (!options.oauthChallenge) {
        return c.json(
          jsonError(401, "INVALID_TOKEN", "Unknown or revoked MCP connection"),
          401,
        );
      }
      return mcpUnauthorized(
        resolveOrigin(deps.serverOrigin),
        "Unknown or revoked MCP connection",
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
      activityRecorder: deps.activityRecorder,
    });
    await store.update(record.id, {
      lastUsedAt: new Date().toISOString(),
    });
    return response;
  }

  app.all("/", async (c) =>
    handleToken(c, bearerToken(c.req.raw), {
      oauthChallenge: Boolean(resolveApprovalUrl(deps)),
    }),
  );

  app.all("/:connectionToken", async (c) => {
    const rawToken = c.req.param("connectionToken");
    return handleToken(c, rawToken, { oauthChallenge: false });
  });

  return app;
}

/**
 * Owner-only activity feed route. Mount at `/v1/mcp/activity` in `app.ts`.
 * Returns the current snapshot from the shared `McpActivityRecorder`.
 */
export function mcpActivityRoutes(deps: McpRouteDeps): Hono {
  const app = new Hono();

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

  app.get("/", async (c) => {
    const err = await requireOwner(c);
    if (err) return err;
    const snapshot = deps.activityRecorder
      ? deps.activityRecorder.snapshot()
      : { events: [], running: 0, total: 0 };
    return c.json(snapshot);
  });

  return app;
}

export { buildMcpUrl, buildStableMcpUrl };
