import { Hono } from "hono";
import type { Context } from "hono";
import { cors } from "hono/cors";
import { isAddress, type Address } from "viem";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  approveMcpConnection,
  approveMcpOAuthAuthorization,
  handleMcpHandshake,
  hashConnectionToken,
  isMcpHandshake,
  parseScopeAccessRequestArguments,
  requestMcpScopeAccess,
  revokeMcpConnection,
  toMcpConnectionView,
  toMcpOAuthAuthorizationView,
  type McpConnectionGrant,
  type McpConnectionRecord,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { authenticateRequest } from "@opendatalabs/personal-server-ts-core/auth";
import {
  ExpiredTokenError,
  ProtocolError,
} from "@opendatalabs/personal-server-ts-core/errors";
import { mcpOAuthRoutes } from "../routes/mcp.js";
import { createBodyLimit } from "../middleware/body-limit.js";
import type { McpDurableState, McpOwnerBinding } from "./durable-state.js";

/** Stable, non-retryable code for a caller whose owner withdrew enclave access
 * (server deregistered, identity epoch bumped, delegation revoked). Retrying
 * cannot help; the owner has to approve this enclave again. */
export const OWNER_ACCESS_REVOKED_CODE = "OWNER_ACCESS_REVOKED";
/** A management claim authorizes one request; the signer picks its own `exp`,
 * so cap what a captured header is worth rather than trusting that choice. */
const MAX_CLAIM_AGE_SECONDS = 300;
const OWNER_ACCESS_REVOKED_MESSAGE =
  "Owner access to this enclave was revoked; ask the owner to approve it again";

export function parseMcpScopeAccessRequest(
  body: unknown,
): { scopes: string[]; reason?: string } | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const message = body as Record<string, unknown>;
  if (
    message.jsonrpc !== "2.0" ||
    (typeof message.id !== "string" && typeof message.id !== "number") ||
    message.method !== "tools/call"
  )
    return null;
  const params = message.params;
  if (!params || typeof params !== "object" || Array.isArray(params))
    return null;
  const call = params as Record<string, unknown>;
  if (call.name !== "request_scope_access") return null;
  return parseScopeAccessRequestArguments(call.arguments);
}

/** Thrown by `dispatch`/`ownerReady` providers when the live protocol identity
 * shows the owner no longer authorizes this enclave. */
export class McpOwnerAccessRevokedError extends Error {
  constructor() {
    super(OWNER_ACCESS_REVOKED_MESSAGE);
    this.name = "McpOwnerAccessRevokedError";
  }
}

export interface TeeMcpIngressDeps {
  state: McpDurableState;
  origin: string;
  approvalUrl: string;
  allowedRedirectUris: string[];
  gateway: GatewayClient;
  registerGrantee(
    connection: McpConnectionRecord,
    redirectUri: string,
  ): Promise<void>;
  verifyGrants(
    connection: McpConnectionRecord,
    binding: McpOwnerBinding,
    grants: McpConnectionGrant[],
  ): Promise<void>;
  dispatch(
    request: Request,
    connection: McpConnectionRecord,
    binding: McpOwnerBinding,
  ): Promise<Response>;
  ownerReady?(binding: McpOwnerBinding): Promise<boolean>;
  /** Runs only after signed grants are verified, before durable approval. */
  beforeOwnerApproval?(binding: McpOwnerBinding): Promise<void>;
}

/** Public ingress: HTTPS terminates in the same CVM as this process. */
export function createTeeMcpIngress(deps: TeeMcpIngressDeps): Hono {
  const app = new Hono();
  const { state } = deps;
  const redirectUris = new Set(deps.allowedRedirectUris);
  app.use("*", createBodyLimit(256 * 1024));
  app.use(
    "*",
    cors({
      origin: new URL(deps.approvalUrl).origin,
      allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
      allowHeaders: ["Content-Type", "Authorization", "MCP-Protocol-Version"],
      exposeHeaders: ["WWW-Authenticate"],
    }),
  );
  app.use("*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    c.header("X-Content-Type-Options", "nosniff");
    await next();
  });
  // One ingress writer serializes the core engine's multi-step OAuth updates.
  app.use("/mcp/oauth/*", (c, next) =>
    state.exclusive(async () => {
      if (
        c.req.path === "/mcp/oauth/authorize" &&
        !redirectUris.has(c.req.query("redirect_uri") ?? "")
      ) {
        return c.json(
          {
            error: "invalid_request",
            error_description: "Unregistered demo redirect URI",
          },
          400,
        );
      }
      if (c.req.path === "/mcp/oauth/register") {
        let body: { redirect_uris?: unknown };
        try {
          body = await c.req.raw.clone().json();
        } catch {
          return c.json({ error: "invalid_client_metadata" }, 400);
        }
        if (
          !Array.isArray(body.redirect_uris) ||
          body.redirect_uris.length === 0 ||
          body.redirect_uris.some(
            (uri) => typeof uri !== "string" || !redirectUris.has(uri),
          )
        ) {
          return c.json({ error: "invalid_redirect_uri" }, 400);
        }
      }
      await next();
    }),
  );
  // An owner manages its own MCP connections. The PS routes compare the
  // signer against one configured `serverOwner`; this CVM holds many owners
  // in one sealed store, so here the signer IS the identity and the durable
  // owner binding is what scopes the answer.
  app.get("/v1/mcp/connections", async (c) => {
    const owner = await authorizeOwner(c, deps.origin);
    if (owner instanceof Response) return owner;
    const owned = await state.ownerConnections(owner);
    return c.json({
      capabilities: { widen: true },
      connections: owned.map(toMcpConnectionView),
    });
  });
  app.post("/v1/mcp/connections/:id/approve", async (c) => {
    const owner = await authorizeOwner(c, deps.origin);
    if (owner instanceof Response) return owner;

    return state.exclusive(async () => {
      let body: { grants?: unknown };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON" }, 400);
      }
      if (!isGrantList(body.grants))
        return c.json({ error: "Grants required" }, 400);

      const id = c.req.param("id");
      const binding = await state.getOwner(id);
      const connection = await state.connections.getById(id);
      if (!binding || !connection || !isSameOwner(binding.owner, owner))
        return c.json({ error: "Connection not found" }, 404);
      if (connection.status !== "approved")
        return c.json({ error: "Connection is not approved" }, 409);
      if (!includesGrants(body.grants, connection.grants))
        return c.json({ error: "Existing grants required" }, 400);

      try {
        await deps.verifyGrants(connection, binding, body.grants);
      } catch {
        return c.json({ error: "Owner grant verification failed" }, 403);
      }
      const approved = await approveMcpConnection(
        { connectionId: id, grants: body.grants },
        { store: state.connections },
      );
      return c.json(toMcpConnectionView(approved));
    });
  });
  app.delete("/v1/mcp/connections/:id", async (c) => {
    const owner = await authorizeOwner(c, deps.origin);
    if (owner instanceof Response) return owner;
    // Revoking only kills this client's token. The on-chain grant it reads
    // under stands until the owner revokes that separately on the Gateway.
    return state.exclusive(async () => {
      const id = c.req.param("id");
      const binding = await state.getOwner(id);
      if (!binding || !isSameOwner(binding.owner, owner))
        return c.json({ error: "Connection not found" }, 404);
      const revoked = await revokeMcpConnection(id, {
        store: state.connections,
      });
      return c.json(toMcpConnectionView(revoked));
    });
  });
  // The random pending authorization ID reveals only the new grantee's public
  // consent metadata. It does not authorize approval or return a private key.
  app.get("/v1/mcp/readiness", async (c) => {
    const owner = c.req.query("owner");
    const chainId = Number(c.req.query("chainId"));
    if (!owner || !isAddress(owner) || !Number.isSafeInteger(chainId))
      return c.json({ error: "Owner and chain required" }, 400);
    return c.json({
      ready: (await deps.ownerReady?.({ owner, chainId })) ?? false,
    });
  });
  app.get("/v1/mcp/oauth/authorizations/:id", async (c) => {
    const record = await state.authorizations.getById(c.req.param("id"));
    if (
      !record ||
      record.status !== "pending" ||
      Date.parse(record.expiresAt) <= Date.now()
    )
      return c.json({ error: "Authorization not found" }, 404);
    const connection = await state.connections.getById(record.connectionId);
    if (!connection) return c.json({ error: "Connection not found" }, 404);
    await deps.registerGrantee(connection, record.redirectUri);
    return c.json(toMcpOAuthAuthorizationView(record));
  });
  app.post("/v1/mcp/oauth/authorizations/:id/approve", (c) =>
    state.exclusive(async () => {
      let body: {
        owner?: string;
        chainId?: number;
        grants?: McpConnectionGrant[];
      };
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON" }, 400);
      }
      if (
        !body.owner ||
        !isAddress(body.owner) ||
        !Number.isSafeInteger(body.chainId) ||
        !Array.isArray(body.grants) ||
        body.grants.length === 0 ||
        body.grants.some(
          (grant) =>
            !grant ||
            typeof grant.grantId !== "string" ||
            !Array.isArray(grant.scopes) ||
            grant.scopes.length === 0 ||
            grant.scopes.some((scope) => typeof scope !== "string"),
        )
      ) {
        return c.json({ error: "Owner, chain and grants required" }, 400);
      }
      const authorization = await state.authorizations.getById(
        c.req.param("id"),
      );
      if (
        !authorization ||
        authorization.status !== "pending" ||
        Date.parse(authorization.expiresAt) <= Date.now()
      )
        return c.json({ error: "Authorization unavailable" }, 409);
      const connection = await state.connections.getById(
        authorization.connectionId,
      );
      if (!connection) return c.json({ error: "Connection unavailable" }, 404);
      const binding: McpOwnerBinding = {
        owner: body.owner,
        chainId: body.chainId!,
      };
      try {
        await deps.verifyGrants(connection, binding, body.grants);
      } catch {
        return c.json({ error: "Owner grant verification failed" }, 403);
      }
      if (deps.ownerReady && !(await deps.ownerReady(binding)))
        return c.json(
          {
            error: "OWNER_PREWARM_REQUIRED",
            message: "Finish owner prewarm before approving MCP",
          },
          503,
        );
      try {
        await deps.beforeOwnerApproval?.(binding);
      } catch {
        return c.json({ error: "Owner scheduling unavailable" }, 503);
      }
      await state.bindOwner(connection.id, binding);
      const approved = await approveMcpOAuthAuthorization(
        { authorizationId: authorization.id, grants: body.grants },
        {
          connectionStore: state.connections,
          authorizationStore: state.authorizations,
        },
      );
      return c.json({ redirectTo: approved.redirectTo });
    }),
  );
  app.all("/mcp", async (c) => {
    const header = c.req.header("authorization");
    const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
    const connection = token
      ? await state.connections.getByTokenHash(await hashConnectionToken(token))
      : null;
    const binding = connection ? await state.getOwner(connection.id) : null;
    if (!connection || !binding) {
      c.header(
        "WWW-Authenticate",
        `Bearer resource_metadata="${deps.origin}/.well-known/oauth-protected-resource/mcp", scope="vana:read"`,
      );
      return c.json({ error: "MCP authorization required" }, 401);
    }
    if (c.req.method !== "POST") return c.body(null, 405, { Allow: "POST" });
    // The handshake reads the static tool table, nothing of the owner's, so it
    // is answered here rather than through grant verification, placement and
    // two attested peer hops per message — the three messages a fresh client
    // sends cost ~18 s each on that path.
    let body: unknown;
    try {
      body = await c.req.raw.clone().json();
    } catch {
      body = undefined;
    }
    if (isMcpHandshake(body)) return handleMcpHandshake(c.req.raw.clone());
    try {
      await deps.verifyGrants(connection, binding, connection.grants);
    } catch {
      return c.json({ error: "MCP grants are no longer valid" }, 403);
    }
    const scopeRequest = parseMcpScopeAccessRequest(body);
    const dispatchConnection = scopeRequest
      ? await state.exclusive(async () => {
          const outcome = await requestMcpScopeAccess(
            { connectionId: connection.id, ...scopeRequest },
            { store: state.connections },
          );
          return outcome.connection;
        })
      : connection;
    return deps.dispatch(c.req.raw, dispatchConnection, binding);
  });
  app.route(
    "/",
    mcpOAuthRoutes({
      gateway: deps.gateway,
      serverOrigin: deps.origin,
      oauthApprovalUrl: deps.approvalUrl,
      connectionStore: state.connections,
      oauthAuthorizationStore: state.authorizations,
    }),
  );
  app.onError((error) => {
    // A revoked owner is a terminal answer, not the transient 503 every other
    // ingress failure gets: the MCP client must stop retrying this connection.
    if (error instanceof McpOwnerAccessRevokedError)
      return jsonError(403, {
        error: OWNER_ACCESS_REVOKED_CODE,
        message: OWNER_ACCESS_REVOKED_MESSAGE,
      });

    return jsonError(503, { error: "MCP request unavailable" });
  });
  return app;
}

/**
 * Owner-signed (EIP-191 `Web3Signed`) identity for one management request.
 * Deliberately no dev / control-plane / session bearer: on a shared ingress
 * such a token would authenticate as every owner at once.
 */
async function authorizeOwner(
  c: Context,
  origin: string,
): Promise<Address | Response> {
  try {
    const authenticated = await authenticateRequest({
      request: c.req.raw,
      serverOrigin: origin,
    });
    const { exp = 0, iat = 0 } = authenticated.auth.payload;
    const age = Math.floor(Date.now() / 1000) - iat;
    if (exp - iat > MAX_CLAIM_AGE_SECONDS || age > MAX_CLAIM_AGE_SECONDS)
      throw new ExpiredTokenError();
    return authenticated.auth.signer;
  } catch (error) {
    if (error instanceof ProtocolError)
      return c.json(error.toJSON(), error.code as 401 | 403);
    throw error;
  }
}

function isSameOwner(left: Address, right: Address): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function isGrantList(value: unknown): value is McpConnectionGrant[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (grant) =>
        grant &&
        typeof grant === "object" &&
        typeof grant.grantId === "string" &&
        grant.grantId.length > 0 &&
        Array.isArray(grant.scopes) &&
        grant.scopes.length > 0 &&
        grant.scopes.every(
          (scope: unknown) => typeof scope === "string" && scope.length > 0,
        ),
    )
  );
}

/** Widening may append grants or scopes, never silently remove prior access. */
function includesGrants(
  next: McpConnectionGrant[],
  current: McpConnectionGrant[],
): boolean {
  return current.every((existing) =>
    existing.scopes.every((scope) =>
      next.some(
        (grant) =>
          grant.grantId === existing.grantId && grant.scopes.includes(scope),
      ),
    ),
  );
}

function jsonError(status: number, body: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}
