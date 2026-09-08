import { Hono } from "hono";
import { cors } from "hono/cors";
import { isAddress } from "viem";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  approveMcpOAuthAuthorization,
  hashConnectionToken,
  toMcpOAuthAuthorizationView,
  type McpConnectionGrant,
  type McpConnectionRecord,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { mcpOAuthRoutes } from "../routes/mcp.js";
import { createBodyLimit } from "../middleware/body-limit.js";
import type { McpDurableState, McpOwnerBinding } from "./durable-state.js";

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
      allowMethods: ["GET", "POST", "OPTIONS"],
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
    try {
      await deps.verifyGrants(connection, binding, connection.grants);
    } catch {
      return c.json({ error: "MCP grants are no longer valid" }, 403);
    }
    return deps.dispatch(c.req.raw, connection, binding);
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
  app.onError(
    () =>
      new Response(JSON.stringify({ error: "MCP request unavailable" }), {
        status: 503,
        headers: {
          "content-type": "application/json",
          "cache-control": "no-store",
        },
      }),
  );
  return app;
}
