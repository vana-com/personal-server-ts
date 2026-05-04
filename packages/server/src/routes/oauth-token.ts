/**
 * RFC 6749 §5 token endpoint.
 *
 * Supports two grant types:
 *
 *   1. `client_credentials` (RFC 6749 §4.4) — used by the cloud control
 *      plane (e.g. account.vana.org) to mint server-issued bearer tokens.
 *      Caller authenticates with `client_id="control-plane"` and
 *      `client_secret=<PS_ACCESS_TOKEN>` (HTTP Basic per §2.3.1, or in the
 *      request body per §2.3.1's "alternative method").
 *
 *   2. `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628 §3.4) —
 *      used by the CLI to redeem an approved device-authorization session
 *      for a bearer token. Wraps the existing `/auth/device/poll` flow in
 *      a standard envelope.
 *
 * All issued tokens are opaque, persisted to the same {@link TokenStore}
 * that backs the existing CLI session tokens, and accepted by every owner
 * route's web3-auth middleware via the `tokenStore` injection. Standard
 * OAuth2 error responses per RFC 6749 §5.2.
 *
 * Why hand-rolled instead of `@node-oauth/oauth2-server`: the wire
 * protocol for these two grants is small enough (RFC 6749 §4.4 + §5 is
 * one page) that the abstraction tax of a full OAuth server framework
 * exceeds the spec implementation cost. We reuse the framework where it
 * matters (clients, see oauth4webapi on the account.vana.org side).
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import { Hono, type Context } from "hono";
import type { Logger } from "pino";
import type { TokenStore } from "../token-store.js";

const ACCESS_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days, matches CLI session token TTL
const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

/**
 * In-memory map of device-flow sessions keyed by device_code. The existing
 * `/auth/device/poll` endpoint maintains the canonical state in
 * `auth-device.ts`; this endpoint reuses that same module-level `sessions`
 * map by accepting a `findDeviceSessionByDeviceCode` dep.
 */
export interface DeviceSessionLookup {
  findByDeviceCode(deviceCode: string): {
    status: "pending" | "approved" | "expired";
    accessToken?: string;
    accessTokenExpiresAt?: string;
    sessionId: string;
  } | null;
  consume(sessionId: string): void;
}

export interface OauthTokenRouteDeps {
  logger: Logger;
  tokenStore: TokenStore;
  /** PS_ACCESS_TOKEN — the long-lived control-plane secret. */
  controlPlaneSecret?: string;
  /** Optional device-flow session lookup. When omitted, only client_credentials is supported. */
  deviceSessions?: DeviceSessionLookup;
}

type OauthError =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "authorization_pending"
  | "access_denied"
  | "expired_token";

function oauthError(
  c: Context,
  error: OauthError,
  description: string,
  status: 400 | 401 = 400,
) {
  return c.json(
    {
      error,
      error_description: description,
    },
    status,
    {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
    },
  );
}

function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf-8");
  const bufB = Buffer.from(b, "utf-8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Per RFC 6749 §2.3.1, the client identifier and password sent via HTTP
 * Basic are first encoded with `application/x-www-form-urlencoded` (per
 * Appendix B). Conformant clients like `oauth4webapi` will percent-encode
 * `-`, `_`, and other URL-significant characters before base64 encoding.
 * The server is required to apply the inverse decoding before comparing.
 */
function parseBasicAuth(headerValue: string | undefined): {
  clientId: string;
  clientSecret: string;
} | null {
  if (!headerValue?.startsWith("Basic ")) return null;
  const decoded = Buffer.from(headerValue.slice(6), "base64").toString("utf-8");
  const idx = decoded.indexOf(":");
  if (idx === -1) return null;
  try {
    return {
      clientId: decodeURIComponent(decoded.slice(0, idx)),
      clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
    };
  } catch {
    return null;
  }
}

export function oauthTokenRoutes(deps: OauthTokenRouteDeps): Hono {
  const app = new Hono();

  app.post("/", async (c) => {
    const contentType = c.req.header("content-type") ?? "";
    if (!contentType.includes("application/x-www-form-urlencoded")) {
      return oauthError(
        c,
        "invalid_request",
        "Content-Type must be application/x-www-form-urlencoded",
      );
    }

    const body = await c.req.parseBody();
    const grantType = asString(body.grant_type);
    if (!grantType) {
      return oauthError(c, "invalid_request", "Missing grant_type");
    }

    if (grantType === "client_credentials") {
      return handleClientCredentials(c, body, deps);
    }
    if (grantType === DEVICE_CODE_GRANT) {
      return handleDeviceCode(c, body, deps);
    }
    return oauthError(
      c,
      "unsupported_grant_type",
      `Grant type '${grantType}' is not supported`,
    );
  });

  return app;
}

async function handleClientCredentials(
  c: Context,
  body: Record<string, unknown>,
  deps: OauthTokenRouteDeps,
): Promise<Response> {
  if (!deps.controlPlaneSecret) {
    return oauthError(
      c,
      "unauthorized_client",
      "Server is not configured for client_credentials",
      401,
    );
  }

  // Credentials may arrive via HTTP Basic (preferred) or form body.
  const fromHeader = parseBasicAuth(c.req.header("authorization"));
  const clientId = fromHeader?.clientId ?? asString(body.client_id);
  const clientSecret = fromHeader?.clientSecret ?? asString(body.client_secret);

  if (!clientId || !clientSecret) {
    return oauthError(c, "invalid_client", "Missing client credentials", 401);
  }

  if (clientId !== "control-plane") {
    return oauthError(
      c,
      "invalid_client",
      `Unknown client_id '${clientId}'`,
      401,
    );
  }

  if (!safeCompare(clientSecret, deps.controlPlaneSecret)) {
    return oauthError(c, "invalid_client", "Invalid client_secret", 401);
  }

  const accessToken = `vana_ps_${randomBytes(32).toString("hex")}`;
  const expiresAt = new Date(
    Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000,
  ).toISOString();

  await deps.tokenStore.addToken(accessToken, { expiresAt });
  deps.logger.info(
    "OAuth2 token issued via client_credentials grant (cloud control plane)",
  );

  return c.json(
    {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    },
    200,
    {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
    },
  );
}

async function handleDeviceCode(
  c: Context,
  body: Record<string, unknown>,
  deps: OauthTokenRouteDeps,
): Promise<Response> {
  if (!deps.deviceSessions) {
    return oauthError(
      c,
      "unsupported_grant_type",
      "Device flow is not configured on this server",
    );
  }

  const deviceCode = asString(body.device_code);
  if (!deviceCode) {
    return oauthError(c, "invalid_request", "Missing device_code");
  }

  const session = deps.deviceSessions.findByDeviceCode(deviceCode);
  if (!session) {
    return oauthError(c, "expired_token", "Device code is expired or unknown");
  }

  if (session.status === "expired") {
    return oauthError(c, "expired_token", "Device code is expired");
  }

  if (session.status === "pending" || !session.accessToken) {
    // RFC 8628 §3.5
    return oauthError(
      c,
      "authorization_pending",
      "User has not yet approved the device",
    );
  }

  // Approved + token issued by the legacy /auth/device flow. Hand it back
  // in the standard envelope and consume the session so it can't be
  // redeemed twice.
  const expiresInSeconds = session.accessTokenExpiresAt
    ? Math.max(
        1,
        Math.floor(
          (Date.parse(session.accessTokenExpiresAt) - Date.now()) / 1000,
        ),
      )
    : ACCESS_TOKEN_TTL_SECONDS;

  deps.deviceSessions.consume(session.sessionId);
  deps.logger.info(
    "OAuth2 token issued via device_code grant (device-authorization redemption)",
  );

  return c.json(
    {
      access_token: session.accessToken,
      token_type: "Bearer",
      expires_in: expiresInSeconds,
    },
    200,
    {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
    },
  );
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}
