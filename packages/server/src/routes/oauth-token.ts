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
import {
  oauthTokenContract,
  type OAuthDeviceSessionLookup,
} from "@opendatalabs/personal-server-ts-core/contracts";
import type { TokenStore } from "../token-store.js";

/**
 * In-memory map of device-flow sessions keyed by device_code. The existing
 * `/auth/device/poll` endpoint maintains the canonical state in
 * `auth-device.ts`; this endpoint reuses that same module-level `sessions`
 * map by accepting a `findDeviceSessionByDeviceCode` dep.
 */
export interface DeviceSessionLookup extends OAuthDeviceSessionLookup {
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
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(body)) {
      if (typeof value === "string") {
        params.set(key, value);
      }
    }
    const result = await oauthTokenContract({
      body: params,
      authorizationHeader: c.req.header("authorization"),
      tokenStore: deps.tokenStore,
      controlPlaneSecret: deps.controlPlaneSecret,
      deviceSessions: deps.deviceSessions,
      randomToken: () => `vana_ps_${randomBytes(32).toString("hex")}`,
      safeCompare,
    });
    return c.json(result.body, result.status, result.headers);
  });

  return app;
}
