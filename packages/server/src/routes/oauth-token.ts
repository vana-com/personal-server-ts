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
import { Hono } from "hono";
import type { Logger } from "pino";
import type { OAuthDeviceSessionLookup } from "@opendatalabs/personal-server-ts-core/contracts";
import { handlePersonalServerOauthTokenRequest } from "@opendatalabs/personal-server-ts-core/api";
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

function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf-8");
  const bufB = Buffer.from(b, "utf-8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function oauthTokenRoutes(deps: OauthTokenRouteDeps): Hono {
  const app = new Hono();

  app.all("/", (c) =>
    handlePersonalServerOauthTokenRequest(c.req.raw, {
      tokenStore: deps.tokenStore,
      controlPlaneSecret: deps.controlPlaneSecret,
      deviceSessions: deps.deviceSessions,
      randomToken: () => `vana_ps_${randomBytes(32).toString("hex")}`,
      safeCompare,
    }),
  );

  return app;
}
