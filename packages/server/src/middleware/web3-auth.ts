import type { MiddlewareHandler } from "hono";
import {
  authenticateRequest,
  mapSdkAuthError,
  type AuthMechanism,
  type RequestAuth,
  type SessionTokenVerifierPort,
} from "@opendatalabs/personal-server-ts-core/auth";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { TokenStore } from "../token-store.js";
// Ambient module augmentation that types `c.get("authMechanism")` etc. —
// must be in the TS module graph so the augmentation takes effect. The
// previous reach-through (data-read-policy.ts) was deleted in the X402
// migration; the web3-auth middleware is the most natural new anchor
// since it's the one writing these context vars in the first place.
import "../hono-context.js";

export { mapSdkAuthError };
export type { AuthMechanism, RequestAuth };

export interface Web3AuthMiddlewareDeps {
  serverOrigin: string | (() => string);
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore | SessionTokenVerifierPort;
  serverOwner?: `0x${string}`;
}

/**
 * Parses + verifies Web3Signed Authorization header.
 * Sets c.set('auth', VerifiedAuth) for downstream handlers.
 *
 * When a devToken is configured and the request carries a matching
 * Bearer token, auth context is populated with the server owner
 * and c.set('devBypass', true) is set to skip downstream checks.
 *
 * When a control-plane token (PS_ACCESS_TOKEN) or tokenStore-issued CLI token is
 * configured and the request carries a matching Bearer token, auth context
 * is populated with the server owner. These are owner-authenticated requests,
 * not dev-bypass requests.
 */
export function createWeb3AuthMiddleware(
  depsOrOrigin: Web3AuthMiddlewareDeps | string,
): MiddlewareHandler {
  const deps: Web3AuthMiddlewareDeps =
    typeof depsOrOrigin === "string"
      ? { serverOrigin: depsOrOrigin }
      : depsOrOrigin;

  return async (c, next) => {
    try {
      const result = await authenticateRequest({
        request: c.req.raw,
        serverOrigin: deps.serverOrigin,
        devToken: deps.devToken,
        accessToken: deps.accessToken,
        sessionTokenVerifier: deps.tokenStore,
        serverOwner: deps.serverOwner,
      });

      c.set("auth", result.auth);
      c.set("authMechanism", result.mechanism satisfies AuthMechanism);
      c.set("isPolicyBypass", result.isPolicyBypass);
      c.set("devBypass", result.devBypass);
      await next();
    } catch (err) {
      const authError = mapSdkAuthError(err);
      if (authError) return c.json(authError.toJSON(), authError.code as 401);
      if (err instanceof ProtocolError) {
        return c.json(err.toJSON(), err.code as 401 | 500);
      }
      throw err;
    }
  };
}
