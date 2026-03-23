import { timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";
import {
  verifyWeb3Signed,
  type Web3SignedPayload,
} from "@opendatalabs/personal-server-ts-core/auth";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { TokenStore } from "../token-store.js";

export type AuthMechanism =
  | "web3-signed"
  | "dev-token"
  | "control-plane-token"
  | "cli-session-token";

export interface RequestAuth {
  signer: `0x${string}`;
  payload: Partial<Web3SignedPayload>;
}

export interface Web3AuthMiddlewareDeps {
  serverOrigin: string | (() => string);
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  serverOwner?: `0x${string}`;
}

/**
 * Constant-time comparison of two strings.
 * Returns false if either string is empty or they differ in length.
 */
function safeCompare(a: string, b: string): boolean {
  if (a.length === 0 || b.length === 0) return false;
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function createOwnerSessionAuth(serverOwner: `0x${string}`): RequestAuth {
  return {
    signer: serverOwner,
    // Bearer/session tokens authenticate the owner but do not carry Web3Signed claims.
    payload: {},
  };
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
    const authHeader = c.req.header("authorization");

    // Dev token bypass: if configured and header matches, skip Web3Signed verification
    if (deps.devToken && authHeader === `Bearer ${deps.devToken}`) {
      if (!deps.serverOwner) {
        return c.json(
          {
            error: {
              code: 500,
              errorCode: "SERVER_NOT_CONFIGURED",
              message:
                "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
            },
          },
          500,
        );
      }
      c.set("auth", createOwnerSessionAuth(deps.serverOwner));
      c.set("authMechanism", "dev-token" satisfies AuthMechanism);
      c.set("isPolicyBypass", true);
      c.set("devBypass", true);
      await next();
      return;
    }

    // Control-plane token: long-lived hosted credential used for session brokerage.
    if (deps.accessToken && authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      if (safeCompare(token, deps.accessToken)) {
        if (!deps.serverOwner) {
          return c.json(
            {
              error: {
                code: 500,
                errorCode: "SERVER_NOT_CONFIGURED",
                message:
                  "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
              },
            },
            500,
          );
        }
        c.set("auth", createOwnerSessionAuth(deps.serverOwner));
        c.set("authMechanism", "control-plane-token" satisfies AuthMechanism);
        c.set("isPolicyBypass", false);
        c.set("devBypass", false);
        await next();
        return;
      }
    }

    // Token store: tokens generated via /auth/device flow
    if (deps.tokenStore && authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      if (await deps.tokenStore.isValid(token)) {
        if (!deps.serverOwner) {
          return c.json(
            {
              error: {
                code: 500,
                errorCode: "SERVER_NOT_CONFIGURED",
                message:
                  "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
              },
            },
            500,
          );
        }
        c.set("auth", createOwnerSessionAuth(deps.serverOwner));
        c.set("authMechanism", "cli-session-token" satisfies AuthMechanism);
        c.set("isPolicyBypass", false);
        c.set("devBypass", false);
        await next();
        return;
      }
    }

    try {
      const auth = await verifyWeb3Signed({
        headerValue: authHeader,
        expectedOrigin:
          typeof deps.serverOrigin === "function"
            ? deps.serverOrigin()
            : deps.serverOrigin,
        expectedMethod: c.req.method,
        expectedPath: new URL(c.req.url).pathname,
      });

      c.set("auth", auth);
      c.set("authMechanism", "web3-signed" satisfies AuthMechanism);
      c.set("isPolicyBypass", false);
      c.set("devBypass", false);
      await next();
    } catch (err) {
      if (err instanceof ProtocolError) {
        return c.json(err.toJSON(), err.code as 401 | 403);
      }
      throw err;
    }
  };
}
