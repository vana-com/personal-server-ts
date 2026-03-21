import { timingSafeEqual } from "node:crypto";
import type { MiddlewareHandler } from "hono";
import { verifyWeb3Signed } from "@opendatalabs/personal-server-ts-core/auth";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";

export interface Web3AuthMiddlewareDeps {
  serverOrigin: string | (() => string);
  devToken?: string;
  accessToken?: string;
  serverOwner?: `0x${string}`;
}

/**
 * Constant-time comparison of two strings.
 * Returns false if either string is empty or they differ in length.
 */
function safeCompare(a: string, b: string): boolean {
  if (a.length === 0 || b.length === 0) return false;
  // Compare buffer byte lengths, not JS string lengths — they differ for
  // non-ASCII characters (e.g. "é" is 1 char but 2 bytes in UTF-8).
  const bufA = Buffer.from(a, "utf-8");
  const bufB = Buffer.from(b, "utf-8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Parses + verifies Web3Signed Authorization header.
 * Sets c.set('auth', VerifiedAuth) for downstream handlers.
 *
 * When a devToken is configured and the request carries a matching
 * Bearer token, auth context is populated with the server owner
 * and c.set('devBypass', true) is set to skip downstream checks.
 *
 * When an accessToken (PS_ACCESS_TOKEN) is configured and the request
 * carries a matching Bearer token, auth context is populated with the
 * server owner — treating the request as owner-authenticated.
 * This is used by the CLI for cloud PS access.
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
      c.set("auth", {
        signer: deps.serverOwner,
        payload: {},
      });
      c.set("devBypass", true);
      await next();
      return;
    }

    // PS access token: Bearer token from CLI/automation, validated with constant-time comparison
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
        c.set("auth", {
          signer: deps.serverOwner,
          payload: {},
        });
        // NOT devBypass — Bearer token gives owner-level auth, but does NOT
        // bypass builder-check or grant-check. Owner identity is sufficient
        // for owner operations; builder/grant checks still apply for data reads.
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
      await next();
    } catch (err) {
      if (err instanceof ProtocolError) {
        return c.json(err.toJSON(), err.code as 401 | 403);
      }
      throw err;
    }
  };
}
