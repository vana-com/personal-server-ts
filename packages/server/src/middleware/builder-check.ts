import type { MiddlewareHandler } from "hono";
import type { GatewayClient } from "@opendatalabs/personal-server-ts-core/gateway";
import { UnregisteredBuilderError } from "@opendatalabs/personal-server-ts-core/errors";
import type { RequestAuth } from "./web3-auth.js";

/**
 * Verifies authenticated signer is a registered builder via Gateway.
 * Must run AFTER web3-auth middleware.
 */
export function createBuilderCheckMiddleware(
  gateway: GatewayClient,
  serverOwner?: `0x${string}`,
): MiddlewareHandler {
  return async (c, next) => {
    if (c.get("isPolicyBypass") ?? c.get("devBypass")) {
      await next();
      return;
    }

    const auth = c.get("auth") as RequestAuth;
    if (
      serverOwner &&
      auth.signer.toLowerCase() === serverOwner.toLowerCase()
    ) {
      await next();
      return;
    }

    try {
      const registered = await gateway.isRegisteredBuilder(auth.signer);

      if (!registered) {
        const err = new UnregisteredBuilderError();
        return c.json(err.toJSON(), 401);
      }

      await next();
    } catch (err) {
      if (err instanceof UnregisteredBuilderError) {
        return c.json(err.toJSON(), 401);
      }
      throw err;
    }
  };
}
