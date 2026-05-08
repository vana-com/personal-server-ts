import type { MiddlewareHandler } from "hono";
import { verifyDataReadPolicy } from "@opendatalabs/personal-server-ts-core/policy";
import type {
  FeeVerifierPort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { GatewayClient } from "@opendatalabs/personal-server-ts-core/gateway";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { RequestAuth } from "./web3-auth.js";

export interface DataReadPolicyMiddlewareDeps {
  gateway: GatewayClient;
  feeVerifier?: FeeVerifierPort;
  runtimeAvailability?: RuntimeAvailabilityPort;
}

export function createDataReadPolicyMiddleware(
  deps: DataReadPolicyMiddlewareDeps,
): MiddlewareHandler {
  return async (c, next) => {
    if (c.get("isPolicyBypass") ?? c.get("devBypass")) {
      await next();
      return;
    }

    const auth = c.get("auth") as RequestAuth;

    try {
      const grant = await verifyDataReadPolicy(
        {
          signer: auth.signer,
          grantId: auth.payload.grantId,
          requestedScope: c.req.param("scope") ?? "",
        },
        {
          authSessionVerifier: deps.gateway,
          grantVerifier: deps.gateway,
          feeVerifier: deps.feeVerifier,
          runtimeAvailability: deps.runtimeAvailability,
        },
      );

      c.set("grant", grant);
      await next();
    } catch (err) {
      if (err instanceof ProtocolError) {
        return c.json(err.toJSON(), err.code as 401 | 403 | 413 | 503);
      }
      throw err;
    }
  };
}
