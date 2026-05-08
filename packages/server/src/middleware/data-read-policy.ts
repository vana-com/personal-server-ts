import type { MiddlewareHandler } from "hono";
import { verifyDataReadPolicy } from "@opendatalabs/personal-server-ts-core/policy";
import type {
  DataStoragePort,
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
  dataStorage?: Pick<DataStoragePort, "findEntry">;
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
    const scope = c.req.param("scope") ?? "";
    const selectedEntry = deps.dataStorage?.findEntry({
      scope,
      fileId: c.req.query("fileId"),
      at: c.req.query("at"),
    });

    try {
      const grant = await verifyDataReadPolicy(
        {
          signer: auth.signer,
          grantId: auth.payload.grantId,
          requestedScope: scope,
          fileId: c.req.query("fileId") ?? selectedEntry?.fileId ?? undefined,
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
