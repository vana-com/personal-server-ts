/**
 * Grants routes — GET / (owner), POST / (create grant), DELETE /:grantId
 * (revoke grant), POST /verify (public).
 */

import { Hono, type Handler } from "hono";
import type { Logger } from "pino";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import {
  handlePersonalServerGrantsRequest,
  type PersonalServerApiDispatchOptions,
} from "@opendatalabs/personal-server-ts-core/api";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";

export interface GrantsRouteDeps {
  logger: Logger;
  gateway: GatewayClient;
  gatewayConfig?: DataPortabilityGatewayConfig;
  serverOwner?: `0x${string}`;
  serverOrigin: string | (() => string);
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  serverSigner?: ServerSigner;
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
}

export function grantsRoutes(deps: GrantsRouteDeps): Hono {
  const app = new Hono();

  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
  });

  const handler: Handler = (c) =>
    handlePersonalServerGrantsRequest(
      c.req.raw,
      {
        auth,
        gateway: deps.gateway,
        gatewayConfig: deps.gatewayConfig,
        serverOwner: deps.serverOwner,
        serverSigner: deps.serverSigner,
      },
      { basePath: deps.mountPath },
    );

  app.all("/", handler);
  app.delete("/:grantId", handler);
  app.all("/*", handler);

  return app;
}
