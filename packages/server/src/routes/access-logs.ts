/**
 * Access logs routes — GET / returns paginated access log entries.
 * Owner auth is wired in Task 4.1.
 */

import { Hono } from "hono";
import type { Logger } from "pino";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import {
  handlePersonalServerAccessLogsRequest,
  type PersonalServerApiDispatchOptions,
} from "@opendatalabs/personal-server-ts-core/api";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";

export interface AccessLogsRouteDeps {
  logger: Logger;
  accessLogReader: AccessLogReader;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
}

export function accessLogsRoutes(deps: AccessLogsRouteDeps): Hono {
  const app = new Hono();

  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  app.all("*", (c) =>
    handlePersonalServerAccessLogsRequest(
      c.req.raw,
      {
        auth,
        accessLogReader: deps.accessLogReader,
      },
      { basePath: deps.mountPath },
    ),
  );

  return app;
}
