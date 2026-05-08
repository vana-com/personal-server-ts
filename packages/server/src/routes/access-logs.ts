/**
 * Access logs routes — GET / returns paginated access log entries.
 * Owner auth is wired in Task 4.1.
 */

import { Hono } from "hono";
import type { Logger } from "pino";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import { listAccessLogsContract } from "@opendatalabs/personal-server-ts-core/contracts";
import type { TokenStore } from "../token-store.js";
import { createWeb3AuthMiddleware } from "../middleware/web3-auth.js";
import { createOwnerCheckMiddleware } from "../middleware/owner-check.js";

export interface AccessLogsRouteDeps {
  logger: Logger;
  accessLogReader: AccessLogReader;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  devToken?: string;
  tokenStore?: TokenStore;
}

export function accessLogsRoutes(deps: AccessLogsRouteDeps): Hono {
  const app = new Hono();

  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: deps.serverOrigin,
    devToken: deps.devToken,
    tokenStore: deps.tokenStore,
    serverOwner: deps.serverOwner,
  });
  const ownerCheck = createOwnerCheckMiddleware(deps.serverOwner);

  // GET / — list access logs with pagination (owner auth required)
  app.get("/", web3Auth, ownerCheck, async (c) => {
    const result = await listAccessLogsContract({
      accessLogReader: deps.accessLogReader,
      limit: c.req.query("limit"),
      offset: c.req.query("offset"),
    });
    return c.json(result.body, result.status as 200);
  });

  return app;
}
