/**
 * Sync routes — endpoints for triggering and monitoring the sync engine.
 * All endpoints require owner authentication.
 */

import { Hono } from "hono";
import type { Logger } from "pino";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import {
  handlePersonalServerSyncRequest,
  type PersonalServerApiDispatchOptions,
} from "@opendatalabs/personal-server-ts-core/api";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";

export interface SyncRouteDeps {
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  tokenStore?: TokenStore;
  syncManager: SyncManager | null; // null when sync disabled
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
}

export function syncRoutes(deps: SyncRouteDeps): Hono {
  const app = new Hono();

  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    tokenStore: deps.tokenStore,
  });

  app.all("*", (c) =>
    handlePersonalServerSyncRequest(
      c.req.raw,
      {
        auth,
        syncManager: deps.syncManager,
        logger: deps.logger,
      },
      { basePath: deps.mountPath },
    ),
  );

  return app;
}
