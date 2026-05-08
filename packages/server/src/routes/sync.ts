/**
 * Sync routes — endpoints for triggering and monitoring the sync engine.
 * All endpoints require owner authentication.
 */

import { Hono } from "hono";
import type { Logger } from "pino";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import {
  getSyncStatusContract,
  syncFileContract,
  triggerSyncContract,
} from "@opendatalabs/personal-server-ts-core/contracts";
import type { TokenStore } from "../token-store.js";
import { createWeb3AuthMiddleware } from "../middleware/web3-auth.js";
import { createOwnerCheckMiddleware } from "../middleware/owner-check.js";

export interface SyncRouteDeps {
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  devToken?: string;
  tokenStore?: TokenStore;
  syncManager: SyncManager | null; // null when sync disabled
}

export function syncRoutes(deps: SyncRouteDeps): Hono {
  const app = new Hono();

  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: deps.serverOrigin,
    devToken: deps.devToken,
    tokenStore: deps.tokenStore,
    serverOwner: deps.serverOwner,
  });
  const ownerCheck = createOwnerCheckMiddleware(deps.serverOwner);

  // POST /trigger — request a full sync (owner auth required)
  app.post("/trigger", web3Auth, ownerCheck, async (c) => {
    const result = await triggerSyncContract(deps.syncManager);
    return c.json(result.body, result.status as 200 | 202);
  });

  // GET /status — current sync status (owner auth required)
  app.get("/status", web3Auth, ownerCheck, async (c) => {
    const result = getSyncStatusContract(deps.syncManager);
    return c.json(result.body, result.status as 200);
  });

  // POST /file/:fileId — request sync for a specific file (owner auth required)
  app.post("/file/:fileId", web3Auth, ownerCheck, async (c) => {
    const fileId = c.req.param("fileId");
    deps.logger.info({ fileId }, "File sync requested, triggering full sync");
    const result = await syncFileContract({
      fileId,
      syncManager: deps.syncManager,
    });
    return c.json(result.body, result.status as 200 | 202);
  });

  return app;
}
