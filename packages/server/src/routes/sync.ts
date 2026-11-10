/**
 * Sync routes — endpoints for triggering and monitoring the sync engine.
 * All endpoints require owner authentication.
 */

import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
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
  accessToken?: string;
  tokenStore?: TokenStore;
  syncManager: SyncManager | null; // null when sync disabled
  localSync?: LocalSync;
  /** Resolve a file selector without reading its body until its connection synced. */
  localFile?: (
    id: string,
  ) => Promise<{ connectionId: string; read: () => Promise<Response> } | null>;
  mountPath?: PersonalServerApiDispatchOptions["basePath"];
}

export function syncRoutes(deps: SyncRouteDeps): Hono {
  const app = new Hono();

  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  app.post("/trigger", async (c, next) => {
    if (!deps.localSync) return next();
    await auth.authorizeOwner(c.req.raw);
    await deps.localSync.cycle();
    return c.json({ status: "started", message: "Sync triggered" }, 202);
  });
  app.get("/status", async (c, next) => {
    if (!deps.localSync) return next();
    await auth.authorizeOwner(c.req.raw);
    return c.json(await deps.localSync.listing.status());
  });
  app.post("/file/:id", async (c, next) => {
    if (!deps.localSync) return next();
    await auth.authorizeOwner(c.req.raw);
    const file = await deps.localFile?.(c.req.param("id"));
    if (!file)
      return c.json({ error: { errorCode: "STREAM_DATA_NOT_FOUND" } }, 404);
    await deps.localSync.syncConnection(file.connectionId);
    return file.read();
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
