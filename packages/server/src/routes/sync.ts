import type { OwnedAccountStorageMode } from "@opendatalabs/personal-server-ts-core/api";
/**
 * Sync routes — endpoints for triggering and monitoring the sync engine.
 * All endpoints require owner authentication.
 */

import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import { Hono } from "hono";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
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
  localSync?: LocalSync | (() => Promise<LocalSync>);
  accountStorageMode?: OwnedAccountStorageMode;
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

  const local = async () => {
    const mode = deps.accountStorageMode?.read();
    if (mode === "unknown")
      throw new ProtocolError(
        503,
        "ACCOUNT_MODE_UNKNOWN",
        "Waiting for the account storage mode",
      );
    if (!deps.localSync)
      throw new ProtocolError(
        503,
        "STREAM_READ_UNAVAILABLE",
        "Stream sync is unavailable",
      );
    return typeof deps.localSync === "function"
      ? deps.localSync()
      : deps.localSync;
  };
  const legacy = () =>
    deps.accountStorageMode
      ? deps.accountStorageMode.read() === "unswitched"
      : !deps.localSync;
  app.post("/trigger", async (c, next) => {
    if (legacy()) return next();
    await auth.authorizeOwner(c.req.raw);
    // A signal, not a sync request: through the manager, which coalesces it
    // with the cycle that is running and cycles only if the registry moved.
    if (c.req.query("when") === "changed" && deps.syncManager) {
      void deps.syncManager.requestPull().catch(() => undefined);
      return c.json({ status: "started", message: "Sync triggered" }, 202);
    }
    await (await local()).cycle();
    return c.json({ status: "started", message: "Sync triggered" }, 202);
  });
  app.get("/status", async (c, next) => {
    if (legacy()) return next();
    await auth.authorizeOwner(c.req.raw);
    const status = await (await local()).listing.status();
    // The probe period is how a client learns this server answers
    // `?when=changed` with a pull and not a full cycle.
    return c.json({
      ...status,
      changeProbeMs: deps.syncManager?.getStatus().changeProbeMs ?? 0,
    });
  });
  app.post("/file/:id", async (c, next) => {
    if (legacy()) return next();
    await auth.authorizeOwner(c.req.raw);
    const file = await deps.localFile?.(c.req.param("id"));
    if (!file)
      return c.json({ error: { errorCode: "STREAM_DATA_NOT_FOUND" } }, 404);
    const result = await (await local()).syncConnection(file.connectionId);
    if (result?.error)
      return c.json({ error: { errorCode: "STREAM_READ_UNAVAILABLE" } }, 503);
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
