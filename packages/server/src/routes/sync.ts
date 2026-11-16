import type { OwnedAccountStorageMode } from "@opendatalabs/personal-server-ts-core/api";
/**
 * Sync routes — endpoints for triggering and monitoring the sync engine.
 * All endpoints require owner authentication.
 */

import type {
  LocalSync,
  ViewChanges,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { Logger } from "pino";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import {
  handlePersonalServerSyncRequest,
  type PersonalServerApiDispatchOptions,
} from "@opendatalabs/personal-server-ts-core/api";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import { createFeedWriter } from "./sync-event-writer.js";
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
  /** The recorder the database was opened with; absent when there is none. */
  viewChanges?: ViewChanges;
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
  // The owner's change feed, so a screen follows the local store instead of
  // polling it. Standard server-sent events:
  //   `ready`  {}                  the feed is live; read now to catch up
  //   `view`   {connectionIds}     what a reader sees of these connections moved
  //   `status` <SyncStatus>        the sync manager's status changed
  // No event carries record data. Both sources are subscribed before `ready`
  // is sent, so a change after `ready` is never missed; a client reads once
  // after every `ready` to cover the change before it. The manager's current
  // status follows `ready`, so a client that listens only for status learns
  // what it missed while it was away without a read.
  app.get("/events", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    return streamSSE(c, async (stream) => {
      // One writer per connection folds what arrives while a frame is being
      // written, so a reader that stops reading holds bounded memory.
      const feed = createFeedWriter((event, data) =>
        stream.writeSSE({ event, data: JSON.stringify(data) }),
      );
      const left = new Promise<void>((resolve) => stream.onAbort(resolve));
      // A subscription joins this list when it is acquired, so whatever
      // happens next releases exactly what was acquired.
      const release: Array<() => void> = [];
      try {
        if (deps.viewChanges)
          release.push(
            deps.viewChanges.subscribe(({ connectionIds }) =>
              feed.views(connectionIds),
            ),
          );
        if (deps.syncManager) {
          release.push(
            deps.syncManager.subscribeStatus((status) => feed.status(status)),
          );
        }
        feed.ready();
        if (deps.syncManager) feed.status(deps.syncManager.getStatus());
        await left;
      } catch (err) {
        deps.logger.warn({ err }, "sync event feed failed; closing it");
      } finally {
        feed.close();
        for (const stop of release.reverse()) {
          try {
            stop();
          } catch (err) {
            deps.logger.warn({ err }, "sync event feed release failed");
          }
        }
      }
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
