/**
 * Stream-sync read counts for the owner (diagnostics).
 *
 *   GET /v1/stream-sync/read-status
 *     -> 200 {listed, streams: [{connector, ns, stream, records}], issues}
 *
 * `records` is the exact count of live rows the read side holds for that
 * stream, or `null` while the stream head is not imported yet. The body has
 * stream names and counts only: never a record, a blob key or an issue detail.
 * `issues` counts import problems still open.
 *
 * Only the owner may call it. With `streamSync.read` off the route answers 404.
 */

import { Hono } from "hono";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { StreamSyncReadPort } from "@opendatalabs/personal-server-ts-core/api";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";

export interface StreamSyncReadStatusRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  /** Absent when `streamSync.read` is off: every call answers 404. */
  streamSyncRead: StreamSyncReadPort | undefined;
}

export function streamSyncReadStatusRoutes(
  deps: StreamSyncReadStatusRouteDeps,
): Hono {
  const app = new Hono();
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  app.get("/", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const status = deps.streamSyncRead?.status?.();
    if (!status) {
      throw new ProtocolError(
        404,
        "STREAM_SYNC_READ_OFF",
        "Stream sync reading is off on this server",
      );
    }
    const streams = status.connections.flatMap((connection) =>
      Object.entries(connection.streams).map(([stream, head]) => ({
        connector: connection.connector,
        ns: connection.ns,
        stream,
        records: head.records,
      })),
    );
    return c.json({
      listed: status.listed,
      streams,
      issues: status.issues.length,
    });
  });

  return app;
}
