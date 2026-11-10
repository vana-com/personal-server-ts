import type { OwnedAccountStorageMode } from "@opendatalabs/personal-server-ts-core/api";
/**
 * Stream-sync read counts for the owner (diagnostics).
 *
 *   GET /v1/stream-sync/read-status
 *     -> 200 {listed, streams: [{connector, ns, stream, records}], issues}
 *
 * `records` is the record count of the stream-sync head imported for that
 * (connector, ns, stream), while that head is live. Logical connection
 * selection, a legacy-file fallback and local outbox overlay rows are outside
 * this count. It is `null` for a head that is pending import, tombstoned, of
 * an older generation, or of a deleted connection. The body has
 * stream names and counts only: never a record, a blob key or an issue detail.
 * `issues` counts import problems still open.
 *
 * Only the owner may call it. With `streamSync.read` off the route answers 404.
 */

import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import { Hono } from "hono";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { liveStreamCounts } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
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
  localSync?: LocalSync | (() => Promise<LocalSync>);
  accountStorageMode?: OwnedAccountStorageMode;
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
    const mode = deps.accountStorageMode?.read();
    if (mode === "unknown")
      throw new ProtocolError(
        503,
        "ACCOUNT_MODE_UNKNOWN",
        "Waiting for the account storage mode",
      );
    if (mode === "switched" && !deps.localSync)
      throw new ProtocolError(
        503,
        "STREAM_READ_UNAVAILABLE",
        "Stream sync is unavailable",
      );
    const local =
      deps.localSync && deps.accountStorageMode?.read() !== "unswitched"
        ? typeof deps.localSync === "function"
          ? await deps.localSync()
          : deps.localSync
        : undefined;
    const status = local
      ? await local.listing.status()
      : deps.streamSyncRead?.status?.();
    if (!status) {
      // An expected state while a diagnostic polls: answered here, not thrown,
      // so the global error handler does not log a warning per request.
      return c.json(
        {
          error: {
            code: 404,
            errorCode: "STREAM_SYNC_READ_OFF",
            message: "Stream sync reading is off on this server",
          },
        },
        404,
      );
    }
    const streams = liveStreamCounts(status);
    return c.json({
      listed: status.listed,
      streams,
      issues: status.issues.length,
      ...(local && {
        olderVersionReads: local.olderVersions.counts(),
      }),
    });
  });

  return app;
}
