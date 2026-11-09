/**
 * What the one-time legacy import left behind, for the owner.
 *
 *   GET /v1/stream-sync/import-status
 *     -> 200 {complete, abandoned, givenUp, stayed, connectors: [{connector, state, attempts,
 *             staged, excluded: [{reason, rows}]}]}
 *
 * Counts per connector and reason only: never a row, a stream name or a key.
 * A host shows it so a user sees what stayed in a legacy file. A connector
 * with `excluded` rows above 0, or `state: "failed"`, keeps its legacy file
 * (the retire gate refuses it).
 *
 * Only the owner may call it. With no importer (stream sync write off) the
 * route answers 404.
 */

import { Hono } from "hono";
import type { ImportStatus } from "@opendatalabs/personal-server-ts-core/sync";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";

export interface StreamSyncImportStatusRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  /** Absent when no importer runs: every call answers 404. */
  importStatus: (() => Promise<ImportStatus>) | undefined;
}

export function streamSyncImportStatusRoutes(
  deps: StreamSyncImportStatusRouteDeps,
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
    if (!deps.importStatus) {
      return c.json(
        {
          error: {
            code: 404,
            errorCode: "STREAM_SYNC_IMPORT_OFF",
            message: "No legacy import runs on this server",
          },
        },
        404,
      );
    }
    return c.json(await deps.importStatus());
  });

  return app;
}
