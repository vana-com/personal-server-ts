/**
 * Run intake over HTTP (whole-file stream sync, run-intake contract v2 §2).
 *
 *   PUT  /v1/stream-sync/runs/:runId            begin
 *   POST /v1/stream-sync/runs/:runId/batches    one ordered batch of records
 *   POST /v1/stream-sync/runs/:runId/end        outcome, covered streams
 *   POST /v1/stream-sync/runs/:runId/abort      {"reason": "failed"|"cancelled"}
 *
 * A thin map from the JSON body to `StreamSyncIntake`; the same adapter
 * serves PS-Lite in process. Only the owner may call it. The route is
 * mounted only when `streamSync.write` is on: with the flag off the paths do
 * not exist, as before.
 *
 * Errors answer `{"error": "<name>", "message", "nextBatch"?}` with the
 * status of the name (V2 §2.6).
 */

import { Hono } from "hono";
import type { Context } from "hono";
import {
  RunIntakeError,
  type StreamSyncIntake,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";

/** The same cap as one spool line (§2.2): a batch is at most 8 MiB. */
export const MAX_BATCH_BYTES = 8 * 1024 * 1024;

export interface StreamSyncRunsRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  intake: StreamSyncIntake;
}

async function body(c: Context, limit: number): Promise<unknown> {
  const declared = Number(c.req.header("content-length") ?? 0);
  if (declared > limit) {
    throw new RunIntakeError("invalid_request", "the body is over 8 MiB");
  }
  const text = await c.req.text();
  if (text.length > limit) {
    throw new RunIntakeError("invalid_request", "the body is over 8 MiB");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new RunIntakeError("invalid_request", "the body is not JSON");
  }
}

export function streamSyncRunsRoutes(deps: StreamSyncRunsRouteDeps): Hono {
  const app = new Hono();
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });
  const { intake } = deps;

  const answer = async (c: Context, work: () => Promise<unknown>) => {
    await auth.authorizeOwner(c.req.raw);
    try {
      return c.json((await work()) ?? {}, 200);
    } catch (error) {
      if (error instanceof RunIntakeError) {
        return c.json(
          {
            error: error.code,
            message: error.message,
            ...(error.nextBatch !== undefined
              ? { nextBatch: error.nextBatch }
              : {}),
          },
          error.status as 400 | 409 | 410 | 422,
        );
      }
      throw error;
    }
  };

  app.put("/:runId", (c) =>
    answer(c, async () =>
      intake.begin(
        c.req.param("runId"),
        (await body(c, 1024 * 1024)) as Parameters<typeof intake.begin>[1],
      ),
    ),
  );
  app.post("/:runId/batches", (c) =>
    answer(c, async () =>
      intake.batch(
        c.req.param("runId"),
        (await body(c, MAX_BATCH_BYTES)) as Parameters<typeof intake.batch>[1],
      ),
    ),
  );
  app.post("/:runId/end", (c) =>
    answer(c, async () =>
      intake.end(
        c.req.param("runId"),
        (await body(c, 1024 * 1024)) as Parameters<typeof intake.end>[1],
      ),
    ),
  );
  app.post("/:runId/abort", (c) =>
    answer(c, async () => {
      const { reason } = (await body(c, 4096)) as { reason?: unknown };
      if (reason !== "failed" && reason !== "cancelled") {
        throw new RunIntakeError("invalid_request", "reason is required");
      }
      await intake.abort(c.req.param("runId"), reason);
      return { result: "aborted" };
    }),
  );
  return app;
}
