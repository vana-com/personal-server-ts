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

import type { BlobStore } from "@opendatalabs/personal-server-ts-core/localdb";
import { Hono } from "hono";
import type { Context } from "hono";
import {
  RunIntakeError,
  type RunIntake,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import {
  createBodyLimit,
  DATA_INGEST_MAX_SIZE,
} from "../middleware/body-limit.js";

/**
 * Ceiling on one batch request: the 512 MiB the legacy ingest routes allow. It
 * guards the server against an unbounded upload; it is not a record limit.
 * The body is read whole and parsed, so a batch costs a few times its size.
 */
export const MAX_BATCH_REQUEST_BYTES = DATA_INGEST_MAX_SIZE;

export interface StreamSyncRunsRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  intake: RunIntake;
  blobs?: BlobStore;
}

async function body(c: Context, limit: number): Promise<unknown> {
  const declared = Number(c.req.header("content-length") ?? 0);
  if (declared > limit) {
    throw new RunIntakeError("invalid_request", "the body is too large");
  }
  const text = await c.req.text();
  if (text.length > limit) {
    throw new RunIntakeError("invalid_request", "the body is too large");
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
            ...(error.lastError !== undefined
              ? { lastError: error.lastError }
              : {}),
          },
          error.status as 400 | 409 | 410 | 422 | 503,
        );
      }
      throw error;
    }
  };

  app.put("/:runId/blobs/:sha256", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    if (!deps.blobs) return c.json({ error: "unavailable" }, 503);
    const limit = 32 * 1024 * 1024;
    if (Number(c.req.header("content-length") ?? 0) > limit)
      return c.json({ error: "too_large" }, 413);
    const reader = c.req.raw.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader) {
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > limit) {
            await reader.cancel();
            return c.json({ error: "too_large" }, 413);
          }
          chunks.push(part.value);
        }
      } finally {
        reader.releaseLock();
      }
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    await deps.blobs.put({
      runId: c.req.param("runId"),
      sha256: c.req.param("sha256"),
      mimeType: c.req.header("content-type") ?? "application/octet-stream",
      bytes,
    });
    return c.json({});
  });

  app.put("/:runId", (c) =>
    answer(c, async () =>
      intake.begin(
        c.req.param("runId"),
        (await body(c, 1024 * 1024)) as Parameters<typeof intake.begin>[1],
      ),
    ),
  );
  app.post("/:runId/batches", createBodyLimit(MAX_BATCH_REQUEST_BYTES), (c) =>
    answer(c, async () =>
      intake.batch(
        c.req.param("runId"),
        (await body(c, MAX_BATCH_REQUEST_BYTES)) as Parameters<
          typeof intake.batch
        >[1],
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
