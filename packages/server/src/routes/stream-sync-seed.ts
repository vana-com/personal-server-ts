/**
 * Desktop seed intake (whole-file stream sync, design revision 4.1, §2.9).
 *
 *   GET /v1/stream-sync/seed/:connector
 *     -> 200 {targetKnown, streams: {<stream>: {state, ...counts}}}
 *   PUT /v1/stream-sync/seed/:connector/:stream   (application/x-ndjson)
 *     line 1: {"primaryKey": [...], "profile": {"key", "version"}, "records": N}
 *     lines 2..N+1: one retained record object per line
 *     -> 200 {state: "merged"}  a receipt exists; body not read
 *     -> 202 {state: "staged", records, invalid}
 *
 * Only the owner may call it; Desktop uses the sidecar access token it
 * already sends. The body is streamed to disk, so memory stays bounded by one
 * record. The host imports the staged rows through the shared database importer
 * with the seed stamp and records the receipt that makes a later PUT a no-op.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  createSeedIntake,
  type LocalSeedCapability,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import {
  SeedUploadError,
  checkSeedNames,
} from "../stream-sync/seed-staging.js";

export interface StreamSyncSeedRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  /** Null on hosts without a database capability. Account mode gates admission. */
  streamSyncSeed: LocalSeedCapability | null;
}

function writeOff(): ProtocolError {
  return new ProtocolError(
    404,
    "STREAM_SYNC_WRITE_OFF",
    "Stream sync writing is off on this server",
  );
}

function badRequest(error: SeedUploadError): ProtocolError {
  return new ProtocolError(400, error.errorCode, error.message);
}

async function* chunks(
  body: ReadableStream<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  const reader = body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      yield value;
    }
  } finally {
    reader.releaseLock();
  }
}

function names(c: Context): { connector: string; stream?: string } {
  const connector = c.req.param("connector") ?? "";
  const stream = c.req.param("stream");
  try {
    checkSeedNames(connector, stream ?? "s");
  } catch (error) {
    if (error instanceof SeedUploadError) throw badRequest(error);
    throw error;
  }
  return { connector, stream };
}

export function streamSyncSeedRoutes(deps: StreamSyncSeedRouteDeps): Hono {
  const app = new Hono();
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  app.get("/:connector", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const seed = deps.streamSyncSeed;
    if (!seed) throw writeOff();
    const { connector } = names(c);
    return c.json(await createSeedIntake(seed).status(connector));
  });

  app.put("/:connector/:stream", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const seed = deps.streamSyncSeed;
    if (!seed) throw writeOff();
    const { connector, stream } = names(c);
    try {
      const body = c.req.raw.body;
      async function* upload() {
        if (!body)
          throw new SeedUploadError("SEED_BAD_DESCRIPTOR", "the body is empty");
        yield* chunks(body);
      }
      const result = await createSeedIntake(seed).put(
        connector,
        stream!,
        upload(),
      );
      if (result.state === "merged") await body?.cancel();
      return c.json(result, result.state === "merged" ? 200 : 202);
    } catch (error) {
      if (error instanceof SeedUploadError) throw badRequest(error);
      throw error;
    }
  });

  return app;
}
