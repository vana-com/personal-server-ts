/**
 * Desktop seed intake (whole-file stream sync, design revision 4.1, §2.9).
 *
 *   GET /v1/stream-sync/seed/:connector
 *     -> 200 {targetKnown, streams: {<stream>: {state, ...counts}}}
 *   PUT /v1/stream-sync/seed/:connector/:stream   (application/x-ndjson)
 *     line 1: {"primaryKey": [...], "profile": {"key", "version"}, "records": N}
 *     lines 2..N+1: one retained record object per line
 *     -> 200 {state: "merged" | "skipped"}  a receipt exists; body not read
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
import type { SeedReceipt } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import {
  SeedUploadError,
  checkSeedNames,
  type SeedStaging,
  type SeedStreamState,
} from "../stream-sync/seed-staging.js";

export interface StreamSyncSeedRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  /** Null on hosts without a database capability. Account mode gates admission. */
  streamSyncSeed: {
    writer: {
      importStaged(connector: string): Promise<void>;
      seedStatus(connector: string): Promise<{
        targetKnown: boolean;
        receipts: Readonly<Record<string, SeedReceipt>>;
      }>;
    };
    staging: SeedStaging;
  } | null;
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
    const status = await seed.writer.seedStatus(connector);
    const streams: Record<string, SeedStreamState> = {};
    for (const [stream, staged] of Object.entries(
      await seed.staging.staged(connector),
    )) {
      streams[stream] = {
        state: "staged",
        records: staged.records,
        invalid: staged.invalid,
      };
    }
    for (const [stream, receipt] of Object.entries(status.receipts)) {
      if (streams[stream]) await seed.staging.drop(connector, stream);
      streams[stream] = { state: receipt };
    }
    return c.json({ targetKnown: status.targetKnown, streams });
  });

  app.put("/:connector/:stream", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const seed = deps.streamSyncSeed;
    if (!seed) throw writeOff();
    const { connector, stream } = names(c);
    const receipt = (await seed.writer.seedStatus(connector)).receipts[stream!];
    if (receipt !== undefined) {
      await seed.staging.drop(connector, stream!);
      await c.req.raw.body?.cancel();
      return c.json({ state: receipt }, 200);
    }
    const body = c.req.raw.body;
    if (!body) {
      throw badRequest(
        new SeedUploadError("SEED_BAD_DESCRIPTOR", "the body is empty"),
      );
    }
    try {
      const staged = await seed.staging.stage(connector, stream!, chunks(body));
      await seed.writer.importStaged(connector);
      return c.json(
        {
          state: "staged",
          records: staged.records,
          invalid: staged.invalid,
        },
        202,
      );
    } catch (error) {
      if (error instanceof SeedUploadError) throw badRequest(error);
      throw error;
    }
  });

  return app;
}
