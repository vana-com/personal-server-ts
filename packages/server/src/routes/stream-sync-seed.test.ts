/**
 * The Desktop seed route (§2.9) over the real staging files and its
 * seed-status port. Database generation-1 publication is covered by P09.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { SeedReceipt } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import {
  createSeedStaging,
  type SeedStaging,
} from "../stream-sync/seed-staging.js";
import {
  streamSyncSeedRoutes,
  type StreamSyncSeedRouteDeps,
} from "./stream-sync-seed.js";
const OWNER = `0x${"12".repeat(20)}` as const;
type SeedStatusPort = NonNullable<
  StreamSyncSeedRouteDeps["streamSyncSeed"]
>["writer"];

const TOKEN = "seed-route-test-token";

function gateway(): GatewayClient {
  return {
    getServer: vi.fn().mockResolvedValue(null),
  } as unknown as GatewayClient;
}

function app(seed: { writer: SeedStatusPort; staging: SeedStaging } | null) {
  const outer = new Hono();
  outer.route(
    "/v1/stream-sync/seed",
    streamSyncSeedRoutes({
      serverOrigin: "http://127.0.0.1",
      serverOwner: OWNER,
      gateway: gateway(),
      accessToken: TOKEN,
      streamSyncSeed: seed,
    }),
  );
  outer.onError((err, c) =>
    err instanceof ProtocolError
      ? c.json(err.toJSON(), err.code as 400)
      : c.json({ error: String(err) }, 500),
  );
  return outer;
}

function body(
  descriptor: Record<string, unknown>,
  lines: readonly string[],
): string {
  return [JSON.stringify(descriptor), ...lines].join("\n") + "\n";
}

const DESCRIPTOR = {
  primaryKey: ["id"],
  profile: { key: null, version: "1.0.0" },
};

function put(
  target: Hono,
  path: string,
  text: string,
  token: string | null = TOKEN,
) {
  return target.request(`/v1/stream-sync/seed/${path}`, {
    method: "PUT",
    headers: {
      "content-type": "application/x-ndjson",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: text,
  });
}

function get(target: Hono, connector: string) {
  return target.request(`/v1/stream-sync/seed/${connector}`, {
    headers: { authorization: `Bearer ${TOKEN}` },
  });
}

describe("stream-sync seed route", () => {
  let root: string;
  let staging: SeedStaging;
  let writer: SeedStatusPort;
  let status: { targetKnown: boolean; receipts: Record<string, SeedReceipt> };
  let routes: Hono;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "stream-sync-seed-route-"));
    staging = createSeedStaging(createFsStreamSyncFiles(join(root, "seed")));
    status = { targetKnown: false, receipts: {} };
    writer = { seedStatus: async () => status, importStaged: async () => {} };
    routes = app({ writer, staging });
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("rejects a caller that is not the owner", async () => {
    const res = await put(
      routes,
      "c/s",
      body({ ...DESCRIPTOR, records: 0 }, []),
      null,
    );
    expect(res.status).toBe(401);
  });

  it("answers 404 when stream sync writing is off", async () => {
    const res = await put(
      app(null),
      "c/s",
      body({ ...DESCRIPTOR, records: 0 }, []),
    );
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "STREAM_SYNC_WRITE_OFF" },
    });
  });

  it("rejects names that cannot form a stream scope", async () => {
    const res = await put(
      routes,
      "bad~name/s",
      body({ ...DESCRIPTOR, records: 0 }, []),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "SEED_BAD_NAME" },
    });
  });

  it("rejects a truncated upload and stages nothing", async () => {
    const res = await put(
      routes,
      "c/s",
      body({ ...DESCRIPTOR, records: 3 }, ['{"id":"a"}', '{"id":"b"}']),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "SEED_COUNT_MISMATCH" },
    });
    expect(await staging.staged("c")).toEqual({});
  });

  it("rejects a bad descriptor", async () => {
    const res = await put(
      routes,
      "c/s",
      body({ primaryKey: [], records: 0 }, []),
    );
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "SEED_BAD_DESCRIPTOR" },
    });
  });

  it("counts invalid rows and stages the rest", async () => {
    const res = await put(
      routes,
      "c/s",
      body({ ...DESCRIPTOR, records: 4 }, [
        '{"id":"a"}',
        '{"other":1}',
        "[1]",
        "not json",
      ]),
    );
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({
      state: "staged",
      records: 1,
      invalid: 3,
    });
  });

  it("returns an acknowledged receipt and removes its staged upload", async () => {
    const c = "fixture";
    expect(
      (
        await put(
          routes,
          `${c}/history`,
          body({ ...DESCRIPTOR, records: 2 }, ['{"id":"h1"}', '{"id":"h2"}']),
        )
      ).status,
    ).toBe(202);
    status = { targetKnown: true, receipts: { history: "merged" } };
    const again = await put(
      routes,
      `${c}/history`,
      body({ ...DESCRIPTOR, records: 1 }, ['{"id":"h3"}']),
    );
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ state: "merged" });
    expect(await (await get(routes, c)).json()).toEqual({
      targetKnown: true,
      streams: { history: { state: "merged" } },
    });
    expect(await staging.staged(c)).toEqual({});
  });

  it("replaces an earlier upload of the same stream", async () => {
    await put(
      routes,
      "c/s",
      body({ ...DESCRIPTOR, records: 1 }, ['{"id":"a"}']),
    );
    await put(
      routes,
      "c/s",
      body({ ...DESCRIPTOR, records: 2 }, ['{"id":"a"}', '{"id":"b"}']),
    );
    expect(await (await get(routes, "c")).json()).toEqual({
      targetKnown: false,
      streams: { s: { state: "staged", records: 2, invalid: 0 } },
    });
    const rowsRead = [];
    const source = staging.source("x", async () => ({
      receipts: {},
      skipped: [],
    }));
    expect(await source.streams("c")).toHaveLength(1);
    for await (const row of source.records("c", "s")) rowsRead.push(row);
    expect(rowsRead).toEqual([{ id: "a" }, { id: "b" }]);
  });
});
