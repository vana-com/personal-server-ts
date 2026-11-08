/**
 * The Desktop seed route (§2.9) over the real staging files and the real
 * writer, with the in-memory exclusive-version registry and local storage.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { StreamSyncWriter } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import {
  createSeedStaging,
  type SeedStaging,
} from "../stream-sync/seed-staging.js";
import {
  OWNER,
  collect,
  createOracleEnv,
  freshConnector,
  readStream,
  startLocalStorage,
  type OracleEnv,
} from "../stream-sync/oracle.test-utils.js";
import { streamSyncSeedRoutes } from "./stream-sync-seed.js";

const TOKEN = "seed-route-test-token";
const T0 = Date.UTC(2026, 10, 1);

function gateway(): GatewayClient {
  return {
    getServer: vi.fn().mockResolvedValue(null),
  } as unknown as GatewayClient;
}

function app(seed: { writer: StreamSyncWriter; staging: SeedStaging } | null) {
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
  let storage: Awaited<ReturnType<typeof startLocalStorage>>;
  let env: OracleEnv;
  let root: string;
  let staging: SeedStaging;
  let writer: StreamSyncWriter;
  let routes: Hono;

  beforeAll(async () => {
    storage = await startLocalStorage();
    env = await createOracleEnv({
      surface: "full",
      backend: "fake",
      storageUrl: storage.url,
    });
  });

  afterAll(async () => {
    await env.cleanup();
    await storage.close();
  });

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "stream-sync-seed-route-"));
    staging = createSeedStaging(createFsStreamSyncFiles(join(root, "seed")));
    let late: StreamSyncWriter | null = null;
    writer = await env.writer(`desktop-${root.slice(-6)}`, {
      seed: staging.source(await staging.installId(), async (c) =>
        late ? (await late.seedStatus(c)).receipts : {},
      ),
    });
    late = writer;
    await writer.refreshControls();
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

  it("merges the staged rows into the first generation-1 publish, then answers with the receipt", async () => {
    const c = freshConnector("seed-route");
    const staged = await put(
      routes,
      `${c}/history`,
      body({ ...DESCRIPTOR, records: 2 }, ['{"id":"h1"}', '{"id":"h2"}']),
    );
    expect(staged.status).toBe(202);
    // The run emits nothing for `history` (zero emission) and one row elsewhere.
    await collect(writer, {
      runId: "run-1",
      connector: c,
      observedAt: T0,
      streams: { live: [{ id: "l1" }] },
    });
    await writer.publishPending();
    const view = await readStream(env.registry, env.blobs, c, "", "history");
    if (!view || view === "tombstoned")
      throw new Error("seeded stream missing");
    expect([...view.records.keys()].sort()).toEqual(["h1", "h2"]);
    expect(view.head.complete).toBe(true);

    const again = await put(
      routes,
      `${c}/history`,
      body({ ...DESCRIPTOR, records: 1 }, ['{"id":"h3"}']),
    );
    expect(again.status).toBe(200);
    expect(await again.json()).toEqual({ state: "merged" });
    // The receipt dropped the staged rows on the next listing.
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
    const source = staging.source("x", async () => ({}));
    expect(await source.streams("c")).toHaveLength(1);
    for await (const row of source.records("c", "s")) rowsRead.push(row);
    expect(rowsRead).toEqual([{ id: "a" }, { id: "b" }]);
  });
});
