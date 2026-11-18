import { describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { StreamSyncReadPort } from "@opendatalabs/personal-server-ts-core/api";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import { streamSyncReadStatusRoutes } from "./stream-sync-read-status.js";

const OWNER = "0x1111111111111111111111111111111111111111" as const;
const TOKEN = "read-status-test-token";
const granteeWallet = createTestWallet(2);

function app(streamSyncRead: StreamSyncReadPort | undefined) {
  const outer = new Hono();
  outer.route(
    "/v1/stream-sync/read-status",
    streamSyncReadStatusRoutes({
      serverOrigin: "http://127.0.0.1",
      serverOwner: OWNER,
      gateway: {
        getServer: vi.fn().mockResolvedValue(null),
      } as unknown as GatewayClient,
      accessToken: TOKEN,
      streamSyncRead,
    }),
  );
  outer.onError((err, c) =>
    err instanceof ProtocolError
      ? c.json(err.toJSON(), err.code as 401)
      : c.json({ error: String(err) }, 500),
  );
  return (authorization: string | null = `Bearer ${TOKEN}`) =>
    outer.request("/v1/stream-sync/read-status", {
      headers: authorization ? { authorization } : {},
    });
}

const port = (status: ReturnType<NonNullable<StreamSyncReadPort["status"]>>) =>
  ({ resolve: vi.fn(), status: () => status }) as unknown as StreamSyncReadPort;

describe("stream-sync read status route", () => {
  it("reads hydration from the local runtime through the route", async () => {
    const localSync = createLocalSync(
      {
        db: {
          query: async () => [],
          batch: async () => {},
          close: async () => {},
        },
        queue: connectionQueue(),
        registry: { listOwnerRows: async () => [] },
        keys: { namespaceHmac: async () => new Uint8Array(32) },
        logger: { info: vi.fn(), warn: vi.fn() },
      } as unknown as LocalSyncDeps,
      { resolveArtifact: () => null },
    );
    const route = streamSyncReadStatusRoutes({
      serverOrigin: "http://127.0.0.1",
      serverOwner: OWNER,
      gateway: {} as GatewayClient,
      accessToken: TOKEN,
      localSync,
      streamSyncRead: undefined,
    });
    const read = async () =>
      (
        await route.request("/", {
          headers: { authorization: `Bearer ${TOKEN}` },
        })
      ).json();
    try {
      expect(await read()).toMatchObject({ accountHydrated: false });
      await localSync.cycle();
      expect(await read()).toMatchObject({ accountHydrated: true });
    } finally {
      await localSync.close();
    }
  });

  it.each([false, true])(
    "exposes the runtime's Account hydration fact (%s)",
    async (accountHydrated) => {
      const response = await app(
        port({ listed: true, connections: [], issues: [], accountHydrated }),
      )();
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        accountHydrated,
        streams: [],
      });
    },
  );

  it("lists exact per-stream counts and nothing else", async () => {
    const call = app(
      port({
        listed: true,
        connections: [
          {
            connector: "conn-a",
            ns: "0123456789abcdef",
            control: "live",
            streams: {
              items: { live: true, complete: true, version: 3, records: 12 },
              stale: { live: false, complete: true, version: 2, records: 9 },
              pending: {
                live: true,
                complete: false,
                version: null,
                records: null,
              },
            },
          },
        ],
        issues: [
          {
            connector: "conn-a",
            ns: "0123456789abcdef",
            stream: "items",
            problem: "blob_missing",
            version: 3,
            detail: "secret-looking-detail",
          },
        ],
      } as never),
    );
    const response = await call();
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(JSON.parse(text)).toEqual({
      listed: true,
      accountHydrated: false,
      streams: [
        {
          connector: "conn-a",
          ns: "0123456789abcdef",
          stream: "items",
          records: 12,
        },
        {
          connector: "conn-a",
          ns: "0123456789abcdef",
          stream: "stale",
          records: null,
        },
        {
          connector: "conn-a",
          ns: "0123456789abcdef",
          stream: "pending",
          records: null,
        },
      ],
      issues: 1,
    });
    expect(text).not.toContain("secret-looking-detail");
  });

  it("answers 404 when stream sync reading is off", async () => {
    const response = await app(undefined)();
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({
      error: { code: 404, errorCode: "STREAM_SYNC_READ_OFF" },
    });
  });

  it("refuses a caller who is not the owner", async () => {
    const response = await app(
      port({ listed: true, connections: [], issues: [] }),
    )("Bearer wrong-token");
    expect(response.status).toBe(401);
  });

  it("refuses a valid grantee-signed request and a request with no auth", async () => {
    const call = app(port({ listed: true, connections: [], issues: [] }));
    const grantee = await buildWeb3SignedHeader({
      wallet: granteeWallet,
      aud: "http://127.0.0.1",
      method: "GET",
      uri: "/v1/stream-sync/read-status",
      grantId: "0xgrant",
    });
    expect((await call(grantee)).status).toBe(401);
    expect((await call(null)).status).toBe(401);
  });
});
