import { describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { StreamSyncReadPort } from "@opendatalabs/personal-server-ts-core/api";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
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
        ownerAddress: OWNER,
        now: Date.now,
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

  it("distinguishes a verified zero record count from an absent live count", async () => {
    const response = await app(
      port({
        listed: false,
        issues: [],
        connections: [
          {
            connector: "conn-empty",
            ns: "0123456789abcdef",
            control: "active",
            streams: {
              empty: { live: true, complete: true, version: 2, records: 0 },
              old: { live: false, complete: true, version: 1, records: 0 },
            },
          },
        ],
      }),
    )();
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      listed: false,
      streams: [
        { stream: "empty", records: 0 },
        { stream: "old", records: null },
      ],
    });
  });

  describe("audit", () => {
    const report = {
      finishedAt: 5,
      stopped: false,
      imported: 3,
      alreadyImported: 0,
      excluded: [{ reason: "older_instance", streams: 1, rows: 4 }],
      refused: [],
      rows: {
        legacy: 7,
        imported: 7,
        blocked: 0,
        quarantined: {},
        refused: 0,
      },
      files: { total: 2, unimported: 1 },
    };
    function audited(legacyStoreImport?: () => typeof report | null) {
      const status = vi.fn(async (options?: { audit?: boolean }) => ({
        listed: true,
        issues: [],
        connections: [
          {
            connector: "conn-a",
            ns: "",
            control: "active",
            streams: {
              items: {
                live: true,
                complete: true,
                tombstoned: false,
                version: 3,
                records: 12,
                ...(options?.audit ? { digest: "ab".repeat(32) } : {}),
              },
            },
          },
        ],
        ...(options?.audit
          ? { importExclusions: [{ reason: "seed_skipped", streams: 2 }] }
          : {}),
      }));
      const route = streamSyncReadStatusRoutes({
        serverOrigin: "http://127.0.0.1",
        serverOwner: OWNER,
        gateway: {} as GatewayClient,
        accessToken: TOKEN,
        localSync: { listing: { status } } as unknown as LocalSync,
        legacyStoreImport,
        streamSyncRead: undefined,
      });
      return {
        status,
        get: async (query = "") =>
          (
            await route.request(`/${query}`, {
              headers: { authorization: `Bearer ${TOKEN}` },
            })
          ).json() as Promise<Record<string, unknown>>,
      };
    }

    it("adds the digest and the seed exclusions only when asked", async () => {
      const { status, get } = audited(() => report);
      const plain = await get();
      expect(status).toHaveBeenLastCalledWith(undefined);
      expect(plain).not.toHaveProperty("seedExclusions");
      expect(JSON.stringify(plain)).not.toContain("digest");

      const body = await get("?audit=1");
      expect(status).toHaveBeenLastCalledWith({ audit: true });
      expect(body).toMatchObject({
        streams: [
          {
            connector: "conn-a",
            stream: "items",
            records: 12,
            digest: "ab".repeat(32),
          },
        ],
        seedExclusions: {
          ledger: [{ reason: "seed_skipped", streams: 2 }],
          legacyStore: report,
        },
      });
    });

    it("honors audit=true but does not treat other nonempty values as opt-in", async () => {
      const { get, status } = audited(() => report);
      const invalid = await get("?audit=yes");
      expect(status).toHaveBeenLastCalledWith(undefined);
      expect(invalid).not.toHaveProperty("seedExclusions");

      const enabled = await get("?audit=true");
      expect(status).toHaveBeenLastCalledWith({ audit: true });
      expect(enabled).toHaveProperty("seedExclusions");
    });

    it("says the legacy store has not finished a run with null", async () => {
      const { get } = audited(() => null);
      expect(await get("?audit=1")).toMatchObject({
        seedExclusions: { legacyStore: null },
      });
      const { get: without } = audited(undefined);
      expect(await without("?audit=1")).toMatchObject({
        seedExclusions: { legacyStore: null },
      });
    });
  });

  it("answers 503 and no streams when the mode leaves switched while the count is in flight", async () => {
    let mode: "switched" | "unswitched" = "switched";
    let release!: (status: unknown) => void;
    const held = new Promise((resolve) => (release = resolve));
    const localSync = {
      listing: { status: vi.fn(() => held) },
    } as unknown as LocalSync;
    const route = streamSyncReadStatusRoutes({
      serverOrigin: "http://127.0.0.1",
      serverOwner: OWNER,
      gateway: {} as GatewayClient,
      accessToken: TOKEN,
      localSync,
      accountStorageMode: { owner: OWNER, read: () => mode },
      streamSyncRead: undefined,
    });
    route.onError((err, c) =>
      err instanceof ProtocolError
        ? c.json(err.toJSON(), err.code as 503)
        : c.json({ error: String(err) }, 500),
    );
    const pending = route.request("/", {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    await vi.waitFor(() =>
      expect(localSync.listing.status).toHaveBeenCalledTimes(1),
    );
    mode = "unswitched";
    release({
      listed: true,
      issues: [],
      connections: [
        {
          connectionId: "c1",
          connector: "x",
          ns: "n",
          streams: [],
        },
      ],
    });
    const response = await pending;
    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body).toMatchObject({
      error: { errorCode: "ACCOUNT_MODE_UNKNOWN" },
    });
    expect(body).not.toHaveProperty("streams");
  });

  it.each([
    ["unknown", "ACCOUNT_MODE_UNKNOWN"],
    ["switched", "STREAM_READ_UNAVAILABLE"],
  ] as const)("does not use the legacy port in %s mode", async (mode, errorCode) => {
    const fallbackStatus = vi.fn(() => ({ listed: true, connections: [], issues: [] }));
    const route = streamSyncReadStatusRoutes({
      serverOrigin: "http://127.0.0.1",
      serverOwner: OWNER,
      gateway: {} as GatewayClient,
      accessToken: TOKEN,
      accountStorageMode: { owner: OWNER, read: () => mode },
      streamSyncRead: { resolve: vi.fn(), status: fallbackStatus } as unknown as StreamSyncReadPort,
    });
    route.onError((error, c) =>
      error instanceof ProtocolError
        ? c.json(error.toJSON(), error.code as 503)
        : c.json({ error: String(error) }, 500),
    );
    const response = await route.request("/", {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: { errorCode } });
    expect(fallbackStatus).not.toHaveBeenCalled();
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
