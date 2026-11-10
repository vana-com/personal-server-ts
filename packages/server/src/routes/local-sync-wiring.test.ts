import { describe, expect, it, vi } from "vitest";
import { pino } from "pino";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { syncRoutes } from "./sync.js";
import { streamSyncRunsRoutes } from "./stream-sync-runs.js";
import { streamSyncReadStatusRoutes } from "./stream-sync-read-status.js";

const auth = {
  serverOrigin: "http://localhost",
  serverOwner: `0x${"1".repeat(40)}` as `0x${string}`,
  accessToken: "test-owner",
  gateway: {} as GatewayClient,
};
const headers = { authorization: "Bearer test-owner" };

describe("database route wiring", () => {
  it("awaits a connection sync before reading a file, uses the cycle for trigger and exposes history counts", async () => {
    const order: string[] = [];
    const counts = { served: 2, gone: 1, off: 3 };
    const status = {
      listed: 1,
      connections: [],
      issues: [],
      olderVersionReads: counts,
    };
    const localSync = {
      cycle: vi.fn(async () => {
        order.push("cycle");
      }),
      syncConnection: vi.fn(async () => {
        order.push("sync");
      }),
      listing: { status: vi.fn(async () => status) },
      olderVersions: { counts: () => counts },
    } as unknown as LocalSync;
    const app = syncRoutes({
      ...auth,
      logger: pino({ level: "silent" }),
      syncManager: null,
      localSync,
      localFile: async () => ({
        connectionId: "connection",
        read: async () => {
          order.push("read");
          return new Response("ready");
        },
      }),
    });
    const file = await app.request("/file/file-id", {
      method: "POST",
      headers,
    });
    expect(file.status).toBe(200);
    expect(order).toEqual(["sync", "read"]);
    expect(localSync.syncConnection).toHaveBeenCalledWith("connection");
    expect(
      (await app.request("/trigger", { method: "POST", headers })).status,
    ).toBe(202);
    expect(order).toEqual(["sync", "read", "cycle"]);
    expect(await (await app.request("/status", { headers })).json()).toEqual(
      status,
    );
    const readStatus = streamSyncReadStatusRoutes({
      ...auth,
      streamSyncRead: undefined,
      localSync,
    });
    expect(
      (await (await readStatus.request("/", { headers })).json())
        .olderVersionReads,
    ).toEqual(counts);
  });

  it("authenticates blob puts and forwards bytes only within the size ceiling", async () => {
    const put = vi.fn(async () => {});
    const intake = {
      begin: vi.fn(),
      batch: vi.fn(),
      end: vi.fn(),
      abort: vi.fn(),
    };
    const app = streamSyncRunsRoutes({
      ...auth,
      intake,
      blobs: { put, get: vi.fn() },
    });
    const url = `/run/blobs/${"a".repeat(64)}`;
    const response = await app.request(url, {
      method: "PUT",
      headers: { ...headers, "content-type": "application/octet-stream" },
      body: new Uint8Array([1, 2]),
    });
    expect(response.status).toBe(200);
    expect(put).toHaveBeenCalledWith({
      runId: "run",
      sha256: "a".repeat(64),
      mimeType: "application/octet-stream",
      bytes: new Uint8Array([1, 2]),
    });
    expect(
      (
        await app.request(url, {
          method: "PUT",
          headers: {
            ...headers,
            "content-length": String(32 * 1024 * 1024 + 1),
          },
        })
      ).status,
    ).toBe(413);
    expect(put).toHaveBeenCalledTimes(1);
  });
});
