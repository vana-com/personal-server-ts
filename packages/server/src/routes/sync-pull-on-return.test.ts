// The Desktop renderer asks for a pull when its window returns, and reads the
// server's probe period to know whether the server can answer it: both go
// through the switched-mode routes, which a stream-sync Account uses.
import { describe, expect, it, vi } from "vitest";
import { pino } from "pino";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { syncRoutes } from "./sync.js";

const auth = {
  serverOrigin: "http://localhost",
  serverOwner: `0x${"1".repeat(40)}` as `0x${string}`,
  accessToken: "test-owner",
  gateway: {} as GatewayClient,
};
const headers = { authorization: "Bearer test-owner" };

function build(changeProbeMs: number | undefined) {
  const listing = { listed: 0, connections: [], issues: [] };
  const localSync = {
    cycle: vi.fn(async () => undefined),
    listing: { status: vi.fn(async () => listing) },
  } as unknown as LocalSync;
  const syncManager = {
    requestPull: vi.fn(async () => undefined),
    trigger: vi.fn(async () => undefined),
    getStatus: vi.fn(() => ({
      enabled: true,
      running: true,
      syncing: false,
      lastSync: null,
      lastProcessedTimestamp: null,
      pendingFiles: 0,
      hydratedScopes: [],
      errors: [],
      ...(changeProbeMs !== undefined && { changeProbeMs }),
    })),
  } as unknown as SyncManager;
  const app = syncRoutes({
    ...auth,
    logger: pino({ level: "silent" }),
    syncManager,
    localSync,
    accountStorageMode: { read: () => "switched" } as never,
  });
  return { app, localSync, syncManager };
}

describe("switched-mode POST /trigger", () => {
  it("?when=changed asks the manager for a pull and runs no cycle itself", async () => {
    const { app, localSync, syncManager } = build(5_000);
    const res = await app.request("/trigger?when=changed", {
      method: "POST",
      headers,
    });
    expect(res.status).toBe(202);
    expect(syncManager.requestPull).toHaveBeenCalledTimes(1);
    expect(localSync.cycle).not.toHaveBeenCalled();
  });

  it("a plain trigger still runs the cycle, as before", async () => {
    const { app, localSync, syncManager } = build(5_000);
    const res = await app.request("/trigger", { method: "POST", headers });
    expect(res.status).toBe(202);
    expect(localSync.cycle).toHaveBeenCalledTimes(1);
    expect(syncManager.requestPull).not.toHaveBeenCalled();
  });
});

describe("switched-mode GET /status", () => {
  it("says how often the server probes, so a client can tell it answers ?when=changed", async () => {
    const { app } = build(5_000);
    const res = await app.request("/status", { headers });
    expect(await res.json()).toMatchObject({ listed: 0, changeProbeMs: 5_000 });
  });

  it("says 0 when the server has no probe", async () => {
    const { app } = build(0);
    const res = await app.request("/status", { headers });
    expect(await res.json()).toMatchObject({ changeProbeMs: 0 });
  });
});
