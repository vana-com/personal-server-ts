// The Desktop renderer asks for a pull when its window returns, and reads the
// server's probe period to know whether the server can answer it: both go
// through the switched-mode routes, which a stream-sync Account uses.
import { describe, expect, it, vi } from "vitest";
import { pino } from "pino";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
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

// The mode can move across any await of a switched-mode route. A route that
// chose the stream branch must not act or answer under a mode that left it.
describe("switched-mode routes re-check the mode after their awaits", () => {
  function setup(
    opts: {
      holdLocal?: boolean;
      holdStatus?: boolean;
      holdFile?: boolean;
    } = {},
  ) {
    // The first read picks the route; `flip()` moves every later read.
    let moved = false;
    let first = true;
    const read = () => {
      if (first) {
        first = false;
        return "switched";
      }
      return moved ? "unswitched" : "switched";
    };
    const hold = <T>() => {
      let release!: (v: T) => void;
      const promise = new Promise<T>((resolve) => (release = resolve));
      return { promise, release };
    };
    const local = hold<void>();
    const localEntered = vi.fn();
    const listing = hold<unknown>();
    const fileReady = hold<void>();
    const readFile = vi.fn(async () => new Response("fixture only"));
    const localFile = vi.fn(async () => {
      await fileReady.promise;
      return { connectionId: "fixture", read: readFile };
    });
    const syncConnection = vi.fn(async () => undefined);
    const localSync = {
      cycle: vi.fn(async () => undefined),
      syncConnection,
      listing: {
        status: vi.fn(() =>
          opts.holdStatus
            ? listing.promise
            : Promise.resolve({ listed: 0, connections: [], issues: [] }),
        ),
      },
    } as unknown as LocalSync;
    const syncManager = {
      requestPull: vi.fn(async () => undefined),
      trigger: vi.fn(async () => undefined),
      getStatus: vi.fn(() => ({ changeProbeMs: 0 })),
    } as unknown as SyncManager;
    const app = syncRoutes({
      ...auth,
      logger: pino({ level: "silent" }),
      syncManager,
      localSync: opts.holdLocal
        ? async () => {
            localEntered();
            await local.promise;
            return localSync;
          }
        : localSync,
      accountStorageMode: { read } as never,
      ...(opts.holdFile ? { localFile } : {}),
    });
    app.onError((err, c) =>
      err instanceof ProtocolError
        ? c.json(err.toJSON(), err.code as 503)
        : c.json({ error: String(err) }, 500),
    );
    return {
      app,
      localEntered,
      localSync,
      syncManager,
      flip: () => (moved = true),
      releaseLocal: () => local.release(),
      releaseFile: () => fileReady.release(),
      localFile,
      readFile,
      syncConnection,
      releaseListing: () =>
        listing.release({ listed: 0, connections: [], issues: [] }),
    };
  }
  const stopped = async (res: Response) => {
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "ACCOUNT_MODE_UNKNOWN" },
    });
  };

  it("does not pull or cycle when the mode moved during auth", async () => {
    for (const path of ["/trigger?when=changed", "/trigger"]) {
      const t = setup();
      t.flip();
      await stopped(await t.app.request(path, { method: "POST", headers }));
      expect(t.syncManager.requestPull).not.toHaveBeenCalled();
      expect(t.localSync.cycle).not.toHaveBeenCalled();
    }
  });

  it("does not cycle when the mode moved while the local runtime was acquired", async () => {
    const t = setup({ holdLocal: true });
    const pending = t.app.request("/trigger", { method: "POST", headers });
    await vi.waitFor(() => expect(t.localEntered).toHaveBeenCalledTimes(1));
    t.flip();
    t.releaseLocal();
    await stopped(await pending);
    expect(t.localSync.cycle).not.toHaveBeenCalled();
  });

  it("refuses a trigger response if the mode moved during a full cycle", async () => {
    const t = setup();
    let releaseCycle!: () => void;
    const cycle = new Promise<void>((resolve) => {
      releaseCycle = resolve;
    });
    const entered = vi.mocked(t.localSync.cycle);
    entered.mockImplementationOnce(async () => (await cycle) as never);
    const pending = t.app.request("/trigger", { method: "POST", headers });
    try {
      await vi.waitFor(() => expect(entered).toHaveBeenCalledOnce());
      t.flip();
    } finally {
      releaseCycle();
    }
    await stopped(await pending);
  });

  it("refuses a file response if its account is no longer switched", async () => {
    const t = setup({ holdFile: true });
    const pending = t.app.request("/file/fixture", { method: "POST", headers });
    await vi.waitFor(() => expect(t.localFile).toHaveBeenCalledTimes(1));
    t.flip();
    t.releaseFile();
    await stopped(await pending);
    expect(t.syncConnection).not.toHaveBeenCalled();
    expect(t.readFile).not.toHaveBeenCalled();
  });

  it("reads a file source only in response to demand from the consumer", async () => {
    const t = setup({ holdFile: true });
    const nextTurn = () =>
      new Promise<void>((resolve) => setTimeout(resolve, 0));
    const pull = vi.fn();
    const cancel = vi.fn();
    const source = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          pull();
          controller.enqueue(new Uint8Array([1]));
        },
        cancel,
      },
      { highWaterMark: 0 },
    );
    t.readFile.mockResolvedValueOnce(new Response(source));
    t.releaseFile();

    const res = await t.app.request("/file/fixture", {
      method: "POST",
      headers,
    });
    expect(res.status).toBe(200);
    const reader = res.body!.getReader();
    try {
      await nextTurn();
      expect(pull).not.toHaveBeenCalled();
      expect(await reader.read()).toEqual({
        value: new Uint8Array([1]),
        done: false,
      });
      await nextTurn();
      expect(pull).toHaveBeenCalledTimes(1);
    } finally {
      await reader.cancel();
    }
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("does not read listing status when the mode moved during local acquisition", async () => {
    const t = setup({ holdLocal: true });
    const pending = t.app.request("/status", { headers });
    try {
      await vi.waitFor(() => expect(t.localEntered).toHaveBeenCalledTimes(1));
      t.flip();
    } finally {
      t.releaseLocal();
    }
    await stopped(await pending);
    expect(t.localSync.listing.status).not.toHaveBeenCalled();
  });

  it("answers no counts when the mode moved while status was read", async () => {
    const t = setup({ holdStatus: true });
    const pending = t.app.request("/status", { headers });
    await vi.waitFor(() =>
      expect(t.localSync.listing.status).toHaveBeenCalledTimes(1),
    );
    t.flip();
    t.releaseListing();
    const res = await pending;
    await stopped(res);
  });

  it("answers no status when the mode moved before it was read", async () => {
    const t = setup();
    t.flip();
    await stopped(await t.app.request("/status", { headers }));
    expect(t.localSync.listing.status).not.toHaveBeenCalled();
  });
});
