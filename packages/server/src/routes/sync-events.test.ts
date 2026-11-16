// The owner's change feed: GET /v1/sync/events.
//
// A real database, device and registry (as in `view-changes.test.ts`). Device
// B is the server under test: it opens its database through the shared
// `openLocalDb` path with a recorder, and a client reads the feed. The only
// waits are reads of the response stream: no sleeps and no timers.
import { afterEach, describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { pino } from "pino";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  connectionQueue,
  createLocalSync,
  createViewChanges,
  openLocalDb,
  type LocalSync,
  type SqlDriver,
  type ViewChangeRecorder,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import { openBetterSqlite3 } from "../localdb/better-sqlite3-driver.js";
import { syncRoutes } from "./sync.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const headers = { authorization: "Bearer t" };
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function device(
  registry: MemoryStreamSyncRegistry,
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>,
  id: string,
  views?: ViewChangeRecorder,
): Promise<LocalSync & { db: SqlDriver }> {
  const db = await openLocalDb(
    openBetterSqlite3(":memory:"),
    { owner: OWNER, network: "test", deviceId: id },
    views
      ? { viewChanges: { recorder: views, logger: { warn: () => {} } } }
      : {},
  );
  drivers.push(db);
  let op = 0;
  const sync = createLocalSync(
    {
      db,
      queue: connectionQueue(),
      registry,
      blobs,
      ownerAddress: OWNER,
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: async (_s, b) => b,
        encryptPart: async (_s, b) => b,
        decrypt: async (_s, b) => b,
      },
      signer: { signAddData: async () => "0x00" },
      logger: { info: () => {}, warn: () => {} },
      now: () => 1000,
      newOp: () => `${id}-op-${++op}`,
    },
    {
      resolveArtifact: (digest) => ({
        connector: digest,
        version: "1",
        streams: [
          {
            name: "s0",
            semantics: "mutable_state" as const,
            primaryKey: ["id"],
          },
        ],
      }),
      declaredStreams: () => ["s0"],
      olderVersionReads: () => true,
    },
  );
  return Object.assign(sync, { db });
}

let runs = 0;
async function collect(sync: LocalSync, connector: string, version: number) {
  const runId = `run-${++runs}`;
  await sync.intake.begin(runId, {
    connector,
    artifactDigest: connector,
    wantFull: true,
    owner: { address: OWNER, leaseId: null },
  });
  await sync.intake.batch(runId, {
    batch: 0,
    records: [{ stream: "s0", data: { id: "s0-0", version } }],
  });
  await sync.intake.end(runId, {
    outcome: "succeeded",
    coveredStreams: ["s0"],
    lastBatch: 0,
  });
}

/** The frames of an event stream, read one at a time. */
function frames(response: Response) {
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  return {
    async next(): Promise<{ event: string; data: unknown }> {
      for (;;) {
        const end = buffer.indexOf("\n\n");
        if (end >= 0) {
          const frame = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          const event = /^event: (.*)$/m.exec(frame)?.[1];
          const data = /^data: (.*)$/m.exec(frame)?.[1];
          if (event === undefined || data === undefined) continue; // a comment
          return { event, data: JSON.parse(data) };
        }
        const { done, value } = await reader.read();
        if (done) throw new Error("the event stream ended");
        buffer += decoder.decode(value, { stream: true });
      }
    },
    close: () => reader.cancel(),
  };
}

const auth = {
  logger: pino({ level: "silent" }),
  serverOrigin: "http://localhost",
  serverOwner: OWNER,
  accessToken: "t",
  gateway: {} as never,
};

describe("GET /v1/sync/events", () => {
  it("delivers an applied change to a connected client with no timer", async () => {
    const registry =
      createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
    const blobs = createMemoryStreamSyncBlobs();
    const a = await device(registry, blobs, "a");
    const views = createViewChanges();
    const b = await device(registry, blobs, "b", views);
    await collect(a, "c0", 1);
    await a.cycle();
    await b.cycle();

    // A timer the route started would be held back here; the change still has
    // to arrive, so the route cannot depend on one.
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval"] });
    try {
      const app = syncRoutes({
        ...auth,
        syncManager: null,
        localSync: b,
        viewChanges: views,
      });
      const response = await app.request("/events", { headers });
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain(
        "text/event-stream",
      );
      const feed = frames(response);
      expect(await feed.next()).toEqual({ event: "ready", data: {} });

      await collect(a, "c0", 2);
      await a.cycle();
      await b.cycle();
      const change = await feed.next();
      expect(change.event).toBe("view");
      expect(
        (change.data as { connectionIds: string[] }).connectionIds,
      ).toHaveLength(1);
      await feed.close();
    } finally {
      vi.useRealTimers();
    }
  });

  it("refuses a caller that is not the owner", async () => {
    // The app's own handler maps a refused caller to its status.
    const app = new Hono();
    app.onError((err, c) =>
      err instanceof ProtocolError
        ? c.json(err.toJSON(), err.code as 401 | 403)
        : c.json({}, 500),
    );
    app.route(
      "/",
      syncRoutes({
        ...auth,
        syncManager: null,
        viewChanges: createViewChanges(),
      }),
    );
    const response = await app.request("/events", {
      headers: { authorization: "Bearer other" },
    });
    expect([401, 403]).toContain(response.status);
    expect(response.headers.get("content-type") ?? "").not.toContain(
      "text/event-stream",
    );
  });

  it("delivers sync status changes from the manager and stops listening when the client leaves", async () => {
    const listeners = new Set<(status: unknown) => void>();
    const subscribeStatus = vi.fn((listener: (status: unknown) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    });
    const app = syncRoutes({
      ...auth,
      syncManager: {
        subscribeStatus,
        getStatus: () => ({ syncing: false, lastSync: null }),
      } as unknown as SyncManager,
      viewChanges: createViewChanges(),
    });
    const response = await app.request("/events", { headers });
    const feed = frames(response);
    expect((await feed.next()).event).toBe("ready");
    expect((await feed.next()).event).toBe("status"); // the opening status
    expect(listeners.size).toBe(1);
    for (const listener of listeners)
      listener({ syncing: true, lastSync: null });
    expect(await feed.next()).toEqual({
      event: "status",
      data: { syncing: true, lastSync: null },
    });
    await feed.close();
    await vi.waitFor(() => expect(listeners.size).toBe(0));
  });

  it("opens with the manager's current status, so a client that reconnects learns what it missed", async () => {
    const current = { syncing: true, pendingFiles: 2, lastSync: null };
    const app = syncRoutes({
      ...auth,
      syncManager: {
        subscribeStatus: () => () => {},
        getStatus: () => current,
      } as unknown as SyncManager,
      viewChanges: createViewChanges(),
    });
    const feed = frames(await app.request("/events", { headers }));
    expect((await feed.next()).event).toBe("ready");
    expect(await feed.next()).toEqual({ event: "status", data: current });
    await feed.close();
  });
});
