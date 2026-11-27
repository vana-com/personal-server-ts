import { describe, it, expect, vi } from "vitest";
import { pino } from "pino";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type { SyncStatus } from "@opendatalabs/personal-server-ts-core/sync";
import type { OwnedAccountStorageMode } from "@opendatalabs/personal-server-ts-core/api";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import { syncRoutes } from "./sync.js";

const logger = pino({ level: "silent" });
const SERVER_ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);

function createMockSyncManager(overrides?: Partial<SyncManager>): SyncManager {
  const status: SyncStatus = {
    enabled: true,
    running: true,
    syncing: false,
    lastSync: "2026-01-21T10:00:00.000Z",
    lastProcessedTimestamp: "2026-01-21T09:00:00.000Z",
    pendingFiles: 3,
    errors: [],
  };

  return {
    start: vi.fn(),
    stop: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
    trigger: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
    requestPull: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
    getStatus: vi.fn<() => SyncStatus>().mockReturnValue(status),
    notifyNewData: vi.fn(),
    running: true,
    ...overrides,
  };
}

describe("syncRoutes", () => {
  describe("with syncManager (sync enabled)", () => {
    const mockSyncManager = createMockSyncManager();
    const app = syncRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: owner.address,
      syncManager: mockSyncManager,
    });

    describe("POST /trigger", () => {
      it("returns 202 and triggers sync", async () => {
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/trigger",
        });
        const res = await app.request("/trigger", {
          method: "POST",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(202);
        const json = await res.json();
        expect(json).toEqual({
          status: "started",
          message: "Sync triggered",
        });
        expect(mockSyncManager.trigger).toHaveBeenCalled();
      });

      it("?when=changed asks for a pull, which the manager gates on a registry probe", async () => {
        const manager = createMockSyncManager();
        const pulling = syncRoutes({
          logger,
          serverOrigin: SERVER_ORIGIN,
          serverOwner: owner.address,
          syncManager: manager,
        });
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/trigger",
        });
        const res = await pulling.request("/trigger?when=changed", {
          method: "POST",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(202);
        expect(manager.requestPull).toHaveBeenCalledTimes(1);
        expect(manager.trigger).not.toHaveBeenCalled();
      });

      it("any other `when` is a plain trigger", async () => {
        const manager = createMockSyncManager();
        const pulling = syncRoutes({
          logger,
          serverOrigin: SERVER_ORIGIN,
          serverOwner: owner.address,
          syncManager: manager,
        });
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/trigger",
        });
        await pulling.request("/trigger?when=now", {
          method: "POST",
          headers: { authorization: auth },
        });
        expect(manager.trigger).toHaveBeenCalledTimes(1);
        expect(manager.requestPull).not.toHaveBeenCalled();
      });

      it("returns immediately while sync continues in the background", async () => {
        const trigger = vi.fn<() => Promise<void>>(
          () => new Promise(() => undefined),
        );
        const app = syncRoutes({
          logger,
          serverOrigin: SERVER_ORIGIN,
          serverOwner: owner.address,
          syncManager: createMockSyncManager({ trigger }),
        });
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/trigger",
        });

        const res = await app.request("/trigger", {
          method: "POST",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(202);
        expect(trigger).toHaveBeenCalledTimes(1);
      });
    });

    describe("GET /status", () => {
      it("returns SyncStatus from syncManager", async () => {
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "GET",
          uri: "/status",
        });
        const res = await app.request("/status", {
          method: "GET",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json).toEqual({
          enabled: true,
          running: true,
          syncing: false,
          lastSync: "2026-01-21T10:00:00.000Z",
          lastProcessedTimestamp: "2026-01-21T09:00:00.000Z",
          pendingFiles: 3,
          errors: [],
        });
        expect(mockSyncManager.getStatus).toHaveBeenCalled();
      });
    });

    describe("POST /file/:fileId", () => {
      it("returns 202 and triggers full sync", async () => {
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/file/0x123",
        });
        const res = await app.request("/file/0x123", {
          method: "POST",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(202);
        const json = await res.json();
        expect(json).toEqual({ fileId: "0x123", status: "started" });
        expect(mockSyncManager.trigger).toHaveBeenCalled();
      });
    });
  });

  describe("without syncManager (sync disabled)", () => {
    const app = syncRoutes({
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: owner.address,
      syncManager: null,
    });

    describe("POST /trigger", () => {
      it("returns 200 with disabled status", async () => {
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/trigger",
        });
        const res = await app.request("/trigger", {
          method: "POST",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json).toEqual({
          status: "disabled",
          message: "Sync is not enabled",
        });
      });
    });

    describe("GET /status", () => {
      it("returns disabled sync status", async () => {
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "GET",
          uri: "/status",
        });
        const res = await app.request("/status", {
          method: "GET",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json).toEqual({
          enabled: false,
          running: false,
          syncing: false,
          lastSync: null,
          lastProcessedTimestamp: null,
          pendingFiles: 0,
          hydratedScopes: [],
          errors: [],
        });
      });
    });

    describe("POST /file/:fileId", () => {
      it("returns 200 with disabled status", async () => {
        const auth = await buildWeb3SignedHeader({
          wallet: owner,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: "/file/0x123",
        });
        const res = await app.request("/file/0x123", {
          method: "POST",
          headers: { authorization: auth },
        });

        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json).toEqual({
          fileId: "0x123",
          status: "disabled",
          message: "Sync is not enabled",
        });
      });
    });
  });

  describe("POST /file/:id stream mode guard", () => {
    // A switched-mode app whose file body is a gated stream: chunk 1 flows
    // at once, later chunks only after the test releases their gate, so a
    // mode change between reads is deterministic.
    function createStreamApp() {
      const modeBox = { current: "switched" };
      const accountStorageMode = {
        read: () => modeBox.current,
      } as unknown as OwnedAccountStorageMode;
      const encoder = new TextEncoder();
      const chunks = ["first-", "second-", "third-"].map((s) =>
        encoder.encode(s),
      );
      let next = 0;
      let cancelled = false;
      const releases: Array<() => void> = [];
      const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
          const n = next++;
          if (n < chunks.length) {
            // Later chunks wait for the test to release their gate, so a
            // mode change between reads is deterministic. The terminal
            // pull closes without a gate.
            if (n > 0)
              await new Promise<void>((resolve) => {
                releases[n] = resolve;
              });
            controller.enqueue(chunks[n]);
          } else controller.close();
        },
        cancel() {
          cancelled = true;
        },
      });
      const read = vi.fn(async () => new Response(body));
      const syncConnection = vi.fn(async () => undefined);
      const app = syncRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: owner.address,
        gateway: undefined as never,
        syncManager: createMockSyncManager(),
        localSync: { syncConnection } as unknown as LocalSync,
        accountStorageMode,
        localFile: async () => ({ connectionId: "conn-1", read }),
      });
      const release = async (n: number) => {
        for (let i = 0; i < 100 && !releases[n]; i++)
          await new Promise((r) => setTimeout(r, 10));
        releases[n]?.();
      };
      return {
        app,
        modeBox,
        read,
        syncConnection,
        release,
        isCancelled: () => cancelled,
      };
    }

    async function postFile(app: ReturnType<typeof createStreamApp>["app"]) {
      const auth = await buildWeb3SignedHeader({
        wallet: owner,
        aud: SERVER_ORIGIN,
        method: "POST",
        uri: "/file/file-1",
      });
      return app.request("/file/file-1", {
        method: "POST",
        headers: { authorization: auth },
      });
    }

    it("stops the body when the account leaves switched mode mid-stream", async () => {
      const { app, modeBox, release, isCancelled } = createStreamApp();
      const res = await postFile(app);
      expect(res.status).toBe(200);
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      const first = await reader.read();
      expect(decoder.decode(first.value)).toBe("first-");
      modeBox.current = "unswitched";
      await release(1);
      await expect(reader.read()).rejects.toThrow(/not switched/i);
      expect(isCancelled()).toBe(true);
    });

    it("streams the whole body when the mode stays switched", async () => {
      const { app, release } = createStreamApp();
      const res = await postFile(app);
      expect(res.status).toBe(200);
      // Release the gated chunks as the reader asks for them.
      void release(1);
      void release(2);
      expect(await res.text()).toBe("first-second-third-");
    });

    it("does not read the file when the mode is lost before the read", async () => {
      const { app, modeBox, read, syncConnection } = createStreamApp();
      syncConnection.mockImplementation(async () => {
        modeBox.current = "unswitched";
        return undefined;
      });
      const res = await postFile(app);
      expect(res.status).not.toBe(200);
      expect(read).not.toHaveBeenCalled();
    });

    it("passes a body-less response through unchanged", async () => {
      const modeBox = { current: "switched" };
      const app = syncRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: owner.address,
        gateway: undefined as never,
        syncManager: createMockSyncManager(),
        localSync: {
          syncConnection: vi.fn(async () => undefined),
        } as unknown as LocalSync,
        accountStorageMode: {
          read: () => modeBox.current,
        } as unknown as OwnedAccountStorageMode,
        localFile: async () => ({
          connectionId: "conn-1",
          read: async () => new Response(null, { status: 200 }),
        }),
      });
      const res = await postFile(app);
      expect(res.status).toBe(200);
      expect(res.body).toBeNull();
    });
  });
});
