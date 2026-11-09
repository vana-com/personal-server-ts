/**
 * Group D read entry points on the Node server: the owner takeover read, the
 * sync-file route and the Oura requirements route. Each must consume the one
 * account storage mode: a switched account touches no legacy store.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pino } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { LegacyScopeViewPort } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { AccountStorageModeValue } from "@opendatalabs/personal-server-ts-core/api";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { dataRoutes } from "./data.js";
import { syncRoutes } from "./sync.js";
import { ouraRoutes } from "./oura.js";

const owner = "0x1111111111111111111111111111111111111111";
const bearer = { Authorization: "Bearer read-other-test" };

function throwing<T extends object>(label: string, touched: string[]): T {
  return new Proxy({} as T, {
    get(_t, name) {
      if (typeof name === "symbol" || name === "then") return undefined;
      return () => {
        touched.push(`${label}.${String(name)}`);
        throw new Error(`legacy ${label}.${String(name)} touched`);
      };
    },
  });
}

const gateway = {} as GatewayClient;

describe("Node server group D routes", () => {
  let root: string;
  let index: ReturnType<typeof createIndexManager>;
  let value: AccountStorageModeValue;
  let touched: string[];

  beforeEach(async () => {
    value = "switched";
    touched = [];
    root = await mkdtemp(join(tmpdir(), "read-other-"));
    index = createIndexManager(initializeDatabase(join(root, "index.db")));
  });
  afterEach(async () => {
    index.close();
    await rm(root, { recursive: true, force: true });
  });

  const mode = () => ({ read: () => value });

  function dataApp() {
    return dataRoutes({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
      logger: pino({ level: "silent" }),
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      devToken: "read-other-test",
      gateway,
      accessLogWriter: { write: async () => undefined },
      legacyScopeView: throwing<LegacyScopeViewPort>("view", touched),
      accountStorageMode: mode(),
    });
  }

  describe("GET /:scope/takeover", () => {
    it("LEGACY_ON_SWITCH_OTHER: a switched account reads no takeover state", async () => {
      const res = await dataApp().request("/claude.conversations/takeover", {
        headers: bearer,
      });
      expect(touched).toEqual([]);
      expect(res.status).toBe(409);
      expect(await res.json()).toMatchObject({
        error: { errorCode: "STREAM_SYNC_LEGACY_READ_UNAVAILABLE" },
      });
    });

    it("an unknown mode answers the retryable 503 and reads nothing", async () => {
      value = "unknown";
      const res = await dataApp().request("/claude.conversations/takeover", {
        headers: bearer,
      });
      expect(touched).toEqual([]);
      expect(res.status).toBe(503);
    });

    it("UNSWITCHED_PARITY: an unswitched account still reads reset and verdicts", async () => {
      value = "unswitched";
      const view = {
        isReset: vi.fn(() => true),
        verdictFor: vi.fn(() => []),
      } as unknown as LegacyScopeViewPort;
      const app = dataRoutes({
        indexManager: index,
        hierarchyOptions: { dataDir: join(root, "data") },
        logger: pino({ level: "silent" }),
        serverOrigin: "http://localhost:8080",
        serverOwner: owner,
        devToken: "read-other-test",
        gateway,
        accessLogWriter: { write: async () => undefined },
        legacyScopeView: view,
        accountStorageMode: mode(),
      });
      const res = await app.request("/claude.conversations/takeover", {
        headers: bearer,
      });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        scope: "claude.conversations",
        reset: true,
        verdicts: [],
      });
    });
  });

  describe("POST /v1/sync/file/:id (mount wiring)", () => {
    const build = (trigger: () => Promise<void>) =>
      syncRoutes({
        logger: pino({ level: "silent" }),
        serverOrigin: "http://localhost:8080",
        serverOwner: owner,
        gateway,
        devToken: "read-other-test",
        syncManager: { trigger, getStatus: vi.fn() } as never,
        accountStorageMode: mode(),
      });

    it("LEGACY_ON_SWITCH_OTHER: the route hands the mode down, so a switched account is refused", async () => {
      const trigger = vi.fn(async () => undefined);
      const res = await build(trigger).request("/file/abc", {
        method: "POST",
        headers: bearer,
      });
      expect(res.status).toBe(409);
      expect(trigger).not.toHaveBeenCalled();
    });

    it("UNSWITCHED_PARITY: an unswitched account starts the sync", async () => {
      value = "unswitched";
      const trigger = vi.fn(async () => undefined);
      const res = await build(trigger).request("/file/abc", {
        method: "POST",
        headers: bearer,
      });
      expect(res.status).toBe(202);
      expect(trigger).toHaveBeenCalledTimes(1);
    });
  });

  describe("GET /requirements (Oura)", () => {
    const build = () =>
      ouraRoutes({
        dataStorage: throwing<DataStoragePort>("storage", touched),
        legacyScopeView: throwing<LegacyScopeViewPort>("view", touched),
        serverOrigin: "http://localhost:8080",
        serverOwner: owner,
        gateway,
        devToken: "read-other-test",
        accountStorageMode: mode(),
      } as never);

    it("LEGACY_ON_SWITCH_OTHER: the route hands the mode down, so a switched account reads no legacy history", async () => {
      const res = await build().request("/requirements", { headers: bearer });
      expect(touched).toEqual([]);
      expect(res.status).toBe(409);
    });
  });
});
