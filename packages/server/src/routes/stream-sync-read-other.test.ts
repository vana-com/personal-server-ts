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
import { createApp } from "../app.js";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";

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

  describe("DELETE /:scope/takeover", () => {
    it("TAKEOVER_RESET_LEGACY_ON_SWITCH: a switched account resets no legacy takeover state", async () => {
      const res = await dataApp().request("/claude.conversations/takeover", {
        method: "DELETE",
        headers: bearer,
      });
      expect(touched).toEqual([]);
      expect(res.status).toBe(409);
      // A reset has its own code, apart from the read code.
      expect(await res.json()).toMatchObject({
        error: { errorCode: "STREAM_SYNC_TAKEOVER_RESET_UNAVAILABLE" },
      });
    });

    it("an unknown mode answers the retryable 503 and resets nothing", async () => {
      value = "unknown";
      const res = await dataApp().request("/claude.conversations/takeover", {
        method: "DELETE",
        headers: bearer,
      });
      expect(touched).toEqual([]);
      expect(res.status).toBe(503);
    });

    it.each(["unswitched", "none"] as const)(
      "%s: UNSWITCHED_PARITY / NO_MODE_PARITY reset still happens",
      async (kind) => {
        const resetTakeover = vi.fn();
        const app = dataRoutes({
          indexManager: index,
          hierarchyOptions: { dataDir: join(root, "data") },
          logger: pino({ level: "silent" }),
          serverOrigin: "http://localhost:8080",
          serverOwner: owner,
          devToken: "read-other-test",
          gateway,
          accessLogWriter: { write: async () => undefined },
          legacyScopeView: {
            resetTakeover,
            isReset: () => true,
            verdictFor: () => [],
          } as unknown as LegacyScopeViewPort,
          ...(kind === "none"
            ? {}
            : { accountStorageMode: { read: () => "unswitched" as const } }),
        });
        const res = await app.request("/claude.conversations/takeover", {
          method: kind === "none" ? "DELETE" : "DELETE",
          headers: bearer,
        });
        expect(res.status).toBe(200);
        expect(resetTakeover).toHaveBeenCalledWith("claude.conversations");
        const get = await app.request("/claude.conversations/takeover", {
          headers: bearer,
        });
        expect(get.status).toBe(200);
      },
    );
  });

  describe("DELETE /:scope/imports/:id", () => {
    const abort = () =>
      dataApp().request("/claude.conversations/imports/abc", {
        method: "DELETE",
        headers: bearer,
      });

    it("IMPORT_ABORT_LEGACY_ON_SWITCH: a switched account refuses the legacy import abort", async () => {
      const res = await abort();
      expect(res.status).toBe(426);
      expect(touched).toEqual([]);
    });

    it("an unknown mode answers the retryable 503", async () => {
      value = "unknown";
      const res = await abort();
      expect(res.status).toBe(503);
      expect(touched).toEqual([]);
    });
  });

  describe("DELETE of a control scope", () => {
    const control = "pdpp.acme~0123456789abcdef";
    const del = () =>
      dataApp().request(`/${control}`, { method: "DELETE", headers: bearer });

    it("CONTROL_SCOPE_BEFORE_MODE: a switched account is told to use the connector delete", async () => {
      const res = await del();
      expect(res.status).toBe(409);
      // The control-scope guard yields to the core delete, so this is not
      // the legacy control-scope code.
      expect(await res.text()).not.toContain("STREAM_SYNC_CONTROL_SCOPE");
    });

    it("an unknown mode answers the retryable 503", async () => {
      value = "unknown";
      expect((await del()).status).toBe(503);
    });

    it("an unswitched account keeps the control-scope refusal", async () => {
      value = "unswitched";
      const res = await del();
      expect(res.status).toBe(409);
      expect(await res.json()).toMatchObject({
        error: "STREAM_SYNC_CONTROL_SCOPE",
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

  describe("POST / (Oura import)", () => {
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

    it("OURA_POST_FAILS_OPEN_ON_UNKNOWN: an unknown mode answers the retryable 503 and touches nothing", async () => {
      value = "unknown";
      const res = await build().request("/", {
        method: "POST",
        headers: { ...bearer, "content-type": "application/json" },
        body: "{}",
      });
      expect(touched).toEqual([]);
      expect(res.status).toBe(503);
    });

    it("a switched account is still refused with 426", async () => {
      const res = await build().request("/", {
        method: "POST",
        headers: { ...bearer, "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status).toBe(426);
    });
  });

  describe("the mounted app", () => {
    it("DELETE_CODE_DIVERGES: a per-scope delete through createApp answers USE_CONNECTOR_DELETE", async () => {
      const app = mounted(vi.fn(async () => undefined));
      for (const q of ["", "?cascade=lineage"]) {
        const res = await app.request(`/v1/data/instagram.profile${q}`, {
          method: "DELETE",
          headers: bearer,
        });
        expect(res.status).toBe(409);
        expect(await res.json()).toMatchObject({
          error: "USE_CONNECTOR_DELETE",
        });
      }
    });

    it("NO_MODE_PARITY: with no mode wired the delete is not refused", async () => {
      const app = createApp({
        logger: pino({ level: "silent" }),
        version: "0.0.1",
        startedAt: new Date(),
        indexManager: index,
        hierarchyOptions: { dataDir: join(root, "data") },
        serverOrigin: "http://localhost:8080",
        serverOwner: owner,
        devToken: "read-other-test",
        gateway,
        accessLogWriter: { write: async () => undefined },
        config: ServerConfigSchema.parse({}),
      });
      const res = await app.request("/v1/data/instagram.profile", {
        method: "DELETE",
        headers: bearer,
      });
      expect(await res.text()).not.toContain("USE_CONNECTOR_DELETE");
    });

    function mounted(trigger: () => Promise<void>) {
      return createApp({
        logger: pino({ level: "silent" }),
        version: "0.0.1",
        startedAt: new Date(),
        indexManager: index,
        hierarchyOptions: { dataDir: join(root, "data") },
        serverOrigin: "http://localhost:8080",
        serverOwner: owner,
        devToken: "read-other-test",
        gateway,
        accessLogWriter: { write: async () => undefined },
        syncManager: { trigger, getStatus: vi.fn() } as never,
        accountStorageMode: mode(),
        config: ServerConfigSchema.parse({}),
      });
    }

    it("LEGACY_ON_SWITCH_OTHER: /v1/sync/file receives the app's mode", async () => {
      const trigger = vi.fn(async () => undefined);
      const res = await mounted(trigger).request("/v1/sync/file/abc", {
        method: "POST",
        headers: bearer,
      });
      expect(res.status).toBe(409);
      expect(trigger).not.toHaveBeenCalled();
    });

    it("UNSWITCHED_PARITY: /v1/sync/file starts the sync", async () => {
      value = "unswitched";
      const trigger = vi.fn(async () => undefined);
      const res = await mounted(trigger).request("/v1/sync/file/abc", {
        method: "POST",
        headers: bearer,
      });
      expect(res.status).toBe(202);
    });
  });
});
