/**
 * `DELETE /v1/owner/connectors/:connectorId` on the mounted app: owner only,
 * refused on an unswitched account, answered 202 only through the writer's
 * durable intent, and refused per scope once the account has switched.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pino } from "pino";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type { ConnectionDeletePort } from "@opendatalabs/personal-server-ts-core/api";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { createApp } from "../app.js";
import { initializeDatabase } from "../storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "../storage/index-manager.js";

const owner = "0x1111111111111111111111111111111111111111";
const token = "owner-connectors-app-token";

describe("DELETE /v1/owner/connectors/:connectorId", () => {
  let dir: string;
  let index: IndexManager;
  let calls: string[];

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "owner-connectors-"));
    index = createIndexManager(initializeDatabase(":memory:"));
    calls = [];
  });
  afterEach(async () => {
    index.close();
    await rm(dir, { recursive: true, force: true });
  });

  const writer: ConnectionDeletePort = {
    async requestConnectionDelete(connector) {
      calls.push(connector);
      return { deleteId: `delete-${connector}` };
    },
  };

  function makeApp(opts: {
    switched: boolean;
    connectionDelete?: ConnectionDeletePort | null;
  }) {
    return createApp({
      logger: pino({ level: "silent" }),
      version: "0.0.1",
      startedAt: new Date(),
      indexManager: index,
      hierarchyOptions: { dataDir: join(dir, "data") },
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      devToken: token,
      config: ServerConfigSchema.parse({
        streamSync: {
          write: opts.switched,
          refuseLegacyWrites: opts.switched,
        },
      }),
      streamSyncConnectionDelete:
        opts.connectionDelete === undefined ? writer : opts.connectionDelete,
    });
  }

  const del = (
    app: ReturnType<typeof makeApp>,
    path: string,
    headers: Record<string, string> = { Authorization: `Bearer ${token}` },
  ) => app.request(path, { method: "DELETE", headers });

  it("refuses anyone but the owner (mutant: NOT_OWNER_ALLOWED)", async () => {
    const response = await del(
      makeApp({ switched: true }),
      "/v1/owner/connectors/github",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThan(404);
    expect(calls).toEqual([]);
  });

  it("refuses an unswitched account and deletes nothing (mutant: UNSWITCHED_DELETES_STREAMS)", async () => {
    const response = await del(
      makeApp({ switched: false }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(409);
    expect((await response.json()).error).toBe("NOT_SWITCHED");
    expect(calls).toEqual([]);
  });

  it("answers 202 with the delete id of a switched account", async () => {
    const response = await del(
      makeApp({ switched: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ deleteId: "delete-github" });
    expect(calls).toEqual(["github"]);
  });

  it("answers 503 when no stream-sync writer is wired (mutant: LITE_UNWIRED)", async () => {
    const response = await del(
      makeApp({ switched: true, connectionDelete: null }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error).toBe("STREAM_SYNC_UNAVAILABLE");
  });

  it("refuses a name that is not a connector key", async () => {
    const response = await del(
      makeApp({ switched: true }),
      "/v1/owner/connectors/a~b",
    );
    expect(response.status).toBe(400);
    expect(calls).toEqual([]);
  });

  describe("per-scope delete", () => {
    it("is refused on a switched account, naming the connector route (mutant: PER_SCOPE_DELETE_ON_SWITCHED)", async () => {
      const response = await del(
        makeApp({ switched: true }),
        "/v1/data/github.events",
      );
      expect(response.status).toBe(409);
      const body = await response.json();
      expect(body.error).toBe("USE_CONNECTOR_DELETE");
      expect(body.message).toContain("/v1/owner/connectors/:connectorId");
    });

    it("says nothing of the switch to anyone but the owner (mutant: SCOPE_409_BEFORE_AUTH)", async () => {
      const response = await del(
        makeApp({ switched: true }),
        "/v1/data/github.events",
        {},
      );
      expect(response.status).toBeGreaterThanOrEqual(401);
      expect(response.status).toBeLessThan(404);
    });

    it("is not refused by the switch on an unswitched account", async () => {
      const response = await del(
        makeApp({ switched: false }),
        "/v1/data/github.events",
      );
      expect((await response.json().catch(() => ({}))).error).not.toBe(
        "USE_CONNECTOR_DELETE",
      );
    });
  });
});
