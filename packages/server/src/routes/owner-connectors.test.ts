/**
 * `DELETE /v1/owner/connectors/:connectorId` on the mounted app: owner only,
 * refused on an unswitched account, answered 202 only through the writer's
 * durable intent, and decided by the account storage mode port (unknown: 503).
 * The per-scope delete refusal is not here; the storage-mode change owns it.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pino } from "pino";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type {
  ConnectionDeletePort,
  StorageModeRead,
} from "@opendatalabs/personal-server-ts-core/api";
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
    mode?: StorageModeRead;
    /** No mode is handed to the app; the config is write-only, as Desktop sets it. */
    unwired?: boolean;
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
          write: opts.switched || opts.unwired === true,
          refuseLegacyWrites: opts.switched,
        },
      }),
      streamSyncConnectionDelete:
        opts.connectionDelete === undefined ? writer : opts.connectionDelete,
      accountStorageMode: opts.unwired
        ? undefined
        : (opts.mode ?? {
            read: () => (opts.switched ? "switched" : "unswitched"),
          }),
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

  it("answers 503, not 409, when no mode is wired, even on a write-only config (mutant: UNWIRED_MODE_FROM_CONFIG)", async () => {
    const response = await del(
      makeApp({ switched: false, unwired: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error).toBe("ACCOUNT_MODE_UNKNOWN");
    expect(calls).toEqual([]);
  });

  it("takes the mode from the port, not from the config (mutant: CONNECTOR_ROUTE_READS_CONFIG)", async () => {
    // The config says unswitched; the port says switched.
    const response = await del(
      makeApp({ switched: false, mode: { read: () => "switched" } }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(202);
    expect(calls).toEqual(["github"]);
  });

  it("answers 503 and deletes nothing while the mode is unknown (mutant: UNKNOWN_MODE_NOT_SWITCHED)", async () => {
    const response = await del(
      makeApp({ switched: true, mode: { read: () => "unknown" } }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error).toBe("ACCOUNT_MODE_UNKNOWN");
    expect(calls).toEqual([]);
  });

  it("asks the unknown mode only of the owner (mutant: MODE_BEFORE_AUTH)", async () => {
    const response = await del(
      makeApp({ switched: true, mode: { read: () => "unknown" } }),
      "/v1/owner/connectors/github",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThan(404);
  });
});
