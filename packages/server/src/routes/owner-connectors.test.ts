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
import { ConnectorNotVerifiedError } from "@opendatalabs/personal-server-ts-core/localdb";
import type {
  ConnectionDeletePort,
  StorageModeRead,
} from "@opendatalabs/personal-server-ts-core/api";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { createApp } from "../app.js";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { initializeDatabase } from "../storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "../storage/index-manager.js";

const owner = "0x1111111111111111111111111111111111111111";
const token = "owner-connectors-app-token";

async function modeAuthorityAnswering(
  owner: string,
  answer: "switched" | "unswitched" | "unknown",
) {
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
    onWarning: () => undefined,
  });
  await authority.ready;
  if (answer !== "unknown") {
    await authority.submitEvidence({
      owner,
      state: answer === "switched" ? "on" : "off",
    });
  }
  return authority;
}

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

  async function makeApp(opts: {
    switched: boolean;
    connectionDelete?: ConnectionDeletePort | null;
    mode?: StorageModeRead;
    /** No mode is handed to the app; the config is write-only, as Desktop sets it. */
    unwired?: boolean;
    /** The stream-sync services are shutting down. */
    closing?: boolean;
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
        },
      }),
      streamSyncAdmitting: () => opts.closing !== true,
      streamSyncConnectionDelete:
        opts.connectionDelete === undefined ? writer : opts.connectionDelete,
      accountModeAuthority: opts.unwired
        ? undefined
        : await modeAuthorityAnswering(
            owner,
            opts.mode
              ? (opts.mode.read() as "switched" | "unswitched" | "unknown")
              : opts.switched
                ? "switched"
                : "unswitched",
          ),
    });
  }

  const del = (
    app: Awaited<ReturnType<typeof makeApp>>,
    path: string,
    headers: Record<string, string> = { Authorization: `Bearer ${token}` },
  ) => app.request(path, { method: "DELETE", headers });

  it("refuses anyone but the owner (mutant: NOT_OWNER_ALLOWED)", async () => {
    const response = await del(
      await makeApp({ switched: true }),
      "/v1/owner/connectors/github",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThan(404);
    expect(calls).toEqual([]);
  });

  it("refuses an unswitched account and deletes nothing (mutant: UNSWITCHED_DELETES_STREAMS)", async () => {
    const response = await del(
      await makeApp({ switched: false }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(409);
    expect((await response.json()).error.errorCode).toBe("NOT_SWITCHED");
    expect(calls).toEqual([]);
  });

  it("answers 202 with the delete id of a switched account", async () => {
    const response = await del(
      await makeApp({ switched: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ deleteId: "delete-github" });
    expect(calls).toEqual(["github"]);
  });

  it("answers 503 when no stream-sync writer is wired (mutant: LITE_UNWIRED)", async () => {
    const response = await del(
      await makeApp({ switched: true, connectionDelete: null }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "STREAM_SYNC_UNAVAILABLE",
    );
  });

  it("refuses a name that is not a connector key", async () => {
    const response = await del(
      await makeApp({ switched: true }),
      "/v1/owner/connectors/a~b",
    );
    expect(response.status).toBe(400);
    expect(calls).toEqual([]);
  });

  it("answers 503, not 409, when no mode is wired, even on a write-only config (mutant: UNWIRED_MODE_FROM_CONFIG)", async () => {
    const response = await del(
      await makeApp({ switched: false, unwired: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(calls).toEqual([]);
  });

  it("takes the mode from the port, not from the config (mutant: CONNECTOR_ROUTE_READS_CONFIG)", async () => {
    // The config says unswitched; the port says switched.
    const response = await del(
      await makeApp({ switched: false, mode: { read: () => "switched" } }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(202);
    expect(calls).toEqual(["github"]);
  });

  it("answers 503 and deletes nothing while the mode is unknown (mutant: UNKNOWN_MODE_NOT_SWITCHED)", async () => {
    const response = await del(
      await makeApp({ switched: true, mode: { read: () => "unknown" } }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(calls).toEqual([]);
  });

  it("asks the unknown mode only of the owner (mutant: MODE_BEFORE_AUTH)", async () => {
    const response = await del(
      await makeApp({ switched: true, mode: { read: () => "unknown" } }),
      "/v1/owner/connectors/github",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThan(404);
  });

  it("tells a caller who is not the owner nothing about shutdown (mutant: CLOSING_BEFORE_AUTH)", async () => {
    const response = await del(
      await makeApp({ switched: true, closing: true }),
      "/v1/owner/connectors/github",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThan(404);
    expect(calls).toEqual([]);
  });

  it("answers the owner 503 while stream sync shuts down", async () => {
    const response = await del(
      await makeApp({ switched: true, closing: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe("STREAM_SYNC_CLOSING");
    expect(calls).toEqual([]);
  });

  it("refuses a malformed percent-escape as a bad id, not a connector (mutant: RAW_ID_ON_BAD_ESCAPE)", async () => {
    const response = await del(
      await makeApp({ switched: true }),
      "/v1/owner/connectors/%E0%A4%A",
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error.errorCode).toBe("INVALID_CONNECTOR");
    expect(calls).toEqual([]);
  });

  it("asks a bad escape of the owner only", async () => {
    const response = await del(
      await makeApp({ switched: true }),
      "/v1/owner/connectors/%E0%A4%A",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThan(404);
  });

  it("gives every refusal the API's one error envelope (mutant: TOP_LEVEL_ERROR_BODY)", async () => {
    const cases: Array<[number, string, Response]> = [
      [
        400,
        "INVALID_CONNECTOR",
        await del(
          await makeApp({ switched: true }),
          "/v1/owner/connectors/a~b",
        ),
      ],
      [
        409,
        "NOT_SWITCHED",
        await del(
          await makeApp({ switched: false }),
          "/v1/owner/connectors/github",
        ),
      ],
      [
        503,
        "ACCOUNT_MODE_UNKNOWN",
        await del(
          await makeApp({ switched: true, mode: { read: () => "unknown" } }),
          "/v1/owner/connectors/github",
        ),
      ],
    ];
    for (const [status, errorCode, response] of cases) {
      expect(response.status).toBe(status);
      expect(await response.json()).toEqual({
        error: { code: status, errorCode, message: expect.any(String) },
      });
    }
  });

  it("answers 503 CONNECTOR_NOT_VERIFIED when the writer cannot name the streams", async () => {
    const response = await del(
      await makeApp({
        switched: true,
        connectionDelete: {
          requestConnectionDelete: async (connector) => {
            throw new ConnectorNotVerifiedError(connector);
          },
        },
      }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "CONNECTOR_NOT_VERIFIED",
    );
  });

  it("answers another method with 405 to the owner only (mutant: METHOD_BEFORE_AUTH)", async () => {
    const app = await makeApp({ switched: true });
    const stranger = await app.request("/v1/owner/connectors/github", {
      method: "GET",
    });
    expect(stranger.status).toBeGreaterThanOrEqual(401);
    expect(stranger.status).toBeLessThan(404);
    const owner = await app.request("/v1/owner/connectors/github", {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(owner.status).toBe(405);
    expect((await owner.json()).error.errorCode).toBe("METHOD_NOT_ALLOWED");
    expect(calls).toEqual([]);
  });
});
