/**
 * `DELETE /v1/owner/connectors/:connectorId` on PS-Lite answers through the
 * same handler as the Node server. These tests pin the Lite side: the owner
 * check, the switch, the writer wiring, and the unknown mode.
 */

import { describe, expect, it } from "vitest";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

const ownerAuth = { Authorization: "Bearer owner-token" };

function runtimeWith(opts: {
  switched: boolean;
  mode?: "switched" | "unswitched" | "unknown";
  /** No mode is handed to the runtime. */
  unwired?: boolean;
  connectionDelete?: {
    requestConnectionDelete: (c: string) => Promise<{ deleteId: string }>;
  } | null;
}) {
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  return createPsLiteRuntime({
    storage: createMemoryPsLiteStorage(),
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
    ...(opts.unwired
      ? {}
      : {
          accountStorageMode: {
            read: () =>
              opts.mode ?? (opts.switched ? "switched" : "unswitched"),
          },
        }),
    streamSyncConnectionDelete:
      opts.connectionDelete === undefined
        ? {
            requestConnectionDelete: async (c) => ({ deleteId: `delete-${c}` }),
          }
        : opts.connectionDelete,
  });
}

const del = (
  runtime: ReturnType<typeof runtimeWith>,
  path: string,
  headers: Record<string, string> = ownerAuth,
) =>
  runtime.fetch(
    new Request(`http://localhost${path}`, { method: "DELETE", headers }),
  );

describe("PS-Lite DELETE /v1/owner/connectors/:connectorId", () => {
  it("refuses anyone but the owner", async () => {
    const response = await del(
      runtimeWith({ switched: true }),
      "/v1/owner/connectors/github",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThanOrEqual(403);
  });

  it("refuses an unswitched account", async () => {
    const response = await del(
      runtimeWith({ switched: false }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(409);
    expect((await response.json()).error).toBe("NOT_SWITCHED");
  });

  it("answers 202 with the delete id on a switched account", async () => {
    const response = await del(
      runtimeWith({ switched: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ deleteId: "delete-github" });
  });

  it("answers 503 when no stream-sync writer is wired (LITE_UNWIRED)", async () => {
    const response = await del(
      runtimeWith({ switched: true, connectionDelete: null }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error).toBe("STREAM_SYNC_UNAVAILABLE");
  });

  it("answers 503, not 409, when no mode is wired (mutant: UNWIRED_MODE_FROM_CONFIG)", async () => {
    const response = await del(
      runtimeWith({ switched: false, unwired: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error).toBe("ACCOUNT_MODE_UNKNOWN");
  });

  it("answers 503 while the mode is unknown (mutant: UNKNOWN_MODE_NOT_SWITCHED)", async () => {
    const response = await del(
      runtimeWith({ switched: true, mode: "unknown" }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error).toBe("ACCOUNT_MODE_UNKNOWN");
  });

  it("answers 400, not 500, for a malformed percent-escape in the id (mutant: DECODE_THROWS_500)", async () => {
    const response = await del(
      runtimeWith({ switched: true }),
      "/v1/owner/connectors/%E0%A4%A",
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error.errorCode).toBe("INVALID_CONNECTOR");
  });
});
