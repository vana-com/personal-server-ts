/**
 * `DELETE /v1/owner/connectors/:connectorId` on PS-Lite answers through the
 * same handler as the Node server. These tests pin the Lite side: the owner
 * check, the switch, the writer wiring, and the unknown mode.
 */

import { describe, expect, it } from "vitest";
import { ConnectorNotVerifiedError } from "@opendatalabs/personal-server-ts-core/localdb";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

const ownerAuth = { Authorization: "Bearer owner-token" };

async function runtimeWith(opts: {
  switched: boolean;
  mode?: "switched" | "unswitched" | "unknown";
  /** No mode is handed to the runtime. */
  unwired?: boolean;
  connectionDelete?: {
    requestConnectionDelete: (
      c: string,
    ) => Promise<{ deleteId: string; fenced: boolean }>;
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
          accountModeAuthority: await modeAuthorityAnswering(
            "",
            opts.mode ?? (opts.switched ? "switched" : "unswitched"),
          ),
        }),
    streamSyncConnectionDelete:
      opts.connectionDelete === undefined
        ? {
            requestConnectionDelete: async (c) => ({
              deleteId: `delete-${c}`,
              fenced: true,
            }),
          }
        : opts.connectionDelete,
  });
}

const del = (
  runtime: Awaited<ReturnType<typeof runtimeWith>>,
  path: string,
  headers: Record<string, string> = ownerAuth,
) =>
  runtime.fetch(
    new Request(`http://localhost${path}`, { method: "DELETE", headers }),
  );

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

describe("PS-Lite DELETE /v1/owner/connectors/:connectorId", () => {
  it("refuses anyone but the owner", async () => {
    const response = await del(
      await runtimeWith({ switched: true }),
      "/v1/owner/connectors/github",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThanOrEqual(403);
  });

  it("refuses an unswitched account", async () => {
    const response = await del(
      await runtimeWith({ switched: false }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(409);
    expect((await response.json()).error.errorCode).toBe("NOT_SWITCHED");
  });

  it("answers 202 with the delete id on a switched account", async () => {
    const response = await del(
      await runtimeWith({ switched: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      deleteId: "delete-github",
      fenced: true,
    });
  });

  it("answers 503 when no stream-sync writer is wired (LITE_UNWIRED)", async () => {
    const response = await del(
      await runtimeWith({ switched: true, connectionDelete: null }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "STREAM_SYNC_UNAVAILABLE",
    );
  });

  it("answers 503, not 409, when no mode is wired (mutant: UNWIRED_MODE_FROM_CONFIG)", async () => {
    const response = await del(
      await runtimeWith({ switched: false, unwired: true }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
  });

  it("answers 503 while the mode is unknown (mutant: UNKNOWN_MODE_NOT_SWITCHED)", async () => {
    const response = await del(
      await runtimeWith({ switched: true, mode: "unknown" }),
      "/v1/owner/connectors/github",
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
  });

  it("answers 400, not 500, for a malformed percent-escape in the id (mutant: DECODE_THROWS_500)", async () => {
    const response = await del(
      await runtimeWith({ switched: true }),
      "/v1/owner/connectors/%E0%A4%A",
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error.errorCode).toBe("INVALID_CONNECTOR");
  });

  it("asks a bad escape of the owner only", async () => {
    const response = await del(
      await runtimeWith({ switched: true }),
      "/v1/owner/connectors/%E0%A4%A",
      {},
    );
    expect(response.status).toBeGreaterThanOrEqual(401);
    expect(response.status).toBeLessThanOrEqual(403);
  });

  it("answers a wrong method only to the owner (mutant: PRE_AUTH_REFUSAL)", async () => {
    const runtime = await runtimeWith({ switched: true });
    const request = (headers: Record<string, string>) =>
      runtime.fetch(
        new Request("http://localhost/v1/owner/connectors/github", {
          method: "GET",
          headers,
        }),
      );
    const stranger = await request({});
    expect(stranger.status).toBeGreaterThanOrEqual(401);
    expect(stranger.status).toBeLessThanOrEqual(403);
    expect((await request(ownerAuth)).status).toBe(405);
  });

  it("gives every refusal the API's one error envelope (mutant: TOP_LEVEL_ERROR_BODY)", async () => {
    const cases: Array<[number, string, Response]> = [
      [
        400,
        "INVALID_CONNECTOR",
        await del(
          await runtimeWith({ switched: true }),
          "/v1/owner/connectors/a~b",
        ),
      ],
      [
        409,
        "NOT_SWITCHED",
        await del(
          await runtimeWith({ switched: false }),
          "/v1/owner/connectors/github",
        ),
      ],
      [
        503,
        "ACCOUNT_MODE_UNKNOWN",
        await del(
          await runtimeWith({ switched: true, mode: "unknown" }),
          "/v1/owner/connectors/github",
        ),
      ],
      [
        405,
        "METHOD_NOT_ALLOWED",
        await (
          await runtimeWith({ switched: true })
        ).fetch(
          new Request("http://localhost/v1/owner/connectors/github", {
            method: "GET",
            headers: ownerAuth,
          }),
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
      await runtimeWith({
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
});
