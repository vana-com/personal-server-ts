import { describe, expect, it } from "vitest";
import { fixedAccountStorageMode } from "@opendatalabs/personal-server-ts-core/test-utils";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import { handlePsLiteBridgeRequest } from "./bridge.js";

type PsLiteRuntimeOptions = Parameters<typeof createPsLiteRuntime>[0];

function createTestRuntime(options: Partial<PsLiteRuntimeOptions> = {}) {
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const defaults: PsLiteRuntimeOptions = {
    storage: createMemoryPsLiteStorage(),
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
  };
  return createPsLiteRuntime({
    accountStorageMode: fixedAccountStorageMode("unswitched"),
    ...defaults,
    ...options,
    storage: options.storage ?? defaults.storage,
    gateway: options.gateway ?? defaults.gateway,
    accessLogReader: options.accessLogReader ?? defaults.accessLogReader,
    accessLogWriter: options.accessLogWriter ?? defaults.accessLogWriter,
    tokenStore: options.tokenStore ?? defaults.tokenStore,
    saveConfig: options.saveConfig ?? defaults.saveConfig,
    stateCapabilities: {
      ...defaults.stateCapabilities,
      ...options.stateCapabilities,
    },
  });
}

describe("handlePsLiteBridgeRequest", () => {
  // A body that fails after the status leaves the relay no response to send:
  // the relay closes the stream (relay.ts drainHttpRequests), so the client
  // never receives a well-formed shorter body.
  it("rejects when the response body fails after the status", async () => {
    let pulls = 0;
    const runtime = {
      fetch: async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            pull(controller) {
              if (pulls++ === 0) {
                controller.enqueue(
                  new TextEncoder().encode('{"data":{"records":[{"id":"a"}'),
                );
                return;
              }
              controller.error(new Error("projection failed"));
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    } as unknown as Parameters<typeof handlePsLiteBridgeRequest>[0];
    await expect(
      handlePsLiteBridgeRequest(runtime, {
        requestId: "req-1",
        method: "GET",
        path: "/v1/data/instagram.posts",
        query: "",
        headers: {},
        body: "",
      }),
    ).rejects.toThrow("projection failed");
  });

  it("adapts relay-style requests to the ps-lite runtime", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const write = await handlePsLiteBridgeRequest(runtime, {
      requestId: "req-1",
      method: "POST",
      path: "/v1/data/instagram.profile",
      query: "",
      headers: {
        authorization: "Bearer owner-token",
        "content-type": "application/json",
      },
      body: "eyJ1c2VybmFtZSI6InRlc3RfdXNlciJ9",
    });

    expect(write).toMatchObject({
      requestId: "req-1",
      status: 201,
    });

    const read = await handlePsLiteBridgeRequest(runtime, {
      requestId: "req-2",
      method: "GET",
      path: "/v1/data/instagram.profile",
      query: "grantId=grant-1",
      headers: { authorization: "Bearer builder-token" },
      body: "",
    });

    expect(read.status).toBe(200);
    expect(read.headers["content-type"]).toContain("application/json");
    expect(JSON.parse(read.textBody).data).toEqual({
      username: "test_user",
    });
  });

  it("returns typed ps_unavailable through the bridge while inactive", async () => {
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      active: false,
    });

    const response = await handlePsLiteBridgeRequest(runtime, {
      requestId: "req-1",
      method: "GET",
      path: "/v1/data/instagram.profile",
      query: "grantId=grant-1",
      headers: {},
      body: "",
    });

    expect(response.status).toBe(503);
    expect(JSON.parse(response.textBody).error.errorCode).toBe(
      "PS_UNAVAILABLE",
    );
  });
});
