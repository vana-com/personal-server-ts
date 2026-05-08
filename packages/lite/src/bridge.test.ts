import { describe, expect, it } from "vitest";
import {
  createBearerTokenPsLiteAuth,
  createMemoryPsLiteStorage,
  createPsLiteRuntime,
} from "./runtime.js";
import { handlePsLiteBridgeRequest } from "./bridge.js";

describe("handlePsLiteBridgeRequest", () => {
  it("adapts relay-style requests to the ps-lite runtime", async () => {
    const runtime = createPsLiteRuntime({
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
    const runtime = createPsLiteRuntime({
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
