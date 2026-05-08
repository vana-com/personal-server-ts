import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { startTestServer, type TestServer } from "./helpers/server.js";
import { startMockGateway, type MockGateway } from "./helpers/mock-gateway.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

describe("Data ingest endpoint (e2e)", () => {
  let server: TestServer;
  let gateway: MockGateway;

  beforeAll(async () => {
    gateway = await startMockGateway();
    server = await startTestServer({
      gatewayUrl: gateway.url,
      masterKeySignature: KNOWN_SIG,
    });
  });

  afterAll(async () => {
    await server.cleanup();
    await gateway.cleanup();
  });

  function ownerHeaders(): Record<string, string> {
    if (!server.devToken) {
      throw new Error("Test server did not expose a dev token");
    }
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${server.devToken}`,
    };
  }

  it("POST /v1/data/{scope} returns 201 with scope, collectedAt, status", async () => {
    const res = await fetch(`${server.url}/v1/data/instagram.profile`, {
      method: "POST",
      headers: ownerHeaders(),
      body: JSON.stringify({ username: "testuser" }),
    });
    expect(res.status).toBe(201);

    const body = await res.json();
    expect(body.scope).toBe("instagram.profile");
    expect(body.collectedAt).toBeDefined();
    expect(body.status).toBe("stored");
  });

  it("POST /v1/data/{scope} collectedAt is valid ISO 8601", async () => {
    const res = await fetch(`${server.url}/v1/data/facebook.profile`, {
      method: "POST",
      headers: ownerHeaders(),
      body: JSON.stringify({ username: "test" }),
    });
    const body = await res.json();

    expect(body).toHaveProperty("collectedAt");
    expect(typeof body.collectedAt).toBe("string");
    expect(body.collectedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    const date = new Date(body.collectedAt);
    expect(date.getTime()).toBeGreaterThan(0);
  });

  it("POST /v1/data/{scope} returns 400 for invalid scope", async () => {
    const res = await fetch(`${server.url}/v1/data/bad`, {
      method: "POST",
      headers: ownerHeaders(),
      body: JSON.stringify({ data: "test" }),
    });
    expect(res.status).toBe(400);

    const body = await res.json();
    expect(body.error).toBe("INVALID_SCOPE");
  });

  it("POST /v1/data/{scope} returns 400 for non-JSON body", async () => {
    const res = await fetch(`${server.url}/v1/data/instagram.profile`, {
      method: "POST",
      headers: ownerHeaders(),
      body: "not json",
    });
    expect(res.status).toBe(400);

    const body = await res.json();
    expect(body.error).toBe("INVALID_BODY");
  });

  it("two POSTs create different versions", async () => {
    const res1 = await fetch(`${server.url}/v1/data/twitter.posts`, {
      method: "POST",
      headers: ownerHeaders(),
      body: JSON.stringify({ version: 1 }),
    });
    expect(res1.status).toBe(201);
    const body1 = await res1.json();

    // Wait to ensure different timestamps
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const res2 = await fetch(`${server.url}/v1/data/twitter.posts`, {
      method: "POST",
      headers: ownerHeaders(),
      body: JSON.stringify({ version: 2 }),
    });
    expect(res2.status).toBe(201);
    const body2 = await res2.json();

    expect(body1.collectedAt).not.toBe(body2.collectedAt);
  });
});
