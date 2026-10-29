/**
 * The scope inventory (`GET /v1/data`) the web shell reads after sync: a
 * readiness hint it cannot read must not fail the listing, and a failure
 * that does reach a 500 hands its cause to the runtime's logger.
 */

import { describe, expect, it, vi } from "vitest";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

async function createRuntime(
  wrap: (storage: DataStoragePort) => DataStoragePort,
) {
  const memory = createMemoryPsLiteStorage();
  const logger = { error: vi.fn() };
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage: wrap(memory),
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
    logger,
    active: true,
  });
  const write = await runtime.fetch(
    new Request("https://ps.local/v1/data/notes.entries", {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ items: [{ id: "a" }] }),
    }),
  );
  expect(write.status).toBe(201);
  // The web shell lists with the builder token, 100 rows a page.
  const list = () =>
    runtime.fetch(
      new Request("https://ps.local/v1/data?limit=100&offset=0", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );
  return { list, logger };
}

describe("PS-Lite scope inventory", () => {
  it("lists a scope whose block readiness cannot be read", async () => {
    const { list } = await createRuntime((storage) => ({
      ...storage,
      // An OPFS manifest file that holds no JSON (a write cut short).
      async hasScopeBlocks() {
        throw new SyntaxError("Unexpected end of JSON input");
      },
    }));

    const res = await list();

    expect(res.status).toBe(200);
    expect((await res.json()).scopes).toEqual([
      expect.objectContaining({
        scope: "notes.entries",
        dataStatus: "indexing",
      }),
    ]);
  });

  it("logs the cause of a listing that fails", async () => {
    const { list, logger } = await createRuntime((storage) => ({
      ...storage,
      listScopes() {
        throw new Error("index unreadable");
      },
    }));

    const res = await list();

    expect(res.status).toBe(500);
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({
        route: "GET /v1/data",
        err: expect.objectContaining({ message: "index unreadable" }),
      }),
      expect.any(String),
    );
  });
});
