import { expect, it, vi } from "vitest";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";

it("routes served reads to shared activity even when browser composition injects a legacy log store", async () => {
  const owner = `0x${"12".repeat(20)}` as const;
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  await authority.submitEvidence({ owner, state: "on" });
  const legacy = createMemoryPsLiteAccessLogStore();
  const write = vi.fn(async () => {});
  const read = vi.fn(async () => ({
    logs: [],
    limit: 50,
    offset: 0,
    nextCursor: null,
  }));
  const runtime = createPsLiteRuntime({
    serverOwner: owner,
    active: true,
    accountModeAuthority: authority,
    auth: createBearerTokenPsLiteAuth({ ownerToken: "owner-token" }),
    storage: createMemoryPsLiteStorage(),
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    accessLogReader: legacy,
    accessLogWriter: legacy,
    localSync: async () => ({ accessActivity: { write, read } }) as never,
    streamSyncRead: {
      resolve: async () => ({
        kind: "view",
        connector: "fixture",
        ns: "",
        cursor: "head",
        served: { scope: "pdpp.fixture~.items", version: 1 },
        body: new Response('{"data":{"records":[]}}').body!,
      }),
    } as never,
  });
  const response = await runtime.fetch(
    new Request("https://server.example/v1/data/pdpp.fixture.items", {
      headers: { authorization: "Bearer owner-token" },
    }),
  );
  expect(response.status).toBe(200);
  await response.body?.cancel();
  expect(write).toHaveBeenCalledOnce();
  expect((await legacy.read()).logs).toEqual([]);
  const history = await runtime.fetch(
    new Request("https://server.example/v1/access-logs?cursor=fixture-cursor", {
      headers: { authorization: "Bearer owner-token" },
    }),
  );
  expect(history.status).toBe(200);
  expect(read).toHaveBeenCalledWith({
    limit: 50,
    offset: 0,
    cursor: "fixture-cursor",
  });
  expect(write).toHaveBeenCalledOnce();
  const denied = await runtime.fetch(
    new Request("https://server.example/v1/access-logs"),
  );
  expect(denied.status).toBeGreaterThanOrEqual(400);
  expect(read).toHaveBeenCalledOnce();
  await authority.close();
});
