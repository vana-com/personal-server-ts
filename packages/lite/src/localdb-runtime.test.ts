import {
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  approveMcpConnection,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { expect, it, vi } from "vitest";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";

it("Lite HTTP history and status use the same database facade and its counters", async () => {
  const owner = `0x${"1".repeat(40)}`;
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  await authority.submitEvidence({ owner, state: "on" });
  const counts = { served: 2, gone: 1, off: 0 };
  const status = {
    listed: true,
    connections: [],
    issues: [],
    olderVersionReads: counts,
  };
  const additions = vi.fn(async () => ({ total: 7 }));
  const local = {
    listing: { status: async () => status },
    olderVersions: { counts: () => counts },
  } as unknown as LocalSync;
  const getLocalSync = vi.fn(async () => local);
  const accessLog = createMemoryPsLiteAccessLogStore();
  const connections = createInMemoryMcpConnectionStore();
  const runtime = createPsLiteRuntime({
    accessLogReader: accessLog,
    accessLogWriter: accessLog,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    mcpConnectionStore: connections,
    storage: createMemoryPsLiteStorage(),
    serverOwner: owner as `0x${string}`,
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-fixture",
      builderToken: "builder-fixture",
    }),
    accountModeAuthority: authority,
    active: true,
    localSync: getLocalSync,
    history: { additions, versions: vi.fn(), lineage: vi.fn() } as never,
  });
  const get = (path: string) =>
    runtime.fetch(
      new Request("https://fixture.test" + path, {
        headers: { authorization: "Bearer owner-fixture" },
      }),
    );
  expect(await (await get("/v1/sync/status")).json()).toEqual(status);
  expect(
    (await (await get("/v1/stream-sync/read-status")).json()).olderVersionReads,
  ).toEqual(counts);
  expect((await (await get("/v1/data/additions")).json()).total).toBe(7);
  expect(additions).toHaveBeenCalledTimes(1);
  const connection = await createMcpConnection(
    { displayName: "fixture" },
    { store: connections, publicOrigin: "https://fixture.test" },
  );
  await approveMcpConnection(
    {
      connectionId: connection.connectionId,
      grants: [{ grantId: "fixture-grant", scopes: ["write:memory.fixture"] }],
    },
    { store: connections },
  );
  const refused = await runtime.fetch(
    new Request(`https://fixture.test/mcp/${connection.connectionToken}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "remember",
          arguments: { text: "fixture", scope: "memory.fixture" },
        },
      }),
    }),
  );
  expect(refused.status).toBe(200);
  const tool = JSON.parse((await refused.json()).result.content[0].text);
  expect(tool).toMatchObject({
    status: 409,
    errorCode: "STREAM_SYNC_WRITE_UNAVAILABLE",
  });
  await authority.close();
});
