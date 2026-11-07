import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";

/**
 * Own-writes reads through the data API: the owner reads its overlay-only
 * view; anyone else, and an unverified activation, get today's answer.
 */

const BUILDER = "0x000000000000000000000000000000000000bEEF";
const STORED = [{ id: "stored", v: 0 }];
const T = Date.parse("2026-11-01T00:00:00Z");

async function setup(seed: number, activate = true, stored = true) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  if (activate) await f.activate("acme", ns);
  f.overlay.runs = [
    {
      runId: "r1",
      ns,
      generation: 1,
      streams: [
        {
          name: "items",
          complete: true,
          rows: [{ o: T, r: "r1", v: { id: "local", v: 1 } }],
        },
      ],
    },
  ];
  const service = await f.service();
  await f.sync(service);

  const storage = createMemoryDataStorage();
  const envelope = {
    version: "1.0" as const,
    scope: "pdpp.acme.items",
    collectedAt: "2026-10-01T00:00:00.000Z",
    data: { records: STORED },
  };
  const written = await storage.writeEnvelope(envelope);
  if (stored)
    storage.insertEntry({
      fileId: null,
      path: written.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: written.sizeBytes,
    } as never);
  const accessLog = vi.fn(async () => undefined);
  const authorizeBuilderRead = vi.fn(
    async ({ request }: { request: Request }) =>
      request.headers.get("x-test-builder")
        ? { builder: BUILDER, grantId: "grant-1" }
        : { builder: BUILDER, grantId: "owner" },
  );
  const deps: PersonalServerDataApiDeps = {
    storage,
    streamSyncRead: service,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead,
    } as never,
    accessLogWriter: { write: accessLog },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
  return { f, deps, accessLog };
}

async function get(deps: PersonalServerDataApiDeps, builder: boolean) {
  const response = await handlePersonalServerDataRequest(
    new Request("https://ps.example.com/pdpp.acme.items", {
      headers: builder ? { "x-test-builder": "1" } : {},
    }),
    deps,
  );
  return {
    status: response.status,
    source: response.headers.get("x-vana-data-source"),
    origin: response.headers.get("x-stream-sync-origin"),
    body: await response.json().catch(() => null),
  };
}

describe("data reads of a device's own rows", () => {
  it("serves the owner an overlay-only view", async () => {
    const { deps, accessLog } = await setup(71);
    const read = await get(deps, false);
    expect(read.status).toBe(200);
    expect(read.source).toBe("stream-sync");
    expect(read.body.data.records).toEqual([{ id: "local", v: 1 }]);
    expect(accessLog).toHaveBeenCalledTimes(1);
  });

  it("answers a grantee with today's stored body, not the overlay-only view", async () => {
    const { f, deps, accessLog } = await setup(72);
    const read = await get(deps, true);
    expect(read.status).toBe(200);
    expect(read.source).toBe("legacy");
    expect(read.body.data.records).toEqual(STORED);
    expect(f.overlay.open).toBe(0);
    expect(accessLog).toHaveBeenCalledTimes(1);
  });

  it("answers the owner with today's stored body when activation is not verified", async () => {
    const { deps } = await setup(73, false);
    const read = await get(deps, false);
    expect(read.source).toBe("legacy");
    expect(read.body.data.records).toEqual(STORED);
  });

  it("marks the owner's unactivated rows as local and pending", async () => {
    const { f, deps } = await setup(74, false, false);
    f.overlay.runs = f.overlay.runs.map((r) => ({ ...r, generation: null }));
    const read = await get(deps, false);
    expect(read.status).toBe(200);
    expect(read.source).toBe("stream-sync");
    expect(read.origin).toBe("local-pending");
    expect(read.body.origin).toBe("local-pending");
    expect(read.body.data.records).toEqual([{ id: "local", v: 1 }]);
  });

  it("never serves unactivated rows to a grantee", async () => {
    const { f, deps } = await setup(75, false);
    f.overlay.runs = f.overlay.runs.map((r) => ({ ...r, generation: null }));
    const read = await get(deps, true);
    expect(read.source).toBe("legacy");
    expect(read.origin).toBeNull();
    expect(read.body.data.records).toEqual(STORED);
  });
});
