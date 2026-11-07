import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";

/**
 * A local run the writer will not publish (an older connector met a changed
 * primary key) is reported to the owner and never to a grantee.
 */

const BUILDER = "0x000000000000000000000000000000000000bEEF";
const T = Date.parse("2026-11-01T00:00:00Z");

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [{ id: "a", v: 1 }],
    observedAt: T - 1000,
    profileVersion: "2.0.0",
  });
  f.overlay.runs = [
    {
      runId: "r1",
      ns,
      generation: 1,
      observedAt: T,
      streams: [
        {
          name: "items",
          complete: true,
          primaryKey: ["uid"],
          version: "1.0.0",
          rows: [{ o: T, r: "r1", v: { uid: "u1" } }],
        },
      ],
    },
  ];
  const service = await f.service();
  await f.sync(service);
  const deps: PersonalServerDataApiDeps = {
    storage: createMemoryDataStorage(),
    streamSyncRead: service,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async ({ request }: { request: Request }) =>
        request.headers.get("x-test-builder")
          ? { builder: BUILDER, grantId: "grant-1" }
          : { builder: BUILDER, grantId: "owner" },
      ),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
  return deps;
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
    withheld: response.headers.get("x-stream-sync-withheld"),
    body: await response.json().catch(() => null),
  };
}

describe("data reads with a withheld local run", () => {
  it("tells the owner in a header and a body field, and serves the base", async () => {
    const read = await get(await setup(321), false);
    expect(read.status).toBe(200);
    expect(read.source).toBe("stream-sync");
    expect(read.withheld).toBe("connector_update_required");
    expect(read.body.withheld).toEqual([
      { runId: "r1", stream: "items", reason: "connector_update_required" },
    ]);
    expect(read.body.data.records).toEqual([{ id: "a", v: 1 }]);
  });

  it("shows a grantee neither the header nor the body field", async () => {
    const read = await get(await setup(322), true);
    expect(read.status).toBe(200);
    expect(read.withheld).toBeNull();
    expect(read.body.withheld).toBeUndefined();
    expect(read.body.data.records).toEqual([{ id: "a", v: 1 }]);
  });
});
