import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";

/**
 * An owner's unpublished local rows are never served to a grant. A full run
 * under a replacement key replaces the registered head once published; until
 * the reader imports it, the owner reads the registered head too, with the
 * run withheld. The grant is served the registered head, as if no local run
 * existed.
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
    records: [
      { id: "base-a", v: 1 },
      { id: "base-b", v: 1 },
    ],
    observedAt: T - 1000,
    profileVersion: "1.0.0",
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
          version: "2.0.0",
          rows: [{ o: T, r: "r1", v: { uid: "local-private" } }],
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
  const text = await response.text();
  return {
    status: response.status,
    source: response.headers.get("x-vana-data-source"),
    withheld: response.headers.get("x-stream-sync-withheld"),
    text,
    body: JSON.parse(text) as { data: { records: unknown[] } },
  };
}

describe("GET /v1/data/:scope with a full replacement-key local run", () => {
  it("serves a grant the registered rows and none of the local ones", async () => {
    const read = await get(await setup(331), true);
    expect(read.status).toBe(200);
    expect(read.source).toBe("stream-sync");
    expect(read.body.data.records).toEqual(
      expect.arrayContaining([
        { id: "base-a", v: 1 },
        { id: "base-b", v: 1 },
      ]),
    );
    expect(read.body.data.records).toHaveLength(2);
    expect(read.text).not.toContain("local-private");
    expect(read.withheld).toBeNull();
  });

  it("serves the owner the base a grant reads, with the reset withheld until it is imported", async () => {
    const read = await get(await setup(332), false);
    expect(read.status).toBe(200);
    expect(read.body.data.records).toEqual([
      { id: "base-a", v: 1 },
      { id: "base-b", v: 1 },
    ]);
    expect(read.withheld).toBe("key_reset_pending");
  });
});
