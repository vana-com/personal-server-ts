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
    pending: response.headers.get("x-stream-sync-pending"),
    body: await response.json().catch(() => null),
  };
}

describe("data reads of a device's own rows", () => {
  it("serves the owner an overlay-only view when no stored body exists", async () => {
    const { deps, accessLog } = await setup(71, true, false);
    const read = await get(deps, false);
    expect(read.status).toBe(200);
    expect(read.source).toBe("stream-sync");
    expect(read.body.data.records).toEqual([{ id: "local", v: 1 }]);
    expect(accessLog).toHaveBeenCalledTimes(1);
  });

  it("answers the owner with the stored body a grantee reads, and says a run is pending", async () => {
    // A complete overlay-only view does not contain the stored body: the
    // owner never reads fewer records than a grantee of the same stream.
    const { deps } = await setup(71);
    const owner = await get(deps, false);
    const grant = await get(deps, true);
    expect(grant.source).toBe("legacy");
    expect(owner.source).toBe("legacy");
    expect(owner.body.data.records).toEqual(STORED);
    expect(owner.pending).toBe("1");
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
    const { f, deps } = await setup(73, false);
    // The stored body (2026-10-01) is the newer collection.
    f.overlay.runs = f.overlay.runs.map((r) => ({
      ...r,
      observedAt: Date.parse("2026-09-01T00:00:00Z"),
    }));
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

describe("data reads of a device's own rows against a stored body", () => {
  it("serves the owner the stored body and marks the pending run", async () => {
    const { deps } = await setup(76, false);
    // The stored body's time is an ingest stamp, not comparable with a run's:
    // the stored body answers whichever is newer, and the pending run is named.
    const read = await get(deps, false);
    expect(read.source).toBe("legacy");
    expect(read.pending).toBe("1");
    expect(read.body.data.records).toEqual(STORED);
  });

  it("counts a pending run with no record, whatever its time", async () => {
    const { f, deps } = await setup(77, false);
    f.overlay.runs = f.overlay.runs.map((r) => ({
      ...r,
      observedAt: Date.parse("2026-09-01T00:00:00Z"),
      streams: r.streams.map((s) => ({ ...s, rows: [] })),
    }));
    const read = await get(deps, false);
    expect(read.source).toBe("legacy");
    // Unpublished runs are counted, never compared by time.
    expect(read.pending).toBe("1");
    expect(read.body.data.records).toEqual(STORED);
  });

  it("never serves a grantee the pending run", async () => {
    const { deps } = await setup(78, false);
    const read = await get(deps, true);
    expect(read.source).toBe("legacy");
    expect(read.origin).toBeNull();
    expect(read.pending).toBeNull();
    expect(read.body.data.records).toEqual(STORED);
  });
});
