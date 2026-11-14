import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

/**
 * The API carries withheld status from its read port to the owner only.
 * Database eligibility is verified in localdb tests; these tests pin the header/body contract.
 */

const BUILDER = "0x000000000000000000000000000000000000bEEF";

function readPort(
  incomplete: boolean,
): NonNullable<PersonalServerDataApiDeps["streamSyncRead"]> {
  return {
    resolve: async (input) => {
      const withheld = input.isOwnerView
        ? [
            {
              runId: "r1",
              stream: "items",
              reason: "connector_update_required" as const,
            },
          ]
        : undefined;
      if (incomplete)
        return { kind: "unavailable", reason: "no_data", withheld };
      return {
        kind: "view",
        connector: "acme",
        ns: "",
        cursor: "fixture",
        served: { scope: "pdpp.acme~.items", version: 1 },
        withheld,
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(
              new TextEncoder().encode(
                JSON.stringify({
                  data: { records: [{ id: "a", v: 1 }] },
                  ...(withheld && { withheld }),
                }),
              ),
            );
            controller.close();
          },
        }),
      };
    },
  };
}
async function setup(_seed: number) {
  return setupDeps(readPort(false), createMemoryDataStorage());
}

async function setupDeps(
  service: PersonalServerDataApiDeps["streamSyncRead"],
  storage: PersonalServerDataApiDeps["storage"],
) {
  const deps: PersonalServerDataApiDeps = {
    storage,
    accountStorageMode: { owner: "fixture", read: () => "switched" },
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

describe("switched incomplete reads refuse legacy fallback", () => {
  /** An incomplete base and a withheld run: no view can be served. */
  async function legacyOnly(_seed: number) {
    const service = readPort(true);
    const storage = createMemoryDataStorage();
    const envelope = {
      version: "1.0" as const,
      scope: "pdpp.acme.items",
      collectedAt: "2026-10-01T00:00:00.000Z",
      data: { records: [{ id: "stored" }] },
    };
    const written = await storage.writeEnvelope(envelope);
    storage.insertEntry({
      fileId: null,
      path: written.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: written.sizeBytes,
    } as never);
    const deps = await setupDeps(service, storage);
    return deps;
  }

  it("tells the owner of the withheld run in the header and the body", async () => {
    const read = await get(await legacyOnly(323), false);
    expect(read.status).toBe(404);
    expect(read.source).toBeNull();
    expect(read.withheld).toBe("connector_update_required");
    expect(read.body.withheld).toEqual([
      { runId: "r1", stream: "items", reason: "connector_update_required" },
    ]);
    expect(read.body.error.errorCode).toBe("STREAM_DATA_NOT_FOUND");
  });

  it("tells a grantee nothing", async () => {
    const read = await get(await legacyOnly(324), true);
    expect(read.status).toBe(404);
    expect(read.source).toBeNull();
    expect(read.withheld).toBeNull();
    expect(read.body.withheld).toBeUndefined();
  });
});

describe("retired mixed HTTP response", () => {
  it("cancels a device-local partial body without serving it or touching legacy storage", async () => {
    const cancel = vi.fn();
    const storage = createMemoryDataStorage();
    const find = vi.spyOn(storage, "findEntry");
    const deps = await setupDeps(
      {
        resolve: async () => ({
          kind: "local_pending",
          connector: "fixture",
          ns: "",
          cursor: "fixture",
          complete: false,
          body: new ReadableStream<Uint8Array>({ cancel }),
        }),
      },
      storage,
    );
    const read = await get(deps, false);
    expect(read.status).toBe(404);
    expect(read.source).toBeNull();
    expect(read.body.error.errorCode).toBe("STREAM_DATA_NOT_FOUND");
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(find).not.toHaveBeenCalled();
  });
});
