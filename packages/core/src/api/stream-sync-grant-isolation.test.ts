import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

/**
 * An owner's unpublished local rows are never served to a grant. A full run
 * under a replacement key replaces the registered head once published; until
 * the reader imports it, the owner reads the registered head too, with the
 * run withheld. The grant is served the registered head, as if no local run
 * existed.
 */

const BUILDER = "0x000000000000000000000000000000000000bEEF";

async function setup(_seed: number) {
  // The resolver's SQLite tests own retained-image selection. This route
  // fixture is the complete image it returns after refusing a key reset.
  const resolve = vi.fn(async () => ({
    kind: "view" as const,
    connector: "fixture",
    ns: "",
    cursor: "head",
    served: { scope: "pdpp.fixture~.items", version: 1 },
    body: new Response(
      JSON.stringify({
        data: {
          records: [
            { id: "base-a", v: 1 },
            { id: "base-b", v: 1 },
          ],
        },
      }),
    ).body!,
  }));
  const deps: PersonalServerDataApiDeps = {
    storage: createMemoryDataStorage(),
    accountStorageMode: { owner: "fixture", read: () => "switched" },
    streamSyncRead: { resolve },
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(
        async ({ request }: { request: Request }) => ({
          builder: BUILDER,
          grantId: request.headers.get("x-test-builder") ? "grant-1" : "owner",
        }),
      ),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
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

  it("serves the owner the base a grant reads, without device-specific overlay diagnostics", async () => {
    const read = await get(await setup(332), false);
    expect(read.status).toBe(200);
    expect(read.body.data.records).toEqual([
      { id: "base-a", v: 1 },
      { id: "base-b", v: 1 },
    ]);
    expect(read.withheld).toBeNull();
  });
});
