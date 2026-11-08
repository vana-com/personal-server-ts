import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";

// Test 8 (preservation): the identity-less physical alias `pdpp.acme~.items`
// is normalized to the logical stream before policy and reader selection, so
// it reads exactly what `pdpp.acme.items` reads. A future raw-name system check
// must not run before that normalization, or this alias would start failing.

const BUILDER = "0x000000000000000000000000000000000000bEEF";
const T = Date.parse("2026-11-01T00:00:00Z");

async function deps(seed: number): Promise<PersonalServerDataApiDeps> {
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
  const service = await f.service();
  await f.sync(service);
  return {
    storage: createMemoryDataStorage(),
    streamSyncRead: service,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => ({
        builder: BUILDER,
        grantId: "grant-1",
      })),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
}

async function read(d: PersonalServerDataApiDeps, path: string) {
  const response = await handlePersonalServerDataRequest(
    new Request(`https://ps.example.com${path}`),
    d,
  );
  return { status: response.status, text: await response.text() };
}

describe("identity-less physical alias reads", () => {
  it("returns the same logical stream body as the logical name", async () => {
    const d = await deps(341);
    const logical = await read(d, "/pdpp.acme.items");
    const alias = await read(d, "/pdpp.acme~.items");
    expect(logical.status).toBe(200);
    expect(alias).toEqual(logical);
    expect(alias.text).toContain("base-a");
  });
});
