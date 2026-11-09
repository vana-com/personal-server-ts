import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type {
  PersonalServerDataApiDeps,
  PersonalServerListAuthResult,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { LegacyScopeViewPort } from "../storage/legacy-scope-view.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";

/**
 * The scope listing shows the scopes a stream-sync read serves: a person who
 * collects on one device lists and reads the data on any other, and after the
 * account switches to stream sync that data exists only as stream heads.
 */

const BUILDER = "0x000000000000000000000000000000000000bEEF";
const HEAD_AT = Date.parse("2026-10-15T12:00:00.000Z");

interface Setup {
  fixture: Fixture;
  ns: string;
  deps: PersonalServerDataApiDeps;
  list(query?: string): Promise<{ scopes: any[]; total: number }>;
  read(scope: string): Promise<Response>;
}

async function setup(
  options: {
    switched?: boolean;
    seed?: (fixture: Fixture, ns: string) => Promise<void>;
    listAuth?: PersonalServerListAuthResult;
    scopeDeletions?: PersonalServerDataApiDeps["scopeDeletions"];
    legacyScopeView?: LegacyScopeViewPort;
    seedStorage?: (
      storage: ReturnType<typeof createMemoryDataStorage>,
    ) => Promise<void>;
    grantee?: boolean;
  } = {},
): Promise<Setup> {
  const fixture = new Fixture(await testOwnerKey(masterKey(7)));
  const ns = await fixture.key.ns("acme", "account-1");
  await fixture.activate("acme", ns);
  await (
    options.seed ??
    (async (f, n) => {
      await f.publish({
        connector: "acme",
        ns: n,
        stream: "items",
        generation: 1,
        records: [{ id: "a" }, { id: "b" }],
        complete: true,
        observedAt: HEAD_AT,
      });
    })
  )(fixture, ns);
  const service = await fixture.service();
  await fixture.sync(service);
  const storage = createMemoryDataStorage();
  await options.seedStorage?.(storage);
  const deps: PersonalServerDataApiDeps = {
    storage,
    streamSyncSwitched: () => options.switched ?? true,
    streamSyncRead: service,
    ...(options.scopeDeletions
      ? { scopeDeletions: options.scopeDeletions }
      : {}),
    ...(options.legacyScopeView
      ? { legacyScopeView: options.legacyScopeView }
      : {}),
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => options.listAuth),
      authorizeBuilderRead: vi.fn(async () =>
        options.grantee
          ? { builder: BUILDER, grantId: "grant-1" }
          : { builder: BUILDER, grantId: "owner" },
      ),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
  const get = (path: string) =>
    handlePersonalServerDataRequest(
      new Request(`https://ps.example.com${path}`),
      deps,
    );
  return {
    fixture,
    ns,
    deps,
    list: async (query = "") => {
      const response = await get(`/${query}`);
      expect(response.status).toBe(200);
      return response.json() as never;
    },
    read: (scope) => get(`/${scope}`),
  };
}

const names = (listing: { scopes: { scope: string }[] }) =>
  listing.scopes.map((s) => s.scope);

describe("one-store canonical boundary", () => {
  it.each([true, false])(
    "switched=%s uses the account switch for canonical reads and lists",
    async (switched) => {
      const at = "2026-10-15T12:00:00.000Z";
      const readLatest = vi.fn(async () => ({
        kind: "canonical",
        revision: "r1",
        envelope: {
          version: "1.0",
          scope: "instagram.profile",
          collectedAt: at,
          data: { username: "canonical" },
        },
      }));
      const listCanonicalScopes = vi.fn(() => [
        { scope: "instagram.profile", collectedAt: at },
      ]);
      const legacyScopeView = {
        readLatest,
        listCanonicalScopes,
        listingFor: () => ({ kind: "canonical", collectedAt: at }),
        ownsScope: () => true,
      } as never;
      const { read, list } = await setup({ switched, legacyScopeView });
      const response = await read("instagram.profile");
      expect(response.status).toBe(switched ? 404 : 200);
      if (!switched)
        expect((await response.json()).data.username).toBe("canonical");
      expect(names(await list()).includes("instagram.profile")).toBe(!switched);
      if (switched) {
        expect(readLatest).not.toHaveBeenCalled();
        expect(listCanonicalScopes).not.toHaveBeenCalled();
      } else {
        expect(readLatest).toHaveBeenCalled();
        expect(listCanonicalScopes).toHaveBeenCalled();
      }
    },
  );
});

describe("switched listing", () => {
  it("lists the stream scope with its collection time and total", async () => {
    const { list } = await setup();
    const listing = await list();
    expect(listing.total).toBe(1);
    expect(listing.scopes).toEqual([
      {
        scope: "pdpp.acme.items",
        latestCollectedAt: expect.any(String),
        versionCount: 0,
      },
    ]);
  });

  it("lists only what the caller's grant covers, and what it lists it can read", async () => {
    const covered = await setup({
      listAuth: { grantedScopes: ["pdpp.acme.items"] },
      grantee: true,
    });
    const listed = names(await covered.list());
    expect(listed).toEqual(["pdpp.acme.items"]);
    for (const scope of listed)
      expect((await covered.read(scope)).status).toBe(200);

    const other = await setup({
      listAuth: { grantedScopes: ["pdpp.other.things"] },
      grantee: true,
    });
    expect(names(await other.list())).toEqual([]);
  });

  it("does not list a scope the same caller cannot read", async () => {
    const { list, read } = await setup({
      seed: async (f, ns) => {
        await f.publish({
          connector: "acme",
          ns,
          stream: "items",
          generation: 1,
          records: [{ id: "a" }],
          complete: false,
          observedAt: HEAD_AT,
        });
      },
    });
    expect((await read("pdpp.acme.items")).status).toBe(404);
    expect(names(await list())).toEqual([]);
  });
});
