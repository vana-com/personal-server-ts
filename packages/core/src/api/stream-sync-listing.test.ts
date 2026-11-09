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

describe("scope listing of stream-sync-only scopes", () => {
  it("lists a scope that only an imported stream head holds, and the read serves it", async () => {
    const { list, read } = await setup();

    expect((await read("pdpp.acme.items")).status).toBe(200);
    const listing = await list();
    expect(listing).toMatchObject({
      scopes: [
        {
          scope: "pdpp.acme.items",
          latestCollectedAt: new Date(HEAD_AT).toISOString(),
          versionCount: 0,
        },
      ],
      total: 1,
    });
  });

  it("hides a stream-only scope the gateway reports deleted", async () => {
    const { list } = await setup({
      scopeDeletions: {
        resolve: async (scope: string) => ({
          deleted: scope === "pdpp.acme.items",
          deletedAt: "2026-10-20T00:00:00.000Z",
        }),
      } as never,
    });

    expect(names(await list())).toEqual([]);
  });

  it("lists a scope once when the legacy store or the canonical view also lists it", async () => {
    const stored = await setup({
      seedStorage: async (storage) => {
        const envelope = {
          version: "1.0" as const,
          scope: "pdpp.acme.items",
          collectedAt: "2026-10-01T00:00:00.000Z",
          data: { records: [{ id: "old" }] },
        };
        const written = await storage.writeEnvelope(envelope);
        storage.insertEntry({
          fileId: null,
          path: written.relativePath,
          scope: envelope.scope,
          collectedAt: envelope.collectedAt,
          sizeBytes: written.sizeBytes,
        } as never);
      },
    });
    const storedListing = await stored.list();
    expect(names(storedListing)).toEqual(["pdpp.acme.items"]);
    expect(storedListing.scopes[0].versionCount).toBe(1);

    const canonical = await setup({
      legacyScopeView: {
        listCanonicalScopes: () => [
          {
            scope: "pdpp.acme.items",
            collectedAt: "2026-10-02T00:00:00.000Z",
          },
        ],
        listingFor: () => ({
          kind: "canonical",
          collectedAt: "2026-10-02T00:00:00.000Z",
        }),
        readLatest: async () => ({ kind: "file", deletion: "file" }),
        ownsScope: () => false,
      } as never,
    });
    const canonicalListing = await canonical.list();
    expect(names(canonicalListing)).toEqual(["pdpp.acme.items"]);
    expect(canonicalListing.total).toBe(1);
  });

  it("filters stream-only scopes by scopePrefix", async () => {
    const { list } = await setup();

    expect(names(await list("?scopePrefix=pdpp.acme"))).toEqual([
      "pdpp.acme.items",
    ]);
    expect(names(await list("?scopePrefix=pdpp.other"))).toEqual([]);
    expect(names(await list("?scopePrefix=chatgpt"))).toEqual([]);
  });

  it("lists only what the caller's grant covers", async () => {
    const covered = await setup({
      listAuth: { grantedScopes: ["pdpp.acme.items"] },
      grantee: true,
    });
    expect(names(await covered.list())).toEqual(["pdpp.acme.items"]);

    const uncovered = await setup({
      listAuth: { grantedScopes: ["instagram.profile"] },
      grantee: true,
    });
    expect(names(await uncovered.list())).toEqual([]);
  });

  it("lists nothing for a deleted connection, which the read refuses", async () => {
    const { list, read } = await setup({
      seed: async (f, ns) => {
        await f.publish({
          connector: "acme",
          ns,
          stream: "items",
          generation: 1,
          records: [{ id: "a" }],
          complete: true,
          observedAt: HEAD_AT,
        });
        await f.deleteConnection("acme", ns);
      },
    });

    expect((await read("pdpp.acme.items")).status).toBe(410);
    expect(names(await list())).toEqual([]);
  });

  describe("a head the read does not show to every caller", () => {
    const incomplete = async (f: Fixture, ns: string) => {
      await f.publish({
        connector: "acme",
        ns,
        stream: "items",
        generation: 1,
        records: [{ id: "partial" }],
        complete: false,
        observedAt: HEAD_AT,
      });
    };

    it("lists an incomplete head to the owner, who reads it as local-pending", async () => {
      const { list, read } = await setup({ seed: incomplete });

      const res = await read("pdpp.acme.items");
      expect(res.status).toBe(200);
      expect((await res.json()).origin).toBe("local-pending");
      expect(names(await list())).toEqual(["pdpp.acme.items"]);
    });

    it("does not list an incomplete head to a grantee, whose read gets nothing", async () => {
      const { list, read } = await setup({
        seed: incomplete,
        listAuth: { grantedScopes: ["pdpp.acme.items"] },
        grantee: true,
      });

      expect((await read("pdpp.acme.items")).status).toBe(404);
      expect(names(await list())).toEqual([]);
    });
  });

  describe("legacy scope names", () => {
    const seedChatgpt = (streams: ("conversations" | "messages")[]) =>
      async function seed(f: Fixture, _ns: string) {
        const ns = await f.key.ns("chatgpt", "account-1");
        await f.activate("chatgpt", ns);
        for (const stream of streams) {
          await f.publish({
            connector: "chatgpt",
            ns,
            stream,
            generation: 1,
            records:
              stream === "conversations"
                ? [
                    {
                      id: "c1",
                      title: "t",
                      create_time: "2026-01-01T00:00:00.000Z",
                      update_time: "2026-01-02T00:00:00.000Z",
                      current_node: "c1:n0",
                      message_count_on_current_branch: 1,
                    },
                  ]
                : [
                    {
                      id: "c1:n0",
                      conversation_id: "c1",
                      parent_id: null,
                      role: "user",
                      content: "hi",
                      content_type: "text",
                      model_slug: null,
                      create_time: "2026-01-01T00:00:00.000Z",
                      on_current_branch: true,
                    },
                  ],
            complete: true,
            observedAt: HEAD_AT,
          });
        }
      };

    it("lists the legacy name only while every stream it joins is served", async () => {
      const partial = await setup({ seed: seedChatgpt(["conversations"]) });
      expect(names(await partial.list("?scopePrefix=chatgpt"))).toEqual([]);
      expect(names(await partial.list("?scopePrefix=pdpp.chatgpt"))).toEqual([
        "pdpp.chatgpt.conversations",
      ]);

      const whole = await setup({
        seed: seedChatgpt(["conversations", "messages"]),
      });
      expect((await whole.read("chatgpt.conversations")).status).toBe(200);
      expect(names(await whole.list("?scopePrefix=chatgpt"))).toEqual([
        "chatgpt.conversations",
      ]);
    });
  });
});
