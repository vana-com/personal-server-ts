import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { createMcpDataReadClient } from "../mcp/read-client.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { isStreamHeadCoveredByTombstone } from "../sync/scope-deletions.js";

/**
 * A delete on any surface holds on every surface. A gateway deletion of a
 * scope that only stream heads hold hides it from the listing AND refuses the
 * read with 410, in the same terms: the deletion covers a head collected at or
 * before the tombstone, and data collected after it is a re-add.
 */

const BUILDER = "0x000000000000000000000000000000000000bEEF";
const SCOPE = "pdpp.acme.items";
const HEAD_AT = Date.parse("2026-10-15T12:00:00.000Z");
const BEFORE_HEAD = "2026-10-10T00:00:00.000Z";
const AFTER_HEAD = "2026-10-20T00:00:00.000Z";

type Tracker = NonNullable<PersonalServerDataApiDeps["scopeDeletions"]>;

/** A tracker that knows one gateway tombstone of `SCOPE`. */
const tombstoneAt = (deletedAt: string, version = "7"): Tracker =>
  ({
    resolve: async (scope: string) =>
      scope === SCOPE
        ? {
            deleted: true,
            deletedAt,
            version,
            source: "gateway",
            verified: true,
          }
        : { deleted: false, source: "gateway", verified: true },
  }) as never;

async function setup(
  options: {
    complete?: boolean;
    observedAt?: number;
    scopeDeletions?: Tracker;
    seedStorage?: (
      storage: ReturnType<typeof createMemoryDataStorage>,
    ) => Promise<void>;
  } = {},
) {
  const fixture = new Fixture(await testOwnerKey(masterKey(7)));
  const ns = await fixture.key.ns("acme", "account-1");
  await fixture.activate("acme", ns);
  await fixture.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [{ id: "a" }, { id: "b" }],
    complete: options.complete ?? true,
    observedAt: options.observedAt ?? HEAD_AT,
  });
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
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => ({
        builder: BUILDER,
        grantId: "owner",
      })),
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
    deps,
    read: (scope = SCOPE) => get(`/${scope}`),
    list: async () => {
      const response = await get("/");
      expect(response.status).toBe(200);
      return (await response.json()) as {
        scopes: { scope: string; latestCollectedAt: string }[];
      };
    },
  };
}

const names = (listing: { scopes: { scope: string }[] }) =>
  listing.scopes.map((s) => s.scope);

describe("a gateway deletion of a stream-sync-only scope", () => {
  it("refuses the read and hides the listing when the head was collected before the deletion", async () => {
    const { read, list } = await setup({
      scopeDeletions: tombstoneAt(AFTER_HEAD),
    });

    const res = await read();
    expect(res.status).toBe(410);
    expect((await res.json()).error.errorCode).toBe("DATA_DELETED");
    expect(names(await list())).toEqual([]);
  });

  it("serves and lists a head collected after the deletion, under one collectedAt", async () => {
    const { read, list } = await setup({
      scopeDeletions: tombstoneAt(BEFORE_HEAD),
    });

    const res = await read();
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.records).toHaveLength(2);
    const listing = await list();
    expect(names(listing)).toEqual([SCOPE]);
    expect(listing.scopes[0]!.latestCollectedAt).toBe(body.collectedAt);
  });

  it("refuses a head collected at the very moment of the deletion", async () => {
    const { read, list } = await setup({
      scopeDeletions: tombstoneAt(new Date(HEAD_AT).toISOString()),
    });

    expect((await read()).status).toBe(410);
    expect(names(await list())).toEqual([]);
  });

  it("refuses the owner's local-pending view of a deleted scope, and serves it after a re-add", async () => {
    const deleted = await setup({
      complete: false,
      scopeDeletions: tombstoneAt(AFTER_HEAD),
    });
    expect((await deleted.read()).status).toBe(410);
    expect(names(await deleted.list())).toEqual([]);

    const readded = await setup({
      complete: false,
      scopeDeletions: tombstoneAt(BEFORE_HEAD),
    });
    const res = await readded.read();
    expect(res.status).toBe(200);
    expect((await res.json()).origin).toBe("local-pending");
    expect(names(await readded.list())).toEqual([SCOPE]);
  });

  it("refuses before any access is logged or demand is notified", async () => {
    const notifyDataRead = vi.fn();
    const { deps, read } = await setup({
      scopeDeletions: tombstoneAt(AFTER_HEAD),
    });
    deps.onDataRead = notifyDataRead;

    expect((await read()).status).toBe(410);
    expect(deps.accessLogWriter.write).not.toHaveBeenCalled();
    expect(notifyDataRead).not.toHaveBeenCalled();
  });

  it("uses the newest remembered tombstone when the gateway now shows the scope live", async () => {
    const history = (deletedAt: string): Tracker =>
      ({
        resolve: async () => ({
          deleted: false,
          source: "gateway",
          verified: true,
        }),
        deletionHistory: {
          get: () => ({ deletedAt, version: "7" }),
          remember: () => undefined,
        },
      }) as never;

    const covered = await setup({ scopeDeletions: history(AFTER_HEAD) });
    expect((await covered.read()).status).toBe(410);
    expect(names(await covered.list())).toEqual([]);

    const readded = await setup({ scopeDeletions: history(BEFORE_HEAD) });
    expect((await readded.read()).status).toBe(200);
    expect(names(await readded.list())).toEqual([SCOPE]);
  });

  it("changes nothing when no deletion tracker is wired", async () => {
    const { read, list } = await setup();

    expect((await read()).status).toBe(200);
    expect(names(await list())).toEqual([SCOPE]);
  });

  it("refuses a head that carries no trustworthy collection time", async () => {
    const { read, list } = await setup({
      observedAt: 0,
      scopeDeletions: tombstoneAt(BEFORE_HEAD),
    });

    expect((await read()).status).toBe(410);
    expect(names(await list())).toEqual([]);
  });

  it("falls back to the stored file's own re-add rule when the covered view has a legacy file", async () => {
    // The stream head predates the deletion, but the stored file was ingested
    // knowing the tombstone (a deliberate re-add): the file answers, as the
    // listing's stored row says it will.
    const seed = async (
      storage: ReturnType<typeof createMemoryDataStorage>,
      afterTombstoneVersion: number | null,
    ) => {
      const envelope = {
        version: "1.0" as const,
        scope: SCOPE,
        collectedAt: "2026-10-25T00:00:00.000Z",
        data: { records: [{ id: "readded" }] },
      };
      const written = await storage.writeEnvelope(envelope);
      storage.insertEntry({
        fileId: null,
        path: written.relativePath,
        scope: SCOPE,
        collectedAt: envelope.collectedAt,
        sizeBytes: written.sizeBytes,
        dataPointId: null,
        afterTombstoneVersion,
      } as never);
    };

    const readded = await setup({
      scopeDeletions: tombstoneAt(AFTER_HEAD, "7"),
      seedStorage: (s) => seed(s, 7),
    });
    const res = await readded.read();
    expect(res.status).toBe(200);
    expect((await res.json()).data.records).toEqual([{ id: "readded" }]);
    expect(names(await readded.list())).toEqual([SCOPE]);

    const covered = await setup({
      scopeDeletions: tombstoneAt(AFTER_HEAD, "7"),
      seedStorage: (s) => seed(s, null),
    });
    expect((await covered.read()).status).toBe(410);
    expect(names(await covered.list())).toEqual([]);
  });
});

describe("the rule that decides whether a stream head is covered", () => {
  const tombstone = { deletedAt: "2026-10-15T12:00:00.000Z" };

  it("covers a head collected at or before the deletion, and frees a later one", () => {
    expect(
      isStreamHeadCoveredByTombstone("2026-10-15T11:59:59.999Z", tombstone),
    ).toBe(true);
    expect(
      isStreamHeadCoveredByTombstone("2026-10-15T12:00:00.000Z", tombstone),
    ).toBe(true);
    expect(
      isStreamHeadCoveredByTombstone("2026-10-15T12:00:00.001Z", tombstone),
    ).toBe(false);
  });

  it("covers a head or a tombstone with no usable time", () => {
    expect(isStreamHeadCoveredByTombstone("not a time", tombstone)).toBe(true);
    expect(
      isStreamHeadCoveredByTombstone("1970-01-01T00:00:00.000Z", tombstone),
    ).toBe(true);
    expect(
      isStreamHeadCoveredByTombstone("2026-11-01T00:00:00.000Z", {
        deletedAt: "garbage",
      }),
    ).toBe(true);
  });
});

describe("the MCP read surface over a deleted stream-sync-only scope", () => {
  const account = () => ({
    address: "0x1111111111111111111111111111111111111111" as const,
    publicKey: "0x04deadbeef" as const,
    signTypedData: vi.fn(),
    signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
  });

  it("does not list the scope for a deleted head, and lists a re-added one", async () => {
    const deleted = await setup({ scopeDeletions: tombstoneAt(AFTER_HEAD) });
    const client = createMcpDataReadClient({
      serverOrigin: "https://ps.example.com",
      granteeAccount: account(),
      dataApiDeps: deleted.deps,
    });
    expect((await client.listScopes()).scopes).toEqual([]);

    const readded = await setup({ scopeDeletions: tombstoneAt(BEFORE_HEAD) });
    const again = createMcpDataReadClient({
      serverOrigin: "https://ps.example.com",
      granteeAccount: account(),
      dataApiDeps: readded.deps,
    });
    expect((await again.listScopes()).scopes.map((s) => s.scope)).toEqual([
      SCOPE,
    ]);
  });

  it("refuses a raw read of a deleted scope with 410, never reaching the stream view", async () => {
    const seedStorage = async (
      storage: ReturnType<typeof createMemoryDataStorage>,
    ) => {
      const envelope = {
        version: "1.0" as const,
        scope: SCOPE,
        collectedAt: "2026-10-01T00:00:00.000Z",
        data: { records: [{ id: "old" }] },
      };
      const written = await storage.writeEnvelope(envelope);
      storage.insertEntry({
        fileId: null,
        path: written.relativePath,
        scope: SCOPE,
        collectedAt: envelope.collectedAt,
        sizeBytes: written.sizeBytes,
        dataPointId: null,
        afterTombstoneVersion: null,
      } as never);
    };
    const { deps } = await setup({
      scopeDeletions: tombstoneAt(AFTER_HEAD),
      seedStorage,
    });
    const client = createMcpDataReadClient({
      serverOrigin: "https://ps.example.com",
      granteeAccount: account(),
      dataApiDeps: deps,
    });

    await expect(
      client.readRawScopeFile({ scope: SCOPE, grantId: "grant-1" }),
    ).rejects.toMatchObject({ status: 410 });
  });
});
