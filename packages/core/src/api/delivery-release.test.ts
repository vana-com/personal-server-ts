/**
 * Every read result of the data API (`/v1/data`, shared by Node, Lite and
 * the MCP read client) is released at one point, through the delivery lease
 * of everything the request read. No route registers anything itself: grant
 * leases come from the auth port, deletion dependencies from the deletion
 * checks. These cover result variants that once had no release gate.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  releaseDataResult,
  resolveReadDeletion,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { authorizeDataRead } from "../policy/data-read.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import {
  createScopeDeletionTracker,
  type ScopeDeletionTracker,
} from "../sync/scope-deletions.js";
import {
  createMcpDataReadClient,
  McpDataReadError,
} from "../mcp/read-client.js";

const OWNER = "0x0000000000000000000000000000000000000001" as const;
const BUILDER = "0x0000000000000000000000000000000000000002" as const;
const SCOPE = "test.records";

afterEach(() => {
  vi.useRealTimers();
});

/** A live chain grant that expires 5 s from now, verified through the policy. */
async function expiringGrantLease() {
  const grant = {
    id: "g",
    grantorAddress: OWNER,
    granteeId: BUILDER,
    scopes: [SCOPE],
    revokedAt: null,
    expiresAt: new Date(Date.now() + 5_000).toISOString(),
  };
  return authorizeDataRead(
    {
      signer: BUILDER,
      grantId: "g",
      requestedScope: SCOPE,
      serverOwner: OWNER,
    },
    {
      authSessionVerifier: {
        getBuilder: async () => ({ id: BUILDER }),
      } as never,
      grantVerifier: { getGrant: async () => grant } as never,
    },
  );
}

describe("lineage", () => {
  it("refuses a lineage graph whose grant expires during the access-log write", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { lease } = await expiringGrantLease();
    const response = await handlePersonalServerDataRequest(
      new Request(`http://ps/v1/data/${SCOPE}/lineage`),
      {
        auth: {
          authorizeBuilderRead: async () => ({
            builder: BUILDER,
            grantId: "g",
            lease,
          }),
        },
        serverOwner: OWNER,
        lineageGateway: {
          getLineage: async () => ({
            ok: true,
            data: { fixture: "private-graph" },
            proof: {},
          }),
        },
        accessLogWriter: {
          write: async () => {
            // The grant expires while the access log is written.
            vi.setSystemTime(Date.now() + 10_000);
          },
        },
      } as unknown as PersonalServerDataApiDeps,
      { basePath: "/v1/data" },
    );
    const text = await response.text();
    expect(response.status, text).toBe(403);
    expect(text).toContain("GRANT_EXPIRED");
    expect(text).not.toContain("private-graph");
  });
});

/**
 * Two versions of SCOPE and one of another scope, and a tracker whose second
 * visibility check marks SCOPE deleted: the deletion lands while the listing
 * is still being aggregated, after SCOPE was found visible.
 */
async function listingFixture() {
  const storage = createMemoryDataStorage();
  for (const [scope, at] of [
    [SCOPE, "2026-01-02T00:00:00Z"],
    ["test.other", "2026-01-02T00:00:00Z"],
    [SCOPE, "2026-01-01T00:00:00Z"],
  ] as const) {
    const envelope = {
      version: "1.0",
      scope,
      collectedAt: at,
      data: { id: "fixture" },
    };
    const written = await storage.writeEnvelope(envelope as never);
    storage.insertEntry({
      scope,
      collectedAt: at,
      path: (written as { path: string }).path,
      sizeBytes: written.sizeBytes,
      fileId: null,
    });
  }
  const tracker = createScopeDeletionTracker({ serverOwner: OWNER });
  let checks = 0;
  const deletingTracker = new Proxy(tracker, {
    get(target, prop, receiver) {
      if (prop === "resolve") {
        return async (
          scope: string,
          options: Parameters<ScopeDeletionTracker["resolve"]>[1],
        ) => {
          const verdict = await target.resolve(scope, options);
          checks += 1;
          if (checks === 2) {
            target.markDeleted(SCOPE, {
              deletedAt: "2099-01-01T00:00:00Z",
              version: "9",
            });
          }
          return verdict;
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  });
  const deps = {
    storage,
    auth: {
      authorizeBuilderList: async () => ({ grantedScopes: ["test.*"] }),
      authorizeScopeVersions: async () => ({ grantedScopes: ["test.*"] }),
    },
    serverOwner: OWNER,
    scopeDeletions: deletingTracker,
    accessLogWriter: { write: async () => undefined },
  } as unknown as PersonalServerDataApiDeps;
  return { deps, tracker, checks: () => checks };
}

describe("listings", () => {
  for (const path of ["/v1/data", `/v1/data/${SCOPE}/versions`]) {
    it(`refuses ${path} when a listed scope is deleted during aggregation`, async () => {
      const { deps, tracker, checks } = await listingFixture();
      const response = await handlePersonalServerDataRequest(
        new Request(`http://ps${path}`),
        deps,
        { basePath: "/v1/data" },
      );
      const text = await response.text();
      expect(checks()).toBeGreaterThanOrEqual(2);
      expect(tracker.knownDeletion(SCOPE)).not.toBeNull();
      expect(response.status, text).toBe(410);
      expect(text).toContain("DATA_DELETED");
      expect(text).not.toContain('"total"');
    });
  }

  it("lists normally when nothing is deleted (positive control)", async () => {
    const { deps } = await listingFixture();
    const tracker = createScopeDeletionTracker({ serverOwner: OWNER });
    const response = await handlePersonalServerDataRequest(
      new Request("http://ps/v1/data"),
      { ...deps, scopeDeletions: tracker },
      { basePath: "/v1/data" },
    );
    expect(response.status).toBe(200);
    expect((await response.json()).total).toBe(2);
  });

  it("refuses MCP discovery (the read client's listing) the same way", async () => {
    const { deps } = await listingFixture();
    const client = createMcpDataReadClient({
      serverOrigin: "http://ps",
      granteeAccount: {
        address: "0x1111111111111111111111111111111111111111",
        publicKey: "0x04deadbeef",
        signTypedData: vi.fn(),
        signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
      } as never,
      dataApiDeps: deps,
    });
    const listed = client.listScopes({ scopePrefix: "test." });
    await expect(listed).rejects.toBeInstanceOf(McpDataReadError);
    await expect(listed).rejects.toMatchObject({ status: 410 });
  });
});

describe("a result-producing handler that registers nothing", () => {
  /**
   * A new route, as a future change would add one: it authorizes through the
   * auth port and checks deletion like any route, and does nothing about the
   * delivery lease. Its result is still released only through it.
   */
  function newRoute(during: () => void) {
    return async (deps: PersonalServerDataApiDeps) => {
      await deps.auth.authorizeBuilderRead({
        request: new Request(`http://ps/v1/data/${SCOPE}/new-view`),
        scope: SCOPE,
      });
      const entry = deps.storage.findEntry({ scope: SCOPE });
      await resolveReadDeletion(deps, SCOPE, entry);
      during();
      return new Response(JSON.stringify({ secret: "new-view-body" }), {
        status: 200,
      });
    };
  }

  async function newRouteDeps(tracker: ScopeDeletionTracker) {
    const { deps } = await listingFixture();
    vi.useFakeTimers({ toFake: ["Date"] });
    const { lease } = await expiringGrantLease();
    return {
      ...deps,
      scopeDeletions: tracker,
      auth: {
        authorizeBuilderRead: async () => ({
          builder: BUILDER,
          grantId: "g",
          lease,
        }),
      },
    } as unknown as PersonalServerDataApiDeps;
  }

  it("is refused when the scope it read is deleted before release", async () => {
    const tracker = createScopeDeletionTracker({ serverOwner: OWNER });
    const deps = await newRouteDeps(tracker);
    const response = await releaseDataResult(
      new Request(`http://ps/v1/data/${SCOPE}/new-view`),
      deps,
      {},
      newRoute(() =>
        tracker.markDeleted(SCOPE, {
          deletedAt: "2099-01-01T00:00:00Z",
          version: "9",
        }),
      ),
    );
    const text = await response.text();
    expect(response.status, text).toBe(410);
    expect(text).not.toContain("new-view-body");
  });

  it("is refused when its grant expires before release", async () => {
    const tracker = createScopeDeletionTracker({ serverOwner: OWNER });
    const deps = await newRouteDeps(tracker);
    const response = await releaseDataResult(
      new Request(`http://ps/v1/data/${SCOPE}/new-view`),
      deps,
      {},
      newRoute(() => vi.setSystemTime(Date.now() + 10_000)),
    );
    const text = await response.text();
    expect(response.status, text).toBe(403);
    expect(text).not.toContain("new-view-body");
  });

  it("is released when nothing changes (positive control)", async () => {
    const tracker = createScopeDeletionTracker({ serverOwner: OWNER });
    const deps = await newRouteDeps(tracker);
    const response = await releaseDataResult(
      new Request(`http://ps/v1/data/${SCOPE}/new-view`),
      deps,
      {},
      newRoute(() => undefined),
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("new-view-body");
  });
});
