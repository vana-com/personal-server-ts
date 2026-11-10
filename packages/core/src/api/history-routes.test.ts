import { describe, expect, it, vi } from "vitest";
import { ProtocolError } from "../errors/catalog.js";
import type { LocalHistory } from "../localdb/history.js";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";

const legacy = vi.hoisted(() => ({
  additions: vi.fn(),
  versions: vi.fn(),
}));

// History routing is tested independently of the storage implementations.
vi.mock("../contracts/data.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../contracts/data.js")>()),
  summarizeDataAdditionsContract: legacy.additions,
  listDataVersionsContract: legacy.versions,
}));

const OWNER = "0x0000000000000000000000000000000000000001";
const SCOPE = "example.items";
const LEGACY_ADDITIONS = {
  version: 1,
  total: 3,
  days: [{ date: "2026-11-01", count: 1 }],
  buckets: [],
  daily: [],
  fineSince: "2026-10-23T00:00:00.000Z",
  trackedSince: null,
  partial: false,
  scopes: [],
};
const LEGACY_VERSIONS = {
  scope: SCOPE,
  versions: [
    {
      fileId: "legacy-head",
      schemaId: null,
      collectedAt: "2026-11-01T00:00:00.000Z",
      version: 2,
      producer: null,
      producer_provenance: null,
    },
  ],
  total: 1,
  limit: 20,
  offset: 0,
};
const LEGACY_LINEAGE = {
  data: { scope: SCOPE, version: 2, sources: ["source-id"] },
  proof: { signature: "fixture-proof" },
};

// Literal bytes keep a change to dispatch, serialization or the envelope visible.
const GOLDEN = [
  '{"version":1,"total":3,"days":[{"date":"2026-11-01","count":1}],"buckets":[],"daily":[],"fineSince":"2026-10-23T00:00:00.000Z","trackedSince":null,"partial":false,"scopes":[]}',
  '{"scope":"example.items","versions":[{"fileId":"legacy-head","schemaId":null,"collectedAt":"2026-11-01T00:00:00.000Z","version":2,"producer":null,"producer_provenance":null}],"total":1,"limit":20,"offset":0}',
  '{"data":{"scope":"example.items","version":2,"sources":["source-id"]},"proof":{"signature":"fixture-proof"}}',
];
const PATHS = ["/additions", `/${SCOPE}/versions`, `/${SCOPE}/lineage`];

function fixture(mode: "switched" | "unswitched") {
  const events: string[] = [];
  const auth = {
    authorizeOwner: vi.fn(async () => {
      events.push("owner-auth");
    }),
    authorizeBuilderList: vi.fn(async () => {
      events.push("list-auth");
    }),
    authorizeScopeVersions: vi.fn(async () => {
      events.push("versions-auth");
    }),
    authorizeBuilderRead: vi.fn(async () => {
      events.push("read-auth");
      return { grantId: "owner" };
    }),
  };
  const history: LocalHistory = {
    additions: vi.fn<LocalHistory["additions"]>(async () => {
      events.push("history-additions");
      return { ...LEGACY_ADDITIONS, total: 9 } as Awaited<
        ReturnType<LocalHistory["additions"]>
      >;
    }),
    versions: vi.fn<LocalHistory["versions"]>(
      async ({ scope, limit, offset }) => {
        events.push("history-versions");
        return {
          ok: true,
          value: { scope, versions: [], total: 0, limit, offset },
        };
      },
    ),
    lineage: vi.fn<LocalHistory["lineage"]>(async ({ scope, version }) => {
      events.push("history-lineage");
      return {
        ok: true,
        value: { scope, version: version ?? 8, sources: [], proof: null },
      };
    }),
  };
  const deps: PersonalServerDataApiDeps & { history: LocalHistory } = {
    auth,
    history,
    serverOwner: OWNER,
    accountMode: { read: vi.fn(() => mode) },
    storage: new Proxy({} as PersonalServerDataApiDeps["storage"], {
      get: () => {
        throw new Error("Unexpected legacy storage access");
      },
    }),
    lineageGateway: {
      getLineage: vi.fn(async () => ({ ok: true, ...LEGACY_LINEAGE })),
    } as unknown as PersonalServerDataApiDeps["lineageGateway"],
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "history-log",
  };
  legacy.additions.mockReset().mockResolvedValue(LEGACY_ADDITIONS);
  legacy.versions.mockReset().mockResolvedValue({
    ok: true,
    scope: SCOPE,
    response: LEGACY_VERSIONS,
  });
  return { deps, history, events };
}

function request(path: string, deps: PersonalServerDataApiDeps) {
  return handlePersonalServerDataRequest(
    new Request(`https://server.example/v1/data${path}`),
    deps,
    { basePath: "/v1/data" },
  );
}

describe("history routes", () => {
  it("unswitched-history-routes-unchanged", async () => {
    const { deps, history } = fixture("unswitched");
    const bytes: string[] = [];
    for (const path of PATHS) {
      const response = await request(path, deps);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("application/json");
      bytes.push(await response.text());
    }
    expect(bytes).toEqual(GOLDEN);
    expect(history.additions).not.toHaveBeenCalled();
    expect(history.versions).not.toHaveBeenCalled();
    expect(history.lineage).not.toHaveBeenCalled();
  });

  it("a switched owner uses local history after existing auth, preserves parsing and maps refusals without 501", async () => {
    const { deps, history, events } = fixture("switched");
    for (const [index, path] of PATHS.entries()) {
      events.length = 0;
      const response = await request(path, deps);
      expect(response.status).toBe(200);
      expect(events).toEqual([
        ["owner-auth", "versions-auth", "read-auth"][index],
        ["history-additions", "history-versions", "history-lineage"][index],
      ]);
      if (index === 2) {
        expect(await response.json()).toEqual({
          data: { scope: SCOPE, version: 8, sources: [] },
          proof: null,
        });
      }
    }
    expect(history.additions).toHaveBeenCalledWith({
      timezone: "UTC",
      days: 7,
    });
    expect(history.versions).toHaveBeenCalledWith({
      scope: SCOPE,
      limit: 20,
      offset: 0,
    });
    expect(history.lineage).toHaveBeenCalledWith({
      scope: SCOPE,
      version: undefined,
    });
    expect(deps.accountMode!.read).toHaveBeenCalledWith(OWNER);
    expect(deps.accessLogWriter.write).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "lineage",
        scope: SCOPE,
        grantId: "owner",
      }),
    );
    expect(legacy.additions).not.toHaveBeenCalled();
    expect(legacy.versions).not.toHaveBeenCalled();
    expect(deps.lineageGateway!.getLineage).not.toHaveBeenCalled();

    for (const [suffix, timezone, days] of [
      ["?tz=America%2FNew_York&days=007", "America/New_York", 7],
      ["?tz=&days=0", "", 0],
      ["?days=999", "UTC", 999],
      ["?days=", "UTC", Number.NaN],
      ["?days=1e1", "UTC", Number.NaN],
      ["?days=0x7", "UTC", Number.NaN],
      ["?days=%207", "UTC", Number.NaN],
      ["?days=1000", "UTC", Number.NaN],
    ] as const) {
      expect((await request(`/additions${suffix}`, deps)).status).toBe(200);
      expect(history.additions).toHaveBeenLastCalledWith({ timezone, days });
    }
    await request(`/${SCOPE}/versions?limit=5&offset=3`, deps);
    expect(history.versions).toHaveBeenLastCalledWith({
      scope: SCOPE,
      limit: 5,
      offset: 3,
    });
    await request(`/${SCOPE}/versions?limit=-1&offset=oops`, deps);
    expect(history.versions).toHaveBeenLastCalledWith({
      scope: SCOPE,
      limit: 20,
      offset: 0,
    });
    await request(`/${SCOPE}/lineage/4`, deps);
    expect(history.lineage).toHaveBeenLastCalledWith({
      scope: SCOPE,
      version: 4,
    });

    // The existing scope/version validation still precedes local lookup.
    for (const path of [
      "/invalid/versions",
      `/${SCOPE}/lineage/0`,
      `/${SCOPE}/lineage?version=2`,
      `/${SCOPE}/lineage/9007199254740993`,
    ]) {
      vi.mocked(history.versions).mockClear();
      vi.mocked(history.lineage).mockClear();
      expect((await request(path, deps)).status).toBe(400);
      expect(history.versions).not.toHaveBeenCalled();
      expect(history.lineage).not.toHaveBeenCalled();
    }

    for (const reason of ["not_found", "deleted"] as const) {
      vi.mocked(history.versions).mockResolvedValue({ ok: false, reason });
      vi.mocked(history.lineage).mockResolvedValue({ ok: false, reason });
      for (const path of PATHS.slice(1)) {
        const response = await request(path, deps);
        expect(response.status).toBe(reason === "not_found" ? 404 : 410);
        expect((await response.json()).error.errorCode).toBe(
          reason === "not_found" ? "NOT_FOUND" : "DATA_DELETED",
        );
      }
    }

    // An absent local service is unavailable, never legacy fallback or 501.
    for (const path of PATHS) {
      expect(
        (await request(path, { ...deps, history: undefined })).status,
      ).toBe(503);
    }

    for (const [index, path] of PATHS.entries()) {
      const denied = fixture("switched");
      const reject = async () => {
        throw new ProtocolError(403, "TEST_DENIED", "Denied");
      };
      if (index === 0) denied.deps.auth.authorizeOwner = reject;
      if (index === 1) denied.deps.auth.authorizeScopeVersions = reject;
      if (index === 2) denied.deps.auth.authorizeBuilderRead = reject;
      expect((await request(path, denied.deps)).status).toBe(403);
      expect(denied.deps.accountMode!.read).not.toHaveBeenCalled();
      expect(denied.history.additions).not.toHaveBeenCalled();
      expect(denied.history.versions).not.toHaveBeenCalled();
      expect(denied.history.lineage).not.toHaveBeenCalled();
    }

    const uncovered = fixture("switched");
    uncovered.deps.auth.authorizeScopeVersions = async () => ({
      grantedScopes: [],
    });
    expect((await request(PATHS[1]!, uncovered.deps)).status).toBe(403);
    expect(uncovered.history.versions).not.toHaveBeenCalled();

    const fallback = fixture("switched");
    delete fallback.deps.auth.authorizeScopeVersions;
    await request(PATHS[1]!, fallback.deps);
    expect(fallback.events).toEqual(["list-auth", "history-versions"]);
  });
});
