import { describe, expect, it, vi } from "vitest";
import {
  handleMcpStreamableHttpRequest,
  type HandleMcpRequestOptions,
} from "./server.js";
import { MCP_TOOLS } from "./tools.js";
import { liveMcpGrantIds } from "./connection-api.js";
import type { McpDataReadClient } from "./read-client.js";
import type { McpConnectionRecord } from "./types.js";
import type { ScopeSummary } from "../storage/index/types.js";

/**
 * A client must learn nothing about data it was not granted. Two owners hold
 * different data (A has youtube.history, B does not); the connection grants,
 * the host options and the catalog are the same. Every response to a request
 * that touches the ungranted scope must be byte-identical across owners.
 */

const CATALOG = ["chatgpt.conversations", "youtube.history", "spotify.library"];

function connection(): McpConnectionRecord {
  return {
    id: "conn-1",
    displayName: "Test client",
    granteeAddress: "0x1111111111111111111111111111111111111111",
    granteePublicKey: "0x04deadbeef",
    encryptedGranteePrivateKey: { kind: "plaintext", privateKey: "0x22" },
    tokenHash: "h",
    status: "approved",
    grants: [{ grantId: "grant-1", scopes: ["chatgpt.conversations"] }],
    createdAt: "2026-06-05T00:00:00Z",
    approvedAt: "2026-06-05T00:00:00Z",
  } as McpConnectionRecord;
}

const owned = (scope: string, at: string): ScopeSummary => ({
  scope,
  latestCollectedAt: at,
  versionCount: 3,
  dataStatus: "ready",
});

/** Owner data differs by construction; every read method is a spy. */
function ownerClient(scopes: ScopeSummary[]) {
  const page = (rows: ScopeSummary[]) => ({
    status: 200 as const,
    scopes: rows,
    total: rows.length,
    limit: 100,
    offset: 0,
  });
  const client: McpDataReadClient = {
    listScopes: vi.fn().mockResolvedValue(page(scopes)),
    getScopeMetadata: vi
      .fn()
      .mockImplementation(
        async (scope: string) => scopes.find((s) => s.scope === scope) ?? null,
      ),
    readScopeBlocks: vi.fn().mockRejectedValue(new Error("owner read")),
    readRawScopeFile: vi.fn().mockRejectedValue(new Error("owner read")),
    listOwnerScopes: vi.fn().mockResolvedValue(scopes),
  };
  return client;
}

const ownerA = () =>
  ownerClient([
    owned("chatgpt.conversations", "2026-11-01T00:00:00Z"),
    owned("youtube.history", "2026-11-02T00:00:00Z"),
  ]);
const ownerB = () =>
  ownerClient([owned("chatgpt.conversations", "2026-10-15T00:00:00Z")]);

let nextId = 0;
async function rpc(
  readClient: McpDataReadClient,
  method: string,
  params: unknown,
  extra: Partial<HandleMcpRequestOptions> = {},
  conn: McpConnectionRecord = connection(),
): Promise<string> {
  const response = await handleMcpStreamableHttpRequest(
    new Request("http://localhost/mcp/t", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++nextId, method, params }),
    }),
    {
      connection: conn,
      readClient,
      exposeUnsharedScopes: false,
      scopeRequestGuidance: true,
      requestableScopes: CATALOG,
      ...extra,
    },
  );
  return response.text();
}

/**
 * Stripped because they differ by construction, not by owner data:
 * - JSON-RPC `id` (a per-call counter),
 * - `elapsedMs` (wall-clock timing).
 * Nothing else is stripped; timestamps from owner data are not present in
 * these responses, and if one appeared the test would fail.
 */
function normalize(body: string): string {
  return body
    .replace(/"id":\d+/gu, '"id":N')
    .replace(/elapsedMs\\*":\d+/gu, 'elapsedMs":N');
}

const tool = (name: string, args: Record<string, unknown>) => ({
  method: "tools/call",
  params: { name, arguments: args },
});

const CASES: Array<{
  name: string;
  method: string;
  params: unknown;
}> = [
  {
    name: "initialize (instructions)",
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "c", version: "1" },
    },
  },
  { name: "tools/list", method: "tools/list", params: {} },
  { name: "list_granted_scopes", ...tool("list_granted_scopes", {}) },
  { name: "resources/list", method: "resources/list", params: {} },
  {
    name: "resources/templates/list",
    method: "resources/templates/list",
    params: {},
  },
  {
    name: "search_personal_context(no scopes)",
    ...tool("search_personal_context", { query: "videos" }),
  },
  {
    name: 'request_scope_access(["youtube.history"])',
    ...tool("request_scope_access", { scopes: ["youtube.history"] }),
  },
  {
    name: 'read_scope("youtube.history")',
    ...tool("read_scope", { scope: "youtube.history" }),
  },
  {
    name: 'search_personal_context(scopes ["youtube.history"])',
    ...tool("search_personal_context", {
      query: "videos",
      scopes: ["youtube.history"],
    }),
  },
  {
    name: 'list_scope_blocks("youtube.history")',
    ...tool("list_scope_blocks", { scope: "youtube.history" }),
  },
  {
    name: 'get_scope_file("youtube.history")',
    ...tool("get_scope_file", {
      scope: "youtube.history",
      path: "manifest.json",
    }),
  },
];

describe("ungranted data is invisible to a connected client (mcpExposeUnsharedScopes=false)", () => {
  it.each(CASES)(
    "$name is byte-identical whether or not the owner has the data",
    async ({ method, params }) => {
      const a = normalize(await rpc(ownerA(), method, params));
      const b = normalize(await rpc(ownerB(), method, params));
      expect(a).toBe(b);
      expect(a.length).toBeGreaterThan(0);
    },
  );

  it("no response mentions notShared or leaks an ungranted scope's existence", async () => {
    for (const { method, params } of CASES) {
      const body = await rpc(ownerA(), method, params);
      expect(body).not.toContain("notShared");
      expect(body).not.toContain("2026-11-02");
    }
  });

  it("request_scope_access does not call any owner-data read", async () => {
    const client = ownerA();
    await rpc(
      client,
      "tools/call",
      tool("request_scope_access", { scopes: ["youtube.history"] }).params,
    );
    for (const method of [
      "listScopes",
      "getScopeMetadata",
      "readScopeBlocks",
      "readRawScopeFile",
      "listOwnerScopes",
    ] as const) {
      expect(client[method]).not.toHaveBeenCalled();
    }
  });

  it("the generic guidance and the host scope list reach the client, sorted", async () => {
    const init = await rpc(ownerB(), "initialize", CASES[0].params);
    expect(init).toContain(
      "If the user's question needs data you were not granted, call request_scope_access with the scope ids you need. The user chooses in Vana; the response does not tell you whether that data exists.",
    );
    const list = JSON.parse(await rpc(ownerB(), "tools/list", {})) as {
      result: { tools: Array<{ name: string; description: string }> };
    };
    const description = list.result.tools.find(
      (t) => t.name === "request_scope_access",
    )?.description;
    expect(description).toContain(
      " Scope ids Vana supports (not a list of what this user has): chatgpt.conversations, spotify.library, youtube.history",
    );
  });

  it("request_scope_access records the request, and answers the same for an owned and a not-owned scope", async () => {
    const run = async (scope: string, owner: McpDataReadClient) => {
      const requestScopeAccess = vi.fn().mockImplementation(async () => ({
        connection: connection(),
        requestRecorded: true,
      }));
      const body = await rpc(
        owner,
        "tools/call",
        tool("request_scope_access", { scopes: [scope] }).params,
        { requestScopeAccess },
      );
      return { body: normalize(body), requestScopeAccess };
    };
    const owned = await run("youtube.history", ownerA());
    const notOwned = await run("youtube.history", ownerB());
    const other = await run("spotify.library", ownerA());
    expect(owned.requestScopeAccess).toHaveBeenCalledWith({
      scopes: ["youtube.history"],
    });
    expect(notOwned.requestScopeAccess).toHaveBeenCalledTimes(1);
    expect(owned.body).toBe(notOwned.body);
    // Not owned by either owner: same shape, only the echoed scope id differs.
    expect(other.body.replaceAll("spotify.library", "youtube.history")).toBe(
      owned.body,
    );
  });
});

describe("a grant the gateway no longer honours reveals nothing new", () => {
  const revoked = { verifyGrantsLive: async () => [] };
  const neverGranted = (): McpConnectionRecord => ({
    ...connection(),
    grants: [],
  });
  const REVOKED_CASES = [
    tool("list_granted_scopes", {}),
    tool("read_scope", { scope: "chatgpt.conversations" }),
    tool("list_scope_blocks", { scope: "chatgpt.conversations" }),
    tool("search_personal_context", {
      query: "x",
      scopes: ["chatgpt.conversations"],
    }),
    tool("get_scope_file", {
      scope: "chatgpt.conversations",
      path: "manifest.json",
    }),
    { method: "resources/list", params: {} },
  ];

  it.each(REVOKED_CASES)(
    "$params.name after revocation: byte-identical with or without newly imported data, and no owner read",
    async ({ method, params }) => {
      const before = ownerClient([]);
      const after = ownerA(); // new data imported after the grant ended
      const a = normalize(await rpc(before, method, params, revoked));
      const b = normalize(await rpc(after, method, params, revoked));
      expect(a).toBe(b);
      for (const client of [before, after]) {
        for (const read of [
          "listScopes",
          "getScopeMetadata",
          "readScopeBlocks",
          "readRawScopeFile",
          "listOwnerScopes",
        ] as const)
          expect(client[read]).not.toHaveBeenCalled();
      }
    },
  );

  it("a revoked grant answers exactly as a connection that never had one", async () => {
    for (const { method, params } of REVOKED_CASES) {
      const gone = normalize(
        await rpc(ownerA(), method, params, revoked, connection()),
      );
      const never = normalize(
        await rpc(ownerA(), method, params, {}, neverGranted()),
      );
      expect(gone).toBe(never);
    }
  });

  it("fails closed when the liveness check throws", async () => {
    const client = ownerA();
    const body = await rpc(
      client,
      "tools/call",
      tool("list_granted_scopes", {}).params,
      {
        verifyGrantsLive: async () => {
          throw new Error("gateway down");
        },
      },
    );
    expect(body).not.toContain("collectedAt");
    expect(client.getScopeMetadata).not.toHaveBeenCalled();
  });

  it("a live grant still reads normally", async () => {
    const client = ownerA();
    await rpc(client, "tools/call", tool("list_granted_scopes", {}).params, {
      verifyGrantsLive: async () => ["grant-1"],
    });
    expect(client.getScopeMetadata).toHaveBeenCalledWith(
      "chatgpt.conversations",
    );
  });
});

describe("a write-only memory grant is not a read oracle", () => {
  const writeOnly = (): McpConnectionRecord => ({
    ...connection(),
    grants: [{ grantId: "g", scopes: ["write:memory.app"] }],
  });
  const writeClient = () => {
    const calls: string[] = [];
    const proxy = new Proxy(
      {},
      {
        get: (_t, prop) => {
          calls.push(String(prop));
          return () => {
            throw new Error("write client used");
          };
        },
      },
    );
    return { proxy: proxy as never, calls };
  };

  it.each([
    ["remember", { scope: "memory.app", text: "probe", key: "k" }],
    ["forget", { scope: "memory.app", key: "k" }],
  ])(
    "%s without a covering read grant is refused as never granted, before any owner access",
    async (name, args) => {
      const writer = writeClient();
      const client = ownerA();
      const result = await MCP_TOOLS.find((t) => t.name === name)!.handler(
        args,
        {
          connection: writeOnly(),
          readClient: client,
          writeClient: writer.proxy,
        },
      );
      const body = JSON.parse(result.content[0]!.text as string) as {
        error: string;
      };
      expect(result.isError).toBe(true);
      expect(body.error).toBe("scope_not_granted");
      expect(writer.calls).toEqual([]);
    },
  );

  it("the write-only remember error names the read and write scopes and equals the never-granted error", async () => {
    const run = async (conn: McpConnectionRecord) => {
      const result = await MCP_TOOLS.find(
        (t) => t.name === "remember",
      )!.handler(
        { scope: "memory.app", text: "probe" },
        { connection: conn, readClient: ownerA() },
      );
      return result.content[0]!.text as string;
    };
    const writeOnlyBody = await run(writeOnly());
    const never = await run({ ...connection(), grants: [] });
    expect(writeOnlyBody).toBe(never);
    const parsed = JSON.parse(writeOnlyBody) as {
      nextAction: string;
      requestScopes: string[];
    };
    expect(parsed.requestScopes).toEqual(["memory.app", "write:memory.app"]);
    expect(parsed.nextAction).toContain(
      JSON.stringify(["memory.app", "write:memory.app"]),
    );
  });
});

describe("only the dead grants are dropped", () => {
  const twoGrants = (): McpConnectionRecord => ({
    ...connection(),
    grants: [
      { grantId: "g-live", scopes: ["chatgpt.conversations"] },
      { grantId: "g-dead", scopes: ["youtube.history"] },
    ],
  });
  const oneGrant = (): McpConnectionRecord => ({
    ...connection(),
    grants: [{ grantId: "g-live", scopes: ["chatgpt.conversations"] }],
  });
  const readYoutube = tool("read_scope", { scope: "youtube.history" }).params;

  it("keeps the live grant, and the revoked one answers as never granted with no owner read", async () => {
    const owner = ownerA();
    const listed = JSON.parse(
      await rpc(
        owner,
        "tools/call",
        tool("list_granted_scopes", {}).params,
        { verifyGrantsLive: async () => ["g-live"] },
        twoGrants(),
      ),
    ) as {
      result: { structuredContent: { scopes: Array<{ scope: string }> } };
    };
    expect(listed.result.structuredContent.scopes.map((x) => x.scope)).toEqual([
      "chatgpt.conversations",
    ]);
    expect(owner.getScopeMetadata).toHaveBeenCalledTimes(1);
    expect(owner.getScopeMetadata).toHaveBeenCalledWith(
      "chatgpt.conversations",
    );

    const probe = ownerA();
    const dead = normalize(
      await rpc(
        probe,
        "tools/call",
        readYoutube,
        { verifyGrantsLive: async () => ["g-live"] },
        twoGrants(),
      ),
    );
    const never = normalize(
      await rpc(ownerB(), "tools/call", readYoutube, {}, oneGrant()),
    );
    expect(dead).toBe(never);
    for (const read of [
      "listScopes",
      "getScopeMetadata",
      "readScopeBlocks",
      "readRawScopeFile",
    ] as const)
      expect(probe[read]).not.toHaveBeenCalled();
  });

  it("a lookup that throws answers as with no grants", async () => {
    const gateway = {
      getGrant: vi.fn().mockImplementation(async (id: string) => {
        if (id === "g-dead") throw new Error("gateway down");
        return { grantId: id };
      }),
    } as never;
    const owner = ownerA();
    const body = await rpc(
      owner,
      "tools/call",
      tool("list_granted_scopes", {}).params,
      { verifyGrantsLive: () => liveMcpGrantIds(twoGrants(), gateway) },
      twoGrants(),
    );
    const none = await rpc(
      ownerA(),
      "tools/call",
      tool("list_granted_scopes", {}).params,
      {},
      { ...twoGrants(), grants: [] },
    );
    expect(normalize(body)).toBe(normalize(none));
    expect(owner.getScopeMetadata).not.toHaveBeenCalled();
  });

  it("looks the grants up concurrently: two 2 s lookups fit the 3 s budget", async () => {
    vi.useFakeTimers();
    try {
      const gateway = {
        getGrant: vi
          .fn()
          .mockImplementation(
            (id: string) =>
              new Promise((resolve) =>
                setTimeout(() => resolve({ grantId: id }), 2000),
              ),
          ),
      } as never;
      const owner = ownerA();
      const pending = rpc(
        owner,
        "tools/call",
        tool("list_granted_scopes", {}).params,
        { verifyGrantsLive: () => liveMcpGrantIds(twoGrants(), gateway) },
        twoGrants(),
      );
      await vi.advanceTimersByTimeAsync(2000);
      const body = await pending;
      expect(body).toContain("chatgpt.conversations");
      expect(body).toContain("youtube.history");
      expect(owner.getScopeMetadata).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
