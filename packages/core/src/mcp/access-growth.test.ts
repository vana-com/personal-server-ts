import { describe, expect, it, vi } from "vitest";
import { MCP_TOOLS, type McpToolContext } from "./tools.js";
import {
  handleMcpStreamableHttpRequest,
  MCP_SERVER_INSTRUCTIONS,
} from "./server.js";

import {
  createMcpDataReadClient,
  McpDataReadError,
  type McpDataReadClient,
} from "./read-client.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { readRawScopeResource } from "./resources.js";
import { areMcpConnectionGrantsLive } from "./connection-api.js";
import { templateMcpScopeRequestApprovalUrl } from "./approval-url.js";
import type { McpConnectionRecord } from "./types.js";
import type { ScopeSummary } from "../storage/index/types.js";

function tool(name: string) {
  const found = MCP_TOOLS.find((t) => t.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}

function connection(scopes = ["instagram.*"]): McpConnectionRecord {
  return {
    id: "conn-1",
    displayName: "Test client",
    granteeAddress: "0x1111111111111111111111111111111111111111",
    granteePublicKey: "0x04deadbeef",
    encryptedGranteePrivateKey: { kind: "plaintext", privateKey: "0x22" },
    tokenHash: "h",
    status: "approved",
    grants: [{ grantId: "grant-1", scopes }],
    createdAt: "2026-06-05T00:00:00Z",
    approvedAt: "2026-06-05T00:00:00Z",
  } as McpConnectionRecord;
}

const owned = (scope: string): ScopeSummary => ({
  scope,
  latestCollectedAt: "2026-11-01T00:00:00Z",
  versionCount: 1,
  dataStatus: "ready",
});

function readClient(
  overrides: Partial<McpDataReadClient> = {},
): McpDataReadClient {
  return {
    listScopes: vi.fn().mockResolvedValue({
      status: 200,
      scopes: [],
      total: 0,
      limit: 0,
      offset: 0,
    }),
    getScopeMetadata: vi.fn().mockResolvedValue(null),
    readScopeBlocks: vi.fn().mockRejectedValue(new Error("not mocked")),
    readRawScopeFile: vi.fn().mockRejectedValue(new Error("not mocked")),
    ...overrides,
  };
}

function parse(result: { content: Array<{ type: string; text?: string }> }) {
  return JSON.parse(result.content[0].text as string) as Record<
    string,
    unknown
  >;
}

async function listGranted(
  ctx: Partial<McpToolContext> & { rc: McpDataReadClient },
) {
  const { rc, ...rest } = ctx;
  return parse(
    await tool("list_granted_scopes").handler(
      {},
      { connection: connection(), readClient: rc, ...rest },
    ),
  );
}

describe("notShared (mcpExposeUnsharedScopes)", () => {
  const ownerScopes = [
    owned("instagram.profile"), // covered by instagram.*
    owned("youtube.history"),
    owned("spotify.library"),
    owned("memory.claude"), // memory: excluded
    owned("vana.system.state"), // system: excluded
  ];

  it("lists only scopes bounded read can serve: indexing or unknown readiness is omitted", async () => {
    const listOwnerScopes = vi
      .fn()
      .mockResolvedValue([
        owned("youtube.history"),
        { ...owned("spotify.library"), dataStatus: "indexing" },
        { ...owned("netflix.views"), dataStatus: undefined },
      ]);
    const body = await listGranted({
      rc: readClient({ listOwnerScopes }),
      exposeUnsharedScopes: true,
      verifyGrantsLive: async () => true,
    });
    expect(body.notShared).toEqual([
      expect.objectContaining({
        scope: "youtube.history",
        dataStatus: "ready",
      }),
    ]);
  });

  it("off: output has no notShared and the owner listing is never read", async () => {
    const listOwnerScopes = vi.fn().mockResolvedValue(ownerScopes);
    const rc = readClient({ listOwnerScopes });
    const body = await listGranted({ rc });
    expect("notShared" in body).toBe(false);
    expect(listOwnerScopes).not.toHaveBeenCalled();
  });

  it("on: lists uncovered owner scopes, not covered, memory or system ones", async () => {
    const rc = readClient({
      listOwnerScopes: vi.fn().mockResolvedValue(ownerScopes),
    });
    const body = await listGranted({
      rc,
      exposeUnsharedScopes: true,
      verifyGrantsLive: async () => true,
    });
    expect(body.notShared).toEqual([
      {
        scope: "spotify.library",
        source: "spotify",
        collectedAt: "2026-11-01T00:00:00Z",
        dataStatus: "ready",
      },
      {
        scope: "youtube.history",
        source: "youtube",
        collectedAt: "2026-11-01T00:00:00Z",
        dataStatus: "ready",
      },
    ]);
  });

  it("on: a read client without listOwnerScopes, or one that fails, gives an empty list", async () => {
    expect(
      (
        await listGranted({
          rc: readClient(),
          exposeUnsharedScopes: true,
          verifyGrantsLive: async () => true,
        })
      ).notShared,
    ).toEqual([]);
    const failing = readClient({
      listOwnerScopes: vi.fn().mockRejectedValue(new Error("boom")),
    });
    expect(
      (
        await listGranted({
          rc: failing,
          exposeUnsharedScopes: true,
          verifyGrantsLive: async () => true,
        })
      ).notShared,
    ).toEqual([]);
  });

  it("adds the description and instruction sentence only when on", async () => {
    const request = (method: string, params: unknown) =>
      new Request("http://localhost/mcp/t", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
    const run = async (exposeUnsharedScopes?: boolean) => {
      const options = {
        connection: connection(),
        readClient: readClient(),
        exposeUnsharedScopes,
      };
      const init = (await (
        await handleMcpStreamableHttpRequest(
          request("initialize", {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "c", version: "1" },
          }),
          options,
        )
      ).json()) as { result: { instructions: string } };
      const list = (await (
        await handleMcpStreamableHttpRequest(request("tools/list", {}), options)
      ).json()) as {
        result: { tools: Array<{ name: string; description: string }> };
      };
      return {
        instructions: init.result.instructions,
        description: list.result.tools.find(
          (t) => t.name === "list_granted_scopes",
        )?.description,
      };
    };
    const off = await run(undefined);
    const on = await run(true);
    expect(off.instructions).toBe(MCP_SERVER_INSTRUCTIONS);
    expect(off.description).toBe(tool("list_granted_scopes").description);
    expect(on.instructions).toContain("notShared");
    expect(on.instructions).toContain("request_scope_access");
    expect(on.description).toContain("notShared");
  });
});

describe("notShared fails closed on dead grants", () => {
  const ownerScopes = [owned("youtube.history")];

  const gatewayWith = (grant: Record<string, unknown> | null) =>
    ({ getGrant: vi.fn().mockResolvedValue(grant) }) as never;

  const live = {
    id: "grant-1",
    scopes: ["instagram.*"],
    grantVersion: "1",
    expiresAt: null,
    revokedAt: null,
    expired: false,
  };

  it.each([
    ["live", live, true],
    ["revoked", { ...live, revokedAt: "2026-11-01T00:00:00Z" }, false],
    ["expired flag", { ...live, expired: true }, false],
    ["past expiresAt", { ...live, expiresAt: "1000" }, false],
    ["unknown at gateway", null, false],
  ])("%s grant", async (_name, grant, shown) => {
    const listOwnerScopes = vi.fn().mockResolvedValue(ownerScopes);
    const rc = readClient({ listOwnerScopes });
    const gateway = gatewayWith(grant);
    const body = await listGranted({
      rc,
      exposeUnsharedScopes: true,
      verifyGrantsLive: () => areMcpConnectionGrantsLive(connection(), gateway),
    });
    if (shown) {
      expect(body.notShared).toHaveLength(1);
      expect(listOwnerScopes).toHaveBeenCalledTimes(1);
    } else {
      expect("notShared" in body).toBe(false);
      expect(listOwnerScopes).not.toHaveBeenCalled();
    }
  });

  it("omits notShared when the gateway lookup fails or no check is wired", async () => {
    const listOwnerScopes = vi.fn().mockResolvedValue(ownerScopes);
    const rc = readClient({ listOwnerScopes });
    const failing = {
      getGrant: vi.fn().mockRejectedValue(new Error("down")),
    } as never;
    for (const verifyGrantsLive of [
      () => areMcpConnectionGrantsLive(connection(), failing),
      undefined,
    ]) {
      const body = await listGranted({
        rc,
        exposeUnsharedScopes: true,
        verifyGrantsLive,
      });
      expect("notShared" in body).toBe(false);
    }
    expect(listOwnerScopes).not.toHaveBeenCalled();
  });

  it("mixed live and revoked grants are not live", async () => {
    const two = {
      ...connection(),
      grants: [
        { grantId: "grant-1", scopes: ["instagram.*"] },
        { grantId: "grant-2", scopes: ["spotify.*"] },
      ],
    };
    const gateway = {
      getGrant: vi.fn(async (id: string) =>
        id === "grant-2"
          ? { ...live, id, revokedAt: "2026-11-01T00:00:00Z" }
          : live,
      ),
    } as never;
    expect(await areMcpConnectionGrantsLive(two, gateway)).toBe(false);
    const listOwnerScopes = vi.fn().mockResolvedValue(ownerScopes);
    const body = await listGranted({
      rc: readClient({ listOwnerScopes }),
      exposeUnsharedScopes: true,
      verifyGrantsLive: () => areMcpConnectionGrantsLive(two, gateway),
    });
    expect("notShared" in body).toBe(false);
    expect(listOwnerScopes).not.toHaveBeenCalled();
  });

  it.each([undefined, false])(
    "option %s: the liveness check and owner listing are never called",
    async (flag) => {
      const verifyGrantsLive = vi.fn().mockResolvedValue(true);
      const listOwnerScopes = vi.fn().mockResolvedValue(ownerScopes);
      const body = await listGranted({
        rc: readClient({ listOwnerScopes }),
        exposeUnsharedScopes: flag,
        verifyGrantsLive,
      });
      expect("notShared" in body).toBe(false);
      expect(verifyGrantsLive).not.toHaveBeenCalled();
      expect(listOwnerScopes).not.toHaveBeenCalled();
    },
  );

  it("a liveness check that never settles times out: granted scopes return, notShared is omitted", async () => {
    vi.useFakeTimers();
    try {
      const listOwnerScopes = vi.fn().mockResolvedValue(ownerScopes);
      const pending = listGranted({
        rc: readClient({ listOwnerScopes }),
        exposeUnsharedScopes: true,
        verifyGrantsLive: () => new Promise<boolean>(() => {}),
      });
      await vi.advanceTimersByTimeAsync(3_500);
      const body = await pending;
      expect(body.scopes).toBeDefined();
      expect("notShared" in body).toBe(false);
      expect(listOwnerScopes).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("a connection with no grants is not live", async () => {
    const empty = { ...connection(), grants: [] };
    expect(await areMcpConnectionGrantsLive(empty, gatewayWith(live))).toBe(
      false,
    );
  });
});

describe("listOwnerScopes (read client)", () => {
  function clientWith(total: number, scopeListing = vi.fn()) {
    const all = Array.from({ length: total }, (_, i) =>
      owned(`src${String(i).padStart(4, "0")}.data`),
    );
    all.push(owned("vana.system.private"));
    const listScopes = vi.fn((p: { limit?: number; offset?: number } = {}) => {
      scopeListing(p);
      const visible = all.filter((s) => !s.scope.startsWith("vana.system."));
      const offset = p.offset ?? 0;
      return {
        scopes: visible.slice(offset, offset + (p.limit ?? 20)),
        total: visible.length,
      };
    });
    const client = createMcpDataReadClient({
      serverOrigin: "https://ps.test",
      granteeAccount: {
        address: "0x1111111111111111111111111111111111111111",
        publicKey: "0x04deadbeef",
        signTypedData: vi.fn(),
        signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
      } as never,
      dataApiDeps: {
        storage: { listScopes, findEntry: () => undefined } as never,
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead: vi.fn(),
        },
        accessLogWriter: { write: vi.fn() },
      },
    });
    return { client, listScopes };
  }

  it("pages past the default limit of 20 and skips system scopes", async () => {
    const { client, listScopes } = clientWith(450);
    const scopes = await client.listOwnerScopes!();
    expect(scopes).toHaveLength(450);
    expect(scopes.some((s) => s.scope.startsWith("vana.system."))).toBe(false);
    expect(listScopes.mock.calls.length).toBeGreaterThan(1);
  });

  it("does not touch storage until called", () => {
    const { listScopes } = clientWith(30);
    expect(listScopes).not.toHaveBeenCalled();
  });
});

describe("scope request guidance (mcpScopeRequestGuidance)", () => {
  const expected = (scope: string) =>
    `Call request_scope_access with scopes ["${scope}"], then ask the user to approve it in Vana.`;

  it.each(["read_scope", "list_scope_blocks", "get_scope_file"])(
    "%s: nextAction only when on",
    async (name) => {
      const run = async (scopeRequestGuidance?: boolean) =>
        parse(
          await tool(name).handler(
            { scope: "youtube.history" },
            {
              connection: connection(),
              readClient: readClient(),
              scopeRequestGuidance,
            },
          ),
        );
      const off = await run();
      const on = await run(true);
      expect(off.error).toBe("scope_not_granted");
      expect("nextAction" in off).toBe(false);
      expect(on.error).toBe("scope_not_granted");
      expect(on.nextAction).toBe(expected("youtube.history"));
      const { nextAction: _n, ...rest } = on;
      expect(rest).toEqual(off);
    },
  );

  it("search: one aggregated hint for all denied scopes", async () => {
    const run = async (scopeRequestGuidance?: boolean) =>
      parse(
        await tool("search_personal_context").handler(
          { query: "x", scopes: ["youtube.history", "spotify.library"] },
          {
            connection: connection(),
            readClient: readClient(),
            scopeRequestGuidance,
          },
        ),
      );
    const off = await run();
    const on = await run(true);
    expect("nextAction" in off).toBe(false);
    expect(on.nextAction).toBe(
      `Call request_scope_access with scopes ["youtube.history","spotify.library"], then ask the user to approve it in Vana.`,
    );
  });

  it("resource read: guidance only when on, as a protocol error with data", async () => {
    const uri = new URL("vana://scope/youtube.history/raw");
    const attempt = async (scopeRequestGuidance?: boolean) => {
      try {
        await readRawScopeResource(uri, {
          connection: connection(),
          readClient: readClient(),
          scopeRequestGuidance,
        });
      } catch (err) {
        return err;
      }
      throw new Error("expected refusal");
    };
    const off = (await attempt()) as McpDataReadError;
    expect(off).toBeInstanceOf(McpDataReadError);
    expect("nextAction" in (off.body as object)).toBe(false);
    const on = (await attempt(true)) as McpError;
    expect(on).toBeInstanceOf(McpError);
    expect(on.message).toContain(expected("youtube.history"));
    expect(on.data).toMatchObject({
      error: "scope_not_granted",
      nextAction: expected("youtube.history"),
    });
  });

  it("resources/read over the transport: the client sees nextAction only when on", async () => {
    const read = async (scopeRequestGuidance?: boolean) => {
      const response = await handleMcpStreamableHttpRequest(
        new Request("http://localhost/mcp/t", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "resources/read",
            params: { uri: "vana://scope/youtube.history/raw" },
          }),
        }),
        {
          connection: connection(),
          readClient: readClient(),
          scopeRequestGuidance,
        },
      );
      return (await response.json()) as {
        error?: { message: string; data?: Record<string, unknown> };
      };
    };
    const off = await read();
    expect(off.error).toBeDefined();
    expect(JSON.stringify(off)).not.toContain("nextAction");
    expect(JSON.stringify(off)).not.toContain("request_scope_access");
    const on = await read(true);
    expect(on.error?.message).toContain(expected("youtube.history"));
    expect(on.error?.data).toMatchObject({
      error: "scope_not_granted",
      scope: "youtube.history",
      nextAction: expected("youtube.history"),
    });
  });

  it("request_scope_access text is unchanged by the option", async () => {
    const run = async (scopeRequestGuidance?: boolean) =>
      parse(
        await tool("request_scope_access").handler(
          { scopes: ["youtube.history"] },
          {
            connection: connection(),
            readClient: readClient(),
            scopeRequestGuidance,
            scopeRequestApprovalUrl: () => "vana://x?connection=conn-1",
          },
        ),
      );
    expect(await run(true)).toEqual(await run());
  });
});

describe("templateMcpScopeRequestApprovalUrl", () => {
  const hook = templateMcpScopeRequestApprovalUrl(
    "vana://mcp-scope-request?connection={connectionId}#t={token}",
  );

  it("encodes the connection id and puts the token only in the fragment", () => {
    expect(hook("a b/c", { readToken: "tok en" })).toBe(
      "vana://mcp-scope-request?connection=a%20b%2Fc#t=tok%20en",
    );
  });

  it("drops the fragment when there is no token", () => {
    expect(hook("c1", {})).toBe("vana://mcp-scope-request?connection=c1");
  });

  it("rejects a template that puts the token before the fragment", () => {
    expect(() =>
      templateMcpScopeRequestApprovalUrl("vana://x?t={token}"),
    ).toThrow(/after '#'/);
  });
});
