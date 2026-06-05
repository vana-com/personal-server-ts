import { describe, expect, it, vi } from "vitest";
import { MCP_TOOLS } from "./tools.js";
import type { McpConnectionRecord } from "./types.js";
import type { McpDataReadClient } from "./read-client.js";

function getTool(name: string) {
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`missing tool ${name}`);
  return tool;
}

function createConnection(): McpConnectionRecord {
  return {
    id: "conn-1",
    displayName: "Test client",
    granteeAddress: "0x1111111111111111111111111111111111111111",
    granteePublicKey: "0x04deadbeef",
    encryptedGranteePrivateKey: {
      kind: "plaintext",
      privateKey:
        "0x2222222222222222222222222222222222222222222222222222222222222222",
    },
    tokenHash: "token-hash",
    status: "approved",
    grants: [
      { grantId: "grant-1", scopes: ["instagram.*"] },
      { grantId: "grant-2", scopes: ["chatgpt.history"], sourceId: "" },
    ],
    createdAt: "2026-06-05T00:00:00Z",
    approvedAt: "2026-06-05T00:00:00Z",
  };
}

function createMinimalReadClient(
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
    getScopeMetadata: vi.fn().mockReturnValue(null),
    readScopeBlocks: vi.fn().mockRejectedValue(new Error("not mocked")),
    ...overrides,
  };
}

describe("mcp/tools", () => {
  it("list_granted_sources derives sources from granted scopes", async () => {
    const result = await getTool("list_granted_sources").handler(
      {},
      {
        connection: createConnection(),
        readClient: createMinimalReadClient(),
      },
    );

    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text)).toEqual({
      sources: ["chatgpt", "instagram"],
    });
  });

  it("read_scope returns bounded blocks and a next cursor", async () => {
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi
        .fn()
        .mockResolvedValueOnce({
          scope: "instagram.profile",
          collectedAt: "2026-06-05T00:00:00Z",
          contentKind: "json",
          blocks: [
            {
              id: "b1",
              path: "$.items[0:1]",
              mediaType: "application/json",
              value: { id: 1 },
              sizeBytes: 20,
            },
          ],
          nextCursor: "cursor-2",
          warnings: [],
        })
        .mockResolvedValueOnce({
          scope: "instagram.profile",
          collectedAt: "2026-06-05T00:00:00Z",
          contentKind: "json",
          blocks: [
            {
              id: "b2",
              path: "$.items[1:2]",
              mediaType: "application/json",
              value: { id: 2 },
              sizeBytes: 20,
            },
          ],
          warnings: [],
        }),
    });

    const result = await getTool("read_scope").handler(
      { scope: "instagram.profile", cursor: "cursor-1", maxBytes: 4096 },
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );

    expect(readClient.readScopeBlocks).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "instagram.profile",
        cursor: "cursor-1",
        maxBytes: 4096,
      }),
    );
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      scope: "instagram.profile",
      grantId: "grant-1",
      nextCursor: "cursor-2",
      page: { cursor: "cursor-1", maxBytes: 4096, returnedBlocks: 1 },
    });
  });

  it("search_personal_context returns partial results within per-scope timeout", async () => {
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn(async ({ scope }: { scope: string }) => {
        if (scope === "chatgpt.history") {
          await new Promise((resolve) => setTimeout(resolve, 2_000));
          return {
            scope,
            collectedAt: "2026-06-05T00:00:00Z",
            contentKind: "json",
            blocks: [
              {
                id: "b2",
                path: "$.text",
                mediaType: "text/plain",
                value: "slow content",
                sizeBytes: 20,
              },
            ],
            warnings: [],
          };
        }
        return {
          scope,
          collectedAt: "2026-06-05T00:00:00Z",
          contentKind: "json",
          blocks: [
            {
              id: "b1",
              path: "$.text",
              mediaType: "text/plain",
              value: "hello query world",
              sizeBytes: 20,
            },
          ],
          warnings: [],
        };
      }),
    });

    const started = Date.now();
    const result = await getTool("search_personal_context").handler(
      {
        query: "query",
        scopes: ["instagram.profile", "chatgpt.history"],
        timeoutMs: 1000,
        maxScopes: 2,
        maxResults: 1,
        maxBytes: 1024,
      },
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );
    const elapsed = Date.now() - started;

    // Should complete well under 2s (chatgpt.history times out via per-scope budget)
    expect(elapsed).toBeLessThan(1800);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.results).toHaveLength(1);
    expect(payload.results[0].scope).toBe("instagram.profile");
    expect(payload.searchedScopes).toEqual(["instagram.profile"]);
    expect(payload.nextSearchCursor).toBeDefined();
    expect(payload.limits.requestedBytesPerPage).toBe(1024);
  });

  it("search_personal_context respects global deadline and returns nextSearchCursor", async () => {
    // All scopes take 300ms each; with 1s budget and 3 scopes only some can finish
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn(async ({ scope }: { scope: string }) => {
        await new Promise((resolve) => setTimeout(resolve, 300));
        return {
          scope,
          collectedAt: "2026-06-05T00:00:00Z",
          contentKind: "json",
          blocks: [
            {
              id: "b1",
              path: "$.text",
              mediaType: "text/plain",
              value: `no match here for scope ${scope}`,
              sizeBytes: 20,
            },
          ],
          warnings: [],
        };
      }),
    });

    const connection: McpConnectionRecord = {
      ...createConnection(),
      grants: [
        {
          grantId: "grant-multi",
          scopes: [
            "instagram.profile",
            "instagram.feed",
            "chatgpt.history",
            "chatgpt.conversations",
            "reddit.posts",
          ],
        },
      ],
    };

    const started = Date.now();
    const result = await getTool("search_personal_context").handler(
      {
        query: "findme",
        scopes: [
          "instagram.profile",
          "instagram.feed",
          "chatgpt.history",
          "chatgpt.conversations",
          "reddit.posts",
        ],
        timeoutMs: 1000,
        maxScopes: 5,
        maxBytes: 1024,
      },
      { connection, readClient: readClient as never },
    );
    const elapsed = Date.now() - started;

    // Must return well within 2x the declared budget (not 300s)
    expect(elapsed).toBeLessThan(3000);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.limits.totalTimeoutMs).toBe(1000);
    // Some scopes searched, some skipped due to budget
    expect(payload.searchedScopes.length).toBeGreaterThan(0);
    // When budget exhausted before all scopes, nextSearchCursor is provided
    if (payload.searchedScopes.length < 5) {
      expect(payload.nextSearchCursor).toBeDefined();
      expect(typeof payload.nextSearchCursor).toBe("string");
    }
  });

  it("search_personal_context cursor continuation resumes from correct scope", async () => {
    const callLog: string[] = [];
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn(async ({ scope }: { scope: string }) => {
        callLog.push(scope);
        return {
          scope,
          collectedAt: "2026-06-05T00:00:00Z",
          contentKind: "json",
          blocks: [
            {
              id: "b1",
              path: "$.text",
              mediaType: "text/plain",
              value: `content for ${scope}`,
              sizeBytes: 20,
            },
          ],
          warnings: [],
        };
      }),
    });

    const connection: McpConnectionRecord = {
      ...createConnection(),
      grants: [
        {
          grantId: "grant-multi",
          scopes: ["instagram.profile", "chatgpt.history", "reddit.posts"],
        },
      ],
    };

    // First call - limit to 1 result so cursor is issued for remaining scopes
    const firstResult = await getTool("search_personal_context").handler(
      {
        query: "content",
        scopes: ["instagram.profile", "chatgpt.history", "reddit.posts"],
        maxResults: 1,
        maxScopes: 3,
        timeoutMs: 5000,
        maxBytes: 1024,
      },
      { connection, readClient: readClient as never },
    );
    const firstPayload = JSON.parse(firstResult.content[0].text);
    expect(firstPayload.results).toHaveLength(1);
    expect(firstPayload.nextSearchCursor).toBeDefined();

    callLog.length = 0;

    // Second call with cursor - should NOT re-search the first scope
    const secondResult = await getTool("search_personal_context").handler(
      {
        query: "content",
        scopes: ["instagram.profile", "chatgpt.history", "reddit.posts"],
        cursor: firstPayload.nextSearchCursor,
        maxResults: 5,
        maxScopes: 3,
        timeoutMs: 5000,
        maxBytes: 1024,
      },
      { connection, readClient: readClient as never },
    );
    const secondPayload = JSON.parse(secondResult.content[0].text);

    // Second call must not re-search scopes that were already covered
    expect(callLog).not.toContain("instagram.profile");
    expect(secondPayload.results.length).toBeGreaterThan(0);
  });

  it("list_granted_scopes returns planning metadata for each scope", async () => {
    const readClient = createMinimalReadClient({
      getScopeMetadata: vi.fn((scope: string) => {
        if (scope === "instagram.profile") {
          return {
            scope,
            collectedAt: "2026-06-05T00:00:00Z",
            sizeBytes: 5_000,
            hasBlocks: true,
          };
        }
        if (scope === "chatgpt.history") {
          return {
            scope,
            collectedAt: "2026-06-04T00:00:00Z",
            sizeBytes: 15_000_000,
            hasBlocks: true,
          };
        }
        return null;
      }),
    });

    const result = await getTool("list_granted_scopes").handler(
      {},
      {
        connection: {
          ...createConnection(),
          grants: [
            {
              grantId: "grant-metadata",
              scopes: ["instagram.profile", "chatgpt.history"],
            },
          ],
        },
        readClient: readClient as never,
      },
    );

    const payload = JSON.parse(result.content[0].text);
    const byScope = Object.fromEntries(
      payload.scopes.map((s: { scope: string }) => [s.scope, s]),
    );

    // instagram.profile: 5KB → tiny → searchRecommended: true
    expect(byScope["instagram.profile"].dataStatus).toBe("ready");
    expect(byScope["instagram.profile"].searchRecommended).toBe(true);
    expect(byScope["instagram.profile"].sizeBytes).toBe(5_000);
    expect(byScope["instagram.profile"].sizeClass).toBe("tiny");

    // chatgpt.history: 15MB → huge → searchRecommended: false
    expect(byScope["chatgpt.history"].dataStatus).toBe("ready");
    expect(byScope["chatgpt.history"].searchRecommended).toBe(false);
    expect(byScope["chatgpt.history"].sizeClass).toBe("huge");
    expect(byScope["chatgpt.history"].reason).toBeDefined();
  });

  it("list_granted_scopes marks scope as needs_refresh when no local data", async () => {
    const readClient = createMinimalReadClient({
      getScopeMetadata: vi.fn().mockReturnValue(null),
    });

    const result = await getTool("list_granted_scopes").handler(
      {},
      { connection: createConnection(), readClient: readClient as never },
    );

    const payload = JSON.parse(result.content[0].text);
    for (const scope of payload.scopes) {
      expect(scope.dataStatus).toBe("needs_refresh");
      expect(scope.searchRecommended).toBe(false);
    }
  });
});
