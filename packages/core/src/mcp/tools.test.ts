import { describe, expect, it, vi } from "vitest";
import { MCP_TOOLS } from "./tools.js";
import type { McpConnectionRecord } from "./types.js";

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

describe("mcp/tools", () => {
  it("list_granted_sources derives sources from granted scopes", async () => {
    const result = await getTool("list_granted_sources").handler(
      {},
      {
        connection: createConnection(),
        readClient: {} as never,
      },
    );

    expect(result.isError).not.toBe(true);
    expect(JSON.parse(result.content[0].text)).toEqual({
      sources: ["chatgpt", "instagram"],
    });
  });

  it("read_scope returns bounded blocks and a next cursor", async () => {
    const readClient = {
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
    };

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

  it("search_personal_context returns partial results on bounded pages", async () => {
    const readClient = {
      readScopeBlocks: vi.fn(async ({ scope }: { scope: string }) => {
        if (scope === "chatgpt.history") {
          await new Promise((resolve) => setTimeout(resolve, 100));
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
    };

    const started = Date.now();
    const result = await getTool("search_personal_context").handler(
      {
        query: "query",
        scopes: ["instagram.profile", "chatgpt.history"],
        timeoutMs: 50,
        maxScopes: 2,
        limit: 1,
        maxBytes: 1024,
      },
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(250);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.matches).toHaveLength(1);
    expect(payload.searchedScopes).toEqual([
      "chatgpt.history",
      "instagram.profile",
    ]);
    expect(
      payload.errors.some(
        (entry: { scope: string }) => entry.scope === "chatgpt.history",
      ),
    ).toBe(true);
    expect(payload.limits.requestedBytesPerPage).toBe(1024);
  });
});
