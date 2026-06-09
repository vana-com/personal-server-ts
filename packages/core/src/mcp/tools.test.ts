import { describe, expect, it, vi } from "vitest";
import { McpActivityRecorder } from "./activity.js";
import { MCP_TOOLS } from "./tools.js";
import { handleMcpStreamableHttpRequest } from "./server.js";
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
    readRawScopeFile: vi.fn().mockRejectedValue(new Error("not mocked")),
    ...overrides,
  };
}

describe("mcp/tools", () => {
  it("keeps the MCP tools/list response parseable and under the tunnel budget", async () => {
    const response = await handleMcpStreamableHttpRequest(
      new Request("http://localhost/mcp/test-token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: {},
        }),
      }),
      {
        connection: createConnection(),
        readClient: createMinimalReadClient(),
      },
    );

    expect(response.status).toBe(200);
    const body = await response.text();
    expect(() => JSON.parse(body)).not.toThrow();
    expect(new TextEncoder().encode(body).byteLength).toBeLessThan(3000);
  });

  it("records activity for MCP HTTP tool calls", async () => {
    const activityRecorder = new McpActivityRecorder();
    const response = await handleMcpStreamableHttpRequest(
      new Request("http://localhost/mcp/test-token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "list_granted_scopes",
            arguments: {},
          },
        }),
      }),
      {
        connection: createConnection(),
        readClient: createMinimalReadClient(),
        activityRecorder,
      },
    );

    expect(response.status).toBe(200);
    const snapshot = activityRecorder.snapshot();
    expect(snapshot.total).toBe(1);
    expect(snapshot.events[0]).toMatchObject({
      phase: "response_ready",
      status: "succeeded",
      tool: "list_granted_scopes",
    });
    expect(typeof snapshot.events[0].handlerDurationMs).toBe("number");
    expect(typeof snapshot.events[0].durationMs).toBe("number");
    expect(snapshot.events[0].payloadBytes).toBeGreaterThan(0);
    expect(snapshot.events[0].textBytes).toBeGreaterThan(0);
  });

  it("serves raw scope files through MCP resources/read", async () => {
    const response = await handleMcpStreamableHttpRequest(
      new Request("http://localhost/mcp/test-token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "resources/read",
          params: { uri: "vana://scope/manual.document/raw" },
        }),
      }),
      {
        connection: {
          ...createConnection(),
          grants: [{ grantId: "grant-3", scopes: ["manual.document"] }],
        },
        readClient: createMinimalReadClient({
          readRawScopeFile: vi.fn().mockResolvedValue({
            status: 200,
            scope: "manual.document",
            mimeType: "application/pdf",
            sizeBytes: 4,
            contentBase64: "JVBERg==",
          }),
        }),
      },
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      result: {
        contents: Array<{ uri: string; mimeType: string; blob: string }>;
      };
    };
    expect(body.result.contents).toEqual([
      expect.objectContaining({
        uri: "vana://scope/manual.document/raw",
        mimeType: "application/pdf",
        blob: "JVBERg==",
      }),
    ]);
  });

  it("MCP HTTP dispatcher returns a typed timeout for stalled tool handlers", async () => {
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn(
        () =>
          new Promise(() => {
            // Deliberately never resolves: proves the dispatcher backstop.
          }),
      ),
    });

    const started = Date.now();
    const response = await handleMcpStreamableHttpRequest(
      new Request("http://localhost/mcp/test-token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "read_scope",
            arguments: {
              scope: "instagram.profile",
              timeoutMs: 1000,
            },
          },
        }),
      }),
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(2500);
    const body = await response.json();
    const text = body.result.content[0].text;
    expect(JSON.parse(text)).toMatchObject({
      error: "scope_read_timeout",
      timeoutMs: 1000,
    });
  });

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
    expect(result.structuredContent).toEqual({
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
      page: {
        cursor: "cursor-1",
        hasMore: true,
        maxBytes: 4096,
        nextCursor: "cursor-2",
        timeoutMs: 60_000,
        returnedBlocks: 1,
      },
    });
  });

  it("get_scope_file returns raw binary data as an MCP resource blob", async () => {
    const readRawScopeFile = vi.fn().mockResolvedValue({
      status: 200,
      scope: "manual.document",
      collectedAt: "2026-06-05T00:00:00Z",
      fileId: "file-1",
      mimeType: "application/pdf",
      filename: "scan.pdf",
      sizeBytes: 4,
      contentBase64: "JVBERg==",
    });
    const result = await getTool("get_scope_file").handler(
      { scope: "manual.document" },
      {
        connection: {
          ...createConnection(),
          grants: [{ grantId: "grant-3", scopes: ["manual.document"] }],
        },
        readClient: createMinimalReadClient({ readRawScopeFile }),
      },
    );

    expect(result.isError).not.toBe(true);
    expect(readRawScopeFile).toHaveBeenCalledWith({
      scope: "manual.document",
      grantId: "grant-3",
      at: undefined,
      fileId: undefined,
    });
    expect(result.content).toContainEqual(
      expect.objectContaining({
        type: "resource",
        resource: expect.objectContaining({
          uri: "vana://scope/manual.document/raw",
          mimeType: "application/pdf",
          blob: "JVBERg==",
        }),
      }),
    );
    expect(result.structuredContent).toMatchObject({
      scope: "manual.document",
      resourceUri: "vana://scope/manual.document/raw",
      contentIncluded: true,
      resourceType: "blob",
    });
  });

  it("get_scope_file links without embedding when the file exceeds maxBytes", async () => {
    const result = await getTool("get_scope_file").handler(
      { scope: "manual.document", maxBytes: 3 },
      {
        connection: {
          ...createConnection(),
          grants: [{ grantId: "grant-3", scopes: ["manual.document"] }],
        },
        readClient: createMinimalReadClient({
          readRawScopeFile: vi.fn().mockResolvedValue({
            status: 200,
            scope: "manual.document",
            mimeType: "application/pdf",
            filename: "scan.pdf",
            sizeBytes: 4,
            contentBase64: "JVBERg==",
          }),
        }),
      },
    );

    expect(result.isError).not.toBe(true);
    expect(result.content).toContainEqual(
      expect.objectContaining({
        type: "resource_link",
        uri: "vana://scope/manual.document/raw",
        mimeType: "application/pdf",
        size: 4,
      }),
    );
    expect(result.content).not.toContainEqual(
      expect.objectContaining({ type: "resource" }),
    );
  });

  it("read_scope defaults to a client-safe page and does not duplicate large payloads", async () => {
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn().mockResolvedValue({
        scope: "instagram.profile",
        collectedAt: "2026-06-05T00:00:00Z",
        contentKind: "json",
        blocks: [
          {
            id: "b1",
            path: "$.large",
            mediaType: "application/json",
            value: { text: "x".repeat(70 * 1024) },
            sizeBytes: 70 * 1024,
          },
        ],
        nextCursor: "cursor-2",
        warnings: [],
      }),
    });

    const result = await getTool("read_scope").handler(
      { scope: "instagram.profile" },
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );

    expect(readClient.readScopeBlocks).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "instagram.profile",
        maxBytes: 64 * 1024,
      }),
    );
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      nextCursor: "cursor-2",
      page: {
        hasMore: true,
        maxBytes: 64 * 1024,
      },
    });
    expect(result.structuredContent).toBeUndefined();
  });

  it("read_scope attaches search guidance for large scopes and omits it for small ones", async () => {
    const block = {
      id: "b1",
      path: "$.items[0:1]",
      mediaType: "application/json",
      value: { id: 1 },
      sizeBytes: 20,
    };
    const makeClient = (sizeBytes: number) =>
      createMinimalReadClient({
        getScopeMetadata: vi.fn(async (scope: string) => ({
          scope,
          collectedAt: "2026-06-05T00:00:00Z",
          sizeBytes,
          hasBlocks: true,
        })),
        readScopeBlocks: vi.fn().mockResolvedValue({
          scope: "instagram.profile",
          collectedAt: "2026-06-05T00:00:00Z",
          contentKind: "json",
          blocks: [block],
          nextCursor: "cursor-2",
          warnings: [],
        }),
      });

    // Large scope (~5MB) → guidance steering to search, read still served.
    const large = await getTool("read_scope").handler(
      { scope: "instagram.profile" },
      {
        connection: createConnection(),
        readClient: makeClient(5_000_000) as never,
      },
    );
    const largePayload = JSON.parse(large.content[0].text);
    expect(largePayload.blocks).toHaveLength(1);
    expect(largePayload.guidance).toMatchObject({
      recommendedAccess: "search",
      sizeClass: "large",
    });

    // Small scope (5KB) → no guidance noise.
    const small = await getTool("read_scope").handler(
      { scope: "instagram.profile" },
      {
        connection: createConnection(),
        readClient: makeClient(5_000) as never,
      },
    );
    expect(JSON.parse(small.content[0].text).guidance).toBeUndefined();
  });

  it("read_scope does not wait for stalled metadata guidance", async () => {
    const readClient = createMinimalReadClient({
      getScopeMetadata: vi.fn(
        () =>
          new Promise(() => {
            // Deliberately never resolves: guidance is advisory only.
          }),
      ),
      readScopeBlocks: vi.fn().mockResolvedValue({
        scope: "instagram.profile",
        collectedAt: "2026-06-05T00:00:00Z",
        contentKind: "json",
        blocks: [
          {
            id: "b1",
            path: "$.profile",
            mediaType: "application/json",
            value: { username: "tim" },
            sizeBytes: 18,
          },
        ],
        warnings: [],
      }),
    });

    const started = Date.now();
    const result = await getTool("read_scope").handler(
      { scope: "instagram.profile", timeoutMs: 1000 },
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(500);
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      scope: "instagram.profile",
      page: {
        returnedBlocks: 1,
      },
    });
  });

  it("read_scope returns a typed timeout instead of hanging on a stalled read", async () => {
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn(
        () =>
          new Promise(() => {
            // Deliberately never resolves: models a degraded storage sidecar.
          }),
      ),
    });

    const started = Date.now();
    const result = await getTool("read_scope").handler(
      {
        scope: "instagram.profile",
        timeoutMs: 1000,
      },
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(1800);
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      error: "scope_read_timeout",
      timeoutMs: 1000,
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

  it("search_personal_context returns a per-scope timeout when a read never resolves", async () => {
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn(
        () =>
          new Promise(() => {
            // Deliberately never resolves: models a sidecar request stuck
            // between healthy and cleanly-unavailable states.
          }),
      ),
    });

    const started = Date.now();
    const result = await getTool("search_personal_context").handler(
      {
        query: "design",
        scopes: ["instagram.profile"],
        timeoutMs: 1000,
        maxScopes: 1,
        maxResults: 5,
        maxBytes: 1024,
      },
      {
        connection: createConnection(),
        readClient: readClient as never,
      },
    );
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(1800);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.results).toEqual([]);
    expect(payload.errors).toEqual([
      expect.objectContaining({
        scope: "instagram.profile",
        error: "scope_search_timeout",
      }),
    ]);
  });

  it("search_personal_context uses an indexed search hit without reading blocks", async () => {
    const readScopeBlocks = vi.fn();
    const searchScopeIndex = vi.fn().mockResolvedValue({
      status: "hit",
      hits: [
        {
          id: "hit-1",
          scope: "instagram.profile",
          preview: "indexed kiln result",
          blockRef: "block-1",
          score: 1.5,
          terms: ["kiln"],
        },
      ],
    });
    const readClient = createMinimalReadClient({
      readScopeBlocks,
      searchScopeIndex,
    });

    const result = await getTool("search_personal_context").handler(
      {
        query: "kiln",
        scopes: ["instagram.profile"],
        maxScopes: 1,
      },
      {
        connection: createConnection(),
        readClient,
      },
    );

    const payload = JSON.parse(result.content[0].text);
    expect(payload.results).toEqual([
      expect.objectContaining({
        scope: "instagram.profile",
        preview: "indexed kiln result",
        blockRef: "block-1",
        score: 1.5,
        terms: ["kiln"],
      }),
    ]);
    expect(searchScopeIndex).toHaveBeenCalledWith({
      scope: "instagram.profile",
      grantId: "grant-1",
      query: "kiln",
      maxResults: 5,
    });
    expect(readScopeBlocks).not.toHaveBeenCalled();
  });

  it("search_personal_context falls back to bounded blocks when an index is missing", async () => {
    const readScopeBlocks = vi.fn().mockResolvedValue({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      contentKind: "json",
      blocks: [
        {
          id: "b1",
          path: "$.text",
          mediaType: "text/plain",
          value: "fallback indexed search result",
          sizeBytes: 20,
        },
      ],
      warnings: [],
    });
    const readClient = createMinimalReadClient({
      readScopeBlocks,
      searchScopeIndex: vi.fn().mockResolvedValue({ status: "missing" }),
    });

    const result = await getTool("search_personal_context").handler(
      {
        query: "fallback",
        scopes: ["instagram.profile"],
        maxScopes: 1,
      },
      {
        connection: createConnection(),
        readClient,
      },
    );

    const payload = JSON.parse(result.content[0].text);
    expect(payload.results[0]).toMatchObject({
      scope: "instagram.profile",
      preview: expect.stringContaining("fallback indexed search result"),
    });
    expect(readScopeBlocks).toHaveBeenCalledTimes(1);
  });

  it("search_personal_context skips index search when continuing a block cursor", async () => {
    const readScopeBlocks = vi.fn().mockResolvedValue({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      contentKind: "json",
      blocks: [
        {
          id: "b1",
          path: "$.text",
          mediaType: "text/plain",
          value: "cursor continuation result",
          sizeBytes: 20,
        },
      ],
      warnings: [],
    });
    const readClient = createMinimalReadClient({
      readScopeBlocks,
      searchScopeIndex: vi.fn().mockResolvedValue({
        status: "hit",
        hits: [
          {
            id: "stale-hit",
            scope: "instagram.profile",
            preview: "should not use index",
            score: 1,
            terms: ["cursor"],
          },
        ],
      }),
    });

    const firstResult = await getTool("search_personal_context").handler(
      {
        query: "missing",
        scopes: ["instagram.profile"],
        maxScopes: 1,
        timeoutMs: 1000,
      },
      {
        connection: createConnection(),
        readClient: createMinimalReadClient({
          readScopeBlocks: vi.fn().mockResolvedValue({
            scope: "instagram.profile",
            collectedAt: "2026-06-05T00:00:00Z",
            contentKind: "json",
            blocks: [
              {
                id: "b0",
                path: "$.text",
                mediaType: "text/plain",
                value: "no match",
                sizeBytes: 20,
              },
            ],
            nextCursor: "next-block",
            warnings: [],
          }),
        }) as never,
      },
    );
    const cursor = JSON.parse(firstResult.content[0].text).nextSearchCursor;

    const result = await getTool("search_personal_context").handler(
      {
        query: "cursor",
        scopes: ["instagram.profile"],
        cursor,
        maxScopes: 1,
      },
      {
        connection: createConnection(),
        readClient,
      },
    );

    const payload = JSON.parse(result.content[0].text);
    expect(payload.results[0].preview).toContain("cursor continuation result");
    expect(readClient.searchScopeIndex).not.toHaveBeenCalled();
    expect(readScopeBlocks).toHaveBeenCalledWith(
      expect.objectContaining({ cursor: "next-block" }),
    );
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

  it("search_personal_context default sweep reaches scopes beyond the old ten-scope cap", async () => {
    const scopes = Array.from({ length: 15 }, (_, index) =>
      index === 14 ? "manual.document" : `source${index}.profile`,
    );
    const readClient = createMinimalReadClient({
      readScopeBlocks: vi.fn(async ({ scope }: { scope: string }) => ({
        scope,
        collectedAt: "2026-06-05T00:00:00Z",
        contentKind: "json",
        blocks: [
          {
            id: "b1",
            path: "$.text",
            mediaType: "text/plain",
            value:
              scope === "manual.document"
                ? "This PDF mentions 78752."
                : `No zip code in ${scope}.`,
            sizeBytes: 32,
          },
        ],
        warnings: [],
      })),
    });

    const result = await getTool("search_personal_context").handler(
      { query: "78752", timeoutMs: 30_000 },
      {
        connection: {
          ...createConnection(),
          grants: [{ grantId: "grant-wide", scopes }],
        },
        readClient,
      },
    );

    const payload = JSON.parse(result.content[0].text) as {
      results: Array<{ scope: string }>;
      limits: { maxScopes: number };
    };
    expect(payload.results).toEqual([
      expect.objectContaining({ scope: "manual.document" }),
    ]);
    expect(payload.limits.maxScopes).toBeGreaterThan(10);
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

    // instagram.profile: 5KB → tiny → read the whole scope directly
    expect(byScope["instagram.profile"].dataStatus).toBe("ready");
    expect(byScope["instagram.profile"].recommendedAccess).toBe("read");
    expect(byScope["instagram.profile"].sizeBytes).toBe(5_000);
    expect(byScope["instagram.profile"].sizeClass).toBe("tiny");

    // chatgpt.history: 15MB → huge → steer to search instead of a full read
    expect(byScope["chatgpt.history"].dataStatus).toBe("ready");
    expect(byScope["chatgpt.history"].recommendedAccess).toBe("search");
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
      expect(scope.recommendedAccess).toBe("wait");
    }
  });

  it("list_granted_scopes marks indexed scopes as indexing when block manifests are not ready", async () => {
    const readClient = createMinimalReadClient({
      getScopeMetadata: vi.fn(async (scope: string) => ({
        scope,
        collectedAt: "2026-06-05T00:00:00Z",
        sizeBytes: 5_000,
        hasBlocks: false,
      })),
    });

    const result = await getTool("list_granted_scopes").handler(
      {},
      {
        connection: {
          ...createConnection(),
          grants: [
            { grantId: "grant-indexing", scopes: ["instagram.profile"] },
          ],
        },
        readClient: readClient as never,
      },
    );

    const payload = JSON.parse(result.content[0].text);
    const profile = payload.scopes.find(
      (scope: { scope: string }) => scope.scope === "instagram.profile",
    );
    expect(profile.dataStatus).toBe("indexing");
    expect(profile.recommendedAccess).toBe("wait");
    expect(profile.reason).toContain("indexing");
  });

  it("list_granted_scopes does not hang when scope metadata stalls", async () => {
    const readClient = createMinimalReadClient({
      getScopeMetadata: vi.fn(
        () =>
          new Promise(() => {
            // Deliberately never resolves: metadata must be best-effort.
          }),
      ),
    });

    const started = Date.now();
    const result = await getTool("list_granted_scopes").handler(
      {},
      {
        connection: {
          ...createConnection(),
          grants: [
            { grantId: "grant-indexing", scopes: ["instagram.profile"] },
          ],
        },
        readClient: readClient as never,
      },
    );
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(2800);
    const payload = JSON.parse(result.content[0].text);
    expect(payload.scopes).toEqual([
      expect.objectContaining({
        scope: "instagram.profile",
        dataStatus: "indexing",
        recommendedAccess: "wait",
      }),
    ]);
  });
});
