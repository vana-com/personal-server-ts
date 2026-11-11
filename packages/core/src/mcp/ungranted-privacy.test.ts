import { describe, expect, it, vi } from "vitest";
import { handleMcpStreamableHttpRequest } from "./server.js";
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
      connection: connection(),
      readClient,
      exposeUnsharedScopes: false,
      scopeRequestGuidance: true,
      requestableScopes: CATALOG,
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
});
