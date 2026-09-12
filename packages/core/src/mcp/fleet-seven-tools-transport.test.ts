import { describe, expect, it, vi } from "vitest";
import { handleMcpStreamableHttpRequest } from "./server.js";
import type { McpDataReadClient } from "./read-client.js";
import type { McpConnectionRecord } from "./types.js";
import type { DataScopeBlock } from "../storage/blocks/types.js";

const NOTES = "manual.notes";
const DOCUMENT = "manual.document";
const UNGRANTED = "private.notes";
const COLLECTED_AT = "2026-09-08T00:00:00Z";
const BLOCKS: DataScopeBlock[] = [
  {
    id: "block-000001",
    path: "$.items[0]",
    mediaType: "text/plain",
    value: "The studio opens on Tuesday.",
    sizeBytes: 27,
  },
  {
    id: "block-000002",
    path: "$.items[1]",
    mediaType: "text/plain",
    value: "The kiln is reserved for Thursday.",
    sizeBytes: 33,
  },
];

function fixture() {
  // Synthetic approved grants and data: this tests the MCP transport contract,
  // not ordinary OAuth, live source support, or physical TEE routing.
  const connection: McpConnectionRecord = {
    id: "fleet-transport-fixture",
    displayName: "Fleet transport fixture",
    granteeAddress: "0x1111111111111111111111111111111111111111",
    granteePublicKey: "0x04deadbeef",
    encryptedGranteePrivateKey: {
      kind: "plaintext",
      privateKey: `0x${"22".repeat(32)}`,
    },
    tokenHash: "synthetic-token-hash",
    status: "approved",
    grants: [{ grantId: "fixture-grant", scopes: [NOTES, DOCUMENT] }],
    createdAt: COLLECTED_AT,
    approvedAt: COLLECTED_AT,
  };
  const readScopeBlocks = vi.fn<McpDataReadClient["readScopeBlocks"]>(
    async ({ scope, grantId, blockIds }) => {
      expect(scope).toBe(NOTES);
      expect(grantId).toBe("fixture-grant");
      return {
        status: 200,
        scope,
        collectedAt: COLLECTED_AT,
        contentKind: "json",
        blocks: blockIds
          ? BLOCKS.filter((block) => blockIds.includes(block.id))
          : BLOCKS,
        warnings: [],
      };
    },
  );
  const readRawScopeFile = vi.fn<McpDataReadClient["readRawScopeFile"]>(
    async ({ scope, grantId }) => {
      expect(scope).toBe(DOCUMENT);
      expect(grantId).toBe("fixture-grant");
      return {
        status: 200,
        scope,
        collectedAt: COLLECTED_AT,
        mimeType: "application/pdf",
        filename: "fixture.pdf",
        sizeBytes: 4,
        contentBase64: "JVBERg==",
      };
    },
  );
  const readClient: McpDataReadClient = {
    listScopes: vi.fn().mockResolvedValue({
      status: 200,
      scopes: [],
      total: 0,
      limit: 0,
      offset: 0,
    }),
    getScopeMetadata: (scope) => ({
      scope,
      collectedAt: COLLECTED_AT,
      sizeBytes: scope === NOTES ? 60 : 4,
      hasBlocks: true,
    }),
    readScopeBlocks,
    readRawScopeFile,
    readBlockManifest: async ({ scope, grantId }) => {
      expect(scope).toBe(NOTES);
      expect(grantId).toBe("fixture-grant");
      return {
        version: 1,
        scope,
        collectedAt: COLLECTED_AT,
        contentKind: "json",
        blocks: BLOCKS.map(({ value: _value, ...ref }) => ref),
        warnings: [],
      };
    },
  };

  let sequence = 0;
  async function rpc(method: string, params: object) {
    sequence += 1;
    const response = await handleMcpStreamableHttpRequest(
      new Request("https://fixture.example/mcp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: sequence, method, params }),
      }),
      { connection, readClient },
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    const body = await response.json();
    expect(body).toMatchObject({ jsonrpc: "2.0", id: sequence });
    expect(body.error).toBeUndefined();
    return body.result;
  }
  async function tool(name: string, args: object = {}) {
    const result = await rpc("tools/call", { name, arguments: args });
    expect(result.isError).not.toBe(true);
    return result;
  }
  return { rpc, tool, connection, readScopeBlocks, readRawScopeFile };
}

function textPayload(result: { content: { type: string; text?: string }[] }) {
  const text = result.content.find((item) => item.type === "text");
  expect(text?.text).toBeDefined();
  return JSON.parse(text!.text!);
}

describe("fleet regression: all seven tools through MCP Streamable HTTP", () => {
  it("discovers granted data, searches, reads selected blocks, and follows file resources", async () => {
    const { rpc, tool, connection, readScopeBlocks, readRawScopeFile } =
      fixture();
    const beforeGrants = structuredClone(connection.grants);
    const sources = textPayload(await tool("list_granted_sources"));
    expect(sources.sources).toEqual(["manual"]);
    const scopes = textPayload(await tool("list_granted_scopes"));
    expect(scopes.scopes).toEqual([
      expect.objectContaining({
        scope: DOCUMENT,
        dataStatus: "ready",
        sizeBytes: 4,
      }),
      expect.objectContaining({
        scope: NOTES,
        dataStatus: "ready",
        sizeBytes: 60,
      }),
    ]);

    const guidance = textPayload(
      await tool("request_scope_access", {
        scopes: [NOTES, UNGRANTED],
        reason: "Find my private notes",
      }),
    );
    expect(guidance).toMatchObject({
      approvalRequired: true,
      grantedRequestedScopes: [NOTES],
      missingScopes: [UNGRANTED],
    });
    expect(guidance.nextAction).toContain("cannot grant access");
    expect(connection.grants).toEqual(beforeGrants);

    const listing = textPayload(
      await tool("list_scope_blocks", { scope: NOTES, limit: 1 }),
    );
    expect(listing).toMatchObject({
      manifestAvailable: true,
      totalBlocks: 2,
      blocks: [{ id: "block-000001", path: "$.items[0]" }],
      page: { returnedBlocks: 1, nextOffset: 1 },
    });
    expect(JSON.stringify(listing)).not.toContain("The studio");

    const search = textPayload(
      await tool("search_personal_context", { query: "kiln", scopes: [NOTES] }),
    );
    expect(search.results).toHaveLength(1);
    expect(search.results[0]).toMatchObject({
      scope: NOTES,
      blockRef: "block-000002",
    });
    expect(search.results[0].preview).toContain("kiln");
    const read = textPayload(
      await tool("read_scope", {
        scope: search.results[0].scope,
        blockIds: [search.results[0].blockRef],
        maxBytes: 4096,
      }),
    );
    expect(read.blocks).toEqual([BLOCKS[1]]);
    expect(readScopeBlocks).toHaveBeenLastCalledWith(
      expect.objectContaining({
        scope: NOTES,
        grantId: "fixture-grant",
        blockIds: ["block-000002"],
        maxBytes: 4096,
      }),
    );
    expect(JSON.stringify(read)).not.toContain("The studio");

    const file = await tool("get_scope_file", { scope: DOCUMENT });
    expect(file.content).toContainEqual(
      expect.objectContaining({
        type: "resource_link",
        uri: `vana://scope/${DOCUMENT}/raw`,
        mimeType: "application/pdf",
        size: 4,
      }),
    );
    expect(file.structuredContent).toMatchObject({ contentIncluded: false });
    const resource = await rpc("resources/read", {
      uri: file.structuredContent.resourceUri,
    });
    expect(resource.contents).toEqual([
      expect.objectContaining({
        mimeType: "application/pdf",
        blob: "JVBERg==",
      }),
    ]);
    expect(readRawScopeFile).toHaveBeenCalledTimes(2);
  });

  it("keeps access-request guidance from authorizing an ungranted read", async () => {
    const { rpc, tool, readScopeBlocks, readRawScopeFile } = fixture();
    await tool("request_scope_access", { scopes: [UNGRANTED] });
    const denied = await rpc("tools/call", {
      name: "read_scope",
      arguments: { scope: UNGRANTED },
    });
    expect(denied.isError).toBe(true);
    expect(textPayload(denied)).toMatchObject({ error: "scope_not_granted" });
    expect(readScopeBlocks).not.toHaveBeenCalled();
    expect(readRawScopeFile).not.toHaveBeenCalled();
  });
});
