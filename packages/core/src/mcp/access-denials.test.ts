import { describe, expect, it, vi } from "vitest";
import { handleMcpStreamableHttpRequest } from "./server.js";
import { McpDataReadError, type McpDataReadClient } from "./read-client.js";
import type { McpConnectionRecord } from "./types.js";
import type { PersonalServerReadFulfillment } from "../api/index.js";

const NOTES = "manual.notes";
const UNGRANTED = "private.notes";
const GRANTEE = "0x1111111111111111111111111111111111111111";
const COLLECTED_AT = "2026-09-08T00:00:00Z";
/** Grant ids are 32-byte hex on the wire; the Gateway refuses anything else. */
const GRANT_ID = `0x${"8f".repeat(32)}`;
const PAID = "spotify.profile";
const PAID_GRANT_ID = `0x${"c3".repeat(32)}`;
const NOTES_GRANT = { grantId: GRANT_ID, scopes: [NOTES] };
const PAID_GRANT = { grantId: PAID_GRANT_ID, scopes: [PAID] };

function fixture(
  readScopeBlocksImpl: McpDataReadClient["readScopeBlocks"],
  grants: McpConnectionRecord["grants"] = [NOTES_GRANT],
) {
  const connection: McpConnectionRecord = {
    id: "denial-fixture",
    displayName: "Denial fixture",
    granteeAddress: GRANTEE,
    granteePublicKey: "0x04deadbeef",
    encryptedGranteePrivateKey: {
      kind: "plaintext",
      privateKey: `0x${"22".repeat(32)}`,
    },
    tokenHash: "synthetic-token-hash",
    status: "approved",
    grants,
    createdAt: COLLECTED_AT,
    approvedAt: COLLECTED_AT,
  };
  const readScopeBlocks = vi.fn(readScopeBlocksImpl);
  const readClient = {
    listScopes: vi.fn(),
    getScopeMetadata: (scope: string) => ({
      scope,
      collectedAt: COLLECTED_AT,
      sizeBytes: 10,
      hasBlocks: true,
    }),
    readScopeBlocks,
    readRawScopeFile: vi.fn(),
    readBlockManifest: vi.fn(),
  } as unknown as McpDataReadClient;

  const reportDenied = vi.fn<
    (e: PersonalServerReadFulfillment) => Promise<void>
  >(async () => undefined);

  async function tool(name: string, args: object) {
    const response = await handleMcpStreamableHttpRequest(
      new Request("https://fixture.example/mcp", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name, arguments: args },
        }),
      }),
      {
        connection,
        readClient,
        reporterDeps: {
          readFulfillmentReporter: { report: vi.fn(), reportDenied },
        },
      },
    );
    return (await response.json()) as { result: { isError?: boolean } };
  }

  return { readScopeBlocks, tool, reportDenied };
}

const served: McpDataReadClient["readScopeBlocks"] = async ({ scope }) => ({
  status: 200,
  scope,
  collectedAt: COLLECTED_AT,
  contentKind: "json",
  blocks: [],
  warnings: [],
});

const paymentRequired: McpDataReadClient["readScopeBlocks"] = async () => {
  throw new McpDataReadError(402, {
    error: {
      errorCode: "PAYMENT_REQUIRED",
      message: "payment required",
      details: { challenge: { scheme: "exact" } },
    },
  });
};

describe("MCP tool-call access denials", () => {
  it("records a denial when the scope is not granted", async () => {
    const { tool, reportDenied } = fixture(served);
    await tool("read_scope", { scope: UNGRANTED });
    expect(reportDenied).toHaveBeenCalledTimes(1);
    expect(reportDenied.mock.calls[0][0]).toMatchObject({
      builder: GRANTEE,
      denyReason: "scope_not_granted",
      grantId: GRANT_ID,
      outcome: "denied",
      scope: UNGRANTED,
      source: "mcp",
      tool: "read_scope",
    });
  });

  it("names the tool on a served read", async () => {
    const { readScopeBlocks, tool } = fixture(served);
    await tool("read_scope", { scope: NOTES });
    expect(readScopeBlocks.mock.calls[0][0]).toMatchObject({
      scope: NOTES,
      tool: "read_scope",
    });
  });

  it("records nothing when the read is served", async () => {
    const { tool, reportDenied } = fixture(served);
    await tool("read_scope", { scope: NOTES });
    expect(reportDenied).not.toHaveBeenCalled();
  });

  it("records nothing for a non-deny failure", async () => {
    const { tool, reportDenied } = fixture(async () => {
      throw new McpDataReadError(503, { error: "STORAGE_UNAVAILABLE" });
    });
    const body = await tool("read_scope", { scope: NOTES });
    expect(body.result.isError).toBe(true);
    expect(reportDenied).not.toHaveBeenCalled();
  });

  it("files the denial under the grant that covers the scope", async () => {
    // Two grants, and the refused scope is on the second: the record must not
    // fall back to the first grant on the connection.
    const { tool, reportDenied } = fixture(paymentRequired, [
      NOTES_GRANT,
      PAID_GRANT,
    ]);
    await tool("read_scope", { scope: PAID });
    expect(reportDenied.mock.calls[0][0]).toMatchObject({
      denyReason: "payment_required",
      grantId: PAID_GRANT_ID,
      scope: PAID,
    });
  });

  it("records nothing when no grant can carry the refusal", async () => {
    const { tool, reportDenied } = fixture(served, []);
    await tool("read_scope", { scope: UNGRANTED });
    expect(reportDenied).not.toHaveBeenCalled();
  });

  it("names the search tool on the reads it serves", async () => {
    const { readScopeBlocks, tool } = fixture(served);
    await tool("search_personal_context", { query: "tim" });
    expect(readScopeBlocks.mock.calls[0][0]).toMatchObject({
      tool: "search_personal_context",
    });
  });

  it("records nothing for a discovery tool", async () => {
    const { tool, reportDenied } = fixture(served);
    await tool("request_scope_access", {
      scopes: [UNGRANTED],
      reason: "please",
    });
    expect(reportDenied).not.toHaveBeenCalled();
  });
});
