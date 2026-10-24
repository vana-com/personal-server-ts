/**
 * MCP tool results are released through the delivery dependencies of every
 * read the call made: success and error results alike, inside the tool
 * timeout. Scope metadata (size, collection time, readiness) is authorized
 * like a read.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { handleMcpStreamableHttpRequest } from "./server.js";
import { createMcpDataReadClient } from "./read-client.js";
import { ProtocolError } from "../errors/catalog.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { DeliveryLease } from "../policy/delivery-lease.js";

afterEach(() => {
  vi.useRealTimers();
});

const builder = "0x0000000000000000000000000000000000000002";

function mcpCall(name: string, args: object, readClient: unknown) {
  return handleMcpStreamableHttpRequest(
    new Request("http://ps/mcp/t", {
      method: "POST",
      headers: {
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name, arguments: args },
      }),
    }),
    {
      connection: {
        grants: [{ grantId: "g", scopes: ["test.records"] }],
        granteeAddress: builder,
      } as never,
      readClient: readClient as never,
    },
  );
}

/** A read client whose raw read hands `lease` to the call, then returns. */
function rawReadClient(
  lease: DeliveryLease,
  file: { sizeBytes: number; contentBase64: string },
) {
  return {
    withDeliveryLeases(sink: (lease: DeliveryLease) => void) {
      return {
        readRawScopeFile: async () => {
          sink(lease);
          return {
            scope: "test.records",
            mimeType: "application/pdf",
            ...file,
          };
        },
      };
    },
  };
}

describe("MCP error results", () => {
  it("an error that carries a file's size is released only through the read's lease", async () => {
    let checks = 0;
    const lease: DeliveryLease = {
      evidence: () => [],
      assertLocal() {
        checks += 1;
        throw new ProtocolError(410, "DATA_DELETED", "gone");
      },
    };
    const response = await mcpCall(
      "get_scope_file",
      { scope: "test.records", payment: "paid", maxBytes: 1 },
      rawReadClient(lease, { sizeBytes: 987654, contentBase64: "" }),
    );
    const text = await response.text();
    expect(checks).toBeGreaterThan(0);
    expect(text).not.toContain("987654");
    expect(text).toContain("DATA_DELETED");
  });
});

describe("MCP tool timeout", () => {
  it("bounds the handler and the release together", async () => {
    vi.useFakeTimers();
    let refreshing = false;
    let settleRefresh: () => void = () => undefined;
    const lease: DeliveryLease = {
      evidence: () => [
        {
          verifiedAt: 0,
          refresh() {
            refreshing = true;
            return new Promise<void>((resolve) => {
              settleRefresh = resolve;
            });
          },
        },
      ],
      assertLocal: () => undefined,
    };
    let settled = false;
    const pending = mcpCall(
      "get_scope_file",
      { scope: "test.records", includeContent: true, timeoutMs: 1000 },
      rawReadClient(lease, { sizeBytes: 1, contentBase64: "YQ==" }),
    ).then((response) => {
      settled = true;
      return response;
    });
    for (let n = 0; n < 200 && !refreshing; n += 1) await Promise.resolve();
    expect(refreshing).toBe(true);
    await vi.advanceTimersByTimeAsync(5000);
    expect(settled).toBe(true);
    expect(await (await pending).text()).toContain("tool_timeout");
    settleRefresh();
  });
});

describe("MCP scope metadata", () => {
  it("is not disclosed when the read authorization refuses", async () => {
    const storage = createMemoryDataStorage();
    const envelope = {
      version: "1.0",
      scope: "test.records",
      collectedAt: "2026-01-01T00:00:00Z",
      data: { id: "k" },
    };
    const written = await storage.writeEnvelope(envelope as never);
    storage.insertEntry({
      scope: "test.records",
      collectedAt: envelope.collectedAt,
      path: (written as { path: string }).path,
      sizeBytes: 987654,
      fileId: null,
    });
    let calls = 0;
    const refuse = async () => {
      calls += 1;
      throw new ProtocolError(403, "GRANT_REVOKED", "Grant has been revoked");
    };
    const client = createMcpDataReadClient({
      serverOrigin: "http://ps",
      granteeAccount: {
        address: "0x1111111111111111111111111111111111111111",
        publicKey: "0x04deadbeef",
        signTypedData: vi.fn(),
        signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
      } as never,
      dataApiDeps: {
        storage,
        auth: { authorizeBuilderRead: refuse, authorizeBuilderList: refuse },
        accessLogWriter: { write: async () => undefined },
      } as never,
    });
    const response = await mcpCall("list_granted_scopes", {}, client);
    const text = await response.text();
    expect(calls).toBeGreaterThan(0);
    expect(text).not.toContain("987654");
  });
});
