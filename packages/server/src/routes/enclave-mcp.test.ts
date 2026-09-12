import { describe, expect, it, vi } from "vitest";
import {
  createMcpConnection,
  createInMemoryMcpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { enclaveMcpRoutes } from "./enclave-mcp.js";

describe("owner sandbox MCP dispatch", () => {
  it("rejects a different owner even with the sandbox access token", async () => {
    const store = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      {},
      { store, publicOrigin: "https://mcp-dev.vana.org" },
    );
    const execute = vi.fn();
    const app = enclaveMcpRoutes({
      accessToken: "sandbox-secret",
      serverOwner: "0x1111111111111111111111111111111111111111",
      execute,
    });
    const response = await app.request("/", {
      method: "POST",
      headers: {
        authorization: "Bearer sandbox-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        owner: "0x2222222222222222222222222222222222222222",
        connection: await store.getById(created.connectionId),
        request: { jsonrpc: "2.0", method: "tools/list", id: 1 },
      }),
    });
    expect(response.status).toBe(403);
    expect(execute).not.toHaveBeenCalled();
  });
});
