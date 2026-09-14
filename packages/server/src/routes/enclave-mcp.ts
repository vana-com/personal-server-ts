import { timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import type { McpConnectionRecord } from "@opendatalabs/personal-server-ts-core/mcp";
import { isAddress, isAddressEqual, type Address } from "viem";
import { createBodyLimit } from "../middleware/body-limit.js";

export function enclaveMcpRoutes(deps: {
  accessToken: string;
  serverOwner: Address;
  execute(request: Request, connection: McpConnectionRecord): Promise<Response>;
}): Hono {
  const app = new Hono();
  app.use("*", createBodyLimit(256 * 1024));
  app.post("/", async (c) => {
    const received = Buffer.from(c.req.header("authorization") ?? "");
    const expected = Buffer.from(`Bearer ${deps.accessToken}`);
    if (
      received.length !== expected.length ||
      !timingSafeEqual(received, expected)
    ) {
      return c.json({ error: "MCP dispatch authentication required" }, 401);
    }
    let body: {
      owner?: string;
      connection?: McpConnectionRecord;
      request?: unknown;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON" }, 400);
    }
    if (
      !body.owner ||
      !isAddress(body.owner) ||
      !isAddressEqual(body.owner, deps.serverOwner)
    ) {
      return c.json({ error: "MCP dispatch owner mismatch" }, 403);
    }
    if (
      !body.connection ||
      body.connection.status !== "approved" ||
      !Array.isArray(body.connection.grants) ||
      body.connection.grants.length === 0 ||
      !body.request ||
      typeof body.request !== "object"
    ) {
      return c.json({ error: "Invalid MCP dispatch" }, 400);
    }
    return deps.execute(
      new Request(new URL("/mcp", c.req.url), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: JSON.stringify(body.request),
      }),
      body.connection,
    );
  });
  return app;
}
