/**
 * MCP Streamable-HTTP server adapter. Per-request, stateless.
 *
 * Pattern adopted from `@pdpp/mcp-server`'s `handleStreamableHttpRequest`:
 * a fresh `McpServer` + `WebStandardStreamableHTTPServerTransport` per
 * inbound request. This keeps authorization checks fresh — the route
 * resolves the connection token, hands us the `McpConnectionRecord`, and we
 * build the server bound to that connection. There is NO MCP session.
 *
 * The transport supports Streamable HTTP (GET=SSE, POST=JSON-RPC,
 * DELETE=close). Claude Web's remote connector speaks this.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { McpConnectionRecord } from "./types.js";
import type { McpDataReadClient } from "./read-client.js";
import { MCP_TOOLS, type McpToolContext } from "./tools.js";

export interface HandleMcpRequestOptions {
  connection: McpConnectionRecord;
  readClient: McpDataReadClient;
  serverName?: string;
  serverVersion?: string;
}

const DEFAULT_SERVER_NAME = "vana-personal-server-mcp";
const DEFAULT_SERVER_VERSION = "0.0.1";

/**
 * Build a fresh `McpServer` instance bound to a single connection + read
 * client. Tools delegate to `MCP_TOOLS` so the surface stays in one place.
 */
export function createMcpServerForConnection(
  options: HandleMcpRequestOptions,
): { server: McpServer } {
  const server = new McpServer({
    name: options.serverName ?? DEFAULT_SERVER_NAME,
    version: options.serverVersion ?? DEFAULT_SERVER_VERSION,
  });

  const ctx: McpToolContext = {
    connection: options.connection,
    readClient: options.readClient,
  };

  for (const tool of MCP_TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
      },
      async (args) => {
        try {
          return await tool.handler(args as Record<string, unknown>, ctx);
        } catch (err) {
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    error: "tool_handler_error",
                    message: err instanceof Error ? err.message : String(err),
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
      },
    );
  }

  return { server };
}

/**
 * Process one inbound MCP request (GET/POST/DELETE) end-to-end. Per-request
 * server + transport; stateless; no MCP session id retained.
 *
 * Returns a Web `Response` suitable to send back to the client.
 */
export async function handleMcpStreamableHttpRequest(
  request: Request,
  options: HandleMcpRequestOptions,
): Promise<Response> {
  const { server } = createMcpServerForConnection(options);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  try {
    await server.connect(transport);
    return await transport.handleRequest(request);
  } finally {
    await Promise.allSettled([transport.close(), server.close()]);
  }
}
