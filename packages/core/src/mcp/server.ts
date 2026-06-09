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
import type { McpActivityRecorder, McpActivityStatus } from "./activity.js";

export interface HandleMcpRequestOptions {
  connection: McpConnectionRecord;
  readClient: McpDataReadClient;
  activityRecorder?: McpActivityRecorder;
  serverName?: string;
  serverVersion?: string;
}

const DEFAULT_SERVER_NAME = "vana-personal-server-mcp";
const DEFAULT_SERVER_VERSION = "0.0.1";
const DEFAULT_MCP_TOOL_TIMEOUT_MS = 30_000;
const MAX_MCP_TOOL_TIMEOUT_MS = 90_000;
const MCP_TOOL_TIMEOUT_GRACE_MS = 1_000;

const QUERY_PREVIEW_CHARS = 120;
const textEncoder = new TextEncoder();

class McpToolTimeoutError extends Error {
  constructor(
    public readonly tool: string,
    public readonly timeoutMs: number,
  ) {
    super(`${tool} timed out after ${timeoutMs}ms`);
    this.name = "McpToolTimeoutError";
  }
}

function clampToolTimeout(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return DEFAULT_MCP_TOOL_TIMEOUT_MS;
  }
  return Math.min(MAX_MCP_TOOL_TIMEOUT_MS, Math.max(1000, Math.trunc(value)));
}

function toolTimeoutMs(tool: string, args: Record<string, unknown>): number {
  if (tool === "read_scope" || tool === "search_personal_context") {
    return clampToolTimeout(args.timeoutMs) + MCP_TOOL_TIMEOUT_GRACE_MS;
  }
  return DEFAULT_MCP_TOOL_TIMEOUT_MS;
}

async function withToolTimeout<T>(
  promise: Promise<T>,
  tool: string,
  timeoutMs: number,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new McpToolTimeoutError(tool, timeoutMs)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function buildActivityStartParams(
  tool: string,
  args: Record<string, unknown>,
): { tool: string; scopes?: string[]; queryPreview?: string } {
  const params: { tool: string; scopes?: string[]; queryPreview?: string } = {
    tool,
  };
  if (tool === "read_scope" && typeof args.scope === "string") {
    params.scopes = [args.scope];
  }
  if (tool === "search_personal_context") {
    if (typeof args.query === "string") {
      params.queryPreview = args.query.slice(0, QUERY_PREVIEW_CHARS);
    }
    if (Array.isArray(args.scopes) && args.scopes.length > 0) {
      params.scopes = (args.scopes as unknown[])
        .filter((s): s is string => typeof s === "string")
        .slice(0, 20);
    }
  }
  return params;
}

function extractActivityFinishParams(
  tool: string,
  result: { content: Array<{ type: string; text: string }>; isError?: boolean },
): {
  resultCount?: number;
  skippedCount?: number;
  errorCode?: string;
  errorMessage?: string;
} {
  if (result.isError || result.content.length === 0) {
    try {
      const body = JSON.parse(result.content[0]?.text ?? "{}") as Record<
        string,
        unknown
      >;
      return {
        errorCode: typeof body.error === "string" ? body.error : undefined,
        errorMessage:
          typeof body.message === "string" ? body.message : undefined,
      };
    } catch {
      return {};
    }
  }
  if (tool === "search_personal_context") {
    try {
      const body = JSON.parse(result.content[0].text) as Record<
        string,
        unknown
      >;
      return {
        resultCount: Array.isArray(body.results)
          ? body.results.length
          : Array.isArray(body.matches)
            ? body.matches.length
            : undefined,
        skippedCount: Array.isArray(body.skippedScopes)
          ? body.skippedScopes.length
          : undefined,
      };
    } catch {
      return {};
    }
  }
  if (tool === "read_scope") {
    try {
      const body = JSON.parse(result.content[0].text) as Record<
        string,
        unknown
      >;
      return {
        resultCount: Array.isArray(body.blocks)
          ? body.blocks.length
          : undefined,
      };
    } catch {
      return {};
    }
  }
  return {};
}

interface ActivityPayloadMetrics {
  payloadBytes: number;
  textBytes: number;
  structuredContentBytes?: number;
}

interface PendingActivityFinish extends ActivityPayloadMetrics {
  status: Exclude<McpActivityStatus, "running">;
  handlerDurationMs: number;
  resultCount?: number;
  skippedCount?: number;
  errorCode?: string;
  errorMessage?: string;
}

function bytes(value: string): number {
  return textEncoder.encode(value).byteLength;
}

function estimatePayloadMetrics(result: {
  content?: Array<{ text?: string }>;
  structuredContent?: unknown;
}): ActivityPayloadMetrics {
  const textBytes =
    result.content?.reduce((total, item) => {
      return total + (typeof item.text === "string" ? bytes(item.text) : 0);
    }, 0) ?? 0;
  // The SDK serializes both text content and structuredContent. Avoid a second
  // JSON stringify over very large payloads here; the pretty text body is a
  // conservative estimate for the structured JSON copy created by textResult.
  const structuredContentBytes =
    result.structuredContent !== undefined ? textBytes : undefined;
  return {
    textBytes,
    ...(structuredContentBytes !== undefined ? { structuredContentBytes } : {}),
    payloadBytes: textBytes + (structuredContentBytes ?? 0),
  };
}

function buildErrorResult(body: Record<string, unknown>): {
  isError: true;
  content: Array<{ type: "text"; text: string }>;
} {
  return {
    isError: true,
    content: [
      {
        type: "text",
        text: JSON.stringify(body, null, 2),
      },
    ],
  };
}

function markResponsePreparing(
  recorder: McpActivityRecorder,
  activityId: string,
  finish: PendingActivityFinish,
): void {
  recorder.update(activityId, {
    phase: "response_preparing",
    handlerDurationMs: finish.handlerDurationMs,
    payloadBytes: finish.payloadBytes,
    textBytes: finish.textBytes,
    structuredContentBytes: finish.structuredContentBytes,
    resultCount: finish.resultCount,
    skippedCount: finish.skippedCount,
    errorCode: finish.errorCode,
    errorMessage: finish.errorMessage,
  });
}

/**
 * Build a fresh `McpServer` instance bound to a single connection + read
 * client. Tools delegate to `MCP_TOOLS` so the surface stays in one place.
 */
export function createMcpServerForConnection(
  options: HandleMcpRequestOptions,
): {
  server: McpServer;
  finishPendingActivities(
    override?: Pick<
      PendingActivityFinish,
      "status" | "errorCode" | "errorMessage"
    >,
  ): void;
} {
  const server = new McpServer({
    name: options.serverName ?? DEFAULT_SERVER_NAME,
    version: options.serverVersion ?? DEFAULT_SERVER_VERSION,
  });
  const pendingActivityFinishes = new Map<string, PendingActivityFinish>();

  const ctx: McpToolContext = {
    connection: options.connection,
    readClient: options.readClient,
    activityRecorder: options.activityRecorder,
  };

  for (const tool of MCP_TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
      },
      async (args: Record<string, unknown>) => {
        const recorder = options.activityRecorder;
        const activityId = recorder
          ? recorder.start(buildActivityStartParams(tool.name, args))
          : undefined;
        const handlerStartedAt = performance.now();
        try {
          const timeoutMs = toolTimeoutMs(tool.name, args);
          const result = await withToolTimeout(
            tool.handler(args as Record<string, unknown>, ctx),
            tool.name,
            timeoutMs,
          );
          if (activityId && recorder) {
            const handlerDurationMs = Math.round(
              performance.now() - handlerStartedAt,
            );
            const payload = extractActivityFinishParams(tool.name, result);
            const finish: PendingActivityFinish = {
              status: result.isError ? "failed" : "succeeded",
              handlerDurationMs,
              ...estimatePayloadMetrics(result),
              ...payload,
            };
            markResponsePreparing(recorder, activityId, finish);
            pendingActivityFinishes.set(activityId, finish);
          }
          return result;
        } catch (err) {
          if (err instanceof McpToolTimeoutError) {
            const result = buildErrorResult({
              error: "tool_timeout",
              message: err.message,
              timeoutMs: err.timeoutMs,
            });
            if (activityId && recorder) {
              const finish: PendingActivityFinish = {
                status: "timed_out",
                handlerDurationMs: Math.round(
                  performance.now() - handlerStartedAt,
                ),
                ...estimatePayloadMetrics(result),
                errorCode: "tool_timeout",
                errorMessage: err.message,
              };
              markResponsePreparing(recorder, activityId, finish);
              pendingActivityFinishes.set(activityId, finish);
            }
            return result;
          }
          const result = buildErrorResult({
            error: "tool_handler_error",
            message: err instanceof Error ? err.message : String(err),
          });
          if (activityId && recorder) {
            const finish: PendingActivityFinish = {
              status: "failed",
              handlerDurationMs: Math.round(
                performance.now() - handlerStartedAt,
              ),
              ...estimatePayloadMetrics(result),
              errorCode: "tool_handler_error",
              errorMessage: err instanceof Error ? err.message : String(err),
            };
            markResponsePreparing(recorder, activityId, finish);
            pendingActivityFinishes.set(activityId, finish);
          }
          return result;
        }
      },
    );
  }

  function finishPendingActivities(
    override?: Pick<
      PendingActivityFinish,
      "status" | "errorCode" | "errorMessage"
    >,
  ): void {
    for (const [activityId, finish] of pendingActivityFinishes) {
      options.activityRecorder?.finish(activityId, {
        ...finish,
        ...override,
      });
      pendingActivityFinishes.delete(activityId);
    }
  }

  return { server, finishPendingActivities };
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
  const { server, finishPendingActivities } =
    createMcpServerForConnection(options);
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  try {
    await server.connect(transport);
    const response = await transport.handleRequest(request);
    finishPendingActivities();
    return response;
  } catch (err) {
    finishPendingActivities({
      status: "failed",
      errorCode: "transport_error",
      errorMessage: err instanceof Error ? err.message : String(err),
    });
    throw err;
  } finally {
    await Promise.allSettled([transport.close(), server.close()]);
  }
}
