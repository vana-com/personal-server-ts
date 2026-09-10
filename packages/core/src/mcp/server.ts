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

import {
  McpServer,
  ResourceTemplate,
} from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { McpConnectionRecord } from "./types.js";
import type { McpDataReadClient } from "./read-client.js";
import {
  MAX_MCP_TOOL_TIMEOUT_MS,
  MCP_TOOLS,
  resolveGrantForScope,
  type McpToolContext,
  type McpToolResultContent,
} from "./tools.js";
import {
  READ_FULFILLMENT_NONE,
  reportPersonalServerReadDenial,
  type PersonalServerReadReporterDeps,
} from "../api/index.js";
import type { McpActivityRecorder, McpActivityStatus } from "./activity.js";
import {
  RAW_SCOPE_RESOURCE_TEMPLATES,
  readRawScopeResource,
} from "./resources.js";

export interface HandleMcpRequestOptions {
  connection: McpConnectionRecord;
  readClient: McpDataReadClient;
  activityRecorder?: McpActivityRecorder;
  /** Emits one access record per denied data tool call; see reportToolDenial. */
  reporterDeps?: PersonalServerReadReporterDeps;
  serverName?: string;
  serverVersion?: string;
}

const DEFAULT_SERVER_NAME = "vana-personal-server-mcp";
const DEFAULT_SERVER_VERSION = "0.0.1";
const DEFAULT_MCP_TOOL_TIMEOUT_MS = 30_000;
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
  if (
    tool === "read_scope" ||
    tool === "search_personal_context" ||
    tool === "get_scope_file"
  ) {
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
  if (
    (tool === "read_scope" || tool === "get_scope_file") &&
    typeof args.scope === "string"
  ) {
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

/**
 * Tools that reach the owner's data. Only these produce access records — the
 * discovery tools (`list_granted_*`, `request_scope_access`) touch none.
 */
const DATA_TOOLS = new Set([
  "get_scope_file",
  "list_scope_blocks",
  "read_scope",
  "search_personal_context",
]);

/**
 * Tool error codes that mean "the read was refused", as opposed to a failure
 * (timeout, storage error). Only these are worth an access record: they are
 * decisions about the grantee's access, not incidents.
 */
const DENY_CODES = new Set([
  "payment_required",
  "scope_deleted",
  "scope_not_granted",
  "unauthorized",
]);

const PAYMENT_REQUIRED_CODE = "payment_required";

/**
 * Extract the deny code from a tool result, or undefined when the call was
 * served or failed for a non-deny reason. `read_scope` signals a chargeable
 * scope with a top-level `payment_required: true` rather than an error code.
 */
function denyCode(result: {
  content: McpToolResultContent[];
  isError?: boolean;
}): string | undefined {
  if (!result.isError) return undefined;

  const first = result.content[0];
  if (first?.type !== "text") return undefined;

  let body: Record<string, unknown>;
  try {
    body = JSON.parse(first.text) as Record<string, unknown>;
  } catch {
    return undefined;
  }

  if (typeof body.error === "string" && DENY_CODES.has(body.error)) {
    return body.error;
  }

  return body[PAYMENT_REQUIRED_CODE] === true
    ? PAYMENT_REQUIRED_CODE
    : undefined;
}

/**
 * One access record per denied data tool call. Fire-and-forget by contract:
 * the tool result is already computed and is returned regardless.
 */
function reportToolDenial(
  options: HandleMcpRequestOptions,
  tool: string,
  args: Record<string, unknown>,
  result: { content: McpToolResultContent[]; isError?: boolean },
): void {
  if (!options.reporterDeps || !DATA_TOOLS.has(tool)) return;

  const reason = denyCode(result);
  if (!reason) return;

  // The denied scope, if the call named one; a multi-scope search records the
  // first, since the owner's decision is one record per tool call.
  const scope =
    buildActivityStartParams(tool, args).scopes?.[0] ?? READ_FULFILLMENT_NONE;

  // A refusal is filed under the grant the call arrived on. A scope no grant
  // covers has no grant of its own, but the connection's grant is the access
  // relationship the owner's feed groups by — and the Gateway only stores a
  // 32-byte grant id, so `READ_FULFILLMENT_NONE` here is refused on ingest and
  // takes its whole batch down with it. A connection left with no grant at all
  // has nothing to attribute the refusal to, so it reports nothing.
  const grantId =
    resolveGrantForScope(options.connection, scope)?.grantId ??
    options.connection.grants[0]?.grantId;
  if (!grantId) return;

  reportPersonalServerReadDenial(options.reporterDeps, {
    builder: options.connection.granteeAddress,
    denyReason: reason,
    grantId,
    logId: crypto.randomUUID(),
    outcome: "denied",
    scope,
    servedAt: new Date().toISOString(),
    source: "mcp",
    tool,
  });
}

function extractActivityFinishParams(
  tool: string,
  result: { content: McpToolResultContent[]; isError?: boolean },
): {
  resultCount?: number;
  skippedCount?: number;
  errorCode?: string;
  errorMessage?: string;
} {
  if (result.isError || result.content.length === 0) {
    try {
      const firstText =
        result.content[0]?.type === "text" ? result.content[0].text : "{}";
      const body = JSON.parse(firstText) as Record<string, unknown>;
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
      const firstText =
        result.content[0]?.type === "text" ? result.content[0].text : "{}";
      const body = JSON.parse(firstText) as Record<string, unknown>;
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
      const firstText =
        result.content[0]?.type === "text" ? result.content[0].text : "{}";
      const body = JSON.parse(firstText) as Record<string, unknown>;
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
  content?: McpToolResultContent[];
  structuredContent?: unknown;
}): ActivityPayloadMetrics {
  const textBytes =
    result.content?.reduce((total, item) => {
      if (item.type === "text") return total + bytes(item.text);
      if (item.type === "resource") {
        return total + bytes(item.resource.blob);
      }
      return total + bytes(JSON.stringify(item));
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
          reportToolDenial(options, tool.name, args, result);
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

  RAW_SCOPE_RESOURCE_TEMPLATES.forEach((template, index) => {
    server.registerResource(
      `raw-scope-file-${index}`,
      new ResourceTemplate(template, { list: undefined }),
      {
        title: "Raw scope file",
        description:
          "Original binary/unstructured file bytes for an approved Vana scope.",
        mimeType: "application/octet-stream",
      },
      async (uri) => readRawScopeResource(uri, ctx),
    );
  });

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
