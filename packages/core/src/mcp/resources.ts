import { isSystemScope } from "../policy/reserved-scopes.js";
import {
  ErrorCode,
  McpError,
  type ReadResourceResult,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { McpDataReadError, type McpDataReadClient } from "./read-client.js";
import type { McpConnectionRecord } from "./types.js";

export const RAW_SCOPE_RESOURCE_TEMPLATES = [
  "vana://scope/{scope}/raw",
  "vana://scope/{scope}/raw/at/{at}",
  "vana://scope/{scope}/raw/file/{fileId}",
] as const;

export interface RawScopeResourceParams {
  scope: string;
  at?: string;
  fileId?: string;
}

export interface RawScopeResourceContext {
  connection: McpConnectionRecord;
  readClient: McpDataReadClient;
  /** Host option `mcpScopeRequestGuidance`: add `nextAction` to the refusal. */
  scopeRequestGuidance?: boolean;
}

export function rawScopeResourceUri(params: RawScopeResourceParams): string {
  const scope = encodeURIComponent(params.scope);
  if (params.fileId) {
    return `vana://scope/${scope}/raw/file/${encodeURIComponent(params.fileId)}`;
  }
  if (params.at) {
    return `vana://scope/${scope}/raw/at/${encodeURIComponent(params.at)}`;
  }
  return `vana://scope/${scope}/raw`;
}

export function parseRawScopeResourceUri(uri: URL): RawScopeResourceParams {
  if (uri.protocol !== "vana:" || uri.hostname !== "scope") {
    throw new Error("Invalid raw scope resource URI");
  }
  const parts = uri.pathname.split("/").filter(Boolean);
  if (parts.length < 2 || parts[1] !== "raw") {
    throw new Error("Invalid raw scope resource URI");
  }
  if (parts.length === 4 && parts[2] === "at") {
    return {
      scope: decodeURIComponent(parts[0] ?? ""),
      at: decodeURIComponent(parts[3] ?? ""),
    };
  }
  if (parts.length === 4 && parts[2] === "file") {
    return {
      scope: decodeURIComponent(parts[0] ?? ""),
      fileId: decodeURIComponent(parts[3] ?? ""),
    };
  }
  if (parts.length !== 2) {
    throw new Error("Invalid raw scope resource URI");
  }
  return {
    scope: decodeURIComponent(parts[0] ?? ""),
  };
}

export function resolveGrantForRawScopeResource(
  connection: McpConnectionRecord,
  scope: string,
): { grantId: string } | null {
  if (isSystemScope(scope)) return null;
  for (const grant of connection.grants) {
    for (const granted of grant.scopes) {
      if (granted === scope || granted === "*") {
        return { grantId: grant.grantId };
      }
      if (granted.endsWith(".*")) {
        const prefix = granted.slice(0, -2);
        if (scope.startsWith(`${prefix}.`)) {
          return { grantId: grant.grantId };
        }
      }
    }
  }
  return null;
}

export async function readRawScopeResource(
  uri: URL,
  ctx: RawScopeResourceContext,
): Promise<ReadResourceResult> {
  const params = parseRawScopeResourceUri(uri);
  const grant = resolveGrantForRawScopeResource(ctx.connection, params.scope);
  if (!grant) {
    const body = {
      error: "scope_not_granted",
      message: `Scope '${params.scope}' is not covered by this MCP connection.`,
    };
    if (ctx.scopeRequestGuidance) {
      // The SDK sends a client only an error's message and `data`, and only
      // when the error carries a numeric `code`; a McpDataReadError's body
      // never reaches the wire. Raise a protocol error that carries both.
      const nextAction = `Call request_scope_access with scopes ${JSON.stringify([params.scope])}, then ask the user to approve it in Vana. This does not indicate whether the data exists.`;
      throw new McpError(
        ErrorCode.InvalidParams,
        `${body.message} ${nextAction}`,
        { ...body, scope: params.scope, nextAction },
      );
    }
    throw new McpDataReadError(403, body);
  }

  const raw = await ctx.readClient.readRawScopeFile({
    scope: params.scope,
    grantId: grant.grantId,
    at: params.at,
    fileId: params.fileId,
  });

  return {
    contents: [
      {
        uri: uri.toString(),
        mimeType: raw.mimeType,
        blob: raw.contentBase64,
        _meta: rawScopeMetadata(raw),
      },
    ],
  };
}

export function rawScopeMetadata(raw: {
  scope: string;
  collectedAt?: string;
  fileId?: string;
  filename?: string;
  mimeType: string;
  sizeBytes: number;
  metadata?: unknown;
}): Record<string, unknown> {
  return {
    scope: raw.scope,
    ...(raw.collectedAt ? { collectedAt: raw.collectedAt } : {}),
    ...(raw.fileId ? { fileId: raw.fileId } : {}),
    ...(raw.filename ? { filename: raw.filename } : {}),
    mimeType: raw.mimeType,
    sizeBytes: raw.sizeBytes,
    ...(raw.metadata !== undefined ? { metadata: raw.metadata } : {}),
  };
}

export const rawScopeFileInputSchema = {
  scope: z.string().min(1).describe("Exact approved file scope."),
  at: z.string().min(1).optional(),
  fileId: z.string().min(1).optional(),
  includeContent: z
    .boolean()
    .optional()
    .describe(
      "Embed bytes as an MCP resource blob. Defaults to false; resource links are safer for broad client compatibility.",
    ),
  maxBytes: z
    .number()
    .int()
    .min(1)
    .max(25 * 1024 * 1024)
    .optional()
    .describe("Max embedded bytes."),
};
