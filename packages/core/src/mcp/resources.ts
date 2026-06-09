import type { ReadResourceResult } from "@modelcontextprotocol/sdk/types.js";
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
    throw new McpDataReadError(403, {
      error: "scope_not_granted",
      message: `Scope '${params.scope}' is not covered by this MCP connection.`,
    });
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
  includeContent: z.boolean().optional().describe("Embed bytes as MCP blob."),
  maxBytes: z
    .number()
    .int()
    .min(1)
    .max(25 * 1024 * 1024)
    .optional()
    .describe("Max embedded bytes."),
};
