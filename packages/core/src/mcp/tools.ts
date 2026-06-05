/**
 * MCP tool surface. Phase 1 / §4 of 260604-PLAN-vana-mcp-personal-server.md.
 *
 * Read-only, small, and only over scopes that the connection's grants cover.
 * No write tools. No grant-management tools. No raw owner/admin status tools.
 *
 * Every tool that returns data first picks a covering grant from the
 * connection's grant list, signs a Web3Signed request as the per-connection
 * grantee, and hands it to `handlePersonalServerDataRequest` — so reads are
 * grant-gated and access-logged identically to external builder reads.
 */

import { z } from "zod";
import type { McpConnectionRecord } from "./types.js";
import type { McpDataReadClient } from "./read-client.js";
import { McpDataReadError } from "./read-client.js";

export interface McpToolContext {
  connection: McpConnectionRecord;
  readClient: McpDataReadClient;
}

export interface McpToolResultContent {
  type: "text";
  text: string;
}

export interface McpToolResult {
  content: McpToolResultContent[];
  isError?: boolean;
  // MCP SDK types include an `[x: string]: unknown` index signature for
  // optional metadata; keep ours wide enough to satisfy it.
  [key: string]: unknown;
}

/**
 * Zod raw-shape input schema. The SDK's `registerTool` accepts this and
 * derives a JSON schema for clients.
 */
export type McpToolInputShape = Record<string, z.ZodTypeAny>;

export interface McpToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: McpToolInputShape;
  handler(
    args: Record<string, unknown>,
    ctx: McpToolContext,
  ): Promise<McpToolResult>;
}

function textResult(value: unknown, isError = false): McpToolResult {
  return {
    content: [
      {
        type: "text",
        text:
          typeof value === "string" ? value : JSON.stringify(value, null, 2),
      },
    ],
    ...(isError ? { isError: true } : {}),
  };
}

function uniqueScopes(connection: McpConnectionRecord): string[] {
  const set = new Set<string>();
  for (const grant of connection.grants) {
    for (const scope of grant.scopes) set.add(scope);
  }
  return Array.from(set).sort();
}

function uniqueSources(connection: McpConnectionRecord): string[] {
  const set = new Set<string>();
  for (const grant of connection.grants) {
    if (grant.sourceId) {
      set.add(grant.sourceId);
      continue;
    }
    for (const scope of grant.scopes) {
      const [sourceId] = scope.split(".");
      if (sourceId && sourceId !== "*") {
        set.add(sourceId);
      }
    }
  }
  return Array.from(set).sort();
}

const SEARCH_PREVIEW_CHARS = 800;

function stringifyForSearch(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}

function previewMatch(haystack: string, matchIndex: number): string {
  const halfWindow = Math.floor(SEARCH_PREVIEW_CHARS / 2);
  const start = Math.max(0, matchIndex - halfWindow);
  const end = Math.min(haystack.length, start + SEARCH_PREVIEW_CHARS);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < haystack.length ? "..." : "";
  return `${prefix}${haystack.slice(start, end)}${suffix}`;
}

function getEnvelopeCollectedAt(value: unknown): string | undefined {
  if (
    typeof value !== "object" ||
    value === null ||
    !("collectedAt" in value)
  ) {
    return undefined;
  }
  const collectedAt = (value as { collectedAt?: unknown }).collectedAt;
  return typeof collectedAt === "string" ? collectedAt : undefined;
}

/**
 * Resolve a requested scope to a covering grant id from the connection's
 * approved grants. A scope is "covered" when an approved grant's scopes
 * either contains the exact scope or contains a wildcard like `instagram.*`
 * that matches it.
 *
 * Mirrors `scopeCoveredByGrant` semantics from `policy/data-read.ts` so the
 * tool surface never offers Claude a scope its grant won't actually pass
 * server-side.
 */
function resolveGrantForScope(
  connection: McpConnectionRecord,
  scope: string,
): { grantId: string; scopes: string[] } | null {
  for (const grant of connection.grants) {
    for (const granted of grant.scopes) {
      if (granted === scope) {
        return { grantId: grant.grantId, scopes: grant.scopes };
      }
      if (granted.endsWith(".*")) {
        const prefix = granted.slice(0, -2);
        if (scope === prefix || scope.startsWith(`${prefix}.`)) {
          return { grantId: grant.grantId, scopes: grant.scopes };
        }
      }
      if (granted === "*") {
        return { grantId: grant.grantId, scopes: grant.scopes };
      }
    }
  }
  return null;
}

async function expandSearchScopes(
  connection: McpConnectionRecord,
  readClient: McpDataReadClient,
  requestedScopes: string[],
): Promise<{
  scopes: string[];
  errors: Array<{
    scope: string;
    grantId: string;
    status: number;
    bodyPreview: string;
  }>;
}> {
  const scopes = new Set<string>();
  const errors: Array<{
    scope: string;
    grantId: string;
    status: number;
    bodyPreview: string;
  }> = [];

  for (const requested of requestedScopes) {
    const grant = resolveGrantForScope(connection, requested);
    if (!grant) continue;

    const wildcardPrefix =
      requested === "*"
        ? ""
        : requested.endsWith(".*")
          ? `${requested.slice(0, -2)}.`
          : null;

    if (wildcardPrefix === null) {
      scopes.add(requested);
      continue;
    }

    try {
      const listed = await readClient.listScopes({
        scopePrefix: wildcardPrefix,
        grantId: grant.grantId,
        limit: 200,
      });
      for (const summary of listed.scopes) {
        if (resolveGrantForScope(connection, summary.scope)) {
          scopes.add(summary.scope);
        }
      }
    } catch (err) {
      errors.push({
        scope: requested,
        grantId: grant.grantId,
        status: err instanceof McpDataReadError ? err.status : 500,
        bodyPreview: stringifyForSearch(
          err instanceof McpDataReadError ? err.body : String(err),
        ).slice(0, SEARCH_PREVIEW_CHARS),
      });
    }
  }

  return { scopes: Array.from(scopes).sort(), errors };
}

const listGrantedSources: McpToolDefinition = {
  name: "list_granted_sources",
  title: "List granted sources",
  description:
    "List the data sources (e.g. instagram, chatgpt) the user has granted this MCP connection access to.",
  inputSchema: {},
  async handler(_args, { connection }) {
    return textResult({ sources: uniqueSources(connection) });
  },
};

const listGrantedScopes: McpToolDefinition = {
  name: "list_granted_scopes",
  title: "List granted scopes",
  description:
    "List the scope identifiers the user has approved this MCP connection to read.",
  inputSchema: {},
  async handler(_args, { connection }) {
    return textResult({ scopes: uniqueScopes(connection) });
  },
};

const readScope: McpToolDefinition = {
  name: "read_scope",
  title: "Read scope",
  description:
    "Read approved data for a single scope. Returns the latest scope envelope (collectedAt, source metadata, data).",
  inputSchema: {
    scope: z
      .string()
      .min(1)
      .describe("Exact scope id, e.g. 'instagram.profile'."),
    limit: z.number().int().min(1).max(100).optional(),
  },
  async handler(args, { connection, readClient }) {
    const scope = typeof args.scope === "string" ? args.scope : null;
    if (!scope) {
      return textResult(
        { error: "scope is required and must be a string" },
        true,
      );
    }
    const grant = resolveGrantForScope(connection, scope);
    if (!grant) {
      return textResult(
        {
          error: "scope_not_granted",
          message: `Scope '${scope}' is not covered by any grant on this MCP connection.`,
          grantedScopes: uniqueScopes(connection),
        },
        true,
      );
    }

    const limit = typeof args.limit === "number" ? args.limit : undefined;
    try {
      const result = await readClient.readScope({
        scope,
        grantId: grant.grantId,
        limit,
      });
      return textResult({
        scope,
        grantId: grant.grantId,
        data: result.body,
      });
    } catch (err) {
      if (err instanceof McpDataReadError) {
        return textResult(
          { error: "data_read_failed", status: err.status, body: err.body },
          true,
        );
      }
      return textResult(
        {
          error: "tool_handler_error",
          message: err instanceof Error ? err.message : String(err),
        },
        true,
      );
    }
  },
};

const searchPersonalContext: McpToolDefinition = {
  name: "search_personal_context",
  title: "Search personal context",
  description:
    "Search across granted scopes for entries containing a query string. Phase-1 implementation is simple case-insensitive substring matching over scope envelopes; no semantic search.",
  inputSchema: {
    query: z.string().min(1),
    scopes: z.array(z.string()).optional(),
    limit: z.number().int().min(1).max(50).optional(),
  },
  async handler(args, { connection, readClient }) {
    const query = typeof args.query === "string" ? args.query.trim() : null;
    if (!query) {
      return textResult(
        { error: "query is required and must be a non-empty string" },
        true,
      );
    }
    const requestedScopes = Array.isArray(args.scopes)
      ? args.scopes.filter((s): s is string => typeof s === "string")
      : uniqueScopes(connection);
    const limit = typeof args.limit === "number" ? args.limit : 10;
    const needle = query.toLowerCase();

    const matches: Array<{
      scope: string;
      grantId: string;
      collectedAt?: string;
      preview: string;
      resultSizeChars: number;
    }> = [];
    const errors: Array<{
      scope: string;
      grantId: string;
      status: number;
      bodyPreview: string;
    }> = [];
    const expanded = await expandSearchScopes(
      connection,
      readClient,
      requestedScopes,
    );
    errors.push(...expanded.errors);

    for (const scope of expanded.scopes) {
      if (matches.length >= limit) break;
      const grant = resolveGrantForScope(connection, scope);
      if (!grant) continue;
      try {
        const result = await readClient.readScope({
          scope,
          grantId: grant.grantId,
        });
        const haystack = stringifyForSearch(result.body ?? "");
        const matchIndex = haystack.toLowerCase().indexOf(needle);
        if (matchIndex >= 0) {
          matches.push({
            scope,
            grantId: grant.grantId,
            collectedAt: getEnvelopeCollectedAt(result.body),
            preview: previewMatch(haystack, matchIndex),
            resultSizeChars: haystack.length,
          });
        }
      } catch (err) {
        if (err instanceof McpDataReadError && err.status === 404) continue;
        // Surface non-404 errors as part of the result so the caller can debug,
        // but keep going across other scopes.
        errors.push({
          scope,
          grantId: grant.grantId,
          status: err instanceof McpDataReadError ? err.status : 500,
          bodyPreview: stringifyForSearch(
            err instanceof McpDataReadError ? err.body : String(err),
          ).slice(0, SEARCH_PREVIEW_CHARS),
        });
      }
    }

    return textResult({ query, matches, errors });
  },
};

export const MCP_TOOLS: readonly McpToolDefinition[] = [
  listGrantedSources,
  listGrantedScopes,
  readScope,
  searchPersonalContext,
] as const;
