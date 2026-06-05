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

const DEFAULT_SEARCH_LIMIT = 5;
const MAX_SEARCH_LIMIT = 20;
const DEFAULT_SEARCH_MAX_SCOPES = 6;
const MAX_SEARCH_SCOPES = 10;
const DEFAULT_SEARCH_TIMEOUT_MS = 3_500;
const MAX_SEARCH_TIMEOUT_MS = 5_000;
const DEFAULT_SEARCH_DISCOVERY_TIMEOUT_MS = 1_000;
const SEARCH_QUERY_MAX_CHARS = 256;
const SEARCH_SCOPE_MAX_CHARS = 128;
const SEARCH_REQUESTED_SCOPES_LIMIT = MAX_SEARCH_SCOPES * 2;
const SEARCH_SKIPPED_SCOPES_LIMIT = 50;
const SEARCH_PREVIEW_CHARS = 600;
const SEARCH_TEXT_CHAR_BUDGET = 100_000;
const LIST_SCOPES_LIMIT = 200;

class OperationTimeoutError extends Error {
  constructor(
    public readonly operation: string,
    public readonly timeoutMs: number,
  ) {
    super(`${operation} timed out after ${timeoutMs}ms`);
    this.name = "OperationTimeoutError";
  }
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
        if (scope.startsWith(`${prefix}.`)) {
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

function clampInteger(
  value: unknown,
  fallback: number,
  min: number,
  max: number,
) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function wildcardPrefix(scope: string): string | null {
  if (scope === "*") return "";
  if (scope.endsWith(".*")) return `${scope.slice(0, -2)}.`;
  return null;
}

function truncateLabel(value: string): string {
  return value.length > SEARCH_SCOPE_MAX_CHARS
    ? `${value.slice(0, SEARCH_SCOPE_MAX_CHARS)}...`
    : value;
}

function stringifyPreview(value: unknown): string {
  if (typeof value === "string") {
    return value.slice(0, SEARCH_PREVIEW_CHARS);
  }
  try {
    return JSON.stringify(value)?.slice(0, SEARCH_PREVIEW_CHARS) ?? "";
  } catch {
    return String(value).slice(0, SEARCH_PREVIEW_CHARS);
  }
}

function previewMatch(text: string, matchIndex: number): string {
  const halfWindow = Math.floor(SEARCH_PREVIEW_CHARS / 2);
  const start = Math.max(0, matchIndex - halfWindow);
  const end = Math.min(text.length, start + SEARCH_PREVIEW_CHARS);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < text.length ? "..." : "";
  return `${prefix}${text.slice(start, end)}${suffix}`;
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timeout = setTimeout(
          () => reject(new OperationTimeoutError(operation, timeoutMs)),
          timeoutMs,
        );
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

function normalizeRequestedScopes(
  value: unknown,
  connection: McpConnectionRecord,
): { requestedScopes: string[]; skippedScopes: string[] } {
  const input = Array.isArray(value) ? value : uniqueScopes(connection);
  const requestedScopes: string[] = [];
  const seen = new Set<string>();
  const skippedScopes: string[] = [];
  const scanned = Math.min(input.length, SEARCH_REQUESTED_SCOPES_LIMIT);
  let invalidCount = 0;

  for (let index = 0; index < scanned; index += 1) {
    const scope = input[index];
    if (typeof scope !== "string") {
      invalidCount += 1;
      continue;
    }
    const trimmed = scope.trim();
    if (!trimmed || trimmed.length > SEARCH_SCOPE_MAX_CHARS) {
      invalidCount += 1;
      continue;
    }
    if (seen.has(trimmed)) continue;
    seen.add(trimmed);
    requestedScopes.push(trimmed);
  }

  if (input.length > SEARCH_REQUESTED_SCOPES_LIMIT) {
    skippedScopes.push(
      `${input.length - SEARCH_REQUESTED_SCOPES_LIMIT} requested scopes omitted by input cap`,
    );
  }
  if (invalidCount > 0) {
    skippedScopes.push(`${invalidCount} invalid requested scopes omitted`);
  }

  return { requestedScopes, skippedScopes };
}

async function resolveSearchScopes({
  connection,
  maxScopes,
  discoveryTimeoutMs,
  readClient,
  requestedScopes,
}: {
  connection: McpConnectionRecord;
  maxScopes: number;
  discoveryTimeoutMs: number;
  readClient: McpDataReadClient;
  requestedScopes: string[];
}): Promise<{
  scopes: string[];
  skippedScopes: string[];
  errors: Array<{
    scope: string;
    error: string;
    status?: number;
    bodyPreview?: string;
  }>;
}> {
  const scopes = new Set<string>();
  const skippedScopes: string[] = [];
  let skippedScopeOverflow = 0;
  const errors: Array<{
    scope: string;
    error: string;
    status?: number;
    bodyPreview?: string;
  }> = [];
  let wildcardDiscoveries = 0;

  function skipScope(scope: string) {
    if (skippedScopes.length < SEARCH_SKIPPED_SCOPES_LIMIT) {
      skippedScopes.push(truncateLabel(scope));
      return;
    }
    skippedScopeOverflow += 1;
  }

  function addScope(scope: string) {
    if (scopes.has(scope)) return;
    if (scopes.size >= maxScopes) {
      skipScope(scope);
      return;
    }
    scopes.add(scope);
  }

  for (const requested of requestedScopes) {
    if (scopes.size >= maxScopes) {
      skipScope(requested);
      continue;
    }

    const grant = resolveGrantForScope(connection, requested);
    if (!grant) {
      errors.push({ scope: requested, error: "scope_not_granted" });
      continue;
    }

    const prefix = wildcardPrefix(requested);
    if (prefix === null) {
      addScope(requested);
      continue;
    }

    if (wildcardDiscoveries >= maxScopes) {
      skipScope(`${requested} (wildcard discovery cap reached)`);
      continue;
    }
    wildcardDiscoveries += 1;

    try {
      const listed = await withTimeout(
        readClient.listScopes({
          scopePrefix: prefix,
          limit: LIST_SCOPES_LIMIT,
        }),
        discoveryTimeoutMs,
        `list scopes for ${requested}`,
      );
      for (const summary of listed.scopes) {
        if (resolveGrantForScope(connection, summary.scope)) {
          addScope(summary.scope);
        }
      }
      if (listed.total > listed.scopes.length) {
        skipScope(`${requested} (more than ${listed.scopes.length})`);
      }
    } catch (err) {
      errors.push({
        scope: requested,
        error:
          err instanceof OperationTimeoutError
            ? "scope_list_timeout"
            : "scope_list_failed",
        status: err instanceof McpDataReadError ? err.status : undefined,
        bodyPreview: stringifyPreview(
          err instanceof McpDataReadError
            ? err.body
            : err instanceof OperationTimeoutError
              ? err.message
              : "unexpected scope list failure",
        ),
      });
    }
  }

  if (skippedScopeOverflow > 0) {
    skippedScopes.push(
      `${skippedScopeOverflow} additional skipped scopes omitted`,
    );
  }

  return {
    scopes: Array.from(scopes).sort(),
    skippedScopes: Array.from(new Set(skippedScopes)).sort(),
    errors,
  };
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
    "Search a bounded set of approved scopes for a literal query string. For large data, call list_granted_scopes first and pass specific scopes. This tool caps scope count, per-scope work, and response previews; skippedScopes means narrow the scopes and retry.",
  inputSchema: {
    query: z.string().min(1).max(SEARCH_QUERY_MAX_CHARS),
    scopes: z
      .array(z.string().min(1).max(SEARCH_SCOPE_MAX_CHARS))
      .max(SEARCH_REQUESTED_SCOPES_LIMIT)
      .optional(),
    limit: z.number().int().min(1).max(MAX_SEARCH_LIMIT).optional(),
    maxScopes: z.number().int().min(1).max(MAX_SEARCH_SCOPES).optional(),
    timeoutMs: z.number().int().min(50).max(MAX_SEARCH_TIMEOUT_MS).optional(),
  },
  async handler(args, { connection, readClient }) {
    const query = typeof args.query === "string" ? args.query.trim() : "";
    if (!query) {
      return textResult(
        { error: "query is required and must be a non-empty string" },
        true,
      );
    }
    if (query.length > SEARCH_QUERY_MAX_CHARS) {
      return textResult(
        {
          error: "query_too_long",
          maxQueryChars: SEARCH_QUERY_MAX_CHARS,
        },
        true,
      );
    }

    const normalizedScopes = normalizeRequestedScopes(args.scopes, connection);
    const requestedScopes = normalizedScopes.requestedScopes;
    const limit = clampInteger(
      args.limit,
      DEFAULT_SEARCH_LIMIT,
      1,
      MAX_SEARCH_LIMIT,
    );
    const maxScopes = clampInteger(
      args.maxScopes,
      DEFAULT_SEARCH_MAX_SCOPES,
      1,
      MAX_SEARCH_SCOPES,
    );
    const timeoutMs = clampInteger(
      args.timeoutMs,
      DEFAULT_SEARCH_TIMEOUT_MS,
      50,
      MAX_SEARCH_TIMEOUT_MS,
    );
    const discoveryTimeoutMs = Math.min(
      timeoutMs,
      DEFAULT_SEARCH_DISCOVERY_TIMEOUT_MS,
    );
    const needle = query.toLowerCase();

    const resolved = await resolveSearchScopes({
      connection,
      maxScopes,
      discoveryTimeoutMs,
      readClient,
      requestedScopes,
    });
    const matches: Array<{
      scope: string;
      grantId: string;
      collectedAt?: string;
      preview: string;
      searchedChars: number;
      truncated: boolean;
    }> = [];
    const truncatedScopes: string[] = [];
    const errors = [...resolved.errors];

    const searchResults = await Promise.all(
      resolved.scopes.map(async (scope) => {
        const grant = resolveGrantForScope(connection, scope);
        if (!grant) return null;
        try {
          const result = await withTimeout(
            readClient.previewScope({
              scope,
              grantId: grant.grantId,
              maxBytes: SEARCH_TEXT_CHAR_BUDGET,
            }),
            timeoutMs,
            `preview scope ${scope}`,
          );
          const matchIndex = result.text.toLowerCase().indexOf(needle);
          if (matchIndex < 0) {
            return {
              match: null,
              scope,
              truncated: result.truncated,
            };
          }
          return {
            match: {
              scope,
              grantId: grant.grantId,
              collectedAt: result.collectedAt,
              preview: previewMatch(result.text, matchIndex),
              searchedChars: result.text.length,
              truncated: result.truncated,
            },
            scope,
            truncated: result.truncated,
          };
        } catch (err) {
          errors.push({
            scope,
            error:
              err instanceof OperationTimeoutError
                ? "scope_search_timeout"
                : "scope_read_failed",
            status: err instanceof McpDataReadError ? err.status : undefined,
            bodyPreview: stringifyPreview(
              err instanceof McpDataReadError
                ? err.body
                : err instanceof OperationTimeoutError
                  ? err.message
                  : "unexpected scope read failure",
            ),
          });
          return null;
        }
      }),
    );

    for (const result of searchResults) {
      if (!result) continue;
      if (result.truncated) {
        truncatedScopes.push(result.scope);
      }
      if (!result.match) continue;
      if (matches.length < limit) {
        matches.push(result.match);
      }
    }

    return textResult({
      query,
      matches,
      searchedScopes: resolved.scopes,
      skippedScopes: [
        ...normalizedScopes.skippedScopes,
        ...resolved.skippedScopes,
      ],
      truncatedScopes,
      errors,
      limits: {
        maxMatches: limit,
        maxScopes,
        maxRequestedScopes: SEARCH_REQUESTED_SCOPES_LIMIT,
        timeoutMs,
        discoveryTimeoutMs,
        queryChars: SEARCH_QUERY_MAX_CHARS,
        scopeChars: SEARCH_SCOPE_MAX_CHARS,
        previewChars: SEARCH_PREVIEW_CHARS,
        searchedCharsPerScope: SEARCH_TEXT_CHAR_BUDGET,
      },
    });
  },
};

export const MCP_TOOLS: readonly McpToolDefinition[] = [
  listGrantedSources,
  listGrantedScopes,
  readScope,
  searchPersonalContext,
] as const;
