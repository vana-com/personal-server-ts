/**
 * MCP tool surface. Phase 1 / §4 of 260604-PLAN-vana-mcp-personal-server.md.
 *
 * Read-only, small, and only over scopes that the connection's grants cover.
 * No write tools. No grant-management tools. No raw owner/admin status tools.
 *
 * Every tool that returns data first picks a covering grant from the
 * connection's grant list, signs a Web3Signed request as the per-connection
 * grantee, and uses the bounded sidecar read path — so reads are grant-gated,
 * access-logged, and safe for large scopes.
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
    const sourceId =
      typeof grant.sourceId === "string" ? grant.sourceId.trim() : "";
    if (sourceId) {
      set.add(sourceId);
      continue;
    }
    for (const scope of grant.scopes) {
      const [scopeSourceId] = scope.split(".");
      if (scopeSourceId && scopeSourceId !== "*") {
        set.add(scopeSourceId);
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
const MAX_SEARCH_TOTAL_TIMEOUT_MS = 10_000;
const DEFAULT_READ_SCOPE_MAX_BYTES = 16_384;
const MAX_READ_SCOPE_MAX_BYTES = 65_536;
const DEFAULT_SEARCH_MAX_BYTES = 8_192;
const MAX_SEARCH_MAX_BYTES = 32_768;
const SEARCH_MAX_PAGES_PER_SCOPE = 4;
const SEARCH_QUERY_MAX_CHARS = 256;
const SEARCH_SCOPE_MAX_CHARS = 128;
const SEARCH_REQUESTED_SCOPES_LIMIT = MAX_SEARCH_SCOPES * 2;
const SEARCH_SKIPPED_SCOPES_LIMIT = 50;
const SEARCH_PREVIEW_CHARS = 600;
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
 * Resolve a concrete requested scope to a covering grant id from the
 * connection's approved grants. A scope is "covered" when an approved grant's
 * scopes either contains the exact scope or contains a wildcard like
 * `instagram.*` that matches a concrete child scope like `instagram.profile`.
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

function collectSearchText(value: unknown): string {
  const chunks: string[] = [];

  function visit(node: unknown) {
    if (typeof node === "string") {
      chunks.push(node);
      return;
    }
    if (
      typeof node === "number" ||
      typeof node === "boolean" ||
      node === null
    ) {
      chunks.push(String(node));
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item);
      return;
    }
    if (typeof node === "object" && node !== null) {
      for (const [key, item] of Object.entries(node)) {
        chunks.push(key);
        visit(item);
      }
    }
  }

  visit(value);
  return chunks.join("\n");
}

function blockPageSearchText(
  blocks: Array<{ path: string; value: unknown }>,
): string {
  return blocks
    .map((block) => `${block.path}\n${collectSearchText(block.value)}`)
    .join("\n\n");
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
    "Read approved data for a single scope as bounded block pages. Returns blocks, page cursors, and warnings instead of an unlimited envelope.",
  inputSchema: {
    scope: z
      .string()
      .min(1)
      .describe("Exact scope id, e.g. 'instagram.profile'."),
    cursor: z.string().min(1).optional(),
    maxBytes: z.number().int().min(1).max(MAX_READ_SCOPE_MAX_BYTES).optional(),
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

    const cursor = typeof args.cursor === "string" ? args.cursor : undefined;
    const maxBytes =
      typeof args.maxBytes === "number"
        ? clampInteger(
            args.maxBytes,
            DEFAULT_READ_SCOPE_MAX_BYTES,
            1,
            MAX_READ_SCOPE_MAX_BYTES,
          )
        : DEFAULT_READ_SCOPE_MAX_BYTES;
    try {
      const result = await readClient.readScopeBlocks({
        scope,
        grantId: grant.grantId,
        cursor,
        maxBytes,
      });
      return textResult({
        scope,
        grantId: grant.grantId,
        collectedAt: result.collectedAt,
        contentKind: result.contentKind,
        blocks: result.blocks,
        nextCursor: result.nextCursor,
        warnings: result.warnings,
        page: {
          cursor: cursor ?? null,
          maxBytes,
          returnedBlocks: result.blocks.length,
        },
      });
    } catch (err) {
      if (err instanceof McpDataReadError) {
        if (err.status === 503) {
          return textResult(
            {
              error: "bounded_data_unavailable",
              status: err.status,
              body: err.body,
            },
            true,
          );
        }
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
    maxBytes: z.number().int().min(1).max(MAX_SEARCH_MAX_BYTES).optional(),
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
    const maxBytes = clampInteger(
      args.maxBytes,
      DEFAULT_SEARCH_MAX_BYTES,
      1,
      MAX_SEARCH_MAX_BYTES,
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
    const searchedScopes: string[] = [];
    const truncatedScopes: string[] = [];
    const errors = [...resolved.errors];
    const totalTimeoutMs = Math.min(
      MAX_SEARCH_TOTAL_TIMEOUT_MS,
      timeoutMs * Math.max(1, resolved.scopes.length),
    );
    const deadline = Date.now() + totalTimeoutMs;

    for (const scope of resolved.scopes) {
      const remainingBeforeScope = deadline - Date.now();
      if (remainingBeforeScope <= 0) {
        errors.push({ scope, error: "search_total_timeout" });
        break;
      }
      const grant = resolveGrantForScope(connection, scope);
      if (!grant) continue;
      let cursor: string | undefined;
      let pageCount = 0;
      let scopeHasMatch = false;
      let scopeTruncated = false;
      let scopeSearched = false;
      try {
        while (pageCount < SEARCH_MAX_PAGES_PER_SCOPE) {
          const remainingMs = deadline - Date.now();
          if (remainingMs <= 0) {
            errors.push({ scope, error: "search_total_timeout" });
            break;
          }
          pageCount += 1;
          if (!scopeSearched) {
            searchedScopes.push(scope);
            scopeSearched = true;
          }
          const result = await withTimeout(
            readClient.readScopeBlocks({
              scope,
              grantId: grant.grantId,
              cursor,
              maxBytes,
            }),
            Math.min(timeoutMs, remainingMs),
            `read blocks for ${scope}`,
          );
          const pageText = blockPageSearchText(result.blocks);
          const matchIndex = pageText.toLowerCase().indexOf(needle);
          if (matchIndex >= 0 && matches.length < limit && !scopeHasMatch) {
            matches.push({
              scope,
              grantId: grant.grantId,
              collectedAt: result.collectedAt,
              preview: previewMatch(pageText, matchIndex),
              searchedChars: pageText.length,
              truncated: Boolean(result.nextCursor),
            });
            scopeHasMatch = true;
          }
          if (result.nextCursor) {
            cursor = result.nextCursor;
            if (
              pageCount >= SEARCH_MAX_PAGES_PER_SCOPE ||
              matches.length >= limit
            ) {
              scopeTruncated = true;
              break;
            }
            continue;
          }
          break;
        }
        if (scopeTruncated) {
          truncatedScopes.push(scope);
        }
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
      }
      if (matches.length >= limit) break;
    }

    return textResult({
      query,
      matches,
      searchedScopes,
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
        requestedBytesPerPage: maxBytes,
        maxPagesPerScope: SEARCH_MAX_PAGES_PER_SCOPE,
        totalTimeoutMs,
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
