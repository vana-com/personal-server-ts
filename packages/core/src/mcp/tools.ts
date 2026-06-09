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
import type { McpActivityRecorder } from "./activity.js";
import { MiniSearchIndex, type SearchDocument } from "./search/index.js";

export interface McpToolContext {
  connection: McpConnectionRecord;
  readClient: McpDataReadClient;
  activityRecorder?: McpActivityRecorder;
}

export interface McpToolResultContent {
  type: "text";
  text: string;
}

export interface McpToolResult {
  content: McpToolResultContent[];
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
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
  const structuredContent =
    !isError &&
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  return {
    content: [
      {
        type: "text",
        text:
          typeof value === "string" ? value : JSON.stringify(value, null, 2),
      },
    ],
    ...(structuredContent ? { structuredContent } : {}),
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
const MAX_SEARCH_LIMIT = 50;
const DEFAULT_SEARCH_MAX_SCOPES = 10;
const MAX_SEARCH_SCOPES = 50;
const DEFAULT_SEARCH_TIMEOUT_MS = 30_000;
const MAX_SEARCH_TIMEOUT_MS = 300_000;
const DEFAULT_SEARCH_DISCOVERY_TIMEOUT_MS = 2_000;
const MAX_SEARCH_TOTAL_TIMEOUT_MS = 300_000;
const DEFAULT_READ_SCOPE_MAX_BYTES = 256 * 1024;
const MAX_READ_SCOPE_MAX_BYTES = 5 * 1024 * 1024;
const DEFAULT_READ_SCOPE_TIMEOUT_MS = 60_000;
const MAX_READ_SCOPE_TIMEOUT_MS = 300_000;
const DEFAULT_SEARCH_MAX_BYTES = 64 * 1024;
const MAX_SEARCH_MAX_BYTES = 1024 * 1024;
const DEFAULT_SCOPE_METADATA_TIMEOUT_MS = 2_000;
const SEARCH_MAX_PAGES_PER_SCOPE = 16;
const SEARCH_QUERY_MAX_CHARS = 256;
const SEARCH_SCOPE_MAX_CHARS = 128;
const SEARCH_REQUESTED_SCOPES_LIMIT = MAX_SEARCH_SCOPES * 2;
const SEARCH_SKIPPED_SCOPES_LIMIT = 50;
const SEARCH_PREVIEW_CHARS = 600;
const LIST_SCOPES_LIMIT = 200;

// Size thresholds for sizeClass classification (raw envelope bytes)
const SIZE_CLASS_TINY_BYTES = 10_000;
const SIZE_CLASS_SMALL_BYTES = 100_000;
const SIZE_CLASS_MEDIUM_BYTES = 1_000_000;
const SIZE_CLASS_LARGE_BYTES = 10_000_000;

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

function blockPageSearchDocuments(
  scope: string,
  blocks: Array<{ id: string; path: string; value: unknown }>,
): { documents: SearchDocument[]; textById: Map<string, string> } {
  const textById = new Map<string, string>();
  const documents = blocks.map((block, index) => {
    const id = `${scope}:${block.id || index}`;
    const text = `${block.path}\n${collectSearchText(block.value)}`;
    textById.set(id, text);
    return {
      id,
      scope,
      title: block.path,
      text,
      preview: text.slice(0, SEARCH_PREVIEW_CHARS),
      blockRef: block.id,
    };
  });
  return { documents, textById };
}

function previewMatch(text: string, matchIndex: number): string {
  const halfWindow = Math.floor(SEARCH_PREVIEW_CHARS / 2);
  const start = Math.max(0, matchIndex - halfWindow);
  const end = Math.min(text.length, start + SEARCH_PREVIEW_CHARS);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < text.length ? "..." : "";
  return `${prefix}${text.slice(start, end)}${suffix}`;
}

function miniSearchMatchIndex(text: string, terms: readonly string[]): number {
  const normalized = text.toLowerCase();
  for (const term of terms) {
    const index = normalized.indexOf(term.toLowerCase());
    if (index >= 0) return index;
  }
  return 0;
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

type SizeClass = "tiny" | "small" | "medium" | "large" | "huge" | "unknown";

function classifySizeBytes(sizeBytes: number | undefined): SizeClass {
  if (sizeBytes === undefined) return "unknown";
  if (sizeBytes < SIZE_CLASS_TINY_BYTES) return "tiny";
  if (sizeBytes < SIZE_CLASS_SMALL_BYTES) return "small";
  if (sizeBytes < SIZE_CLASS_MEDIUM_BYTES) return "medium";
  if (sizeBytes < SIZE_CLASS_LARGE_BYTES) return "large";
  return "huge";
}

type RecommendedAccess = "read" | "search" | "wait";

// Directive guidance the MCP client (e.g. Claude) uses to pick read_scope vs
// search_personal_context for a scope WITHOUT operator intervention. The signal
// must be unambiguous: a misnamed flag here (the old `searchRecommended: false`
// on large scopes) reads to a model as "don't search → read the whole thing",
// which is exactly the slow path — a full read of a large scope returns many
// pages it must walk via nextCursor and tends to stall the agent loop.
function recommendAccessForScope(
  sizeClass: SizeClass,
  hasBlocks: boolean,
): { recommendedAccess: RecommendedAccess; reason: string } {
  if (!hasBlocks) {
    return {
      recommendedAccess: "wait",
      reason:
        "bounded block data is still indexing or unavailable; retry shortly before reading or searching",
    };
  }
  if (sizeClass === "large" || sizeClass === "huge") {
    return {
      recommendedAccess: "search",
      reason: `scope is ${sizeClass}; prefer search_personal_context and name this scope explicitly. A full read_scope returns many pages you must walk via nextCursor.`,
    };
  }
  if (sizeClass === "unknown") {
    return {
      recommendedAccess: "search",
      reason:
        "scope size is unknown; prefer search_personal_context and name this scope explicitly",
    };
  }
  return {
    recommendedAccess: "read",
    reason: `scope is ${sizeClass}; read_scope returns it in one or few pages. search_personal_context also works for targeted lookups.`,
  };
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
    scopes: Array.from(scopes),
    skippedScopes: Array.from(new Set(skippedScopes)),
    errors,
  };
}

const listGrantedSources: McpToolDefinition = {
  name: "list_granted_sources",
  title: "List granted sources",
  description:
    "List granted data source ids. Use list_granted_scopes for scope readiness and size.",
  inputSchema: {},
  async handler(_args, { connection }) {
    return textResult({ sources: uniqueSources(connection) });
  },
};

const listGrantedScopes: McpToolDefinition = {
  name: "list_granted_scopes",
  title: "List granted scopes",
  description:
    "List granted scopes with dataStatus, sizeClass, sizeBytes, and recommendedAccess ('read' for small scopes, 'search' for large/huge scopes, 'wait' while indexing). Call first, then follow recommendedAccess.",
  inputSchema: {},
  async handler(_args, { connection, readClient }) {
    const grantedScopes = uniqueScopes(connection);
    const scopeEntries = await Promise.all(
      grantedScopes.map(async (scope) => {
        let meta = null;
        if (typeof readClient.getScopeMetadata === "function") {
          try {
            meta = await withTimeout(
              readClient.getScopeMetadata(scope),
              DEFAULT_SCOPE_METADATA_TIMEOUT_MS,
              `scope metadata for ${scope}`,
            );
          } catch {
            return {
              scope,
              source: scope.split(".")[0],
              dataStatus: "indexing" as const,
              sizeClass: "unknown" as SizeClass,
              recommendedAccess: "wait" as RecommendedAccess,
              reason:
                "scope metadata is still indexing or temporarily unavailable; retry shortly",
            };
          }
        }
        if (!meta) {
          return {
            scope,
            dataStatus: "needs_refresh" as const,
            sizeClass: "unknown" as SizeClass,
            recommendedAccess: "wait" as RecommendedAccess,
            reason: "no local data found; refresh your data connection",
          };
        }
        const sizeClass = classifySizeBytes(meta.sizeBytes);
        const { recommendedAccess, reason } = recommendAccessForScope(
          sizeClass,
          meta.hasBlocks,
        );
        return {
          scope,
          source: scope.split(".")[0],
          collectedAt: meta.collectedAt,
          dataStatus: meta.hasBlocks
            ? ("ready" as const)
            : ("indexing" as const),
          sizeBytes: meta.sizeBytes,
          sizeClass,
          recommendedAccess,
          reason,
        };
      }),
    );
    return textResult({ scopes: scopeEntries });
  },
};

const readScope: McpToolDefinition = {
  name: "read_scope",
  title: "Read scope",
  description:
    "Read one full approved scope as bounded blocks. Best for tiny/small/medium scopes (see sizeClass from list_granted_scopes). For large/huge scopes prefer search_personal_context — a full read returns many pages you must walk via nextCursor and is slow. The response includes a `guidance` hint when a scope is large enough that search is the better tool.",
  inputSchema: {
    scope: z
      .string()
      .min(1)
      .describe("Exact scope id, e.g. 'instagram.profile'."),
    cursor: z.string().min(1).optional(),
    maxBytes: z.number().int().min(1).max(MAX_READ_SCOPE_MAX_BYTES).optional(),
    timeoutMs: z
      .number()
      .int()
      .min(1000)
      .max(MAX_READ_SCOPE_TIMEOUT_MS)
      .optional()
      .describe(
        "Wall-clock read budget in ms. Capped at 300000 by the server.",
      ),
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
    const timeoutMs = clampInteger(
      args.timeoutMs,
      DEFAULT_READ_SCOPE_TIMEOUT_MS,
      1000,
      MAX_READ_SCOPE_TIMEOUT_MS,
    );

    // In-band steer: the model may call read_scope on a large scope without
    // first consulting list_granted_scopes. Fetch lightweight planning metadata
    // (storage-index only, no network/auth) so we can attach a `guidance` hint
    // pointing at search_personal_context when a full read would be slow. This
    // is best-effort and never blocks the read.
    let guidance:
      | {
          sizeClass: SizeClass;
          sizeBytes?: number;
          recommendedAccess: RecommendedAccess;
          reason: string;
        }
      | undefined;
    if (typeof readClient.getScopeMetadata === "function") {
      try {
        const meta = await withTimeout(
          readClient.getScopeMetadata(scope),
          DEFAULT_SCOPE_METADATA_TIMEOUT_MS,
          `scope metadata for ${scope}`,
        );
        if (meta) {
          const sizeClass = classifySizeBytes(meta.sizeBytes);
          const recommendation = recommendAccessForScope(
            sizeClass,
            meta.hasBlocks,
          );
          // Only steer when search is the better tool; a normal small read
          // gets no extra noise.
          if (recommendation.recommendedAccess === "search") {
            guidance = {
              sizeClass,
              sizeBytes: meta.sizeBytes,
              recommendedAccess: recommendation.recommendedAccess,
              reason: recommendation.reason,
            };
          }
        }
      } catch {
        // Advisory only — fall through and serve the read without guidance.
      }
    }

    try {
      const result = await withTimeout(
        readClient.readScopeBlocks({
          scope,
          grantId: grant.grantId,
          cursor,
          maxBytes,
        }),
        timeoutMs,
        `read blocks for ${scope}`,
      );
      const nextCursor = result.nextCursor ?? null;
      return textResult({
        scope,
        grantId: grant.grantId,
        collectedAt: result.collectedAt,
        contentKind: result.contentKind,
        blocks: result.blocks,
        ...(result.nextCursor ? { nextCursor: result.nextCursor } : {}),
        ...(guidance ? { guidance } : {}),
        warnings: result.warnings,
        page: {
          cursor: cursor ?? null,
          nextCursor,
          hasMore: Boolean(result.nextCursor),
          maxBytes,
          timeoutMs,
          returnedBlocks: result.blocks.length,
        },
      });
    } catch (err) {
      if (err instanceof OperationTimeoutError) {
        return textResult(
          {
            error: "scope_read_timeout",
            message: err.message,
            timeoutMs: err.timeoutMs,
          },
          true,
        );
      }
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

// Opaque cross-scope search cursor. Encodes which scope to resume from and
// the block cursor within that scope. Base64-encoded JSON for transparency.
interface SearchCursorPayload {
  /** Index into the resolved scope list to start from. */
  scopeIndex: number;
  /** Block cursor within that scope (if partial page was in progress). */
  blockCursor?: string;
}

function encodeSearchCursor(payload: SearchCursorPayload): string {
  const json = JSON.stringify(payload);
  // TextEncoder + Uint8Array → base64url without Node.js Buffer dependency
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeSearchCursor(raw: string): SearchCursorPayload | null {
  try {
    const base64 = raw.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const json = new TextDecoder().decode(bytes);
    const payload = JSON.parse(json);
    if (
      typeof payload === "object" &&
      payload !== null &&
      typeof payload.scopeIndex === "number"
    ) {
      return {
        scopeIndex: payload.scopeIndex,
        blockCursor:
          typeof payload.blockCursor === "string"
            ? payload.blockCursor
            : undefined,
      };
    }
    return null;
  } catch {
    return null;
  }
}

const searchPersonalContext: McpToolDefinition = {
  name: "search_personal_context",
  title: "Search personal context",
  description:
    "Search approved scopes by keyword — the preferred way to pull from large/huge scopes without reading every page. Omit scopes to sweep all small ready data; name scopes (including large ones) to target them. Continue with nextSearchCursor.",
  inputSchema: {
    query: z.string().min(1).max(SEARCH_QUERY_MAX_CHARS),
    scopes: z
      .array(z.string().min(1).max(SEARCH_SCOPE_MAX_CHARS))
      .max(SEARCH_REQUESTED_SCOPES_LIMIT)
      .optional(),
    cursor: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Continuation cursor from a prior search response's nextSearchCursor.",
      ),
    maxResults: z.number().int().min(1).max(MAX_SEARCH_LIMIT).optional(),
    limit: z.number().int().min(1).max(MAX_SEARCH_LIMIT).optional(),
    maxScopes: z.number().int().min(1).max(MAX_SEARCH_SCOPES).optional(),
    timeoutMs: z
      .number()
      .int()
      .min(1000)
      .max(MAX_SEARCH_TIMEOUT_MS)
      .optional()
      .describe("Wall-clock budget in ms. Capped at 300000 by the server."),
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
    // maxResults takes precedence over deprecated limit for forward compat
    const limit = clampInteger(
      args.maxResults ?? args.limit,
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
      1000,
      MAX_SEARCH_TIMEOUT_MS,
    );
    const maxBytes = clampInteger(
      args.maxBytes,
      DEFAULT_SEARCH_MAX_BYTES,
      1,
      MAX_SEARCH_MAX_BYTES,
    );
    const totalTimeoutMs = Math.min(MAX_SEARCH_TOTAL_TIMEOUT_MS, timeoutMs);
    const startedAt = Date.now();
    const deadline = startedAt + totalTimeoutMs;
    const discoveryTimeoutMs = Math.min(
      totalTimeoutMs,
      DEFAULT_SEARCH_DISCOVERY_TIMEOUT_MS,
    );

    // Decode continuation cursor if provided
    const resumeCursor =
      typeof args.cursor === "string" ? decodeSearchCursor(args.cursor) : null;

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
      blockRef?: string;
      score?: number;
      terms?: string[];
    }> = [];
    const searchedScopes: string[] = [];
    const truncatedScopes: string[] = [];
    const errors = [...resolved.errors];

    // When resuming, start from the scope index encoded in the cursor
    const startScopeIndex = resumeCursor
      ? Math.max(0, Math.min(resumeCursor.scopeIndex, resolved.scopes.length))
      : 0;
    const initialBlockCursor = resumeCursor?.blockCursor ?? undefined;

    let nextSearchCursor: string | undefined;

    for (
      let scopeIndex = startScopeIndex;
      scopeIndex < resolved.scopes.length;
      scopeIndex += 1
    ) {
      const scope = resolved.scopes[scopeIndex];
      const remainingBeforeScope = deadline - Date.now();
      if (remainingBeforeScope <= 0) {
        // Budget exhausted — offer cursor to continue from this scope
        nextSearchCursor = encodeSearchCursor({ scopeIndex });
        errors.push({ scope, error: "search_total_timeout" });
        break;
      }
      const grant = resolveGrantForScope(connection, scope);
      if (!grant) continue;

      if (!resumeCursor && typeof readClient.searchScopeIndex === "function") {
        const remainingMs = deadline - Date.now();
        if (remainingMs <= 0) {
          nextSearchCursor = encodeSearchCursor({ scopeIndex });
          errors.push({ scope, error: "search_total_timeout" });
          break;
        }
        const remainingScopes = resolved.scopes.length - scopeIndex;
        const perScopeTimeoutMs = Math.min(
          Math.max(250, Math.floor(remainingMs / Math.max(1, remainingScopes))),
          remainingMs,
        );
        try {
          const indexed = await withTimeout(
            readClient.searchScopeIndex({
              scope,
              grantId: grant.grantId,
              query,
              maxResults: limit - matches.length,
            }),
            perScopeTimeoutMs,
            `search index for ${scope}`,
          );
          if (indexed.status === "hit") {
            searchedScopes.push(scope);
            for (const hit of indexed.hits) {
              if (matches.length >= limit) break;
              matches.push({
                scope,
                grantId: grant.grantId,
                preview: hit.preview ?? hit.title ?? "",
                searchedChars: 0,
                truncated: false,
                blockRef: hit.blockRef,
                score: hit.score,
                terms: hit.terms,
              });
            }
            if (matches.length >= limit) {
              const nextScopeIndex = scopeIndex + 1;
              if (nextScopeIndex < resolved.scopes.length) {
                nextSearchCursor = encodeSearchCursor({
                  scopeIndex: nextScopeIndex,
                });
              }
              break;
            }
            continue;
          }
        } catch (err) {
          errors.push({
            scope,
            error:
              err instanceof OperationTimeoutError
                ? "scope_index_timeout"
                : "scope_index_failed",
            bodyPreview: stringifyPreview(
              err instanceof OperationTimeoutError
                ? err.message
                : "unexpected scope index failure",
            ),
          });
        }
      }

      // Use block cursor from resume only for the first scope we process
      let cursor: string | undefined =
        scopeIndex === startScopeIndex ? initialBlockCursor : undefined;
      let pageCount = 0;
      let scopeHasMatch = false;
      let scopeTruncated = false;
      let scopeSearched = false;
      try {
        while (pageCount < SEARCH_MAX_PAGES_PER_SCOPE) {
          const remainingMs = deadline - Date.now();
          if (remainingMs <= 0) {
            // Budget hit mid-scope — encode cursor pointing at this scope + block
            nextSearchCursor = encodeSearchCursor({
              scopeIndex,
              blockCursor: cursor,
            });
            errors.push({ scope, error: "search_total_timeout" });
            scopeTruncated = Boolean(cursor);
            break;
          }
          pageCount += 1;
          if (!scopeSearched) {
            searchedScopes.push(scope);
            scopeSearched = true;
          }
          const remainingScopes = resolved.scopes.length - scopeIndex;
          const perScopeTimeoutMs = Math.min(
            Math.max(
              250,
              Math.floor(remainingMs / Math.max(1, remainingScopes)),
            ),
            remainingMs,
          );
          const result = await withTimeout(
            readClient.readScopeBlocks({
              scope,
              grantId: grant.grantId,
              cursor,
              maxBytes,
            }),
            perScopeTimeoutMs,
            `read blocks for ${scope}`,
          );
          const pageText = blockPageSearchText(result.blocks);
          const { documents, textById } = blockPageSearchDocuments(
            scope,
            result.blocks,
          );
          const pageHits =
            documents.length > 0
              ? MiniSearchIndex.build(documents).search({ query, limit: 1 })
              : [];
          const pageHit = pageHits[0];
          if (pageHit && matches.length < limit && !scopeHasMatch) {
            const hitText = textById.get(pageHit.id) ?? pageText;
            matches.push({
              scope,
              grantId: grant.grantId,
              collectedAt: result.collectedAt,
              preview: previewMatch(
                hitText,
                miniSearchMatchIndex(hitText, pageHit.terms),
              ),
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
              // More pages remain in this scope — cursor points here
              nextSearchCursor = encodeSearchCursor({
                scopeIndex,
                blockCursor: cursor,
              });
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
      if (matches.length >= limit) {
        // Result limit hit — if more scopes remain, offer cursor for next scope
        const nextScopeIndex = scopeIndex + 1;
        if (nextScopeIndex < resolved.scopes.length) {
          nextSearchCursor = encodeSearchCursor({
            scopeIndex: nextScopeIndex,
          });
        }
        break;
      }
    }

    const elapsedMs = Date.now() - startedAt;

    return textResult({
      query,
      results: matches,
      matches,
      searchedScopes,
      skippedScopes: [
        ...normalizedScopes.skippedScopes,
        ...resolved.skippedScopes,
      ],
      truncatedScopes,
      errors,
      ...(nextSearchCursor ? { nextSearchCursor } : {}),
      elapsedMs,
      limits: {
        maxResults: limit,
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
