import { isSystemScope } from "../policy/reserved-scopes.js";
/**
 * MCP tool surface. Phase 1 / §4 of 260604-PLAN-vana-mcp-personal-server.md.
 *
 * Small, and only over scopes that the connection's grants cover. No
 * grant-approval tools. No raw owner/admin status tools.
 *
 * Every tool that returns data first picks a covering grant from the
 * connection's grant list, signs a Web3Signed request as the per-connection
 * grantee, and uses the bounded sidecar read path — so reads are grant-gated,
 * access-logged, and safe for large scopes.
 *
 * The one write tool, `remember`, saves only into a scope a `write:` grant
 * entry covers, and goes through the delegated-write path a builder uses
 * (see write-client.ts). A read grant never confers write access, and a
 * `write:` entry never confers read access.
 */

import { z } from "zod";
import {
  MCP_SCOPE_ACCESS_REQUEST_LIMIT,
  type McpConnectionRecord,
} from "./types.js";
import type { McpDataReadClient } from "./read-client.js";
import { McpDataReadError } from "./read-client.js";
import type { McpDataWriteClient } from "./write-client.js";
import { McpDataWriteError } from "./write-client.js";
import {
  isWriteScopeEntry,
  writeScopePatterns,
  WRITE_SCOPE_PREFIX,
} from "../policy/data-write.js";
import { toMcpScopeAccessRequestView } from "./connection-api.js";
import type { McpActivityRecorder } from "./activity.js";
import type {
  McpScopeRequestApprovalUrlContext,
  McpScopeRequestApprovalUrlHook,
} from "./approval-url.js";
import { MiniSearchIndex, type SearchDocument } from "./search/index.js";
import { MAX_SELECTED_BLOCK_IDS } from "../storage/blocks/index.js";
import {
  rawScopeFileInputSchema,
  rawScopeMetadata,
  rawScopeResourceUri,
} from "./resources.js";

export interface McpToolContext {
  connection: McpConnectionRecord;
  readClient: McpDataReadClient;
  /**
   * Writes as the connection grantee. Absent on hosts that do not support MCP
   * writes (PS-Lite, self-signing sessions): `remember` then reports
   * `write_unavailable`.
   */
  writeClient?: McpDataWriteClient;
  activityRecorder?: McpActivityRecorder;
  requestScopeAccess?(input: { scopes: string[]; reason?: string }): Promise<{
    connection: McpConnectionRecord;
    requestRecorded: boolean;
    /** Raw read token for the request just written; goes into the link. */
    readToken?: string;
  }>;
  /**
   * Host-provided page where the owner answers this connection's scope
   * request. When it returns a URL, `request_scope_access` hands it to the
   * agent to show the user; when absent, the owner is pointed at Vana.
   */
  scopeRequestApprovalUrl?: McpScopeRequestApprovalUrlHook;
  /**
   * This server's current public origin, handed to the approval-URL hook so
   * the link can name the server that holds the request.
   */
  serverOrigin?: string;
}

export type McpToolResultContent =
  | {
      type: "text";
      text: string;
    }
  | {
      type: "resource_link";
      uri: string;
      name: string;
      title?: string;
      description?: string;
      mimeType?: string;
      size?: number;
    }
  | {
      type: "resource";
      resource: {
        uri: string;
        mimeType?: string;
        blob: string;
        _meta?: Record<string, unknown>;
      };
    };

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

/** Tool names the read path stamps onto access records. */
const READ_SCOPE_TOOL = "read_scope";
const SEARCH_PERSONAL_CONTEXT_TOOL = "search_personal_context";

const STRUCTURED_CONTENT_TEXT_LIMIT_BYTES = 64 * 1024;
const resultTextEncoder = new TextEncoder();

/**
 * Tool payloads are machine-read, never displayed as-is: pretty-printing them
 * inflated the wire size 1.37x-1.63x on real scopes for no reader benefit.
 */
function textResult(value: unknown, isError = false): McpToolResult {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  const textBytes = resultTextEncoder.encode(text).byteLength;
  const structuredContent =
    !isError &&
    textBytes <= STRUCTURED_CONTENT_TEXT_LIMIT_BYTES &&
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : undefined;
  return {
    content: [
      {
        type: "text",
        text,
      },
    ],
    ...(structuredContent ? { structuredContent } : {}),
    ...(isError ? { isError: true } : {}),
  };
}

/** A grant entry that names readable data: not a system scope, not `write:`. */
function isReadableScopeEntry(scope: string): boolean {
  return !isSystemScope(scope) && !isWriteScopeEntry(scope);
}

function uniqueScopes(connection: McpConnectionRecord): string[] {
  const set = new Set<string>();
  for (const grant of connection.grants) {
    for (const scope of grant.scopes) {
      if (isReadableScopeEntry(scope)) set.add(scope);
    }
  }
  return Array.from(set).sort();
}

/**
 * A scope `remember` may save into under these grant entries: an exact
 * `write:<scope>` entry. MCP writes never honor a `write:` wildcard, even one
 * an older grant still carries, although builder writes do: a memory grant
 * names the one scope the agent saves into.
 */
function exactWriteScopes(grantScopes: readonly string[]): string[] {
  return writeScopePatterns(grantScopes).filter(
    (scope) => !scope.includes("*") && !isSystemScope(scope),
  );
}

/** Scopes the connection may save into, `write:` prefix stripped. */
function uniqueWritableScopes(connection: McpConnectionRecord): string[] {
  const set = new Set<string>();
  for (const grant of connection.grants) {
    for (const scope of exactWriteScopes(grant.scopes)) set.add(scope);
  }
  return Array.from(set).sort();
}

/**
 * Every data scope (or pattern) the connection may read or write, `write:`
 * prefix stripped. A host that copies data in before serving a connection
 * (the enclave) must copy write targets too: `remember` rewrites the whole
 * memory list from the local copy, so a missing copy would drop memories.
 */
export function connectionDataScopes(
  connection: McpConnectionRecord,
): string[] {
  const set = new Set<string>();
  for (const grant of connection.grants) {
    for (const scope of grant.scopes) {
      const target = isWriteScopeEntry(scope)
        ? scope.slice(WRITE_SCOPE_PREFIX.length)
        : scope;
      if (target) set.add(target);
    }
  }
  return Array.from(set).sort();
}

/**
 * Resolve a scope to a grant with an exact `write:` entry for it (see
 * exactWriteScopes). The server-side write policy still runs on every save;
 * this only narrows what the tool will attempt.
 */
export function resolveWriteGrantForScope(
  connection: McpConnectionRecord,
  scope: string,
): { grantId: string; scopes: string[] } | null {
  for (const grant of connection.grants) {
    if (exactWriteScopes(grant.scopes).includes(scope)) {
      return { grantId: grant.grantId, scopes: grant.scopes };
    }
  }
  return null;
}

/**
 * Whether the connection already holds `scope` as a scope request names it:
 * a `write:` entry is covered only by write grants, anything else by reads.
 */
function connectionCoversRequestedScope(
  connection: McpConnectionRecord,
  scope: string,
): boolean {
  return isWriteScopeEntry(scope)
    ? Boolean(
        resolveWriteGrantForScope(
          connection,
          scope.slice(WRITE_SCOPE_PREFIX.length),
        ),
      )
    : Boolean(resolveGrantForScope(connection, scope));
}

function uniqueSources(connection: McpConnectionRecord): string[] {
  const set = new Set<string>();
  for (const grant of connection.grants) {
    if (!grant.scopes.some(isReadableScopeEntry)) continue;
    const sourceId =
      typeof grant.sourceId === "string" ? grant.sourceId.trim() : "";
    if (sourceId) {
      set.add(sourceId);
      continue;
    }
    for (const scope of grant.scopes) {
      if (!isReadableScopeEntry(scope)) continue;
      const [scopeSourceId] = scope.split(".");
      if (scopeSourceId && scopeSourceId !== "*") {
        set.add(scopeSourceId);
      }
    }
  }
  return Array.from(set).sort();
}

/**
 * Block ids a caller may name in one block-addressed read. Bounded so a model
 * cannot turn `blockIds` into an unbounded fan-out; `maxBytes` still applies on
 * top of it.
 */
function normalizeBlockIdsInput(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const blockIds: string[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (typeof raw !== "string") continue;
    const blockId = raw.trim();
    if (!blockId || blockId.length > BLOCK_ID_MAX_CHARS || seen.has(blockId)) {
      continue;
    }
    seen.add(blockId);
    blockIds.push(blockId);
    if (blockIds.length >= MAX_SELECTED_BLOCK_IDS) break;
  }
  return blockIds;
}

function normalizeScopeListInput(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const scopes: string[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (typeof raw !== "string") continue;
    const scope = raw.trim();
    if (!scope || scope.length > SEARCH_SCOPE_MAX_CHARS || seen.has(scope)) {
      continue;
    }
    seen.add(scope);
    scopes.push(scope);
  }
  return scopes;
}

/**
 * Hard ceiling the MCP dispatcher enforces on any tool call (see
 * `clampToolTimeout` in `server.ts`, which imports this).
 *
 * Tools must never advertise a larger `timeoutMs` than the dispatcher allows: a
 * client that trusts the advertised maximum gets killed with a hard
 * `tool_timeout` instead of the graceful "budget exhausted, here are partial
 * results plus nextSearchCursor" path the tools implement.
 */
export const MAX_MCP_TOOL_TIMEOUT_MS = 90_000;

const DEFAULT_SEARCH_LIMIT = 5;
const MAX_SEARCH_LIMIT = 50;
const MAX_SEARCH_SCOPES = 200;
const DEFAULT_SEARCH_MAX_SCOPES = MAX_SEARCH_SCOPES;
const DEFAULT_SEARCH_TIMEOUT_MS = 30_000;
const MAX_SEARCH_TIMEOUT_MS = MAX_MCP_TOOL_TIMEOUT_MS;
const DEFAULT_SEARCH_DISCOVERY_TIMEOUT_MS = 2_000;
const MAX_SEARCH_TOTAL_TIMEOUT_MS = MAX_MCP_TOOL_TIMEOUT_MS;
const DEFAULT_READ_SCOPE_MAX_BYTES = 64 * 1024;
const MAX_READ_SCOPE_MAX_BYTES = 5 * 1024 * 1024;
const DEFAULT_READ_SCOPE_TIMEOUT_MS = 60_000;
const MAX_READ_SCOPE_TIMEOUT_MS = MAX_MCP_TOOL_TIMEOUT_MS;
const DEFAULT_READ_FILE_TIMEOUT_MS = 60_000;
const MAX_READ_FILE_TIMEOUT_MS = MAX_MCP_TOOL_TIMEOUT_MS;
const DEFAULT_READ_FILE_MAX_BYTES = 10 * 1024 * 1024;
const MAX_READ_FILE_MAX_BYTES = 25 * 1024 * 1024;
const DEFAULT_SEARCH_MAX_BYTES = 64 * 1024;
const MAX_SEARCH_MAX_BYTES = 1024 * 1024;
const DEFAULT_SCOPE_METADATA_TIMEOUT_MS = 2_000;
const DEFAULT_LIST_BLOCKS_LIMIT = 100;
const MAX_LIST_BLOCKS_LIMIT = 500;
const LIST_BLOCKS_TIMEOUT_MS = 15_000;
/**
 * Safety net, not a search budget: a scope is scanned page by page until the
 * result limit or the time budget is hit, and this only stops a pathological
 * scope from monopolising the run. Pages beyond it are resumable through
 * `nextSearchCursor`, so raising it costs latency, never correctness.
 */
const SEARCH_MAX_PAGES_PER_SCOPE = 256;
const SEARCH_QUERY_MAX_CHARS = 256;
const SEARCH_SCOPE_MAX_CHARS = 128;
const BLOCK_ID_MAX_CHARS = 128;
const SEARCH_REQUESTED_SCOPES_LIMIT = MAX_SEARCH_SCOPES * 2;
const SEARCH_SKIPPED_SCOPES_LIMIT = 50;
const SEARCH_PREVIEW_CHARS = 600;
const LIST_SCOPES_LIMIT = 200;
const scopeAccessRequestInputShape = {
  scopes: z
    .array(z.string().min(1).max(SEARCH_SCOPE_MAX_CHARS))
    .min(1)
    .max(MCP_SCOPE_ACCESS_REQUEST_LIMIT)
    .describe("Exact scope ids to read, or write:<scope> to save into."),
  reason: z
    .string()
    .max(500)
    .optional()
    .describe("Brief reason to show the user."),
} satisfies McpToolInputShape;

export function parseScopeAccessRequestArguments(
  value: unknown,
): { scopes: string[]; reason?: string } | null {
  const parsed = z.object(scopeAccessRequestInputShape).safeParse(value);
  if (!parsed.success) return null;
  const scopes = normalizeScopeListInput(parsed.data.scopes);
  if (scopes.length === 0) return null;
  const reason = parsed.data.reason?.trim();
  return { scopes, ...(reason ? { reason } : {}) };
}

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
export function resolveGrantForScope(
  connection: McpConnectionRecord,
  scope: string,
): { grantId: string; scopes: string[] } | null {
  if (isSystemScope(scope)) return null;
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
          grantId: grant.grantId,
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
    "List granted scopes, readiness, size, and recommendedAccess. Call first.",
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
    // Lets an agent that asked for more scopes see whether the owner has
    // answered yet without re-recording the request.
    const writableScopes = uniqueWritableScopes(connection);
    return textResult({
      scopes: scopeEntries,
      ...(writableScopes.length > 0 ? { writableScopes } : {}),
      ...(connection.scopeAccessRequest
        ? {
            pendingScopeRequest: toMcpScopeAccessRequestView(
              connection.scopeAccessRequest,
            ),
          }
        : {}),
      ...(connection.scopeAccessDecision
        ? { lastScopeDecision: connection.scopeAccessDecision }
        : {}),
    });
  },
};

const requestScopeAccess: McpToolDefinition = {
  name: "request_scope_access",
  title: "Request scope access",
  description:
    "Record missing scopes on this MCP connection for explicit owner approval in Vana.",
  inputSchema: scopeAccessRequestInputShape,
  async handler(
    args,
    { connection, requestScopeAccess, scopeRequestApprovalUrl, serverOrigin },
  ) {
    const requestedScopes = normalizeScopeListInput(args.scopes);
    // Read before recording: a new request must not hide the owner's last
    // answer from the agent that is checking back.
    const previousDecision = connection.scopeAccessDecision;
    let effectiveConnection = connection;
    let grantedRequestedScopes = requestedScopes.filter((scope) =>
      connectionCoversRequestedScope(effectiveConnection, scope),
    );
    let missingScopes = requestedScopes.filter(
      (scope) => !connectionCoversRequestedScope(connection, scope),
    );
    const reason = typeof args.reason === "string" ? args.reason.trim() : "";
    const approvalRequired = missingScopes.length > 0;
    const alreadyRecorded =
      approvalRequired &&
      missingScopes.every((scope) =>
        connection.scopeAccessRequest?.scopes.includes(scope),
      );
    let requestRecorded = alreadyRecorded;
    let readToken: string | undefined;
    if (approvalRequired && requestScopeAccess) {
      const outcome = await requestScopeAccess({
        scopes: missingScopes,
        ...(reason ? { reason } : {}),
      });
      effectiveConnection = outcome.connection;
      requestRecorded = outcome.requestRecorded;
      readToken = outcome.readToken;
      grantedRequestedScopes = requestedScopes.filter((scope) =>
        connectionCoversRequestedScope(effectiveConnection, scope),
      );
      missingScopes = requestedScopes.filter(
        (scope) => !connectionCoversRequestedScope(effectiveConnection, scope),
      );
    }
    const finalApprovalRequired = missingScopes.length > 0;
    const recorded = finalApprovalRequired && requestRecorded;
    const approvalUrl = recorded
      ? resolveScopeRequestApprovalUrl(scopeRequestApprovalUrl, connection.id, {
          serverOrigin,
          ...(readToken ? { readToken } : {}),
        })
      : undefined;
    const declinedScopes =
      previousDecision?.deniedScopes.filter((scope) =>
        missingScopes.includes(scope),
      ) ?? [];

    return textResult({
      approvalRequired: finalApprovalRequired,
      client: {
        id: connection.id,
        displayName: connection.displayName,
        status: connection.status,
      },
      requestedScopes,
      grantedRequestedScopes,
      missingScopes,
      grantedScopes: uniqueScopes(effectiveConnection),
      reason: reason || undefined,
      requestRecorded: recorded,
      approvalUrl,
      previousDecision,
      nextAction: scopeRequestNextAction({
        finalApprovalRequired,
        recorded,
        approvalUrl,
        declinedScopes,
      }),
    });
  },
};

function resolveScopeRequestApprovalUrl(
  hook: McpToolContext["scopeRequestApprovalUrl"],
  connectionId: string,
  context: McpScopeRequestApprovalUrlContext,
): string | undefined {
  if (!hook) return undefined;
  try {
    const url = hook(connectionId, context);
    return typeof url === "string" && url.trim() ? url.trim() : undefined;
  } catch {
    // A broken host hook must not fail the request itself; fall back to Vana.
    return undefined;
  }
}

function scopeRequestNextAction(input: {
  finalApprovalRequired: boolean;
  recorded: boolean;
  approvalUrl?: string;
  declinedScopes: string[];
}): string {
  if (!input.finalApprovalRequired) {
    return "No new grant is needed for the requested scopes.";
  }
  const declined =
    input.declinedScopes.length > 0
      ? `The owner previously declined ${input.declinedScopes.join(", ")}; only ask again if the user wants to. `
      : "";
  if (!input.recorded) {
    return `${declined}Ask the user to open Vana's Personal Server page and add the missing scopes to this MCP client. This tool cannot grant access by itself.`;
  }
  if (input.approvalUrl) {
    return `${declined}Show the user this link to review the request: ${input.approvalUrl} . Ask them to approve or decline it there and to tell you when they are done, then call list_granted_scopes to see what was granted. Access remains unchanged until the owner approves.`;
  }
  return `${declined}The request is waiting for owner approval in Vana. Access remains unchanged until the owner approves it.`;
}

const readScope: McpToolDefinition = {
  name: READ_SCOPE_TOOL,
  title: "Read scope",
  description:
    "Read approved scope blocks. Pass blockIds to fetch exact blocks; otherwise page with nextCursor.",
  inputSchema: {
    scope: z.string().min(1).describe("Exact scope id."),
    cursor: z.string().min(1).optional(),
    blockIds: z
      .array(z.string().min(1).max(BLOCK_ID_MAX_CHARS))
      .min(1)
      .max(MAX_SELECTED_BLOCK_IDS)
      .optional()
      .describe(
        "Block ids from a search hit's blockRef or list_scope_blocks. Ignores cursor; maxBytes still applies.",
      ),
    maxBytes: z.number().int().min(1).max(MAX_READ_SCOPE_MAX_BYTES).optional(),
    timeoutMs: z
      .number()
      .int()
      .min(1000)
      .max(MAX_READ_SCOPE_TIMEOUT_MS)
      .optional(),
    payment: z
      .string()
      .optional()
      .describe(
        "Base64 X-PAYMENT proof (x402). Provide it after a prior call returned payment_required.",
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
    const blockIds = normalizeBlockIdsInput(args.blockIds);
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
    // (storage-index only, no network/auth) opportunistically so we can attach a
    // `guidance` hint when it is already available. This is advisory only: it
    // must never delay the read or consume the read timeout budget.
    let guidance:
      | {
          sizeClass: SizeClass;
          sizeBytes?: number;
          recommendedAccess: RecommendedAccess;
          reason: string;
        }
      | undefined;
    if (typeof readClient.getScopeMetadata === "function") {
      void withTimeout(
        readClient.getScopeMetadata(scope),
        DEFAULT_SCOPE_METADATA_TIMEOUT_MS,
        `scope metadata for ${scope}`,
      )
        .then((meta) => {
          if (!meta) return;
          const sizeClass = classifySizeBytes(meta.sizeBytes);
          const recommendation = recommendAccessForScope(
            sizeClass,
            meta.hasBlocks,
          );
          // Only steer when search is the better tool; a normal small read gets
          // no extra noise.
          if (recommendation.recommendedAccess === "search") {
            guidance = {
              sizeClass,
              sizeBytes: meta.sizeBytes,
              recommendedAccess: recommendation.recommendedAccess,
              reason: recommendation.reason,
            };
          }
        })
        .catch(() => {
          // Advisory only — serve the read without guidance.
        });
    }

    const payment = typeof args.payment === "string" ? args.payment : undefined;

    try {
      const result = await withTimeout(
        readClient.readScopeBlocks({
          scope,
          grantId: grant.grantId,
          cursor,
          maxBytes,
          payment,
          tool: READ_SCOPE_TOOL,
          ...(blockIds.length > 0 ? { blockIds } : {}),
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
          ...(blockIds.length > 0 ? { requestedBlockIds: blockIds } : {}),
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
        if (err.status === 402) {
          const body = err.body as {
            error?: {
              errorCode?: string;
              message?: string;
              details?: { challenge?: unknown };
            };
          };
          const challenge = body?.error?.details?.challenge;
          // Only a genuine PAYMENT_REQUIRED with a challenge is signable. A
          // gateway failure that also surfaces as 402 (e.g. PAYMENT_GATEWAY_ERROR
          // — insufficient escrow balance) is NOT signable; presenting it as a
          // challenge would make the client sign an error envelope in a loop.
          if (body?.error?.errorCode === "PAYMENT_REQUIRED" && challenge) {
            return textResult(
              {
                payment_required: true,
                status: 402,
                challenge,
                message:
                  "This read requires payment. Sign the x402 challenge and call read_scope again with the `payment` argument.",
              },
              true,
            );
          }
          // Gateway-side payment failure — surface the real error + remediation.
          return textResult(
            {
              error: "payment_failed",
              status: 402,
              errorCode: body?.error?.errorCode ?? "PAYMENT_ERROR",
              message:
                body?.error?.message ??
                "Payment could not be completed (e.g. insufficient escrow balance). This is not a signable challenge; resolve the gateway error and retry.",
            },
            true,
          );
        }
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

const listScopeBlocks: McpToolDefinition = {
  name: "list_scope_blocks",
  title: "List scope blocks",
  description:
    "Scope table of contents: block ids, paths, sizes. Feed ids to read_scope blockIds.",
  inputSchema: {
    scope: z.string().min(1).describe("Exact scope id."),
    offset: z.number().int().min(0).optional(),
    limit: z.number().int().min(1).max(MAX_LIST_BLOCKS_LIMIT).optional(),
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
    if (typeof readClient.readBlockManifest !== "function") {
      return textResult({
        scope,
        blocks: [],
        manifestAvailable: false,
        reason: "this server build does not expose block manifests",
        nextStep: "Use read_scope with nextCursor, or search_personal_context.",
      });
    }

    const offset = clampInteger(args.offset, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = clampInteger(
      args.limit,
      DEFAULT_LIST_BLOCKS_LIMIT,
      1,
      MAX_LIST_BLOCKS_LIMIT,
    );

    try {
      const manifest = await withTimeout(
        readClient.readBlockManifest({ scope, grantId: grant.grantId }),
        LIST_BLOCKS_TIMEOUT_MS,
        `read block manifest for ${scope}`,
      );
      // Scopes stored before block sidecars existed, and scopes still
      // indexing, simply have no manifest. That is not an error.
      if (!manifest) {
        return textResult({
          scope,
          grantId: grant.grantId,
          blocks: [],
          manifestAvailable: false,
          reason:
            "no block manifest for this scope yet; it may still be indexing",
          nextStep:
            "Use read_scope with nextCursor, or search_personal_context.",
        });
      }

      const page = manifest.blocks.slice(offset, offset + limit);
      const nextOffset = offset + page.length;
      return textResult({
        scope,
        grantId: grant.grantId,
        collectedAt: manifest.collectedAt,
        contentKind: manifest.contentKind,
        manifestAvailable: true,
        totalBlocks: manifest.blocks.length,
        blocks: page.map((block) => ({
          id: block.id,
          path: block.path,
          sizeBytes: block.sizeBytes,
          ...(block.itemCount === undefined
            ? {}
            : { itemCount: block.itemCount }),
        })),
        warnings: manifest.warnings,
        page: {
          offset,
          limit,
          returnedBlocks: page.length,
          ...(nextOffset < manifest.blocks.length ? { nextOffset } : {}),
        },
      });
    } catch (err) {
      if (err instanceof OperationTimeoutError) {
        return textResult(
          {
            error: "scope_blocks_timeout",
            message: err.message,
            timeoutMs: err.timeoutMs,
          },
          true,
        );
      }
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
  name: SEARCH_PERSONAL_CONTEXT_TOOL,
  title: "Search personal context",
  description:
    "Search approved scopes. Omit scopes for default sweep; name scopes for targeted search. Continue with nextSearchCursor. Free discovery/preview — it does not settle payments; chargeable scopes are returned in paymentRequiredScopes, fetch those via read_scope with a `payment` proof.",
  inputSchema: {
    query: z.string().min(1).max(SEARCH_QUERY_MAX_CHARS),
    scopes: z
      .array(z.string().min(1).max(SEARCH_SCOPE_MAX_CHARS))
      .max(SEARCH_REQUESTED_SCOPES_LIMIT)
      .optional(),
    cursor: z.string().min(1).optional(),
    maxResults: z.number().int().min(1).max(MAX_SEARCH_LIMIT).optional(),
    limit: z.number().int().min(1).max(MAX_SEARCH_LIMIT).optional(),
    maxScopes: z.number().int().min(1).max(MAX_SEARCH_SCOPES).optional(),
    timeoutMs: z.number().int().min(1000).max(MAX_SEARCH_TIMEOUT_MS).optional(),
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
    // Chargeable scopes hit on a paid (self-signing) session. Search is a free
    // discovery/preview surface and does not settle x402 payments — it surfaces
    // these explicitly so the client retrieves them via read_scope with a
    // `payment` proof, instead of burying the 402 as an opaque scope error.
    const paymentRequiredScopes: string[] = [];
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

      // The index preview path bypasses the data API auth port (and thus
      // x402). Skip it when reads are payment-enforced so paid content is never
      // previewed for free — search falls back to the paid bounded block read.
      if (
        !resumeCursor &&
        !readClient.enforcesPayment &&
        typeof readClient.searchScopeIndex === "function"
      ) {
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
              tool: SEARCH_PERSONAL_CONTEXT_TOOL,
            }),
            perScopeTimeoutMs,
            `read blocks for ${scope}`,
          );
          const pageText = blockPageSearchText(result.blocks);
          const { documents, textById } = blockPageSearchDocuments(
            scope,
            result.blocks,
          );
          // Every hit the page can still contribute, not one per page: the
          // index is thrown away with the page, so a discarded hit is a block
          // the caller can never reach again.
          const pageHits =
            documents.length > 0
              ? MiniSearchIndex.build(documents).search({
                  query,
                  limit: limit - matches.length,
                })
              : [];
          for (const pageHit of pageHits) {
            if (matches.length >= limit) break;
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
              // The id of the block that matched, so the caller can fetch it
              // with read_scope({ blockIds }) instead of walking cursors.
              ...(pageHit.blockRef ? { blockRef: pageHit.blockRef } : {}),
              score: pageHit.score,
              terms: pageHit.terms,
            });
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
        const paymentChallenge =
          err instanceof McpDataReadError &&
          err.status === 402 &&
          (err.body as { error?: { errorCode?: string } })?.error?.errorCode ===
            "PAYMENT_REQUIRED";
        if (paymentChallenge) {
          // Paid session hit a chargeable scope. Surface it as payment-required
          // (retrieve via read_scope with `payment`) rather than a scope error.
          // A gateway 402 (PAYMENT_GATEWAY_ERROR) falls through to `errors`.
          if (!paymentRequiredScopes.includes(scope)) {
            paymentRequiredScopes.push(scope);
          }
        } else {
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
      }
      if (matches.length >= limit) {
        // Result limit hit — if more scopes remain, offer cursor for next scope.
        // A cursor set inside the scope wins: it still has unread pages, and
        // pointing past it would silently drop them.
        const nextScopeIndex = scopeIndex + 1;
        if (!nextSearchCursor && nextScopeIndex < resolved.scopes.length) {
          nextSearchCursor = encodeSearchCursor({
            scopeIndex: nextScopeIndex,
          });
        }
        break;
      }
    }

    const elapsedMs = Date.now() - startedAt;

    // Matches accumulate in page order, so a weak early hit would otherwise
    // outrank a strong later one. Scores are only comparable within one page's
    // index, but best-first is still strictly better than page order for the
    // caller. Unscored matches (budget-exhausted fallback path) keep their
    // relative order at the end.
    matches.sort((a, b) => (b.score ?? -1) - (a.score ?? -1));

    return textResult({
      query,
      results: matches,
      // Backward-compatible alias for existing clients/tests. `results` is the
      // canonical field, but removing `matches` is a separate migration.
      matches,
      searchedScopes,
      skippedScopes: [
        ...normalizedScopes.skippedScopes,
        ...resolved.skippedScopes,
      ],
      truncatedScopes,
      errors,
      ...(paymentRequiredScopes.length > 0
        ? {
            payment_required: true,
            paymentRequiredScopes,
            paymentHint:
              "These scopes are chargeable; search does not settle x402 payments. Retrieve each with read_scope (it returns a payment_required challenge; sign it and re-call read_scope with the `payment` argument).",
          }
        : {}),
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

const getScopeFile: McpToolDefinition = {
  name: "get_scope_file",
  title: "Get scope file",
  description:
    "Fetch an approved file/PDF scope. Defaults to metadata plus a resource link; set includeContent=true only when the client supports inline resource blobs. Use search_personal_context for extracted text.",
  inputSchema: {
    ...rawScopeFileInputSchema,
    // x402 proof (see read_scope's `payment`); provide after a payment_required.
    payment: z.string().optional(),
    timeoutMs: z
      .number()
      .int()
      .min(1000)
      .max(MAX_READ_FILE_TIMEOUT_MS)
      .optional(),
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

    const at = typeof args.at === "string" ? args.at : undefined;
    const fileId = typeof args.fileId === "string" ? args.fileId : undefined;
    const includeContent =
      typeof args.includeContent === "boolean" ? args.includeContent : false;
    const maxBytes = clampInteger(
      args.maxBytes,
      DEFAULT_READ_FILE_MAX_BYTES,
      1,
      MAX_READ_FILE_MAX_BYTES,
    );
    const timeoutMs = clampInteger(
      args.timeoutMs,
      DEFAULT_READ_FILE_TIMEOUT_MS,
      1000,
      MAX_READ_FILE_TIMEOUT_MS,
    );
    const resourceUri = rawScopeResourceUri({ scope, at, fileId });

    const payment = typeof args.payment === "string" ? args.payment : undefined;

    try {
      const raw = await withTimeout(
        readClient.readRawScopeFile({
          scope,
          grantId: grant.grantId,
          at,
          fileId,
          payment,
        }),
        timeoutMs,
        `read raw file for ${scope}`,
      );
      const metadata = rawScopeMetadata(raw);
      const base = {
        ...metadata,
        grantId: grant.grantId,
        resourceUri,
        includeContent,
        maxBytes,
        timeoutMs,
      };
      // A paid read settles a SINGLE-USE x402 payment for this fetch. A resource
      // link would force a second, unpaid resources/read → another 402 that
      // cannot be satisfied, so a paid read returns the bytes inline (regardless
      // of includeContent) — BUT the hard size cap is still enforced to protect
      // server/client memory and the MCP transport. An oversized paid file
      // returns a structured error, never an inline dump; clients size maxBytes
      // from the payment challenge's `sizeBytes` before paying.
      const paidRead = Boolean(payment);
      if (paidRead && raw.sizeBytes > maxBytes) {
        return textResult(
          {
            error: "paid_file_exceeds_max_bytes",
            status: 413,
            sizeBytes: raw.sizeBytes,
            maxBytes,
            message:
              "Payment settled, but the file exceeds maxBytes and is not returned inline. Retry with a larger maxBytes (and a fresh payment); files above the inline ceiling cannot be delivered over MCP.",
          },
          true,
        );
      }
      if (!paidRead && (!includeContent || raw.sizeBytes > maxBytes)) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                ...base,
                contentIncluded: false,
                reason: !includeContent
                  ? "includeContent=false"
                  : "file exceeds maxBytes for inline MCP tool response",
                nextStep:
                  "Use resources/read with resourceUri if your MCP client supports resources, or retry with a higher maxBytes if appropriate.",
              }),
            },
            {
              type: "resource_link",
              uri: resourceUri,
              name: raw.filename ?? scope,
              title: raw.filename ?? scope,
              description: `Raw file for ${scope}`,
              mimeType: raw.mimeType,
              size: raw.sizeBytes,
            },
          ],
          structuredContent: {
            ...base,
            contentIncluded: false,
          },
        };
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              ...base,
              contentIncluded: true,
              resourceType: "blob",
            }),
          },
          {
            type: "resource",
            resource: {
              uri: resourceUri,
              mimeType: raw.mimeType,
              blob: raw.contentBase64,
              _meta: metadata,
            },
          },
        ],
        structuredContent: {
          ...base,
          contentIncluded: true,
          resourceType: "blob",
        },
      };
    } catch (err) {
      if (err instanceof OperationTimeoutError) {
        return textResult(
          {
            error: "scope_file_timeout",
            message: err.message,
            timeoutMs: err.timeoutMs,
          },
          true,
        );
      }
      if (err instanceof McpDataReadError) {
        if (err.status === 402) {
          const body = err.body as {
            error?: {
              errorCode?: string;
              message?: string;
              details?: { challenge?: unknown };
            };
          };
          const challenge = body?.error?.details?.challenge;
          // Only a genuine PAYMENT_REQUIRED with a challenge is signable; a
          // gateway 402 (e.g. insufficient escrow) is surfaced as an error.
          if (body?.error?.errorCode === "PAYMENT_REQUIRED" && challenge) {
            // Surface the file size so the client can set maxBytes >= sizeBytes
            // BEFORE paying — a paid read must fit the inline size cap (the
            // single-use payment can't fund a second resources/read).
            let meta: { sizeBytes?: number } | null = null;
            try {
              meta = await readClient.getScopeMetadata(scope);
            } catch {
              meta = null;
            }
            const sizeBytes = meta?.sizeBytes;
            return textResult(
              {
                payment_required: true,
                status: 402,
                challenge,
                ...(typeof sizeBytes === "number"
                  ? { sizeBytes, recommendedMaxBytes: sizeBytes }
                  : {}),
                message:
                  "This file requires payment. Sign the x402 challenge and call get_scope_file again with the `payment` argument" +
                  (typeof sizeBytes === "number"
                    ? ` and maxBytes >= ${sizeBytes}.`
                    : "."),
              },
              true,
            );
          }
          return textResult(
            {
              error: "payment_failed",
              status: 402,
              errorCode: body?.error?.errorCode ?? "PAYMENT_ERROR",
              message:
                body?.error?.message ??
                "Payment could not be completed. This is not a signable challenge; resolve the gateway error and retry.",
            },
            true,
          );
        }
        return textResult(
          {
            error:
              err.status === 404
                ? "scope_file_not_found"
                : "scope_file_read_failed",
            status: err.status,
            body: err.body,
          },
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

const REMEMBER_TOOL = "remember";
const FORGET_TOOL = "forget";
const REMEMBER_TEXT_MAX_CHARS = 4_000;
const REMEMBER_KEY_MAX_CHARS = 128;
const MEMORY_ID_MAX_CHARS = 64;
/**
 * Every save stores a new snapshot of the scope's record list, so the list is
 * bounded by size rather than count. Sync publishes only the newest snapshot of
 * a memory scope (see `isCoalescedScope` in sync/workers/upload.ts).
 */
export const MEMORY_SCOPE_MAX_BYTES = 20 * 1024 * 1024;

/**
 * One saved memory: a row of the scope's PDPP `{ records: [...] }` body. Field
 * names follow the `chatgpt.memories` stream (id, content, created_at,
 * updated_at) so one declaration can cover both. `id` is stable for the life
 * of the memory, including when a save under the same `key` replaces it.
 */
export interface MemoryRecord {
  id: string;
  content: string;
  created_at: string;
  updated_at: string;
  /** Saving again under the same key replaces this memory. */
  key?: string;
  /** Address of the agent connection that last wrote this memory. */
  written_by: string | null;
}

class RememberRefusal extends Error {
  constructor(public readonly body: Record<string, unknown>) {
    super(String(body.message));
    this.name = "RememberRefusal";
  }
}

/** A save that would only repeat a memory the scope already holds. */
class DuplicateMemory extends Error {
  constructor(public readonly record: MemoryRecord) {
    super("duplicate memory");
    this.name = "DuplicateMemory";
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The memory records of a stored body. A memory scope holds exactly
 * `{ records: [...] }` of memory rows, or the earlier `{ memories: [...] }`
 * list, which is converted here (ids kept). Anything else was written by
 * someone else and is never overwritten.
 */
function storedMemoryRecords(
  scope: string,
  data: Record<string, unknown>,
): MemoryRecord[] {
  const keys = Object.keys(data);
  if (
    keys.length === 1 &&
    Array.isArray(data.records) &&
    data.records.every(
      (row) =>
        isPlainRecord(row) &&
        typeof row.id === "string" &&
        typeof row.content === "string",
    )
  ) {
    return data.records as MemoryRecord[];
  }
  if (
    keys.length === 1 &&
    Array.isArray(data.memories) &&
    data.memories.every(
      (item) =>
        isPlainRecord(item) &&
        typeof item.id === "string" &&
        typeof item.text === "string",
    )
  ) {
    return (data.memories as Array<Record<string, unknown>>).map((item) => {
      const at = typeof item.savedAt === "string" ? item.savedAt : "";
      return {
        id: item.id as string,
        content: item.text as string,
        created_at: at,
        updated_at: at,
        ...(typeof item.key === "string" ? { key: item.key } : {}),
        written_by: null,
      };
    });
  }
  throw new RememberRefusal({
    error: "scope_not_memory",
    scope,
    message: `Scope ${scope} holds data that is not a memory list; it will not be changed. Use another write scope.`,
  });
}

/**
 * The scope a memory tool acts on and the grant that covers it, or the error
 * result to return. A call may omit `scope` when the connection can write to
 * exactly one scope.
 */
function resolveMemoryTarget(
  args: Record<string, unknown>,
  connection: McpConnectionRecord,
): { scope: string; grantId: string } | { error: McpToolResult } {
  const writableScopes = uniqueWritableScopes(connection);
  const namedScope = typeof args.scope === "string" ? args.scope.trim() : "";
  const onlyScope =
    writableScopes.length === 1 && !writableScopes[0]!.includes("*")
      ? writableScopes[0]!
      : "";
  const scope = namedScope || onlyScope;
  if (!scope) {
    return {
      error: textResult(
        {
          error: "scope_required",
          writableScopes,
          message:
            writableScopes.length === 0
              ? 'This connection cannot save memories. Call request_scope_access with scopes ["write:memory.<app>"] and ask the user to approve it.'
              : "Name the scope; this connection can write to more than one.",
        },
        true,
      ),
    };
  }
  const grant = resolveWriteGrantForScope(connection, scope);
  if (!grant) {
    const requestScope = `${WRITE_SCOPE_PREFIX}${scope}`;
    return {
      error: textResult(
        {
          error: "scope_not_granted",
          scope,
          requestScope,
          writableScopes,
          message: `This connection may not write to ${scope}. Call request_scope_access with scopes ["${requestScope}"] and ask the user to approve it.`,
        },
        true,
      ),
    };
  }
  return { scope, grantId: grant.grantId };
}

const WRITE_UNAVAILABLE = textResult(
  {
    error: "write_unavailable",
    message: "This Personal Server does not accept MCP writes.",
  },
  true,
);

/** Map a refused or failed memory write to the tool's error result. */
function memoryWriteError(err: unknown, scope: string): McpToolResult {
  if (err instanceof RememberRefusal) return textResult(err.body, true);
  if (err instanceof McpDataWriteError) {
    const body = err.body as {
      error?: { errorCode?: string; message?: string } | string;
      message?: string;
    } | null;
    const detail =
      typeof body?.error === "object" && body.error !== null
        ? body.error
        : { errorCode: body?.error, message: body?.message };
    return textResult(
      {
        error:
          err.status === 401 || err.status === 403
            ? "unauthorized"
            : err.status === 412
              ? "write_conflict"
              : "write_failed",
        status: err.status,
        scope,
        ...(detail.errorCode ? { errorCode: detail.errorCode } : {}),
        ...(detail.message ? { message: detail.message } : {}),
      },
      true,
    );
  }
  throw err;
}

function memoryBody(records: MemoryRecord[], scope: string) {
  const body = { records };
  if (
    new TextEncoder().encode(JSON.stringify(body)).byteLength >
    MEMORY_SCOPE_MAX_BYTES
  ) {
    throw new RememberRefusal({
      error: "memory_full",
      scope,
      limitBytes: MEMORY_SCOPE_MAX_BYTES,
      message: `Scope ${scope} is full. Forget or replace memories to make room.`,
    });
  }
  return body;
}

const remember: McpToolDefinition = {
  name: REMEMBER_TOOL,
  title: "Remember",
  description:
    "Save a fact, preference, goal or decision the user shares, without being asked, so any allowed agent can recall it. Tell the user briefly. Never save secrets, passwords, IDs or account numbers. Needs a write:<scope> grant (writableScopes).",
  inputSchema: {
    text: z
      .string()
      .min(1)
      .max(REMEMBER_TEXT_MAX_CHARS)
      .describe("Self-contained; readable without this chat."),
    scope: z
      .string()
      .min(1)
      .max(SEARCH_SCOPE_MAX_CHARS)
      .optional()
      .describe("e.g. memory.claude; optional with one writable scope."),
    key: z
      .string()
      .min(1)
      .max(REMEMBER_KEY_MAX_CHARS)
      .optional()
      .describe("Saving again with the same key replaces the memory."),
  },
  async handler(args, { connection, writeClient }) {
    const content = typeof args.text === "string" ? args.text.trim() : "";
    if (!content) {
      return textResult(
        { error: "invalid_arguments", message: "text must not be empty." },
        true,
      );
    }
    const key =
      typeof args.key === "string" && args.key.trim()
        ? args.key.trim()
        : undefined;
    const target = resolveMemoryTarget(args, connection);
    if ("error" in target) return target.error;
    const { scope, grantId } = target;
    if (!writeClient) return WRITE_UNAVAILABLE;

    const now = new Date().toISOString();
    let saved: MemoryRecord | undefined;
    let replaced = false;
    let memoryCount = 0;
    try {
      await writeClient.updateScope({
        scope,
        grantId,
        update(current) {
          const records =
            current.data === null
              ? []
              : storedMemoryRecords(scope, current.data);
          const previous = key
            ? records.find((record) => record.key === key)
            : undefined;
          if (!key) {
            const same = records.find((record) => record.content === content);
            if (same) throw new DuplicateMemory(same);
          }
          replaced = previous !== undefined;
          saved = {
            id: previous?.id ?? crypto.randomUUID(),
            content,
            created_at: previous?.created_at ?? now,
            updated_at: now,
            ...(key ? { key } : {}),
            written_by: connection.granteeAddress,
          };
          // Newest last: a replaced memory moves to the end, so list order is
          // the order the memories were last saved in.
          const next = [
            ...records.filter((record) => record !== previous),
            saved,
          ];
          memoryCount = next.length;
          return memoryBody(next, scope);
        },
      });
    } catch (err) {
      if (err instanceof DuplicateMemory) {
        return textResult({
          saved: false,
          duplicate: true,
          scope,
          id: err.record.id,
          message: "This memory is already saved.",
        });
      }
      return memoryWriteError(err, scope);
    }

    return textResult({
      saved: true,
      scope,
      id: saved!.id,
      savedAt: saved!.updated_at,
      ...(key ? { key } : {}),
      replaced,
      memoryCount,
    });
  },
};

const forget: McpToolDefinition = {
  name: FORGET_TOOL,
  title: "Forget",
  description:
    "Delete a saved memory by id or key. Needs a write:<scope> grant.",
  inputSchema: {
    id: z.string().min(1).max(MEMORY_ID_MAX_CHARS).optional(),
    key: z.string().min(1).max(REMEMBER_KEY_MAX_CHARS).optional(),
    scope: z.string().min(1).max(SEARCH_SCOPE_MAX_CHARS).optional(),
  },
  async handler(args, { connection, writeClient }) {
    const id = typeof args.id === "string" ? args.id.trim() : "";
    const key = typeof args.key === "string" ? args.key.trim() : "";
    if (!id && !key) {
      return textResult(
        { error: "invalid_arguments", message: "Pass id or key." },
        true,
      );
    }
    const target = resolveMemoryTarget(args, connection);
    if ("error" in target) return target.error;
    const { scope, grantId } = target;
    if (!writeClient) return WRITE_UNAVAILABLE;

    const forgotten: string[] = [];
    let memoryCount = 0;
    try {
      await writeClient.updateScope({
        scope,
        grantId,
        update(current) {
          const records =
            current.data === null
              ? []
              : storedMemoryRecords(scope, current.data);
          const keep = records.filter(
            (record) =>
              !((id && record.id === id) || (key && record.key === key)),
          );
          if (keep.length === records.length) {
            throw new RememberRefusal({
              error: "not_found",
              scope,
              message: "No saved memory matches that id or key.",
            });
          }
          forgotten.push(
            ...records
              .filter((record) => !keep.includes(record))
              .map((record) => record.id),
          );
          memoryCount = keep.length;
          return memoryBody(keep, scope);
        },
      });
    } catch (err) {
      return memoryWriteError(err, scope);
    }
    return textResult({ forgotten: true, scope, ids: forgotten, memoryCount });
  },
};

export const MCP_TOOLS: readonly McpToolDefinition[] = [
  listGrantedSources,
  listGrantedScopes,
  requestScopeAccess,
  readScope,
  listScopeBlocks,
  getScopeFile,
  searchPersonalContext,
  remember,
  forget,
] as const;
