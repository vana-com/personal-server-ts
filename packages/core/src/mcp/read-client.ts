/**
 * In-process MCP read client.
 *
 * The MCP route accepts a tool call from an MCP client, then needs to read scoped data
 * from the user's Personal Server *as the per-connection grantee*. We do NOT
 * round-trip through the public HTTP origin for this — the relay/tunnel is only
 * for inbound MCP traffic. Instead we:
 *
 *  1. Build a Web Request signed by the connection's grantee, with the
 *     existing grantId in the Web3Signed payload.
 *  2. Use the same auth and access-log ports as `/v1/data`, then read bounded
 *     block sidecars from storage. MCP tools must not fall back to full envelope
 *     reads when sidecars are unavailable.
 *
 * This guarantees parity: the MCP read goes through the same policy check
 * (`verifyDataReadPolicy`) and access-log path as an external builder read.
 * No special owner-mode code path; no shared global grantee; logs record the
 * per-connection grantee address.
 */

import type { ServerAccount } from "../keys/server-account.js";
import type { ScopeSummary } from "../storage/index/types.js";
import type { ReadScopeBlocksResponse } from "../storage/blocks/types.js";
import { decodeDataBlockCursor } from "../storage/blocks/index.js";
import { signMcpGranteeRequest } from "./grantee.js";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../api/index.js";
import { ProtocolError } from "../errors/catalog.js";

export interface McpDataReadClient {
  /**
   * Perform `GET /v1/data?scopePrefix=…` as the connection grantee. This is
   * used only for discovery/expanding wildcard grants before a grant-gated
   * read; it does not return scope contents.
   */
  listScopes(params?: {
    scopePrefix?: string;
    limit?: number;
    offset?: number;
  }): Promise<McpDataListResult>;

  /**
   * Perform a grant-gated bounded block read for MCP. This is the path used by
   * MCP tools that need pagination and must not fall back to full envelope
   * reads when the bounded storage path is unavailable.
   */
  readScopeBlocks(params: {
    scope: string;
    grantId: string;
    cursor?: string;
    maxBytes?: number;
  }): Promise<McpDataReadBlocksResult>;
}

export interface McpDataListResult {
  status: number;
  scopes: ScopeSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface McpDataReadBlocksResult extends ReadScopeBlocksResponse {
  status: number;
}

export class McpDataReadError extends Error {
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(
      typeof body === "object" && body !== null && "error" in body
        ? String(
            (body as { error?: { message?: string } }).error?.message ??
              `mcp data read failed (status ${status})`,
          )
        : `mcp data read failed (status ${status})`,
    );
  }
}

export interface CreateMcpDataReadClientOptions {
  /**
   * Origin the Web3Signed payload's `aud` claim is bound to. This MUST match
   * the `serverOrigin` configured on the data API auth port — otherwise the
   * signature audience check will fail.
   */
  serverOrigin: string;
  granteeAccount: ServerAccount;
  /**
   * The data API deps used to mount `/v1/data` for external traffic. We reuse
   * the exact same handler + ports so policy and access-logging are identical.
   */
  dataApiDeps: PersonalServerDataApiDeps;
  /**
   * Base path the data API was mounted under externally — required so the
   * Web3Signed signature URI matches what `handlePersonalServerDataRequest`
   * expects after strip-base-path. Defaults to `/v1/data`.
   */
  basePath?: string;
}

export function createMcpDataReadClient(
  options: CreateMcpDataReadClientOptions,
): McpDataReadClient {
  const basePath = options.basePath ?? "/v1/data";

  return {
    async listScopes({ scopePrefix, limit, offset } = {}) {
      const params = new URLSearchParams();
      if (scopePrefix) params.set("scopePrefix", scopePrefix);
      if (limit !== undefined) params.set("limit", String(limit));
      if (offset !== undefined) params.set("offset", String(offset));
      const query = params.toString();
      const pathWithQuery = query ? `${basePath}?${query}` : basePath;

      const authorization = await signMcpGranteeRequest({
        account: options.granteeAccount,
        aud: options.serverOrigin,
        method: "GET",
        uri: basePath,
        grantId: "mcp-list",
      });

      const url = new URL(pathWithQuery, options.serverOrigin).toString();
      const request = new Request(url, {
        method: "GET",
        headers: { Authorization: authorization },
      });

      const response = await handlePersonalServerDataRequest(
        request,
        options.dataApiDeps,
        { basePath },
      );

      const body = await parseJsonOrText(response);

      if (!response.ok) {
        throw new McpDataReadError(response.status, body);
      }

      return { status: response.status, ...normalizeListScopesPayload(body) };
    },

    async readScopeBlocks({ scope, grantId, cursor, maxBytes }) {
      const storage = options.dataApiDeps.storage;
      if (!storage.readScopeBlocks) {
        throw new McpDataReadError(503, {
          error: "BOUNDED_DATA_UNAVAILABLE",
          message:
            "Bounded scope data is unavailable while the storage sidecar is missing or still indexing.",
          scope,
        });
      }

      const pinnedCollectedAt = collectedAtFromCursor(scope, cursor);
      const selectedEntry = storage.findEntry({
        scope,
        ...(pinnedCollectedAt ? { at: pinnedCollectedAt } : {}),
      });
      if (!selectedEntry) {
        throw new McpDataReadError(404, {
          error: "NOT_FOUND",
          message: `No data found for scope "${scope}"`,
        });
      }

      const safeScope = encodeURIComponent(scope);
      const signingUri = `${basePath}/${safeScope}`;
      const authorization = await signMcpGranteeRequest({
        account: options.granteeAccount,
        aud: options.serverOrigin,
        method: "GET",
        uri: signingUri,
        grantId,
      });
      const url = new URL(signingUri, options.serverOrigin).toString();
      const request = new Request(url, {
        method: "GET",
        headers: { Authorization: authorization },
      });

      let authResult:
        | Awaited<
            ReturnType<
              CreateMcpDataReadClientOptions["dataApiDeps"]["auth"]["authorizeBuilderRead"]
            >
          >
        | undefined;
      try {
        authResult = await options.dataApiDeps.auth.authorizeBuilderRead({
          request,
          scope,
          grantId,
          fileId: selectedEntry.fileId ?? undefined,
        });
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw new McpDataReadError(err.code, err.toJSON());
        }
        throw err;
      }

      try {
        const result = await storage.readScopeBlocks(
          scope,
          selectedEntry.collectedAt,
          {
            cursor,
            maxBytes: maxBytes ?? 16_384,
          },
        );
        await options.dataApiDeps.accessLogWriter.write({
          logId: options.dataApiDeps.createLogId?.() ?? crypto.randomUUID(),
          grantId: authResult?.grantId ?? grantId,
          builder: authResult?.builder ?? options.granteeAccount.address,
          action: "read",
          scope,
          timestamp: (
            options.dataApiDeps.now ?? (() => new Date())
          )().toISOString(),
          ipAddress:
            request.headers.get("x-forwarded-for") ??
            request.headers.get("x-real-ip") ??
            "unknown",
          userAgent: request.headers.get("user-agent") ?? "unknown",
        });
        return { status: 200, ...result };
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw new McpDataReadError(err.code, err.toJSON());
        }
        if (err instanceof Error) {
          const code = dataBlockStorageErrorCode(err);
          const status = code === "cursor_invalid" ? 400 : 503;
          throw new McpDataReadError(status, {
            error:
              code === "cursor_invalid"
                ? "INVALID_CURSOR"
                : "BOUNDED_DATA_UNAVAILABLE",
            message:
              code === "cursor_invalid"
                ? "The bounded read cursor is invalid for this scope."
                : "Bounded scope data is unavailable while the storage sidecar is missing or still indexing.",
            scope,
            ...(code ? { reason: code } : {}),
          });
        }
        throw err;
      }
    },
  };
}

async function parseJsonOrText(response: Response): Promise<unknown> {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return text;
  }
}

function collectedAtFromCursor(
  scope: string,
  cursor: string | undefined,
): string | undefined {
  if (!cursor) return undefined;
  const decoded = decodeDataBlockCursor(cursor);
  if (!decoded.ok || decoded.cursor.scope !== scope) return undefined;
  return decoded.cursor.collectedAt;
}

function dataBlockStorageErrorCode(err: Error): string | undefined {
  if (!("code" in err)) return undefined;
  const code = (err as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

function normalizeListScopesPayload(
  body: unknown,
): Omit<McpDataListResult, "status"> {
  if (typeof body !== "object" || body === null) {
    return { scopes: [], total: 0, limit: 0, offset: 0 };
  }
  const payload = body as {
    scopes?: unknown;
    total?: unknown;
    limit?: unknown;
    offset?: unknown;
  };
  const scopes = Array.isArray(payload.scopes)
    ? payload.scopes.filter(isScopeSummary)
    : [];
  return {
    scopes,
    total: typeof payload.total === "number" ? payload.total : scopes.length,
    limit: typeof payload.limit === "number" ? payload.limit : scopes.length,
    offset: typeof payload.offset === "number" ? payload.offset : 0,
  };
}

function isScopeSummary(value: unknown): value is ScopeSummary {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const summary = value as {
    scope?: unknown;
    latestCollectedAt?: unknown;
    versionCount?: unknown;
  };
  return (
    typeof summary.scope === "string" &&
    typeof summary.latestCollectedAt === "string" &&
    typeof summary.versionCount === "number"
  );
}
