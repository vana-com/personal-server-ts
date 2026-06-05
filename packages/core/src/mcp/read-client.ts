/**
 * In-process MCP read client.
 *
 * The MCP route accepts a tool call from Claude, then needs to read scoped data
 * from the user's Personal Server *as the per-connection grantee*. We do NOT
 * round-trip through the public HTTP origin for this — the relay/tunnel is
 * only for inbound Claude traffic. Instead we:
 *
 *  1. Build a Web Request signed by the connection's grantee, with the
 *     existing grantId in the Web3Signed payload.
 *  2. Hand normal reads to `handlePersonalServerDataRequest` directly.
 *     Search previews use the same auth and access-log ports, then read only a
 *     bounded text prefix from storage.
 *
 * This guarantees parity: the MCP read goes through the same policy check
 * (`verifyDataReadPolicy`) and access-log path as an external builder read.
 * No special owner-mode code path; no shared global grantee; logs record the
 * per-connection grantee address.
 */

import type { ServerAccount } from "../keys/server-account.js";
import type { IndexEntry, ScopeSummary } from "../storage/index/types.js";
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
   * Perform `GET /v1/data/:scope?grantId=…` as the connection grantee and
   * return the parsed response body. Throws `McpDataReadError` if the read
   * fails for any reason (no matching grant, scope not covered, runtime
   * unavailable, …) — the caller turns this into an MCP `isError` result.
   */
  readScope(params: {
    scope: string;
    grantId: string;
    limit?: number;
  }): Promise<McpDataReadResult>;

  /**
   * Perform a grant-gated, access-logged read of a bounded text prefix for MCP
   * search. This deliberately does not parse the full envelope, so one huge
   * scope cannot consume the whole MCP client timeout before search can skip it.
   */
  previewScope(params: {
    scope: string;
    grantId: string;
    maxBytes: number;
  }): Promise<McpDataPreviewResult>;
}

export interface McpDataReadResult {
  status: number;
  body: unknown;
}

export interface McpDataListResult {
  status: number;
  scopes: ScopeSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface McpDataPreviewResult {
  status: number;
  scope: string;
  collectedAt: string;
  text: string;
  truncated: boolean;
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

    async readScope({ scope, grantId, limit }) {
      const safeScope = encodeURIComponent(scope);
      const query = limit !== undefined ? `?limit=${limit}` : "";
      const pathWithQuery = `${basePath}/${safeScope}${query}`;
      // The data-API auth verifier checks `payload.uri === url.pathname` on the
      // incoming Request — pathname has no query string, so sign the path only.
      const signingUri = `${basePath}/${safeScope}`;

      const authorization = await signMcpGranteeRequest({
        account: options.granteeAccount,
        aud: options.serverOrigin,
        method: "GET",
        uri: signingUri,
        grantId,
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

      return { status: response.status, body };
    },

    async previewScope({ scope, grantId, maxBytes }) {
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
      const selectedEntry = options.dataApiDeps.storage.findEntry({ scope });

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
          fileId: selectedEntry?.fileId ?? undefined,
        });
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw new McpDataReadError(err.code, err.toJSON());
        }
        throw err;
      }

      if (!selectedEntry) {
        throw new McpDataReadError(404, {
          error: "NOT_FOUND",
          message: `No data found for scope "${scope}"`,
        });
      }

      let preview: { text: string; truncated: boolean };
      try {
        preview = await readStoragePreview(
          options.dataApiDeps.storage,
          selectedEntry,
          maxBytes,
        );
      } catch (err) {
        if (err instanceof McpDataReadError) {
          throw err;
        }
        options.dataApiDeps.logger?.error?.(
          { err, scope },
          "MCP scope preview read failed",
        );
        throw new McpDataReadError(500, {
          error: "INTERNAL_ERROR",
          message: "Failed to read scope preview",
        });
      }

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

      return {
        status: 200,
        scope,
        collectedAt: selectedEntry.collectedAt,
        ...preview,
      };
    },
  };
}

async function readStoragePreview(
  storage: PersonalServerDataApiDeps["storage"],
  entry: IndexEntry,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  if (storage.readEnvelopePreview) {
    return storage.readEnvelopePreview(entry.scope, entry.collectedAt, {
      maxBytes,
    });
  }

  if (entry.sizeBytes > maxBytes) {
    throw new McpDataReadError(413, {
      error: "PREVIEW_UNAVAILABLE",
      message:
        "This storage backend cannot provide bounded search previews for large scopes.",
      scope: entry.scope,
      maxBytes,
      sizeBytes: entry.sizeBytes,
    });
  }

  const envelope = await storage.readEnvelope(entry.scope, entry.collectedAt);
  const text = JSON.stringify(envelope);
  const encoded = new TextEncoder().encode(text);
  return {
    text: new TextDecoder().decode(encoded.slice(0, maxBytes)),
    truncated: encoded.byteLength > maxBytes,
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
