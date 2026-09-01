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
import type {
  DataBlockManifest,
  ReadScopeBlocksResponse,
} from "../storage/blocks/types.js";
import type { SearchHit } from "./search/index.js";
import { decodeDataBlockCursor } from "../storage/blocks/index.js";
import {
  bytesToBase64,
  isBinaryEnvelope,
  parseMetadataHeader,
} from "../contracts/binary.js";
import { LINEAGE_KEY } from "../lineage/lineage.js";
import { signMcpGranteeRequest } from "./grantee.js";
import {
  assertScopeNotDeleted,
  handlePersonalServerDataRequest,
  isOwnerView,
  reportPersonalServerReadFulfillment,
  resolveReadDeletion,
  type PersonalServerDataApiDeps,
  type ReadDeletionEntry,
} from "../api/index.js";
import { ProtocolError } from "../errors/catalog.js";

/**
 * Block sidecars are built from the FULL stored envelope, so they carry the
 * server-stamped `$writtenBy` / `$lineage` keys and the consumed caller
 * lineage field that grantee reads of the record itself never see. The same
 * redaction applies here at serve time: dedicated blocks under those paths
 * are dropped, data-level object payloads (`$.data`, grouped-key blocks,
 * `$.data.metadata`) have the keys stripped, and group labels naming a
 * redacted key are rewritten. The caller lineage field follows the envelope
 * path's contract — dropped from the location the write path consumed
 * (top-level `lineage` for JSON, `metadata.lineage` for binary) only when
 * `$lineage` is stamped — which is why redaction reads the envelope for
 * stamped-ness; if that read fails, both locations are dropped (fail
 * closed).
 */
interface BlockRedactionContext {
  dropTopLevelLineage: boolean;
  dropMetadataLineage: boolean;
}

const FAIL_CLOSED_CONTEXT: BlockRedactionContext = {
  dropTopLevelLineage: true,
  dropMetadataLineage: true,
};

function pathUnder(path: string, prefix: string): boolean {
  return (
    path === prefix ||
    (path.startsWith(prefix) && /[.[{]/.test(path.charAt(prefix.length)))
  );
}

function groupLabelSegments(path: string): string[] {
  const match = /^\$\.data(?:\.metadata)?\.\{(.+):(.+)\}$/.exec(path);
  return match ? [match[1]!, match[2]!] : [];
}

/**
 * Whether the served blocks carry anything the caller-lineage rule could
 * apply to. When they don't (the overwhelmingly common case — ordinary
 * content blocks), no stamped-ness decision is needed and the envelope is
 * never read, keeping bounded reads bounded.
 */
function servedLineageShaped(
  blocks: readonly { path: string; value?: unknown }[],
): boolean {
  return blocks.some((block) => {
    if (
      pathUnder(block.path, "$.data.lineage") ||
      pathUnder(block.path, "$.data.metadata.lineage")
    ) {
      return true;
    }
    if (
      groupLabelSegments(block.path).some(
        (segment) => segment === "lineage" || segment === LINEAGE_KEY,
      )
    ) {
      return true;
    }
    if (!("value" in block) || !isPlainObject(block.value)) return false;
    const data =
      block.path === "$" ? (block.value["data"] ?? null) : block.value;
    return (
      isPlainObject(data) &&
      ("lineage" in data ||
        (isPlainObject(data["metadata"]) && "lineage" in data["metadata"]))
    );
  });
}

/**
 * Stamped-ness evidence visible in the served blocks themselves: a
 * `$.data.$lineage` path (dedicated block or manifest ref) or a `$lineage`
 * key inside a data-level payload. Both occur only on JSON records — the
 * binary block emitter never serializes the stamped keys — so visible
 * evidence always means "JSON record, drop the top-level field".
 */
function visibleStampEvidence(
  blocks: readonly { path: string; value?: unknown }[],
): BlockRedactionContext | null {
  for (const block of blocks) {
    if (
      pathUnder(block.path, `$.data.${LINEAGE_KEY}`) ||
      groupLabelSegments(block.path).includes(LINEAGE_KEY)
    ) {
      return { dropTopLevelLineage: true, dropMetadataLineage: false };
    }
    if ("value" in block && isPlainObject(block.value)) {
      const data =
        block.path === "$" ? (block.value["data"] ?? null) : block.value;
      if (isPlainObject(data) && LINEAGE_KEY in data) {
        return { dropTopLevelLineage: true, dropMetadataLineage: false };
      }
    }
  }
  return null;
}

/**
 * The caller-lineage decision for a set of served blocks or manifest refs.
 * Decided from the blocks themselves when possible; the stored envelope is
 * read only when lineage-shaped content is present without visible
 * stamped-ness evidence (a pagination or blockIds slice), and an unreadable
 * envelope redacts both locations rather than serving them.
 */
async function resolveBlockRedactionContext(
  storage: Pick<PersonalServerDataApiDeps["storage"], "readEnvelope">,
  scope: string,
  collectedAt: string,
  blocks: readonly { path: string; value?: unknown }[],
): Promise<BlockRedactionContext> {
  if (!servedLineageShaped(blocks)) {
    return { dropTopLevelLineage: false, dropMetadataLineage: false };
  }
  const visible = visibleStampEvidence(blocks);
  if (visible) return visible;
  try {
    const envelope = await storage.readEnvelope(scope, collectedAt);
    if (!(LINEAGE_KEY in envelope.data)) {
      return { dropTopLevelLineage: false, dropMetadataLineage: false };
    }
    return isBinaryEnvelope(envelope)
      ? { dropTopLevelLineage: false, dropMetadataLineage: true }
      : { dropTopLevelLineage: true, dropMetadataLineage: false };
  } catch {
    return FAIL_CLOSED_CONTEXT;
  }
}

function redactedBlockPathPrefixes(ctx: BlockRedactionContext): string[] {
  return [
    "$.data.$writtenBy",
    "$.data.$lineage",
    ...(ctx.dropTopLevelLineage ? ["$.data.lineage"] : []),
    ...(ctx.dropMetadataLineage ? ["$.data.metadata.lineage"] : []),
  ];
}

function isRedactedBlockPath(
  path: string,
  ctx: BlockRedactionContext,
): boolean {
  return redactedBlockPathPrefixes(ctx).some(
    (prefix) =>
      path === prefix ||
      (path.startsWith(prefix) && /[.[{]/.test(path.charAt(prefix.length))),
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isRedactedKeyName(
  parent: "data" | "metadata",
  key: string,
  ctx: BlockRedactionContext,
): boolean {
  if (parent === "data") {
    return (
      key === "$writtenBy" ||
      key === "$lineage" ||
      (ctx.dropTopLevelLineage && key === "lineage")
    );
  }
  return ctx.dropMetadataLineage && key === "lineage";
}

/**
 * Group blocks are labeled `<parent>.{first:last}` after the first and last
 * key they pack; a redacted key name in the label is rewritten so not even
 * the key's existence is served.
 */
function sanitizeGroupLabel(path: string, ctx: BlockRedactionContext): string {
  const match = /^(\$\.data(?:\.metadata)?)\.\{(.+):(.+)\}$/.exec(path);
  if (!match) return path;
  const parent = match[1] === "$.data" ? "data" : "metadata";
  const first = isRedactedKeyName(parent, match[2]!, ctx) ? "…" : match[2]!;
  const last = isRedactedKeyName(parent, match[3]!, ctx) ? "…" : match[3]!;
  return `${match[1]}.{${first}:${last}}`;
}

function stripMetadataLineage(
  value: Record<string, unknown>,
  ctx: BlockRedactionContext,
): Record<string, unknown> {
  if (!ctx.dropMetadataLineage || !isPlainObject(value["metadata"])) {
    return value;
  }
  const { lineage: _metadataLineage, ...metadataRest } = value["metadata"];
  if (Object.keys(metadataRest).length === 0) {
    const { metadata: _emptied, ...rest } = value;
    return rest;
  }
  return { ...value, metadata: metadataRest };
}

function stripDataLevelKeys(
  value: Record<string, unknown>,
  ctx: BlockRedactionContext,
): Record<string, unknown> {
  const { $writtenBy: _writtenBy, $lineage: _lineage, ...rest } = value;
  let data: Record<string, unknown> = rest;
  if (ctx.dropTopLevelLineage) {
    const { lineage: _callerLineage, ...dataRest } = data;
    data = dataRest;
  }
  return stripMetadataLineage(data, ctx);
}

function redactBlockValue(
  path: string,
  value: unknown,
  ctx: BlockRedactionContext,
): unknown {
  if (!isPlainObject(value)) return value;
  if (path === "$.data" || /^\$\.data\.\{.*\}$/.test(path)) {
    return stripDataLevelKeys(value, ctx);
  }
  if (path === "$.data.metadata" || /^\$\.data\.metadata\.\{.*\}$/.test(path)) {
    if (!ctx.dropMetadataLineage) return value;
    const { lineage: _metadataLineage, ...rest } = value;
    return rest;
  }
  if (path === "$" && isPlainObject(value["data"])) {
    return { ...value, data: stripDataLevelKeys(value["data"], ctx) };
  }
  return value;
}

function redactBlockRefsForGrantee<T extends { path: string }>(
  blocks: T[],
  ctx: BlockRedactionContext,
): T[] {
  return blocks
    .filter((block) => !isRedactedBlockPath(block.path, ctx))
    .map((block) => ({ ...block, path: sanitizeGroupLabel(block.path, ctx) }));
}

function redactBlockPayloadsForGrantee<
  T extends { path: string; value: unknown },
>(blocks: T[], ctx: BlockRedactionContext): T[] {
  return blocks
    .filter((block) => !isRedactedBlockPath(block.path, ctx))
    .flatMap((block) => {
      const value = redactBlockValue(block.path, block.value, ctx);
      // A group emptied by the strip carried only redacted keys.
      if (
        isPlainObject(block.value) &&
        Object.keys(block.value).length > 0 &&
        isPlainObject(value) &&
        Object.keys(value).length === 0
      ) {
        return [];
      }
      return [{ ...block, path: sanitizeGroupLabel(block.path, ctx), value }];
    });
}

export interface McpScopeMetadata {
  scope: string;
  collectedAt: string;
  sizeBytes: number;
  /** True when the bounded block read path is available for this scope. */
  hasBlocks: boolean;
}

export interface McpDataReadClient {
  /**
   * True when reads through this client are x402-payment-enforced (a paid
   * self-signing session). Payment-bypassing shortcuts — notably the optional
   * `searchScopeIndex` preview path, which does not route through the data API
   * auth port — MUST NOT be used when this is set.
   */
  enforcesPayment?: boolean;

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
   * Return lightweight planning metadata for a scope using the storage index
   * only — no network call, no block read, no auth. Used by list_granted_scopes
   * to populate sizeBytes/sizeClass/recommendedAccess without reading data.
   * Returns null when the scope has no local index entry.
   */
  getScopeMetadata(scope: string): Promise<McpScopeMetadata | null>;

  /**
   * Perform a grant-gated bounded block read for MCP. This is the path used by
   * MCP tools that need pagination and must not fall back to full envelope
   * reads when the bounded storage path is unavailable.
   *
   * `blockIds` switches the read to block-addressed mode: only those blocks are
   * returned, `cursor` is ignored, and no `nextCursor` is produced. `maxBytes`
   * still bounds the response.
   */
  readScopeBlocks(params: {
    scope: string;
    grantId: string;
    cursor?: string;
    maxBytes?: number;
    /**
     * Optional base64 `X-PAYMENT` proof (x402). Forwarded as a header on the
     * in-process read request so a payment-enforcing auth port (self-signing
     * MCP sessions) can settle it. The owner/OAuth path never sets this.
     */
    payment?: string;
    blockIds?: readonly string[];
  }): Promise<McpDataReadBlocksResult>;

  /**
   * Read a scope's block manifest (ids, paths, sizes) as a table of contents.
   * Grant-gated like `readScopeBlocks`, but returns no block values. Resolves
   * null when the scope has no manifest — older scopes and scopes that are
   * still indexing must degrade, not fail.
   */
  readBlockManifest?(params: {
    scope: string;
    grantId: string;
  }): Promise<DataBlockManifest | null>;

  /**
   * Perform a grant-gated raw binary read for an approved binary scope. This
   * reuses `/v1/data/{scope}?content=raw` so policy checks and access logs stay
   * identical to normal builder reads.
   */
  readRawScopeFile(params: {
    scope: string;
    grantId: string;
    at?: string;
    fileId?: string;
    /**
     * Optional base64 `X-PAYMENT` proof (x402), forwarded like
     * `readScopeBlocks` so a paid self-signing session can settle raw reads.
     */
    payment?: string;
  }): Promise<McpDataReadRawFileResult>;

  /**
   * Optional indexed search path. Implementations may return `missing` while
   * an index is absent/stale; callers must keep the bounded block read path as
   * fallback so full data remains accessible.
   */
  searchScopeIndex?(params: {
    scope: string;
    grantId: string;
    query: string;
    maxResults: number;
  }): Promise<
    | {
        status: "hit";
        hits: SearchHit[];
      }
    | {
        status: "missing";
      }
  >;
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

export interface McpDataReadRawFileResult {
  status: number;
  scope: string;
  collectedAt?: string;
  fileId?: string;
  mimeType: string;
  filename?: string;
  sizeBytes: number;
  contentBase64: string;
  metadata?: unknown;
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
  /**
   * Marks reads through this client as x402-enforced (paid self-signing
   * session). Surfaced as `McpDataReadClient.enforcesPayment`.
   */
  enforcesPayment?: boolean;
}

type BuilderReadAuthorization = Awaited<
  ReturnType<
    CreateMcpDataReadClientOptions["dataApiDeps"]["auth"]["authorizeBuilderRead"]
  >
>;

export function createMcpDataReadClient(
  options: CreateMcpDataReadClientOptions,
): McpDataReadClient {
  const basePath = options.basePath ?? "/v1/data";

  /**
   * Same deletion gate as GET /v1/data/:scope, surfaced as the MCP error
   * shape. Runs before `authorizeScopeRead`, which may settle payment.
   */
  async function assertScopeReadable(
    scope: string,
    entry: ReadDeletionEntry,
  ): Promise<void> {
    try {
      await assertScopeNotDeleted(options.dataApiDeps, scope, entry);
    } catch (err) {
      if (err instanceof ProtocolError) {
        throw new McpDataReadError(err.code, err.toJSON());
      }
      throw err;
    }
  }

  /**
   * Sign a grantee request for `scope` and run the same policy check
   * `/v1/data/:scope` runs. Shared by every grant-gated read below so none of
   * them can drift away from the external read path's authorization.
   */
  async function authorizeScopeRead(params: {
    scope: string;
    grantId: string;
    fileId?: string;
    /**
     * The exact version this read serves (cursor-pinned or latest). A
     * payment-enforcing auth port (self-signing MCP sessions) binds the x402
     * settlement to it; the owner/OAuth path ignores it.
     */
    at?: string;
    /**
     * Optional base64 `X-PAYMENT` proof (x402), forwarded as a header on the
     * in-process read request so a payment-enforcing auth port can settle it.
     * The owner/OAuth path never sets this.
     */
    payment?: string;
  }): Promise<{ request: Request; authResult?: BuilderReadAuthorization }> {
    const safeScope = encodeURIComponent(params.scope);
    const signingUri = `${basePath}/${safeScope}`;
    const authorization = await signMcpGranteeRequest({
      account: options.granteeAccount,
      aud: options.serverOrigin,
      method: "GET",
      uri: signingUri,
      grantId: params.grantId,
    });
    const url = new URL(signingUri, options.serverOrigin).toString();
    const request = new Request(url, {
      method: "GET",
      headers: {
        Authorization: authorization,
        ...(params.payment ? { "X-PAYMENT": params.payment } : {}),
      },
    });

    try {
      const authResult = await options.dataApiDeps.auth.authorizeBuilderRead({
        request,
        scope: params.scope,
        grantId: params.grantId,
        fileId: params.fileId,
        ...(params.at ? { at: params.at } : {}),
      });
      return { request, authResult };
    } catch (err) {
      if (err instanceof ProtocolError) {
        throw new McpDataReadError(err.code, err.toJSON());
      }
      throw err;
    }
  }

  async function writeReadAccessLog(
    request: Request,
    params: {
      scope: string;
      grantId: string;
      authResult?: BuilderReadAuthorization;
    },
  ): Promise<{
    logId: string;
    timestamp: string;
    ipAddress: string;
    userAgent: string;
  }> {
    const logId = options.dataApiDeps.createLogId?.() ?? crypto.randomUUID();
    const timestamp = (
      options.dataApiDeps.now ?? (() => new Date())
    )().toISOString();
    const ipAddress =
      request.headers.get("x-forwarded-for") ??
      request.headers.get("x-real-ip") ??
      "unknown";
    const userAgent = request.headers.get("user-agent") ?? "unknown";
    await options.dataApiDeps.accessLogWriter.write({
      logId,
      grantId: params.authResult?.grantId ?? params.grantId,
      builder: params.authResult?.builder ?? options.granteeAccount.address,
      action: "read",
      scope: params.scope,
      timestamp,
      ipAddress,
      userAgent,
    });
    return { logId, timestamp, ipAddress, userAgent };
  }

  return {
    enforcesPayment: options.enforcesPayment ?? false,
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

    async getScopeMetadata(scope: string): Promise<McpScopeMetadata | null> {
      const storage = options.dataApiDeps.storage;
      const entry = storage.findEntry({ scope });
      if (!entry) return null;
      // A tombstoned scope is absent for discovery purposes, exactly like a
      // scope with no local copy; the same gate the HTTP read applies.
      if (await resolveReadDeletion(options.dataApiDeps, scope, entry)) {
        return null;
      }
      const hasBlocks =
        typeof storage.hasScopeBlocks === "function"
          ? await storage.hasScopeBlocks(scope, entry.collectedAt)
          : false;
      return {
        scope,
        collectedAt: entry.collectedAt,
        sizeBytes: entry.sizeBytes,
        hasBlocks,
      };
    },

    async readScopeBlocks({
      scope,
      grantId,
      cursor,
      maxBytes,
      payment,
      blockIds,
    }) {
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
      // Before authorizeScopeRead: a payment-enforcing auth port settles
      // x402 there, and deleted data must never be charged for.
      await assertScopeReadable(scope, selectedEntry);

      const { request, authResult } = await authorizeScopeRead({
        scope,
        grantId,
        fileId: selectedEntry.fileId ?? undefined,
        // The exact version this read serves (cursor-pinned or latest) —
        // a payment-enforcing auth port binds the x402 settlement to it.
        at: selectedEntry.collectedAt,
        payment,
      });

      try {
        const result = await storage.readScopeBlocks(
          scope,
          selectedEntry.collectedAt,
          {
            cursor,
            maxBytes: maxBytes ?? 16_384,
            ...(blockIds?.length ? { blockIds } : {}),
          },
        );
        const { logId, timestamp, ipAddress, userAgent } =
          await writeReadAccessLog(request, { scope, grantId, authResult });
        // A block-addressed read serves a hand-picked subset, so it never
        // completes the scope the way an uncursored full read does; reporting
        // fulfillment for it would settle the read on partial data.
        if (
          authResult?.grantId &&
          authResult.builder &&
          !cursor &&
          !blockIds?.length &&
          !result.nextCursor
        ) {
          reportPersonalServerReadFulfillment(options.dataApiDeps, {
            builder: authResult.builder,
            fileId: selectedEntry.fileId ?? undefined,
            grantId: authResult.grantId,
            ipAddress,
            logId,
            scope,
            servedAt: timestamp,
            userAgent,
          });
        }
        return isOwnerView(authResult)
          ? { status: 200, ...result }
          : {
              status: 200,
              ...result,
              blocks: redactBlockPayloadsForGrantee(
                result.blocks,
                await resolveBlockRedactionContext(
                  storage,
                  scope,
                  selectedEntry.collectedAt,
                  result.blocks,
                ),
              ),
            };
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

    async readBlockManifest({ scope, grantId }) {
      const storage = options.dataApiDeps.storage;
      if (!storage.readBlockManifest) return null;

      const selectedEntry = storage.findEntry({ scope });
      if (!selectedEntry) {
        throw new McpDataReadError(404, {
          error: "NOT_FOUND",
          message: `No data found for scope "${scope}"`,
        });
      }
      await assertScopeReadable(scope, selectedEntry);

      const { request, authResult } = await authorizeScopeRead({
        scope,
        grantId,
        fileId: selectedEntry.fileId ?? undefined,
      });
      const manifest = await storage.readBlockManifest(
        scope,
        selectedEntry.collectedAt,
      );
      // Logged like any other grant-gated read, but never reported as a read
      // fulfillment: a table of contents carries no block values.
      await writeReadAccessLog(request, { scope, grantId, authResult });
      if (manifest && !isOwnerView(authResult)) {
        return {
          ...manifest,
          blocks: redactBlockRefsForGrantee(
            manifest.blocks,
            await resolveBlockRedactionContext(
              storage,
              scope,
              selectedEntry.collectedAt,
              manifest.blocks,
            ),
          ),
        };
      }
      return manifest;
    },

    async readRawScopeFile({ scope, grantId, at, fileId, payment }) {
      const storage = options.dataApiDeps.storage;
      const selectedEntry = storage.findEntry({
        scope,
        ...(fileId ? { fileId } : {}),
        ...(at ? { at } : {}),
      });
      if (!selectedEntry) {
        throw new McpDataReadError(404, {
          error: "NOT_FOUND",
          message: `No data found for scope "${scope}"`,
        });
      }

      const safeScope = encodeURIComponent(scope);
      const signingUri = `${basePath}/${safeScope}`;
      const query = new URLSearchParams({ content: "raw" });
      if (fileId) query.set("fileId", fileId);
      if (at) query.set("at", at);
      query.set("grantId", grantId);

      const authorization = await signMcpGranteeRequest({
        account: options.granteeAccount,
        aud: options.serverOrigin,
        method: "GET",
        uri: signingUri,
        grantId,
      });
      const url = new URL(
        `${signingUri}?${query.toString()}`,
        options.serverOrigin,
      ).toString();
      const request = new Request(url, {
        method: "GET",
        headers: {
          Authorization: authorization,
          ...(payment ? { "X-PAYMENT": payment } : {}),
        },
      });

      const response = await handlePersonalServerDataRequest(
        request,
        options.dataApiDeps,
        { basePath },
      );
      if (!response.ok) {
        throw new McpDataReadError(
          response.status,
          await parseJsonOrText(response),
        );
      }

      const mimeType =
        response.headers.get("content-type") ?? "application/octet-stream";
      if (mimeType.includes("application/json")) {
        throw new McpDataReadError(400, {
          error: "NOT_BINARY_SCOPE",
          message: `Scope "${scope}" does not expose raw binary content.`,
        });
      }

      const bytes = new Uint8Array(await response.arrayBuffer());
      const contentDisposition = response.headers.get("content-disposition");
      const metadataHeader = response.headers.get("x-vana-metadata");
      return {
        status: response.status,
        scope,
        collectedAt: selectedEntry.collectedAt,
        fileId: selectedEntry.fileId ?? undefined,
        mimeType,
        filename: filenameFromContentDisposition(contentDisposition),
        sizeBytes: bytes.byteLength,
        contentBase64: bytesToBase64(bytes),
        metadata: parseMetadataHeader(metadataHeader),
      };
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

function filenameFromContentDisposition(
  value: string | null,
): string | undefined {
  if (!value) return undefined;
  const match =
    /filename="([^"]+)"/i.exec(value) ?? /filename=([^;]+)/i.exec(value);
  return match?.[1]?.trim();
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
