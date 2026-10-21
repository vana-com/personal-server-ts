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
import {
  decodeDataBlockCursor,
  encodeDataBlockCursor,
} from "../storage/blocks/index.js";
import { bytesToBase64, parseMetadataHeader } from "../contracts/binary.js";
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
import { authorizeLegacyRead } from "../policy/data-read.js";
import { granteeReadPort } from "../storage/disclosure-policy.js";
import type { IndexEntry } from "../storage/index/types.js";

import {
  resolveBlockRedactionContext,
  redactBlockRefsForGrantee,
  redactBlockPayloadsForGrantee,
} from "../storage/blocks/redaction.js";
import { blockRepresentationId } from "../storage/blocks/representation.js";

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
   * read; it does not return scope contents. The listing only shows scopes
   * the signed `grantId` covers (absent: the owner's grants to the grantee).
   */
  listScopes(params?: {
    scopePrefix?: string;
    limit?: number;
    offset?: number;
    grantId?: string;
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
   * returned, cursor positions are ignored but version/layout binding is
   * checked, and no `nextCursor` is produced. `maxBytes` is a UTF-8 content
   * budget; a 1–3 byte budget may emit one whole code point (up to 4 bytes).
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
    /** MCP tool the read came from, stamped onto the served access record. */
    tool?: string;
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
  }): Promise<McpBlockManifest | null>;

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

/**
 * A table of contents with the cursor that pins its version. Pass
 * `versionCursor` as `cursor` with `blockIds` so the selected blocks come
 * from this version, or the read is refused.
 */
export type McpBlockManifest = DataBlockManifest & { versionCursor?: string };

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
  // Every body this client returns goes to a grantee.
  const granteeStorage = granteeReadPort(options.dataApiDeps.storage);

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
    /** A block manifest read: no values, so never charged. */
    metadataOnly?: boolean;
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
        ...(params.metadataOnly ? { metadataOnly: true } : {}),
      });
      return { request, authResult };
    } catch (err) {
      if (err instanceof ProtocolError) {
        throw new McpDataReadError(err.code, err.toJSON());
      }
      throw err;
    }
  }

  /**
   * Early refusal of a version whose row is known to be PDPP. This client
   * reads only as a grantee (see the header), so it runs before
   * `authorizeScopeRead` may settle payment, right after the deletion gate,
   * in the same order as `/v1/data`. The blocks themselves are read through
   * `granteeStorage`, which decides on what it actually read.
   */
  function authorizeGranteeVersion(entry: Pick<IndexEntry, "pdppOrigin">) {
    try {
      authorizeLegacyRead("grantee", { kind: "indexed-version", entry });
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
    async listScopes({ scopePrefix, limit, offset, grantId } = {}) {
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
      tool,
    }) {
      const storage = granteeStorage;
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
      authorizeGranteeVersion(selectedEntry);
      // A cursor (from a page or a table of contents) names the version the
      // logical read started on. Refused before payment when the selected
      // row is another version.
      const cursorGeneration = generationFromCursor(scope, cursor);
      if (selectedEntry.generation !== undefined) {
        assertSameVersion(scope, cursorGeneration, selectedEntry.generation);
      }

      try {
        // Backfill is a storage write: the owner's port does it.
        const pinned = pinnedVersion(
          scope,
          await establishVersion(options.dataApiDeps.storage, selectedEntry),
        );
        const generation = pinned.generation;
        assertSameVersion(scope, cursorGeneration, generation);
        // Scope admission is uncharged. Establish the immutable served representation before settlement.
        const admission = await authorizeScopeRead({
          scope,
          grantId,
          fileId: selectedEntry.fileId ?? undefined,
          at: selectedEntry.collectedAt,
          metadataOnly: true,
        });
        if (cursor && !isOwnerView(admission.authResult)) {
          const decoded = decodeDataBlockCursor(cursor);
          if (!decoded.ok || !decoded.cursor.representationId) {
            throw new McpDataReadError(409, {
              error: "VERSION_CHANGED",
              reason: "representation_mismatch",
              scope,
              message:
                "This cursor has no block representation identity. Restart without a cursor.",
            });
          }
        }
        const blockStorage = isOwnerView(admission.authResult)
          ? options.dataApiDeps.storage
          : storage;
        const read = await blockStorage.readScopeBlocks!(
          scope,
          selectedEntry.collectedAt,
          {
            cursor,
            maxBytes: maxBytes ?? 16_384,
            ...(blockIds?.length ? { blockIds } : {}),
            // Pin the version authorized above: the view serves only its
            // bytes, never a version published later at the same path.
            generation,
            representation: isOwnerView(admission.authResult)
              ? "stored"
              : "grantee",
          },
        );
        // The next page continues this version only.
        const result = read.nextCursor
          ? { ...read, nextCursor: cursorFor(read.nextCursor, pinned) }
          : read;
        const { request, authResult } = await authorizeScopeRead({
          scope,
          grantId,
          fileId: selectedEntry.fileId ?? undefined,
          // The exact version this read serves (cursor-pinned or latest) —
          // a payment-enforcing auth port binds the x402 settlement to it.
          at: selectedEntry.collectedAt,
          payment,
        });

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
            outcome: "served",
            scope,
            servedAt: timestamp,
            source: "mcp",
            ...(tool ? { tool } : {}),
            userAgent,
          });
        }
        return isOwnerView(authResult) || result.representationId !== undefined
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
        if (err instanceof McpDataReadError) throw err;
        if (err instanceof Error) {
          const code = dataBlockStorageErrorCode(err);
          const status =
            code === "representation_mismatch"
              ? 409
              : code === "cursor_invalid"
                ? 400
                : 503;
          throw new McpDataReadError(status, {
            error:
              code === "representation_mismatch"
                ? "VERSION_CHANGED"
                : code === "cursor_invalid"
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
      const storage = granteeStorage;
      if (!storage.readBlockManifest) return null;

      const selectedEntry = storage.findEntry({ scope });
      if (!selectedEntry) {
        throw new McpDataReadError(404, {
          error: "NOT_FOUND",
          message: `No data found for scope "${scope}"`,
        });
      }
      await assertScopeReadable(scope, selectedEntry);
      authorizeGranteeVersion(selectedEntry);

      let manifest;
      let admission: Awaited<ReturnType<typeof authorizeScopeRead>>;
      let pinned: PinnedVersion;
      try {
        pinned = pinnedVersion(
          scope,
          await establishVersion(options.dataApiDeps.storage, selectedEntry),
        );
        admission = await authorizeScopeRead({
          scope,
          grantId,
          fileId: selectedEntry.fileId ?? undefined,
          at: selectedEntry.collectedAt,
          metadataOnly: true,
        });
        const manifestStorage = isOwnerView(admission.authResult)
          ? options.dataApiDeps.storage
          : storage;
        manifest = await manifestStorage.readBlockManifest!(
          scope,
          selectedEntry.collectedAt,
          { generation: pinned.generation },
        );
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw new McpDataReadError(err.code, err.toJSON());
        }
        throw err;
      }
      const { request, authResult } = admission;
      // Logged like any other grant-gated read, but never reported as a read
      // fulfillment: a table of contents carries no block values.
      await writeReadAccessLog(request, { scope, grantId, authResult });
      if (!manifest) return manifest;
      // Selection by these block ids reads this version only when the
      // caller passes this cursor with them.
      const versionCursor = cursorFor(
        encodeDataBlockCursor({
          scope,
          collectedAt: selectedEntry.collectedAt,
          blockIndex: 0,
          representationId:
            manifest.representationId ??
            blockRepresentationId(
              manifest,
              isOwnerView(authResult) ? "stored" : "grantee",
              manifest.cursorView,
            ),
          ...(manifest.cursorView ? { view: manifest.cursorView } : {}),
        }),
        pinned,
      );
      if (!isOwnerView(authResult)) {
        return {
          ...manifest,
          versionCursor,
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
      return { ...manifest, versionCursor };
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

/** The generation a cursor was issued for, when it names one. */
function generationFromCursor(
  scope: string,
  cursor: string | undefined,
): string | undefined {
  if (!cursor) return undefined;
  const decoded = decodeDataBlockCursor(cursor);
  if (!decoded.ok || decoded.cursor.scope !== scope) return undefined;
  return decoded.cursor.generation;
}

/** Refuse a cursor issued for another version than the one selected. */
function assertSameVersion(
  scope: string,
  cursorGeneration: string | undefined,
  generation: string | undefined,
): void {
  if (cursorGeneration === undefined || cursorGeneration === generation) {
    return;
  }
  throw new McpDataReadError(409, {
    error: "VERSION_CHANGED",
    message:
      "The version this cursor reads was replaced. Start the read again without the cursor.",
    scope,
    reason: "generation_mismatch",
  });
}

declare const PINNED: unique symbol;

/**
 * The version a logical read is pinned to. Only `establishVersion` makes
 * one, so a cursor (which needs one) cannot name no version.
 */
type PinnedVersion = { readonly generation: string; readonly [PINNED]: true };

type VersionIdentity =
  | { ok: true; version: PinnedVersion }
  | { ok: false; reason: "identity_unavailable" };

/**
 * Establish the generation a logical read pins: the row's, or for a row
 * from before rows recorded one, the value storage backfills from the
 * published bytes. Fails explicitly when storage cannot establish it, for
 * example when the row was replaced while it was being backfilled.
 */
async function establishVersion(
  // Only storage's own backfill: never a body read.
  storage: Pick<PersonalServerDataApiDeps["storage"], "backfillGeneration">,
  entry: IndexEntry,
): Promise<VersionIdentity> {
  const generation =
    entry.generation ?? (await storage.backfillGeneration?.(entry));
  return generation
    ? { ok: true, version: { generation } as PinnedVersion }
    : { ok: false, reason: "identity_unavailable" };
}

/** The pinned version, or a retryable refusal: never an unpinned read. */
function pinnedVersion(
  scope: string,
  identity: VersionIdentity,
): PinnedVersion {
  if (identity.ok) return identity.version;
  throw new McpDataReadError(409, {
    error: "VERSION_CHANGED",
    message: "The version changed while this read started. Retry the read.",
    scope,
    reason: identity.reason,
    retryable: true,
  });
}

/** A cursor that also names the version it reads. */
function cursorFor(cursor: string, version: PinnedVersion): string {
  const decoded = decodeDataBlockCursor(cursor);
  if (!decoded.ok) {
    throw new Error("Storage returned a cursor that does not decode");
  }
  const { version: _version, ...fields } = decoded.cursor;
  return encodeDataBlockCursor({ ...fields, generation: version.generation });
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
