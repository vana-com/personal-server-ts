import type { OwnerRecordDeleteResult } from "@opendatalabs/personal-server-ts-core/localdb";
import {
  listPdppRecords,
  resolveOwnerSource,
  localRecord,
  localRecordJson,
  servedRecordJson,
  ownerViewFields,
  createCursorSeal,
  type ServedRow,
  refuseLegacyWrite,
  type LocalRecord,
  type OwnedAccountStorageMode,
  type RecordHistory,
  type RecordListPlan,
} from "@opendatalabs/personal-server-ts-core/api";
import { type RecordQuery } from "@opendatalabs/personal-server-ts-core/localdb";
import { parseRecordQuery } from "./pdpp-record-query.js";
import type { ReplicaReader } from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";
import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import {
  isRfc3339DateTime,
  PdppBindingError,
  type createSqliteRecordStore,
} from "../storage/pdpp-records-sqlite-store.js";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import {
  pdppVersionFailure,
  pdppVersionMiddleware,
  versionedHeaders,
} from "./pdpp-version-negotiation.js";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import type {
  PdppAuthorizationService,
  PdppTokenContext,
  StreamGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  clientHandleFor,
  PdppAuthorizationUnavailableError,
  storedInstanceFor,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";

/**
 * AS item 29: the row as its reader may see it. A client sees its pairwise
 * handle as `instance_id` (and in `fetch_url`); an owner sees stored ids.
 */
function asClientRow<T extends { instance: string }>(
  context: Pick<PdppTokenContext, "tokenKind" | "clientInstanceHandles">,
  row: T,
): T {
  const handle = clientHandleFor(context, row.instance);
  return handle === row.instance ? row : { ...row, instance: handle };
}
import {
  REPLICA_SOURCE_MAX_BLOB_BYTES,
  REPLICA_SOURCE_MAX_RECORD_JSON_BYTES,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import {
  CursorExpiredError,
  InvalidCursorError,
  InvalidCursorSyntaxError,
  recordKeyWithinGrantResources,
  mapInactiveToError,
  recordWithinGrantTimeConstraint,
  resolveReadScope,
  summarizeIngest,
  type IngestOutcome,
  type PdppRecordEnvelopeInput,
  type PdppRecordRow,
  type PdppRecordStore,
  type PdppReplicaReadStore,
  type StreamDeclaration,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createRecordDataValidator } from "../pdpp/record-schema.js";
import {
  StreamCompletionError,
  type StreamCompletionFailure,
} from "../storage/pdpp-stream-completion.js";

export const MAX_BLOB_UPLOAD_BYTES = REPLICA_SOURCE_MAX_BLOB_BYTES;

/** 512 MiB — max body size for PDPP record ingest and replace routes. */
export const MAX_INGEST_BODY_BYTES = REPLICA_SOURCE_MAX_RECORD_JSON_BYTES;
/** 64 KiB of UTF-8 — max body size for the completion metadata route. */
export const MAX_COMPLETION_BODY_BYTES = 64 * 1024;

class CompletionBodyTooLarge extends Error {}

/**
 * Read a completion body, counting the bytes actually received. Unlike
 * `readBoundedBody`, the size decision never consults Content-Length, so an
 * absent or lying header cannot move the limit, and the over-limit answer is
 * a 413 rather than a 400.
 */
async function readCompletionBody(request: Request): Promise<Uint8Array> {
  const reader = request.body?.getReader();
  if (!reader) {
    throw new PdppError("invalid_request", "Completion body is empty");
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_COMPLETION_BODY_BYTES) {
      void reader.cancel().catch(() => undefined);
      throw new CompletionBodyTooLarge();
    }
    chunks.push(value);
  }
  if (size === 0) {
    throw new PdppError("invalid_request", "Completion body is empty");
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

const COMPLETION_BODY_KEYS = [
  "source_id",
  "instance",
  "source_collected_at",
  "collection_time_basis",
  "streams",
];
const COMPLETION_STREAM_KEYS = [
  "stream",
  "coverage",
  "live_count",
  "snapshot_sha256",
];

function hasExactKeys(value: object, keys: string[]): boolean {
  const actual = Object.keys(value);
  return (
    actual.length === keys.length && keys.every((key) => actual.includes(key))
  );
}

/** Store refusals that are the caller's conflict with current state. */
const COMPLETION_CONFLICTS: StreamCompletionFailure[] = [
  "snapshot_conflict",
  "time_conflict",
  "invalid_snapshot_data",
  "invalid_prior_receipt",
];

const BLOB_MEDIA_TYPE =
  /^(application|audio|example|font|haptics|image|message|model|multipart|text|video)\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/i;

function blobMediaType(contentType: string | undefined): string {
  const mediaType = contentType?.split(";", 1)[0]?.trim().toLowerCase();
  if (!mediaType || !BLOB_MEDIA_TYPE.test(mediaType)) {
    throw new PdppError(
      "invalid_request",
      "Content-Type must be a valid media type",
    );
  }
  return mediaType;
}

/**
 * Read a request body of at most `maxBytes`, refusing early on a declared
 * Content-Length over the limit and while streaming otherwise, so an
 * oversize body is never buffered whole.
 */
async function readBoundedBody(
  request: Request,
  maxBytes: number,
  label: "Blob" | "Ingest",
): Promise<Uint8Array> {
  const tooLarge = () =>
    new PdppError(
      "invalid_request",
      `${label} body exceeds the ${maxBytes / (1024 * 1024)} MiB limit`,
    );
  const contentLength = request.headers.get("content-length");
  if (
    contentLength !== null &&
    (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes)
  ) {
    throw tooLarge();
  }
  const reader = request.body?.getReader();
  if (!reader) throw new PdppError("invalid_request", `${label} body is empty`);
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      // Cancellation is best effort; a stalled source must not hold the 400 response.
      void reader.cancel().catch(() => undefined);
      throw tooLarge();
    }
    chunks.push(value);
  }
  if (size === 0)
    throw new PdppError("invalid_request", `${label} body is empty`);
  if (contentLength !== null && size !== Number(contentLength)) {
    throw new PdppError(
      "invalid_request",
      `Content-Length does not match ${label.toLowerCase()} body`,
    );
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function parseIngestBody(bytes: Uint8Array): unknown {
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new PdppError("invalid_request", "Ingest body is not valid JSON");
  }
  if (body === null || typeof body !== "object") {
    throw new PdppError(
      "invalid_request",
      "Ingest body must be a RECORD envelope or an array of envelopes",
    );
  }
  return body;
}

/** The record routes read everything a reader serves except completion receipts. */
type RouteReadStore = Omit<PdppReplicaReadStore, "listStreamCompletions">;

export interface PdppRecordsRouteDeps {
  /** The same owner-bound mode used by the legacy-write seal. */
  accountStorageMode?: OwnedAccountStorageMode;
  /** Host-linked database query; callers pass logical PDPP instance ids. */
  recordQuery?: RecordQuery;
  /** Query-backed frozen snapshots for grant listing and changes. Filter the
   * authorized projection at both horizons, return unprojected rows, and expire
   * when current records cannot answer exactly. No legacy or current-only
   * approximation may substitute for an unavailable historical body. */
  recordHistory?: RecordHistory;
  /** Writes and write-side lookups. Reads go through `reads`. */
  store: PdppRecordStore;
  /**
   * Reader capability for every read. The app host (`createApp`) always
   * supplies it. Absent only when the route runs without a host, in tests:
   * then every token class reads `store`.
   */
  reads?: (reader: ReplicaReader) => RouteReadStore;
  bindingStore?: {
    getInstanceBinding(instance: string): {
      sourceId: string | null;
      deletedAt: string | null;
    };
    storeBlobBytesForInstance(input: {
      instance: string;
      method: string;
      generation: number;
      bytes: Uint8Array;
      mimeType: string;
    }): ReturnType<PdppRecordStore["storeBlobBytes"]>;
    replaceStream: ReturnType<typeof createSqliteRecordStore>["replaceStream"];
    /** Absent on a store that cannot record completion metadata. */
    completeStreams?: ReturnType<
      typeof createSqliteRecordStore
    >["completeStreams"];
  };
  configuredMethods?: Map<string, string[]>;
  auth: PdppAuthorizationService;
  declarations: StreamDeclarationRegistry;
  /** The exact owner of this Personal Server; required for ingest. */
  ownerSubjectId?: string;
  /** Current ownership used to narrow the instance stored in an owner token. */
  instancesForSubject?: (subjectId: string) => string[];
  /** Active connections covered by a source-scoped owner token. */
  instancesForSource?: (subjectId: string, sourceId: string) => string[];
  /** The registered source a connector id names; `source=` accepts it. */
  sourceIdForConnector?: (connector: string) => string | undefined;
  /**
   * Owner access feed. PDPP reads must appear in the SAME feed as legacy
   * `/v1/data/{scope}` reads, or adopting PDPP would silently make an owner's
   * access history less complete than it was before — the one thing a data
   * portability product must not do.
   *
   * Optional so a deployment that has not wired a writer still boots; when it
   * is absent no PDPP read is logged, which `records-bootstrap.ts` makes
   * explicit rather than leaving to chance.
   */
  accessLog?: PdppAccessLogPort;
  /**
   * Vana chain enforcement for client reads. Absent by default, and absence
   * is the chain-NEUTRAL path: a standalone PDPP deployment has no chain, so
   * omitting this leaves the bearer path exactly as it was.
   *
   * When a deployment DOES set it, every client-token read must present a
   * PDPP grant that is bound to a live chain permission. This is the gate the
   * bearer path was missing: a PDPP token alone proved consent, but nothing
   * checked the Vana permission that authorizes the read, so a chain-side
   * revocation had no effect on a PDPP client and the ledger's authority was
   * silently not enforced.
   *
   * It fails closed on purpose — see `PdppChainEnforcementPort`.
   */
  chainEnforcement?: PdppChainEnforcementPort;
  /**
   * Where an `api_error` (500) goes. Optional so a deployment that wires no
   * logger still boots, but without one a genuine server fault on this
   * surface leaves nothing behind but the client's 500 — the exact
   * observability hole that made a missing-file read take a day to diagnose.
   */
  logger?: PdppRouteLogger;
  /**
   * 32-byte key that seals page cursors and `changes_since` tokens (spec-core
   * §4; RS item 21). Hosts pass a persisted key so a stored
   * `next_changes_since` survives a restart; without one the router draws a
   * random key and its tokens stop opening when the process ends.
   */
  cursorSealKey?: Uint8Array;
  /**
   * Owner record delete on a switched account, written as a run that
   * reaches every device (core localdb/owner-delete.ts). Absent: a switched
   * account refuses DELETE with `update_required`.
   */
  switchedDelete?: (input: {
    instance: string;
    stream: string;
    recordKey: string;
  }) => Promise<OwnerRecordDeleteResult>;
}

export interface PdppRouteLogger {
  error(payload: Record<string, unknown>, message: string): void;
}

/**
 * The chain check a client read must pass, when a deployment enforces one.
 *
 * ## Why this is a port and not a direct chain call
 *
 * The route must not import a chain SDK: PDPP Core is chain-neutral, and a
 * deployment with no chain must still serve reads. Keeping the dependency as
 * an injected port is what lets standalone PDPP stay standalone while a Vana
 * deployment enforces the ledger, without two code paths through the route.
 *
 * ## Fail closed, and the three outcomes are NOT interchangeable
 *
 * `authorize` answers one of three things, and the distinction matters
 * because two of them deny while only one of those is worth retrying:
 *
 *   - `{ ok: true }` — a binding exists, the live chain grant is unrevoked,
 *     the owner matches, and the grantee is this client's app.
 *   - `{ ok: false, retryable: false }` — a definite denial. No binding, or
 *     a revoked/mismatched one. The answer will not change by asking again.
 *   - `{ ok: false, retryable: true }` — the chain or gateway could not be
 *     reached, so we do not KNOW the answer.
 *
 * The third case is the one that decides whether this design is honest. Not
 * knowing is not permission. Serving a read because the gateway was down
 * would make an outage into an authorization bypass, and it would do so
 * silently, which is worse than refusing. So an unknown answer denies, and
 * is reported as `503` with `Retry-After` rather than `403`, because the
 * client's grant may be perfectly valid and a permanent-looking refusal
 * would send them to re-consent for no reason.
 *
 * This also means a binding is never accepted as nullable: a deployment that
 * enforces the chain and cannot resolve a grant denies the read. There is no
 * "no binding yet, allow it" state, because that state is indistinguishable
 * from "never bound".
 */
export interface PdppChainEnforcementPort {
  authorize(input: {
    /** The PDPP grant presented by the client token. */
    pdppGrantId: string;
    /** The OAuth client the token was issued to. */
    clientId: string;
  }): Promise<PdppChainDecision>;
}

export type PdppChainDecision =
  { ok: true } | { ok: false; retryable: boolean; reason: string };

/**
 * The slice of the owner access feed a PDPP read can populate.
 *
 * Deliberately narrower than `AccessLogWriter`: this route knows the grant,
 * the client, the stream and the outcome, and nothing about scopes or
 * builders in the legacy sense. Keeping the port small is what lets the
 * bootstrap adapt it onto the existing writer without this module importing
 * the legacy entry shape.
 */
export interface PdppAccessLogPort {
  record(entry: {
    grantId: string;
    clientId: string;
    /** `{source}.{stream}` — the legacy feed's `scope` position. */
    stream: string;
    operation: "read";
    outcome: "completed" | "denied" | "failed";
    requestId: string;
    ipAddress: string;
    userAgent: string;
  }): Promise<void>;
}

function requestId(): string {
  return `req_${randomUUID()}`;
}

/** Maps a thrown store-layer error to the PdppError the spec's Errors table requires. */
function toPdppError(err: unknown): PdppError {
  if (err instanceof PdppError) return err;
  if (err instanceof CursorExpiredError) {
    return new PdppError("cursor_expired", "changes_since cursor has expired");
  }
  // Two distinct classes reach here and both mean "this cursor is not usable":
  // the stores throw `InvalidCursorError` (decoded fine, but wrong order or
  // wrong kind), while `decodeCursor` throws `InvalidCursorSyntaxError` for a
  // token that is not even base64url JSON. Only the first was mapped, so a
  // malformed cursor escaped as an unhandled throw -- a 500 with no PDPP error
  // body, telling a client nothing and looking like a server fault when it was
  // a bad request.
  if (
    err instanceof InvalidCursorError ||
    err instanceof InvalidCursorSyntaxError
  ) {
    return new PdppError(
      "invalid_cursor",
      "Cursor token is malformed, unrecognized, or was reused with a different order",
    );
  }
  // Anything else is our fault, not the client's. Rethrowing sent it past
  // every route-level catch to the framework's generic handler, which
  // answered a body that is not a PDPP error object and knows neither the
  // route nor this request's `Request-Id` — so the line an operator finds in
  // the log could not be tied to the response a client reported. Mapping it
  // here keeps the wire contract intact (§8 Errors: `api_error`, 500) and
  // gives the caller a correlatable id; `logApiError` writes the detail.
  return new PdppError("api_error", "Internal server error");
}

/**
 * The one place an `api_error` is recorded. Structured, and deliberately
 * narrow: route, request id, error code, and the error's own name/message/
 * stack. No Authorization header, no token, no grant, no record body — a
 * resource server's log must not become a second copy of the data it
 * protects, nor a place credentials come to rest.
 */
function logApiError(
  deps: PdppRecordsRouteDeps,
  route: string,
  reqId: string,
  err: unknown,
): void {
  if (!deps.logger) return;
  deps.logger.error(
    {
      route,
      requestId: reqId,
      errorCode: "api_error",
      err:
        err instanceof Error
          ? { name: err.name, message: err.message, stack: err.stack }
          : { message: String(err) },
    },
    "PDPP resource server error",
  );
}

/**
 * Map a thrown error to its PDPP error, logging it first when it is a server
 * fault rather than a client one — a 403 on a revoked grant is normal traffic
 * and must not fill the log. Returns the mapped error so callers can both
 * send it and (on the record routes) record the access-feed outcome from it.
 */
function mapAndLog(
  deps: PdppRecordsRouteDeps,
  route: string,
  reqId: string,
  err: unknown,
): PdppError {
  const mapped = toPdppError(err);
  if (mapped.status === 500 && !(err instanceof PdppError)) {
    logApiError(deps, route, reqId, err);
  }
  return mapped;
}

/**
 * `PdppTokenContext.subjectId` is optional in the real AS contract (it may
 * be absent on an inactive token). By the time route code reaches an
 * owner-token branch the token is already known active, so a missing
 * subjectId here is an AS-side bug, not a client error — fail closed rather
 * than pass `undefined` through to instance-scoping.
 */
function requireSubjectId(context: PdppTokenContext): string {
  if (!context.subjectId) {
    throw new PdppError(
      "authentication_error",
      "Token context is missing subject_id",
    );
  }
  return context.subjectId;
}

function sendError(c: Context, err: PdppError, reqId: string) {
  // Every 401 carries the challenge, whichever branch produced it.
  //
  // Previously only the missing-token branch built one, so a client holding a
  // STALE token -- the exact case §8's challenge exists to bootstrap -- got a
  // bare 401 with no `WWW-Authenticate` and no pointer to the metadata it
  // needed in order to re-authorize. Attaching it here rather than at each
  // call site means a future 401 path cannot forget it.
  const headers = versionedHeaders(c, { "Request-Id": reqId }, PDPP_VERSION);
  if (err instanceof PdppAuthorizationUnavailableError) {
    headers["Retry-After"] = String(err.retryAfterSeconds);
  }
  if (err.status === 503) {
    headers["Retry-After"] ??= "5";
    headers["Cache-Control"] = "no-store";
  }
  if (err.status === 401) {
    headers["WWW-Authenticate"] =
      `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrlFor(c)}"`;
  }
  // A refusal's machine-readable reason, outside the closed §8 error body.
  if (err.reason) headers["PDPP-Refusal-Reason"] = err.reason;
  return c.json(err.toJSON(reqId), err.status as never, headers);
}

/**
 * The RFC 9728 protected-resource metadata URL for THIS request's origin.
 *
 * RFC 9728 §5.1 requires `resource_metadata` to be a URI the client can
 * dereference. A relative path only resolves if the client already knows the
 * origin -- which an unauthenticated client bootstrapping discovery from a
 * failed read cannot be assumed to have. Deriving it from the request also
 * keeps it correct behind a tunnel or proxy, where a hardcoded origin would
 * point the client somewhere it cannot reach.
 */
export function resourceMetadataUrlFor(c: Context): string {
  return new URL(
    "/.well-known/oauth-protected-resource",
    new URL(c.req.url).origin,
  ).toString();
}

/**
 * The blob endpoint beside this router's mount (`<mount>/blobs`), absolute
 * from the request origin, for the `fetch_url` a served `blob_ref` carries
 * (spec-core §4 "Binary data", §8 "Get a blob").
 */
function blobBaseFor(c: Context): string {
  const url = new URL(c.req.url);
  const mount = url.pathname.slice(0, url.pathname.indexOf("/streams/"));
  return `${url.origin}${mount}/blobs`;
}

function unauthorized(c: Context, reqId: string, resourceMetadataUrl: string) {
  const err = new PdppError(
    "authentication_error",
    "Missing or invalid access token",
  );
  return c.json(
    err.toJSON(reqId),
    401,
    versionedHeaders(
      c,
      {
        "Request-Id": reqId,
        "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrl}"`,
      },
      PDPP_VERSION,
    ),
  );
}

export function pdppRecordsRoutes(deps: PdppRecordsRouteDeps): Hono {
  const app = new Hono();
  // Metadata handlers also use the guarded reader. Preserve its typed refusal
  // when it throws outside a record handler's local try/catch.
  app.onError((error, c) => {
    const reqId = requestId();
    return sendError(c, mapAndLog(deps, c.req.path, reqId, error), reqId);
  });
  const validateData = createRecordDataValidator(deps.declarations);
  const cursorSeal = createCursorSeal(deps.cursorSealKey);
  const readsFor = deps.reads ?? (() => deps.store);
  /** The token class selects the reader; request input never does. */
  function reads(context: PdppTokenContext): RouteReadStore {
    const mode = deps.accountStorageMode?.read() ?? "unknown";
    if (mode === "unknown")
      throw new PdppError(
        "ACCOUNT_MODE_UNKNOWN",
        "The account mode is not known yet",
      );
    if (mode === "switched")
      throw new PdppError(
        "STREAM_READ_UNAVAILABLE",
        "This legacy reader is unavailable for a switched account",
      );
    return readsFor(context.tokenKind === "owner" ? "owner" : "grant");
  }

  /** Read the mode once per request. A switched read never uses legacy rows. */
  function localRecords(): RecordQuery | undefined {
    const mode = deps.accountStorageMode?.read() ?? "unknown";
    if (mode === "unknown")
      throw new PdppError(
        "ACCOUNT_MODE_UNKNOWN",
        "The account mode is not known yet",
      );
    if (mode === "unswitched") return undefined;
    if (!deps.recordQuery) {
      throw new PdppError(
        "STREAM_READ_UNAVAILABLE",
        "Local record query is unavailable for a switched account",
      );
    }
    return deps.recordQuery;
  }

  /** The unswitched account's list: legacy rows, read through `reads`. */
  function legacyRecordList(
    context: PdppTokenContext,
    plan: RecordListPlan,
  ): Record<string, unknown> {
    const { stream, scope, instanceIds, query, sort } = plan;
    const { limit, clamped, order, cursor } = query;
    const fields = scope.fields;
    const tokenKind = context.tokenKind === "owner" ? "owner" : "client";
    const meta = clamped
      ? {
          warnings: [
            { code: "limit_clamped", message: "limit clamped to 100" },
          ],
        }
      : undefined;

    if (query.changesSince !== undefined) {
      // Eligibility compares the frozen grant projection (owner: the
      // session's effective `fields`); sparse request fields shape only the
      // response (spec §4: a record whose only change was to an
      // unauthorized field must not appear as "changed" at all). The store
      // returns each row's RAW, unprojected data regardless of `fields` —
      // response-shaping projection happens only at servedRecordJson below,
      // after visibility has run against the real field value. If the store
      // projected the returned data too, a grant whose fields exclude the
      // time_constraint field would silently break that filter.
      //
      // Visibility is evaluated at both horizons for every token kind, so a
      // tombstone is emitted for each record visible at h0 and not at h1, and
      // for no other record (spec-core §4 "Visibility"; RS items 7, 20).
      const page = reads(context).changesSince(stream, {
        instanceIds,
        // spec-core §4 "Starting a sync": `beginning` on every stream.
        changesSince:
          query.changesSince === "beginning" ? undefined : query.changesSince,
        cursor,
        limit,
        order,
        fields:
          context.tokenKind === "owner" ? fields : scope.streamGrant!.fields,
        expireOnErasure: true,
        isVisible: (row: {
          recordKey: string;
          data: Record<string, unknown>;
        }) =>
          recordKeyWithinGrantResources(row.recordKey, scope.streamGrant) &&
          recordWithinGrantTimeConstraint(row.data, scope.streamGrant),
      });
      return {
        object: "list",
        has_more: page.hasMore,
        ...(page.nextCursor && { next_cursor: page.nextCursor }),
        ...(page.nextChangesSince && {
          next_changes_since: page.nextChangesSince,
        }),
        data: page.data.map((row) =>
          servedRecordJson(
            stream,
            asClientRow(context, toServedRow(row)),
            fields,
            tokenKind,
            plan.blobBase,
          ),
        ),
        ...(clamped && { meta }),
      };
    }

    const page = reads(context).listRecords(stream, {
      instanceIds,
      limit,
      order,
      cursor,
      sort,
      // Only a replica preview reader returns removal rows; only the owner
      // may see one.
      isVisible: (row) =>
        recordKeyWithinGrantResources(row.recordKey, scope.streamGrant) &&
        (row.deleted
          ? context.tokenKind === "owner"
          : recordWithinGrantTimeConstraint(row.data, scope.streamGrant)),
    });
    return {
      object: "list",
      has_more: page.hasMore,
      ...(page.nextCursor && { next_cursor: page.nextCursor }),
      data: page.data.map((row) =>
        servedRecordJson(
          stream,
          asClientRow(context, toServedRow(row)),
          fields,
          tokenKind,
          plan.blobBase,
        ),
      ),
      ...(meta && { meta }),
    };
  }

  /** Retain the standalone legacy behaviour when no mode port is supplied. */
  function refuseRecordWrite(reqId: string): Response | null {
    const refusal = refuseLegacyWrite(deps.accountStorageMode);
    if (refusal) {
      refusal.headers.set("Request-Id", reqId);
      refusal.headers.set("PDPP-Version", PDPP_VERSION);
    }
    return refusal;
  }

  /**
   * Append one PDPP read to the owner access feed.
   *
   * Only CLIENT reads are logged. An owner reading their own store is not a
   * third-party access event, and the legacy feed does not record those
   * either — logging them would change what the feed means.
   *
   * Never throws: a feed write that fails must not turn a served read into an
   * error, and must not turn a denial into a 500. Failures are surfaced by
   * the writer's own logging, not by breaking the request.
   */
  async function logClientRead(
    c: Context,
    context: PdppTokenContext | undefined,
    stream: string,
    outcome: "completed" | "denied" | "failed",
    reqId: string,
  ): Promise<void> {
    if (!deps.accessLog) return;
    if (context?.tokenKind !== "client") return;
    const grantId = context.grant?.grant_id;
    const clientId = context.clientId;
    if (!grantId || !clientId) return;

    try {
      await deps.accessLog.record({
        clientId,
        grantId,
        ipAddress:
          c.req.header("x-forwarded-for") ??
          c.req.header("x-real-ip") ??
          "unknown",
        operation: "read",
        outcome,
        requestId: reqId,
        stream,
        userAgent: c.req.header("user-agent") ?? "unknown",
      });
    } catch {
      // Intentionally swallowed; see the doc comment.
    }
  }
  app.use("*", async (c, next) => {
    const reqId = requestId();
    c.set("reqId" as never, reqId as never);
    // Record responses carry personal data: no shared or stored copies.
    c.header("Cache-Control", "private, no-store");
    await next();
  });

  async function authenticate(c: Context, reqId: string) {
    const header = c.req.header("Authorization");
    const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      return { error: unauthorized(c, reqId, resourceMetadataUrlFor(c)) };
    }
    let context;
    try {
      context = await deps.auth.resolveToken(token);
    } catch (error) {
      if (!(error instanceof PdppAuthorizationUnavailableError)) throw error;
      logApiError(deps, "authorization", reqId, error);
      return { error: sendError(c, error, reqId) };
    }

    // Chain enforcement, when the deployment configures it. Placed here so
    // EVERY endpoint is covered by one gate: a check added per-route is a
    // check that a later route forgets, and an unenforced read path is
    // exactly the defect this closes.
    //
    // Only client tokens are gated. An owner token is the owner reading their
    // own data, which no chain permission mediates -- requiring a grantee
    // permission for it would lock owners out of their own server.
    if (deps.chainEnforcement && context?.active) {
      if (context.tokenKind === "client") {
        const grantId = context.grant?.grant_id;
        if (!grantId) {
          // An active client token with no grant cannot be bound to anything,
          // so there is nothing to verify and nothing to allow.
          return {
            error: sendError(
              c,
              new PdppError("grant_revoked", "No chain binding for this grant"),
              reqId,
            ),
          };
        }

        const decision = await deps.chainEnforcement.authorize({
          clientId: context.clientId ?? "",
          pdppGrantId: grantId,
        });

        if (!decision.ok) {
          await logClientRead(c, context, "unknown", "denied", reqId);

          // A retryable failure is NOT reported as a denial. The grant may be
          // perfectly valid and the chain merely unreachable, so answering
          // `grant_revoked` would send a good client off to re-consent over an
          // outage. §8 defines no 503 code and inventing one would be a spec
          // extension, so this maps to `api_error` (500) -- which is honest:
          // the failure is on our side, not in the client's request. The
          // `Retry-After` hint costs nothing and tells a well-behaved client
          // to come back rather than give up.
          if (decision.retryable) {
            c.header("Retry-After", "5");
            return {
              error: sendError(
                c,
                new PdppError(
                  "api_error",
                  "Chain authorization could not be verified",
                ),
                reqId,
              ),
            };
          }
          return {
            error: sendError(
              c,
              new PdppError("grant_revoked", decision.reason),
              reqId,
            ),
          };
        }
      }
    }

    const versionFailure = pdppVersionFailure(c);
    if (versionFailure && context?.active) {
      return { error: sendError(c, versionFailure, reqId) };
    }

    return { context };
  }

  // PDPP-Version negotiation (spec-core §8 "API versioning"). The outcome is
  // recorded here and reported by `authenticate` once the token is active,
  // so an inactive token still gets its 401 first.
  // Registered on this router's own relative paths, not "*": Hono prefixes
  // these with the mount point (/v1 in the product app, /pdpp/v1 in the
  // separated-RS harnesses), whereas "*" mounted at /v1 would also wrap the
  // non-PDPP routers mounted later under /v1 (/v1/data, /v1/grants, …).
  const negotiateVersion = pdppVersionMiddleware(requestId);
  for (const pattern of [
    "/streams",
    "/streams/*",
    "/records/*",
    "/blobs/ingest",
  ]) {
    app.use(pattern, negotiateVersion);
  }

  /**
   * The declaration a read of `stream` is measured against.
   *
   * A client reads under its grant, which names one source. An owner reads
   * only the token's currently owned instance whose source declares the
   * stream. The declaration only answers whether that stream exists;
   * records carry their own shape.
   */
  function readDeclaration(
    context: PdppTokenContext,
    stream: string,
  ): {
    declaration: StreamDeclaration | undefined;
    ownerInstanceIds: string[];
  } {
    if (context.tokenKind !== "owner") {
      return {
        declaration: deps.declarations.get(stream, context.grant?.source.id),
        ownerInstanceIds: [],
      };
    }
    const owned = ownerInstances(context);
    const ownerInstanceIds = owned.filter((instance) =>
      deps.declarations.forInstance(instance, stream),
    );
    const declaration =
      ownerInstanceIds.length > 0
        ? deps.declarations.forInstance(ownerInstanceIds[0], stream)
        : deps.declarations.get(stream);
    return { declaration, ownerInstanceIds };
  }

  /**
   * The connections an owner token may read. A `source` narrows the read and
   * never widens it: a token scoped to one source refuses any other, and a
   * token with no source scope reads only the source the request names.
   */
  function ownerInstances(
    context: PdppTokenContext,
    source?: string,
  ): string[] {
    if (context.tokenKind !== "owner") return [];
    const subject = requireSubjectId(context);
    const requested =
      source === undefined
        ? undefined
        : resolveOwnerSource(source, {
            sourceIdForConnector: (connector) =>
              deps.sourceIdForConnector?.(connector),
          });
    if (context.sourceId) {
      if (requested !== undefined && requested !== context.sourceId) {
        throw new PdppError(
          "grant_stream_not_allowed",
          "Owner token is not scoped to the requested source",
        );
      }
      const current =
        deps.instancesForSource?.(subject, context.sourceId) ?? [];
      if (!context.instanceIds) return current;
      return context.instanceIds.filter((instance) =>
        current.includes(instance),
      );
    }
    if (requested !== undefined) {
      const inSource = deps.instancesForSource?.(subject, requested) ?? [];
      if (!context.instanceIds) return inSource;
      return context.instanceIds.filter((instance) =>
        inSource.includes(instance),
      );
    }
    const current = deps.instancesForSubject?.(subject);
    if (!current) return [];
    if (!context.instanceIds) return [];
    return context.instanceIds.filter((instance) => current.includes(instance));
  }

  function requireRegisteredConnections(instanceIds: string[]): void {
    if (!deps.bindingStore) return;
    if (
      instanceIds.some((instance) => {
        const binding = deps.bindingStore!.getInstanceBinding(instance);
        return binding.sourceId === null || binding.deletedAt !== null;
      })
    ) {
      throw new PdppError(
        "instance_unavailable",
        "The connection for this grant is unavailable",
      );
    }
  }

  /**
   * The instances a single-record read or delete looks in (spec-core §8
   * "Get a single record"). `instance_id` is required when the query context
   * covers more than one instance of the stream, and a missing one is a 400
   * before any lookup; an `instance_id` the context does not cover is 404
   * (RS item 23).
   */
  function selectRecordInstances(
    covered: string[],
    instanceId: string | undefined,
  ): string[] {
    const unique = [...new Set(covered)];
    if (instanceId === undefined) {
      if (unique.length > 1) {
        throw new PdppError(
          "invalid_request",
          "instance_id is required when the query context covers more than one instance of the stream",
          { param: "instance_id" },
        );
      }
      return unique;
    }
    if (!unique.includes(instanceId)) {
      throw new PdppError("not_found", "Record not found");
    }
    return [instanceId];
  }

  app.get("/streams", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;
    // An inactive token gets its 401 before any query validation (spec-core
    // §8: "Every inactive access token produces HTTP 401").
    if (!context?.active) {
      return sendError(c, mapInactiveToError(context!), reqId);
    }
    try {
      parseRecordQuery(c.req.url, "listStreams");
    } catch (err) {
      return sendError(
        c,
        mapAndLog(deps, "GET /v1/streams", reqId, err),
        reqId,
      );
    }
    // An inactive token must report the SAME reason here as on a record read.
    // This branch used to answer a flat `authentication_error` (401) while
    // `/streams/:stream/records` answered `grant_revoked` (403 before the RS item 19 fix; 401 now) for the very
    // same token, so a client could not tell a revoked grant from a bad token
    // depending only on which endpoint it happened to call first. Found by
    // driving Context Gateway's real PdppContextClient against this server.
    if (!context?.active) {
      return sendError(c, mapInactiveToError(context!), reqId);
    }

    const instanceIds =
      context.tokenKind === "owner"
        ? ownerInstances(context)
        : (context.grant?.streams.flatMap((s) => s.instance_ids) ?? []);

    if (context.tokenKind === "owner" && instanceIds.length === 0) {
      return sendError(
        c,
        mapAndLog(
          deps,
          "GET /v1/streams",
          reqId,
          new PdppError(
            "grant_stream_not_allowed",
            "Owner token is not scoped to a currently owned instance",
          ),
        ),
        reqId,
      );
    }

    const localQuery = localRecords();
    if (localQuery) {
      const names =
        context.tokenKind === "owner"
          ? deps.declarations.list().map((d) => d.name)
          : (context.grant?.streams.map((s) => s.name) ?? []);
      const data = [];
      for (const stream of new Set(names)) {
        const { declaration, ownerInstanceIds } = readDeclaration(
          context,
          stream,
        );
        const scope = resolveReadScope(context, stream, declaration);
        let count = 0,
          scanned = 0,
          latest: number | null = null;
        for (const instance of context.tokenKind === "owner"
          ? ownerInstanceIds
          : scope.instanceIds) {
          for await (const row of localQuery.streamRecords(instance, stream)) {
            if (++scanned > STREAM_COUNT_CAP) break;
            const body = JSON.parse(row.body);
            if (
              !recordKeyWithinGrantResources(
                row.recordKey,
                scope.streamGrant,
              ) ||
              !recordWithinGrantTimeConstraint(body, scope.streamGrant)
            )
              continue;
            count++;
            latest = Math.max(latest ?? row.emittedAt, row.emittedAt);
          }
        }
        data.push({
          object: "stream",
          name: stream,
          record_count: scanned > STREAM_COUNT_CAP ? null : count,
          last_updated: latest === null ? null : new Date(latest).toISOString(),
        });
      }
      return c.json({ object: "list", data }, 200, {
        "Request-Id": reqId,
        "PDPP-Version": PDPP_VERSION,
      });
    }
    const streams = reads(context).listStreams(instanceIds);

    // A client token gets a closed projection: only the streams its grant
    // names, and counts/recency computed over only the records the grant
    // actually exposes. The store's raw listing counts every record in the
    // instance, so returning it unchanged would leak the existence and
    // recency of records outside the grant's time_constraint / resources.
    const visibleStreams =
      context.tokenKind === "owner"
        ? streams.map((s) => ({
            name: s.stream,
            confirmation: s.confirmation,
            visibility: s.visibility,
            status: s.status,
            recordCount: s.recordCount as number | null,
            lastUpdated: s.lastUpdated,
            budgetExhausted: false,
          }))
        : streams
            .filter((s) =>
              context.grant?.streams.some((g) => g.name === s.stream),
            )
            .map((s) => {
              const streamGrant = context.grant?.streams.find(
                (g) => g.name === s.stream,
              );
              return {
                name: s.stream,
                confirmation: undefined,
                visibility: undefined,
                status: undefined,
                ...summarizeGrantVisible(
                  reads(context),
                  s.stream,
                  streamGrant?.instance_ids ?? [],
                  streamGrant,
                ),
              };
            });

    // Report truncation explicitly rather than letting a capped count read as
    // exact. `meta.warnings` is the same shape the list endpoint uses for
    // `limit_clamped`.
    const cappedStreams = visibleStreams
      .filter((s) => s.budgetExhausted)
      .map((s) => s.name);

    return c.json(
      {
        object: "list",
        data: visibleStreams.map((s) => ({
          object: "stream",
          name: s.name,
          record_count: s.recordCount,
          last_updated: s.lastUpdated,
          ...(s.confirmation && { confirmation: s.confirmation }),
          ...(s.status && { visibility: s.visibility, status: s.status }),
        })),
        ...(cappedStreams.length > 0 && {
          meta: {
            warnings: [
              {
                code: "record_count_not_counted",
                // Machine-readable: clients must not parse the prose to learn
                // which streams were truncated.
                streams: cappedStreams,
                message: `record_count is null for ${cappedStreams.join(", ")}: more than ${STREAM_COUNT_CAP} grant-visible records, or the scan budget was reached`,
              },
            ],
          },
        }),
      },
      200,
      { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
    );
  });

  app.get("/streams/:stream", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;
    // Every inactive access token gets 401 first (spec-core §8, RS item 19).
    if (!context?.active)
      return sendError(c, mapInactiveToError(context!), reqId);

    try {
      parseRecordQuery(c.req.url, "streamMetadata");
      const stream = c.req.param("stream");
      const { declaration, ownerInstanceIds } = readDeclaration(
        context!,
        stream,
      );
      const scope = resolveReadScope(context!, stream, declaration);

      if (context!.tokenKind === "owner" && ownerInstanceIds.length === 0) {
        throw new PdppError(
          "grant_stream_not_allowed",
          "Owner token is not scoped to a currently owned instance",
        );
      }

      if (context!.tokenKind === "owner") {
        // spec-core §8 "Get stream metadata", owner token: the full current
        // metadata (RS item 14). `cursor_field` is the declared field, not
        // the store's internal emitted-time order. `views` are the retained
        // declaration's views for this stream, which owner reads accept as
        // `view=<id>`. `query` and `relationships` are empty: the §5
        // declaration format this server retains (DeclarationSnapshot in
        // core/src/pdpp/types.ts) carries neither relationships nor query
        // capabilities, and this RS implements no owner range filter or
        // expansion.
        return c.json(
          {
            object: "stream_metadata",
            name: declaration!.name,
            schema: declaration!.schema ?? null,
            primary_key: declaration!.primaryKey,
            ...(declaration!.cursorField !== undefined && {
              cursor_field: declaration!.cursorField,
            }),
            consent_time_field: declaration!.consentTimeField ?? null,
            selection: declaration!.selection ?? null,
            query: {},
            views: declaration!.views ?? [],
            relationships: [],
          },
          200,
          { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
        );
      }

      // spec-core §8 "Get stream metadata", client token: a closed
      // projection of the frozen grant only (RS item 15). The granted fields
      // and, when frozen, `sort_field`; no `cursor_field`, primary key,
      // selection, or current schema, so a declaration change after issuance
      // cannot show through this endpoint.
      const streamGrant = scope.streamGrant!;
      return c.json(
        {
          object: "stream_metadata",
          name: streamGrant.name,
          schema: {
            properties: Object.fromEntries(
              streamGrant.fields.map((field) => [field, {}]),
            ),
          },
          ...(streamGrant.sort_field !== undefined && {
            sort_field: streamGrant.sort_field,
          }),
          query: {},
          views: [],
          relationships: [],
        },
        200,
        { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
      );
    } catch (err) {
      return sendError(
        c,
        mapAndLog(deps, "GET /v1/streams/:stream", reqId, err),
        reqId,
      );
    }
  });

  app.get("/streams/:stream/records", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;
    if (!context?.active)
      return sendError(c, mapInactiveToError(context!), reqId);

    try {
      const stream = c.req.param("stream");
      const result = await listPdppRecords(
        {
          accountMode: deps.accountStorageMode,
          recordQuery: deps.recordQuery,
          recordHistory: deps.recordHistory,
          declarations: deps.declarations,
          ownerInstances,
          requireRegisteredConnections,
          legacy: (plan) => Promise.resolve(legacyRecordList(context!, plan)),
          cursorSeal,
        },
        {
          url: c.req.url,
          stream,
          context: context!,
          prefer: c.req.header("prefer"),
          blobBase: blobBaseFor(c),
        },
      );
      const response = c.json(result.body, 200, {
        "Request-Id": reqId,
        "PDPP-Version": PDPP_VERSION,
      });
      if (result.feed)
        await logClientRead(c, context, stream, "completed", reqId);
      return response;
    } catch (err) {
      const mapped = mapAndLog(
        deps,
        "GET /v1/streams/:stream/records",
        reqId,
        err,
      );
      // A refusal is an access event too: the §7 access feed must show denied
      // attempts, not only successful ones, or an owner cannot see that an
      // app tried to read something it was not granted.
      await logClientRead(
        c,
        context,
        c.req.param("stream"),
        mapped.status === 500 ? "failed" : "denied",
        reqId,
      );
      return sendError(c, mapped, reqId);
    }
  });

  app.get("/streams/:stream/records/:id", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;
    if (!context?.active)
      return sendError(c, mapInactiveToError(context!), reqId);

    try {
      const query = parseRecordQuery(
        c.req.url,
        "getRecord",
        context!.tokenKind,
      );
      const localQuery = localRecords();
      // §8 requires client-token `expand[]` to be REJECTED before the
      // declaration is consulted, on single-record reads as well as lists.
      // Silently ignoring it told a client its request was honored when a
      // narrower thing happened instead.
      const stream = c.req.param("stream");
      // spec-core §4 "Compound key encoding": the RS decodes a path key
      // exactly once. Hono's `param()` has already decoded it, so a second
      // `decodeURIComponent` read `a%2541` as `aA` (RS item 2).
      const recordKey = c.req.param("id");
      const tokenKind = context!.tokenKind === "owner" ? "owner" : "client";
      const scope = resolveReadScope(
        context!,
        stream,
        // Looked up after the client's field check (RS item 32).
        () => readDeclaration(context!, stream).declaration,
        tokenKind === "owner"
          ? (ownerViewFields(
              readDeclaration(context!, stream).declaration,
              query.view,
            ) ?? query.fields)
          : query.fields,
      );
      const { ownerInstanceIds } =
        tokenKind === "owner"
          ? readDeclaration(context!, stream)
          : { ownerInstanceIds: [] };

      // AS item 29: a client names its pairwise handle; resolve it to the
      // stored instance (a handle that is not this client's matches none).
      const effectiveInstanceIds = selectRecordInstances(
        tokenKind === "owner" ? ownerInstanceIds : scope.instanceIds,
        query.instanceId === undefined
          ? undefined
          : storedInstanceFor(context!, query.instanceId),
      );
      if (context!.tokenKind === "client") {
        requireRegisteredConnections(effectiveInstanceIds);
      }

      if (!recordKeyWithinGrantResources(recordKey, scope.streamGrant)) {
        throw new PdppError("not_found", "Record not found");
      }

      if (localQuery) {
        let found: LocalRecord | undefined;
        for (const instance of effectiveInstanceIds) {
          const record = await localQuery.getRecord({
            connectionId: instance,
            stream,
            recordKey,
          });
          if (record) {
            const row = localRecord(instance, record);
            if (recordWithinGrantTimeConstraint(row.data, scope.streamGrant)) {
              found = row;
              break;
            }
          }
        }
        if (!found) throw new PdppError("not_found", "Record not found");
        const response = c.json(
          localRecordJson(
            stream,
            asClientRow(context!, found),
            scope.fields,
            tokenKind,
            blobBaseFor(c),
          ),
          200,
          { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
        );
        await logClientRead(c, context, stream, "completed", reqId);
        return response;
      }

      let found;
      for (const instance of effectiveInstanceIds) {
        const record = reads(context!).getRecord(instance, stream, recordKey);
        if (record) {
          found = record;
          break;
        }
      }
      if (
        !found ||
        (!(found.deleted && context!.tokenKind === "owner") &&
          !recordWithinGrantTimeConstraint(found.data, scope.streamGrant))
      ) {
        throw new PdppError("not_found", "Record not found");
      }

      const response = c.json(
        servedRecordJson(
          stream,
          asClientRow(context!, toServedRow(found)),
          scope.fields,
          tokenKind,
          blobBaseFor(c),
        ),
        200,
        { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
      );
      await logClientRead(c, context, stream, "completed", reqId);
      return response;
    } catch (err) {
      const mapped = mapAndLog(
        deps,
        "GET /v1/streams/:stream/records/:id",
        reqId,
        err,
      );
      await logClientRead(
        c,
        context,
        c.req.param("stream"),
        mapped.status === 500 ? "failed" : "denied",
        reqId,
      );
      return sendError(c, mapped, reqId);
    }
  });

  app.delete("/streams/:stream/records/:id", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;
    // Every inactive access token gets 401 first (spec-core §8, RS item 19).
    if (!context?.active)
      return sendError(c, mapInactiveToError(context!), reqId);

    try {
      const query = parseRecordQuery(c.req.url, "deleteRecord");
      if (context!.tokenKind !== "owner") {
        throw new PdppError(
          "authentication_error",
          "Delete requires an owner token",
        );
      }
      // A §8 endpoint answers the unified error body (RS item 6), not the
      // legacy-write refusal body.
      const mode = deps.accountStorageMode?.read() ?? "unknown";
      if (mode === "unknown")
        throw new PdppError(
          "ACCOUNT_MODE_UNKNOWN",
          "The account mode is not known yet",
        );
      if (mode === "switched") {
        // A switched (stream-sync) account's records travel to the owner's
        // other devices, so a delete is written as a run through the same
        // intake and publication a connector's explicit delete uses
        // (core localdb/owner-delete.ts). A host without that port refuses.
        if (!deps.switchedDelete)
          throw new PdppError(
            "update_required",
            "This server cannot write a delete run for a stream-sync account. Update the Personal Server app, then delete again.",
            { reason: "delete_port_missing" },
          );
        const stream = c.req.param("stream");
        const recordKey = c.req.param("id");
        if (!deps.declarations.declares(stream)) {
          throw new PdppError("not_found", "Stream not found");
        }
        const instances = selectRecordInstances(
          ownerInstances(context!).filter((instance) =>
            deps.declarations.forInstance(instance, stream),
          ),
          query.instanceId,
        );
        for (const instance of instances) {
          const result = await deps.switchedDelete({
            instance,
            stream,
            recordKey,
          });
          if (result.kind === "not_found") continue;
          if (result.kind === "refused")
            throw new PdppError(
              result.retryable ? "STREAM_READ_UNAVAILABLE" : "conflict",
              result.reason,
              { reason: result.code },
            );
          return c.body(null, 204, {
            "Request-Id": reqId,
            "PDPP-Version": PDPP_VERSION,
          });
        }
        throw new PdppError("not_found", "Record not found");
      }
      const stream = c.req.param("stream");
      // Decoded once, by the router (spec-core §4; RS item 2).
      const recordKey = c.req.param("id");
      if (!deps.declarations.declares(stream)) {
        throw new PdppError("not_found", "Stream not found");
      }

      // spec-core §8 "Delete a record": `instance_id` follows the rule for a
      // single-record read (RS item 23).
      const effectiveInstanceIds = selectRecordInstances(
        ownerInstances(context!).filter((instance) =>
          deps.declarations.forInstance(instance, stream),
        ),
        query.instanceId,
      );
      let deletedAny = false;
      for (const instance of effectiveInstanceIds) {
        const declaration = deps.declarations.forInstance(instance, stream);
        if (!declaration) continue;
        if (
          deps.store.deleteRecord(
            instance,
            stream,
            recordKey,
            new Date().toISOString(),
            declaration.semantics,
          )
        ) {
          deletedAny = true;
        }
      }
      if (!deletedAny) throw new PdppError("not_found", "Record not found");
      return c.body(null, 204, {
        "Request-Id": reqId,
        "PDPP-Version": PDPP_VERSION,
      });
    } catch (err) {
      // A connection-state refusal uses the unified §8 error body like every
      // other PDPP error (spec-core §8 "Errors"; RS item 6).
      if (err instanceof PdppBindingError) {
        return sendError(c, new PdppError("conflict", err.reason), reqId);
      }
      return sendError(
        c,
        mapAndLog(deps, "DELETE /v1/streams/:stream/records/:id", reqId, err),
        reqId,
      );
    }
  });

  // Owner-authenticated ingest. Not one of the six §8 read/delete endpoints —
  // this lane's own write path so there is data to serve. Body is a single
  // RECORD envelope or an array of envelopes; the whole call is one
  // ingestBatch invocation (one SQLite transaction on the desktop backend).
  app.post("/streams/:stream/records/ingest", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;

    try {
      if (
        context!.tokenKind !== "owner" ||
        !context!.subjectId ||
        !deps.ownerSubjectId ||
        context!.subjectId.toLowerCase() !== deps.ownerSubjectId.toLowerCase()
      ) {
        throw new PdppError(
          "authentication_error",
          "Ingest requires an owner token",
        );
      }
      if (!context?.active) throw mapInactiveToError(context!);
      const refusal = refuseRecordWrite(reqId);
      if (refusal) return refusal;
      const stream = c.req.param("stream");
      if (!deps.declarations.declares(stream)) {
        throw new PdppError("not_found", "Stream not found");
      }

      const body = parseIngestBody(
        await readBoundedBody(c.req.raw, MAX_INGEST_BODY_BYTES, "Ingest"),
      );
      const method = c.req.query("method");
      const rawGeneration = c.req.query("binding_generation");
      const generation =
        rawGeneration === undefined ? NaN : Number(rawGeneration);
      if (
        deps.bindingStore &&
        (!method || !Number.isSafeInteger(generation) || generation < 1)
      ) {
        throw new PdppError(
          "invalid_request",
          "method and positive binding_generation query parameters are required",
        );
      }
      const entries = Array.isArray(body) ? body : [body];

      // Each entry gets exactly one outcome, by input index. Entries that
      // cannot reach the store are decided here; the rest go to the store in
      // one batch and their outcomes are mapped back to input positions.
      const results: IngestOutcome[] = new Array(entries.length);
      const admitted: { index: number; envelope: PdppRecordEnvelopeInput }[] =
        [];
      const ownedInstances = ownerInstances(context!);
      entries.forEach((entry, index) => {
        if (
          entry === null ||
          typeof entry !== "object" ||
          Array.isArray(entry)
        ) {
          results[index] = {
            index,
            outcome: "rejected",
            reason: "envelope must be a JSON object",
          };
          return;
        }
        const e = entry as Record<string, unknown>;
        if (
          typeof e.instance !== "string" ||
          !ownedInstances.includes(e.instance)
        ) {
          throw new PdppError(
            "authentication_error",
            "Ingest requires an owned instance",
          );
        }
        if (deps.bindingStore && method) {
          const configured = deps.configuredMethods?.get(e.instance) ?? [];
          if (configured.length > 1) {
            throw new PdppBindingError("config_multiple_active_methods");
          }
          if (configured.length !== 1 || configured[0] !== method) {
            throw new PdppBindingError("method_inactive");
          }
        }
        if (!deps.declarations.forInstance(e.instance, stream)) {
          results[index] = {
            index,
            outcome: "rejected",
            reason: `the source of instance '${e.instance}' does not declare stream '${stream}'`,
          };
          return;
        }
        admitted.push({
          index,
          envelope: {
            instance: e.instance,
            stream,
            key: e.key as PdppRecordEnvelopeInput["key"],
            data: (e.data ?? null) as PdppRecordEnvelopeInput["data"],
            emitted_at: e.emitted_at as string,
            op: e.op as PdppRecordEnvelopeInput["op"],
          },
        });
      });

      const declarationFor = (instance: string) =>
        deps.declarations.forInstance(instance, stream)!;
      const stored = deps.store.ingestBatch(
        admitted.map((a) => a.envelope),
        (_stream, instance) => declarationFor(instance).semantics,
        (_stream, instance) => declarationFor(instance).primaryKey,
        deps.bindingStore && method ? { method, generation } : undefined,
        validateData,
      );
      stored.results.forEach((result, position) => {
        const index = admitted[position].index;
        results[index] = { ...result, index };
      });
      const summary = summarizeIngest(results);

      return c.json(
        {
          accepted: summary.accepted,
          unchanged: summary.unchanged,
          rejected: summary.rejected,
          results: summary.results,
        },
        200,
        { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
      );
    } catch (err) {
      if (err instanceof PdppBindingError) {
        return c.json(
          {
            error: { code: err.reason, message: err.reason },
            request_id: reqId,
          },
          409,
          { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
        );
      }
      return sendError(
        c,
        mapAndLog(deps, "POST /v1/streams/:stream/records/ingest", reqId, err),
        reqId,
      );
    }
  });

  // P7, owner-authenticated snapshot replace of one (instance, stream). A
  // Vana PS contract, not Core. Body: `{instance, emitted_at,
  // source_collected_at?, records[]}`; `records` is the complete live set from
  // a covered full refresh by the instance's bound method, and `emitted_at` is
  // the time stamped on the tombstone of each live key the snapshot lacks.
  // `source_collected_at` (RFC 3339) is when the producer collected that set;
  // with it, the replace also stores a completion receipt. One transaction: a
  // binding failure is 409, any rejected record is 422, and neither writes
  // anything.
  // It exists only under method authority, so a server without configured
  // methods does not mount it.
  if (deps.bindingStore) {
    const bindingStore = deps.bindingStore;
    app.post("/streams/:stream/records/replace", async (c) => {
      const reqId = requestId();
      const { context, error } = await authenticate(c, reqId);
      if (error) return error;
      const headers = { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION };

      try {
        if (
          context!.tokenKind !== "owner" ||
          !context!.subjectId ||
          !deps.ownerSubjectId ||
          context!.subjectId.toLowerCase() !== deps.ownerSubjectId.toLowerCase()
        ) {
          throw new PdppError(
            "authentication_error",
            "Replace requires an owner token",
          );
        }
        if (!context?.active) throw mapInactiveToError(context!);
        const refusal = refuseRecordWrite(reqId);
        if (refusal) return refusal;
        const stream = c.req.param("stream");
        if (!deps.declarations.declares(stream)) {
          throw new PdppError("not_found", "Stream not found");
        }
        const method = c.req.query("method");
        const generation = Number(c.req.query("binding_generation") ?? NaN);
        if (!method || !Number.isSafeInteger(generation) || generation < 1) {
          throw new PdppError(
            "invalid_request",
            "method and positive binding_generation query parameters are required",
          );
        }
        const body = parseIngestBody(
          await readBoundedBody(c.req.raw, MAX_INGEST_BODY_BYTES, "Ingest"),
        ) as Record<string, unknown>;
        const {
          instance,
          emitted_at: emittedAt,
          source_collected_at: sourceCollectedAt,
          completion_policy: completionPolicy,
          records,
        } = body;
        if (
          Array.isArray(body) ||
          typeof instance !== "string" ||
          typeof emittedAt !== "string" ||
          !emittedAt ||
          !Array.isArray(records)
        ) {
          throw new PdppError(
            "invalid_request",
            "Replace body must be {instance, emitted_at, records[]}",
          );
        }
        if (
          sourceCollectedAt !== undefined &&
          !isRfc3339DateTime(sourceCollectedAt)
        ) {
          throw new PdppError(
            "invalid_request",
            "source_collected_at must be an RFC 3339 date-time",
          );
        }
        if (
          completionPolicy !== undefined &&
          (completionPolicy !== "preserve_if_unchanged" ||
            sourceCollectedAt !== undefined)
        ) {
          throw new PdppError(
            "invalid_request",
            'completion_policy must be "preserve_if_unchanged" and cannot be sent with source_collected_at',
          );
        }
        const ownedInstances = ownerInstances(context!);
        if (!ownedInstances.includes(instance)) {
          throw new PdppError(
            "authentication_error",
            "Replace requires an owned instance",
          );
        }
        const configured = deps.configuredMethods?.get(instance) ?? [];
        if (configured.length > 1) {
          throw new PdppBindingError("config_multiple_active_methods");
        }
        if (configured.length !== 1 || configured[0] !== method) {
          throw new PdppBindingError("method_inactive");
        }
        const declaration = deps.declarations.forInstance(instance, stream);
        if (!declaration) {
          throw new PdppError("not_found", "Stream not found");
        }
        if (declaration.semantics !== "mutable_state") {
          throw new PdppError(
            "invalid_request",
            "Replace requires a mutable_state stream",
          );
        }

        const result = bindingStore.replaceStream({
          instance,
          stream,
          method,
          generation,
          emittedAt,
          primaryKey: declaration.primaryKey,
          validateData,
          ...(sourceCollectedAt === undefined ? {} : { sourceCollectedAt }),
          ...(completionPolicy === undefined
            ? {}
            : { completionPolicy: "preserve_if_unchanged" as const }),
          envelopes: records.map((entry) => {
            const e = (
              entry !== null && typeof entry === "object" ? entry : {}
            ) as Record<string, unknown>;
            return {
              instance,
              stream,
              key: e.key as PdppRecordEnvelopeInput["key"],
              data: (e.data ?? null) as PdppRecordEnvelopeInput["data"],
              emitted_at: e.emitted_at as string,
              op: e.op as PdppRecordEnvelopeInput["op"],
            };
          }),
        });
        if (!result.applied) {
          return c.json(
            {
              error: {
                type: "invalid_request_error",
                code: "invalid_request",
                message: "Replace rejected; nothing was written",
              },
              rejected: result.rejected,
              request_id: reqId,
            },
            422,
            headers,
          );
        }
        return c.json(
          {
            accepted: result.accepted,
            unchanged: result.unchanged,
            deleted: result.deleted,
            rejected: result.rejected,
            results: result.results,
          },
          200,
          headers,
        );
      } catch (err) {
        if (err instanceof PdppBindingError) {
          return c.json(
            {
              error: { code: err.reason, message: err.reason },
              request_id: reqId,
            },
            409,
            headers,
          );
        }
        return sendError(
          c,
          mapAndLog(
            deps,
            "POST /v1/streams/:stream/records/replace",
            reqId,
            err,
          ),
          reqId,
        );
      }
    });
  }

  // Owner-authenticated completion metadata: "this stream's live set is
  // exactly what the host's full-stream collection saw". It writes only
  // completion receipts (never records, history, arrival or the write
  // clock) and is mounted only over a store that can record them. Authority
  // is the replace route's: an owner token of the server owner, an owned
  // instance, the instance's one configured method. Primary keys come from
  // the loaded declarations, never from the body.
  if (deps.bindingStore?.completeStreams) {
    const bindingStore = deps.bindingStore;
    const completeStreams = deps.bindingStore.completeStreams;
    app.post("/records/completions", async (c) => {
      const reqId = requestId();
      const { context, error } = await authenticate(c, reqId);
      if (error) return error;
      const headers = { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION };

      try {
        if (
          context!.tokenKind !== "owner" ||
          !context!.subjectId ||
          !deps.ownerSubjectId ||
          context!.subjectId.toLowerCase() !== deps.ownerSubjectId.toLowerCase()
        ) {
          throw new PdppError(
            "authentication_error",
            "Completion requires an owner token",
          );
        }
        const refusal = refuseRecordWrite(reqId);
        if (refusal) return refusal;
        const method = c.req.query("method");
        const generation = Number(c.req.query("binding_generation") ?? NaN);
        if (!method || !Number.isSafeInteger(generation) || generation < 1) {
          throw new PdppError(
            "invalid_request",
            "method and positive binding_generation query parameters are required",
          );
        }
        let bytes: Uint8Array;
        try {
          bytes = await readCompletionBody(c.req.raw);
        } catch (err) {
          if (!(err instanceof CompletionBodyTooLarge)) throw err;
          return c.json(
            {
              error: {
                type: "invalid_request_error",
                code: "invalid_request",
                message: `Completion body exceeds the ${MAX_COMPLETION_BODY_BYTES} byte limit`,
                request_id: reqId,
              },
            },
            413,
            headers,
          );
        }
        let body: unknown;
        try {
          body = JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(bytes),
          );
        } catch {
          throw new PdppError(
            "invalid_request",
            "Completion body is not valid JSON",
          );
        }
        const shapeError = () =>
          new PdppError(
            "invalid_request",
            "Completion body must be {source_id, instance, source_collected_at, collection_time_basis, streams[{stream, coverage, live_count, snapshot_sha256}]}",
          );
        if (
          body === null ||
          typeof body !== "object" ||
          Array.isArray(body) ||
          !hasExactKeys(body, COMPLETION_BODY_KEYS)
        ) {
          throw shapeError();
        }
        const wire = body as Record<string, unknown>;
        const streams = wire.streams;
        if (
          typeof wire.source_id !== "string" ||
          typeof wire.instance !== "string" ||
          typeof wire.source_collected_at !== "string" ||
          typeof wire.collection_time_basis !== "string" ||
          !Array.isArray(streams) ||
          streams.length === 0 ||
          // No source declares more streams than the registry holds.
          streams.length > deps.declarations.list().length ||
          !streams.every(
            (entry) =>
              entry !== null &&
              typeof entry === "object" &&
              !Array.isArray(entry) &&
              hasExactKeys(entry, COMPLETION_STREAM_KEYS) &&
              typeof entry.stream === "string" &&
              typeof entry.coverage === "string" &&
              typeof entry.live_count === "number" &&
              typeof entry.snapshot_sha256 === "string",
          )
        ) {
          throw shapeError();
        }

        // Authority. A source-scoped token is for that source alone, and the
        // instance must be one the token currently covers.
        if (context!.sourceId && context!.sourceId !== wire.source_id) {
          throw new PdppError(
            "authentication_error",
            "Completion requires the source of the owner token",
          );
        }
        if (!ownerInstances(context!).includes(wire.instance)) {
          throw new PdppError(
            "authentication_error",
            "Completion requires an owned instance",
          );
        }
        const configured = deps.configuredMethods?.get(wire.instance) ?? [];
        if (configured.length > 1) {
          throw new PdppBindingError("config_multiple_active_methods");
        }
        if (configured.length !== 1 || configured[0] !== method) {
          throw new PdppBindingError("method_inactive");
        }
        if (
          bindingStore.getInstanceBinding(wire.instance).sourceId !==
          wire.source_id
        ) {
          throw new PdppBindingError("source_mismatch");
        }

        const result = completeStreams(
          {
            instance: wire.instance,
            sourceId: wire.source_id,
            method,
            generation,
            sourceCollectedAt: wire.source_collected_at,
            collectionTimeBasis:
              wire.collection_time_basis as "host_run_finished",
            streams: (streams as Record<string, unknown>[]).map((entry) => ({
              stream: entry.stream as string,
              coverage: entry.coverage as "full_stream",
              liveCount: entry.live_count as number,
              snapshotSha256: entry.snapshot_sha256 as string,
            })),
          },
          (sourceId, stream) =>
            deps.declarations.get(stream, sourceId)?.primaryKey,
        );
        return c.json(
          {
            receipts: result.receipts.map((receipt) => ({
              instance: receipt.instance,
              stream: receipt.stream,
              method: receipt.method,
              generation: receipt.generation,
              source_collected_at: receipt.sourceCollectedAt,
              write_seq: receipt.writeSeq,
              live_count: receipt.liveCount,
              snapshot_sha256: receipt.snapshotSha256,
              collection_time_basis: receipt.collectionTimeBasis,
            })),
          },
          200,
          headers,
        );
      } catch (err) {
        if (err instanceof PdppBindingError) {
          return c.json(
            {
              error: { code: err.reason, message: err.reason },
              request_id: reqId,
            },
            409,
            headers,
          );
        }
        if (err instanceof StreamCompletionError) {
          if (COMPLETION_CONFLICTS.includes(err.reason)) {
            return c.json(
              {
                error: { code: err.reason, message: err.reason },
                request_id: reqId,
              },
              409,
              headers,
            );
          }
          if (err.reason !== "invalid_declaration") {
            return sendError(
              c,
              new PdppError("invalid_request", err.reason),
              reqId,
            );
          }
        }
        return sendError(
          c,
          mapAndLog(deps, "POST /v1/records/completions", reqId, err),
          reqId,
        );
      }
    });
  }

  // Owner-authenticated blob ingest, the write half of GET /v1/blobs/:blob_id.
  //
  // The store has always been able to hold blob bytes and the read route has
  // always been able to serve them, but nothing could put bytes in over HTTP:
  // the only writers were in-process test fixtures. So a deployment could
  // implement the whole §8 blob surface and still have no blob for anyone to
  // fetch, which is not a hypothetical -- it is why the conformance suite's
  // three RS-1 blob cases report `skip` against this server today. They need a
  // persisted blob and a record referencing it, and declined to fabricate
  // either.
  //
  // Owner-only for the same reason ingest above is: a client that could upload
  // bytes could plant a blob and then read it back through its own grant.
  // Body is the raw bytes; Content-Type is the declared media type, which is
  // what the read route later serves back.
  app.post("/blobs/ingest", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;

    try {
      if (
        context!.tokenKind !== "owner" ||
        !context!.subjectId ||
        !deps.ownerSubjectId ||
        context!.subjectId.toLowerCase() !==
          deps.ownerSubjectId.toLowerCase() ||
        ownerInstances(context!).length === 0
      ) {
        throw new PdppError(
          "authentication_error",
          "Blob ingest requires an owner token",
        );
      }
      const mimeType = blobMediaType(c.req.header("content-type"));
      const instance = c.req.query("instance");
      const method = c.req.query("method");
      const rawGeneration = c.req.query("binding_generation");
      const generation =
        rawGeneration === undefined ? NaN : Number(rawGeneration);
      if (
        deps.bindingStore &&
        (!instance || !ownerInstances(context!).includes(instance))
      ) {
        throw new PdppError(
          "authentication_error",
          "Blob ingest requires an owned instance",
        );
      }
      if (
        deps.bindingStore &&
        (!method || !Number.isSafeInteger(generation) || generation < 1)
      ) {
        throw new PdppError(
          "invalid_request",
          "instance, method, and positive binding_generation query parameters are required",
        );
      }
      if (deps.bindingStore && method) {
        const configured = deps.configuredMethods?.get(instance!) ?? [];
        if (configured.length > 1) {
          throw new PdppBindingError("config_multiple_active_methods");
        }
        if (configured.length !== 1 || configured[0] !== method) {
          throw new PdppBindingError("method_inactive");
        }
      }
      const bytes = await readBoundedBody(
        c.req.raw,
        MAX_BLOB_UPLOAD_BYTES,
        "Blob",
      );

      const meta =
        deps.bindingStore && method
          ? deps.bindingStore.storeBlobBytesForInstance({
              instance: instance!,
              method,
              generation,
              bytes,
              mimeType,
            })
          : deps.store.storeBlobBytes(bytes, mimeType);
      return c.json(
        {
          blob_id: meta.blobId,
          mime_type: meta.mimeType,
          size_bytes: meta.sizeBytes,
          sha256: meta.sha256,
        },
        200,
        { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
      );
    } catch (err) {
      if (err instanceof PdppBindingError) {
        return c.json(
          {
            error: { code: err.reason, message: err.reason },
            request_id: reqId,
          },
          409,
          { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
        );
      }
      return sendError(
        c,
        mapAndLog(deps, "POST /v1/blobs/ingest", reqId, err),
        reqId,
      );
    }
  });

  return app;
}

/**
 * How many grant-visible records a client-token stream listing will count
 * before it stops counting and says so.
 *
 * `GET /v1/streams` is a metadata endpoint, and the grant predicate cannot be
 * pushed into the store today (`time_constraint` is evaluated in JS against
 * each record's data), so an exact count costs a full scan plus a JSON parse
 * per row. Letting that run unbounded makes the cheap metadata call strictly
 * more expensive than the data call it summarizes — a request-amplification
 * lever, multiplied by the number of streams in the grant.
 *
 * So the count is capped. Past the cap the response reports `record_count:
 * null` and a `meta.warnings` entry rather than a confidently wrong number:
 * an approximate count presented as exact is worse than an explicit "not
 * counted", because a client cannot tell it was truncated.
 */
const STREAM_COUNT_CAP = 1_000;

/**
 * Rows either walk may scan before giving up, shared across both walks.
 *
 * The budget is in ROWS, not pages. An earlier version bounded the count walk
 * at 1000 *pages* of 100 rows — 100,000 rows — which made a filtering grant
 * the slow path: a `time_constraint` excluding the newest records forced the
 * `last_updated` walk through every page looking for its first visible row.
 * Measured 25s at 100k rows and 38s at 150k, against 137ms for an
 * all-visible grant at 60k. One request, a normal grant, a time window
 * excluding recent records.
 */
const STREAM_SCAN_ROW_BUDGET = 10_000;

interface GrantVisibleSummary {
  /**
   * Exact count, or null when the scan budget ran out first. Null means
   * "more than we were willing to count", never "unknown" or "error".
   */
  recordCount: number | null;
  /** Newest grant-visible record, or null if none was found within budget. */
  lastUpdated: string | null;
  /** True when either walk hit the budget, so the summary is incomplete. */
  budgetExhausted: boolean;
}

/**
 * Summarize the records a grant exposes in one stream, for a client-token
 * stream listing.
 *
 * Both walks are bounded by the same row budget, because both are adversarial
 * in the same way: the grant decides which rows are visible, so a grant that
 * hides the newest records makes `last_updated` expensive exactly as a grant
 * with many visible records makes the count expensive. Neither may turn a
 * metadata call into a full scan.
 *
 * When a walk exhausts its budget the caller reports null plus a warning. A
 * confident `0`/`null` after an incomplete scan would be indistinguishable
 * from a genuinely empty grant, which is the failure this bound exists to
 * avoid.
 *
 * Rows stay unprojected throughout: the `time_constraint` must be evaluated
 * against the record's real value, not a projected one.
 */
function summarizeGrantVisible(
  store: Pick<PdppReplicaReadStore, "listRecords">,
  stream: string,
  instanceIds: string[],
  streamGrant: StreamGrant | undefined,
): GrantVisibleSummary {
  // A pending removal has no current grant-visible value to summarize.
  const visible = (row: PdppRecordRow) =>
    !row.deleted &&
    recordKeyWithinGrantResources(row.recordKey, streamGrant) &&
    recordWithinGrantTimeConstraint(row.data, streamGrant);

  // Newest-first until the first visible row: that row's emittedAt is the
  // grant-visible `last_updated`, and usually it is on the first page.
  let lastUpdated: string | null = null;
  let cursor: string | undefined;
  let scanned = 0;
  let lastUpdatedExhausted = true;
  outer: while (scanned < STREAM_SCAN_ROW_BUDGET) {
    const page = store.listRecords(stream, {
      instanceIds,
      limit: 100,
      order: "desc",
      cursor,
    });
    for (const row of page.data) {
      scanned++;
      if (visible(row)) {
        lastUpdated = row.emittedAt;
        lastUpdatedExhausted = false;
        break outer;
      }
    }
    if (!page.hasMore || !page.nextCursor) {
      // Reached the end of the stream: "no visible rows" is a real answer,
      // not a truncated one.
      lastUpdatedExhausted = false;
      break;
    }
    cursor = page.nextCursor;
  }

  // Count forward, stopping at the cap or the budget, whichever comes first.
  let count = 0;
  let capped = false;
  let countExhausted = false;
  scanned = 0;
  cursor = undefined;
  for (;;) {
    const page = store.listRecords(stream, {
      instanceIds,
      limit: 100,
      order: "asc",
      cursor,
    });
    for (const row of page.data) {
      scanned++;
      if (visible(row)) count++;
      if (count > STREAM_COUNT_CAP) {
        capped = true;
        break;
      }
      if (scanned >= STREAM_SCAN_ROW_BUDGET) {
        // Budget spent before the cap: we cannot claim this count is exact.
        countExhausted = true;
        break;
      }
    }
    if (capped || countExhausted || !page.hasMore || !page.nextCursor) break;
    cursor = page.nextCursor;
  }

  const incomplete = capped || countExhausted || lastUpdatedExhausted;
  return {
    recordCount: capped || countExhausted ? null : count,
    lastUpdated,
    budgetExhausted: incomplete,
  };
}

/** A store row in the shape `servedRecordJson` serves (spec-core §4). */
function toServedRow(row: PdppRecordRow): ServedRow {
  return row.deleted
    ? {
        instance: row.instance,
        recordKey: row.recordKey,
        deleted: true,
        deletedAt: row.deletedAt,
        emittedAt: row.emittedAt,
        ...(row.removal && { removal: row.removal }),
        confirmation: row.confirmation,
        visibility: row.visibility,
        status: row.status,
      }
    : {
        instance: row.instance,
        recordKey: row.recordKey,
        data: row.data,
        emittedAt: row.emittedAt,
        confirmation: row.confirmation,
        visibility: row.visibility,
        status: row.status,
      };
}
