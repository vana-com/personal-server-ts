import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppBindingError } from "../storage/pdpp-records-sqlite-store.js";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import type {
  PdppAuthorizationService,
  PdppTokenContext,
  StreamGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  CursorExpiredError,
  encodeCursor,
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
  type StreamDeclaration,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
export const MAX_BLOB_UPLOAD_BYTES = 32 * 1024 * 1024;
/**
 * Desktop caps one connector run's captured records at 32 MiB, and it sends
 * one record per ingest request. JSON escaping can grow a record's encoded
 * size, so the limit leaves room above the capture cap rather than matching it.
 */
export const MAX_INGEST_BODY_BYTES = 64 * 1024 * 1024;

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

export interface PdppRecordsRouteDeps {
  store: PdppRecordStore;
  bindingStore?: {
    storeBlobBytesForInstance(input: {
      instance: string;
      method: string;
      generation: number;
      bytes: Uint8Array;
      mimeType: string;
    }): ReturnType<PdppRecordStore["storeBlobBytes"]>;
  };
  configuredMethods?: Map<string, string[]>;
  auth: PdppAuthorizationService;
  declarations: StreamDeclarationRegistry;
  /** The exact owner of this Personal Server; required for ingest. */
  ownerSubjectId?: string;
  /**
   * Resolves every instance_id owned by a subject, for owner-token
   * current-capability reads (which carry no grant, so the effective
   * instance scope is "everything this subject owns"). A minimal seam —
   * the real ownership registry is out of this lane's scope (it likely
   * lives with source-declaration/connection bookkeeping) so this defaults
   * to "the store already only contains one owner's data" when omitted.
   */
  instancesForSubject?: (subjectId: string) => string[];
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
  const headers: Record<string, string> = {
    "Request-Id": reqId,
    "PDPP-Version": PDPP_VERSION,
  };
  if (err.status === 401) {
    headers["WWW-Authenticate"] =
      `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrlFor(c)}"`;
  }
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

function unauthorized(c: Context, reqId: string, resourceMetadataUrl: string) {
  const err = new PdppError(
    "authentication_error",
    "Missing or invalid access token",
  );
  return c.json(err.toJSON(reqId), 401, {
    "Request-Id": reqId,
    "PDPP-Version": PDPP_VERSION,
    "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrl}"`,
  });
}

function parseLimit(raw: string | undefined): {
  limit: number;
  clamped: boolean;
} {
  if (!raw) return { limit: DEFAULT_LIMIT, clamped: false };
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new PdppError("invalid_request", "limit must be a positive integer", {
      param: "limit",
    });
  }
  if (parsed > MAX_LIMIT) return { limit: MAX_LIMIT, clamped: true };
  return { limit: parsed, clamped: false };
}

function parseOrder(raw: string | undefined): "asc" | "desc" {
  if (raw === undefined) return "desc";
  if (raw === "asc" || raw === "desc") return raw;
  throw new PdppError("invalid_request", "order must be 'asc' or 'desc'", {
    param: "order",
  });
}

/** Query parameters implemented by each endpoint. Unsupported shapes must fail. */
const KNOWN_QUERY_PARAMS: Record<string, readonly string[]> = {
  listStreams: [],
  streamMetadata: [],
  listRecords: ["limit", "order", "cursor", "fields", "changes_since"],
  getRecord: ["fields"],
  deleteRecord: [],
};

/** Validate exact parameter names before consulting serving metadata. */
function rejectUnknownParams(
  c: Context,
  endpoint: keyof typeof KNOWN_QUERY_PARAMS,
  tokenKind?: PdppTokenContext["tokenKind"],
) {
  const allowed = KNOWN_QUERY_PARAMS[endpoint];
  const recordRead = endpoint === "listRecords" || endpoint === "getRecord";
  for (const key of new URL(c.req.url).searchParams.keys()) {
    if (allowed.includes(key)) continue;
    const base = key.replace(/\[.*$/, "");
    // Current serving metadata declares no expandable relations. Client
    // requests must still receive invalid_request, before metadata lookup.
    if (
      recordRead &&
      tokenKind === "owner" &&
      (base === "expand" || base === "expand_limit")
    ) {
      throw new PdppError(
        "invalid_expand",
        "No expandable relation is declared",
        {
          param: key,
        },
      );
    }
    throw new PdppError(
      "invalid_request",
      `Unsupported query parameter '${key}'`,
      {
        param: key,
      },
    );
  }
}

/**
 * Narrow a client's requested `fields` within what its grant already allows.
 *
 * Three rules, in order:
 *   - a field outside the grant is a 400, not a silent drop. A client asking
 *     for something it was never granted has made an error it needs to see;
 *     quietly returning less would let it believe it received that field.
 *   - the result is the intersection, so a request can only ever narrow.
 *   - under a v0.1 grant ONLY, the declaration's required fields are re-added,
 *     because v0.1 §8 keeps schema-required fields in every projection
 *     regardless of the request. A v0.2 grant gets the bare intersection:
 *     `v0.2-4-2` builds disclosed `data` from only the members permitted by
 *     the grant AND the request-time selection, and `v0.2-4-1` forbids adding
 *     one back because the schema requires it. Re-widening a sparse v0.2
 *     request would disclose more than both the owner and the client asked
 *     for, which is the one direction this function must never move.
 *
 * Returns the full granted set when no `fields` was requested, preserving the
 * existing default.
 */
function narrowClientFields(
  requested: string[] | undefined,
  granted: string[] | undefined,
  declaration: StreamDeclaration | undefined,
  schemaRequiredFloor: boolean,
): string[] | undefined {
  if (!requested || requested.length === 0) return granted;
  if (!granted) return requested;

  const grantedSet = new Set(granted);
  for (const field of requested) {
    if (!grantedSet.has(field)) {
      throw new PdppError(
        "invalid_request",
        `Field '${field}' is not in this grant's authorized fields for the stream`,
        { param: "fields" },
      );
    }
  }

  const narrowed = new Set(requested.filter((f) => grantedSet.has(f)));
  if (schemaRequiredFloor) {
    // v0.1 only: the consent floor survives a sparse request.
    for (const required of declaration?.requiredFields ?? []) {
      if (grantedSet.has(required)) narrowed.add(required);
    }
  }
  return Array.from(narrowed);
}

/**
 * Project a declared JSON Schema down to exactly the granted fields.
 *
 * A client token must not learn that a field exists outside its grant, so
 * `properties` is filtered rather than passed through, and `required` is
 * intersected. Without a declared schema this degrades to bare property names
 * — the previous behavior — rather than inventing structure.
 */
function projectSchemaToFields(
  schema: Record<string, unknown> | undefined,
  fields: string[] | undefined,
): Record<string, unknown> {
  const allowed = new Set(fields ?? []);
  if (!schema) {
    return {
      properties: Object.fromEntries([...allowed].map((f) => [f, {}])),
    };
  }

  const properties = (schema.properties ?? {}) as Record<string, unknown>;
  const required = Array.isArray(schema.required)
    ? (schema.required as string[]).filter((f) => allowed.has(f))
    : [];

  return {
    ...schema,
    properties: Object.fromEntries(
      Object.entries(properties).filter(([name]) => allowed.has(name)),
    ),
    ...(required.length > 0 ? { required } : { required: [] }),
  };
}

export function pdppRecordsRoutes(deps: PdppRecordsRouteDeps): Hono {
  const app = new Hono();

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
    await next();
  });

  async function authenticate(c: Context, reqId: string) {
    const header = c.req.header("Authorization");
    const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      return { error: unauthorized(c, reqId, resourceMetadataUrlFor(c)) };
    }
    const context = await deps.auth.resolveToken(token);

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

    return { context };
  }

  // PDPP-Version negotiation: only PDPP_VERSION is supported in v0.1.
  app.use("*", async (c, next) => {
    const requested = c.req.header("PDPP-Version");
    if (requested && requested !== PDPP_VERSION) {
      const reqId = requestId();
      const err = new PdppError(
        "unsupported_version",
        `Unsupported PDPP-Version '${requested}'`,
      );
      return sendError(c, err, reqId);
    }
    await next();
  });

  /**
   * The declaration a read of `stream` is measured against.
   *
   * A client reads under its grant, which names one source. An owner reads
   * every owned instance whose source declares the stream; `ownerInstanceIds`
   * is that set, so an owner read of a shared name never reaches an instance
   * of a source that does not declare it. For an owner read the declaration
   * only answers "does this stream exist"; records carry their own shape.
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
    const owned = deps.instancesForSubject?.(requireSubjectId(context)) ?? [];
    const ownerInstanceIds = owned.filter((instance) =>
      deps.declarations.forInstance(instance, stream),
    );
    const declaration =
      ownerInstanceIds.length > 0
        ? deps.declarations.forInstance(ownerInstanceIds[0], stream)
        : deps.declarations.get(stream);
    return { declaration, ownerInstanceIds };
  }

  app.get("/streams", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;
    try {
      rejectUnknownParams(c, "listStreams");
    } catch (err) {
      return sendError(
        c,
        mapAndLog(deps, "GET /v1/streams", reqId, err),
        reqId,
      );
    }
    // An inactive token must report the SAME reason here as on a record read.
    // This branch used to answer a flat `authentication_error` (401) while
    // `/streams/:stream/records` answered `grant_revoked` (403) for the very
    // same token, so a client could not tell a revoked grant from a bad token
    // depending only on which endpoint it happened to call first. Found by
    // driving Context Gateway's real PdppContextClient against this server.
    if (!context?.active) {
      return sendError(c, mapInactiveToError(context!), reqId);
    }

    const instanceIds =
      context.tokenKind === "owner"
        ? (deps.instancesForSubject?.(requireSubjectId(context)) ?? [])
        : (context.grant?.streams.flatMap((s) => s.instance_ids) ?? []);

    const streams = deps.store.listStreams(instanceIds);

    // A client token gets a closed projection: only the streams its grant
    // names, and counts/recency computed over only the records the grant
    // actually exposes. The store's raw listing counts every record in the
    // instance, so returning it unchanged would leak the existence and
    // recency of records outside the grant's time_constraint / resources.
    const visibleStreams =
      context.tokenKind === "owner"
        ? streams.map((s) => ({
            name: s.stream,
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
                ...summarizeGrantVisible(
                  deps.store,
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

    try {
      rejectUnknownParams(c, "streamMetadata");
      const stream = c.req.param("stream");
      const declaration =
        context!.tokenKind === "client"
          ? deps.declarations.get(stream, context!.grant?.source.id)
          : deps.declarations.get(stream);
      if (
        !declaration &&
        context!.tokenKind === "owner" &&
        deps.declarations.declares(stream)
      ) {
        // An owner token spans every owned instance, and more than one
        // source declares this name with its own key and schema. There is
        // no single honest answer until owner reads can name an instance.
        throw new PdppError(
          "invalid_request",
          `Stream '${stream}' is declared by more than one source`,
        );
      }
      const scope = resolveReadScope(context!, stream, declaration);

      if (context!.tokenKind === "owner") {
        return c.json(
          {
            object: "stream_metadata",
            name: declaration!.name,
            primary_key: declaration!.primaryKey,
            cursor_field: declaration!.cursorField,
            consent_time_field: declaration!.consentTimeField ?? null,
            query: {},
            views: [],
            relationships: [],
            // §8 owner metadata carries the full declared schema and
            // selection capability. Omitting them made this a public response
            // contract mismatch that access-behavior fixtures could not see.
            schema: declaration!.schema ?? null,
            selection: declaration!.selection ?? null,
          },
          200,
          { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
        );
      }

      return c.json(
        {
          object: "stream_metadata",
          name: declaration!.name,
          primary_key: declaration!.primaryKey,
          cursor_field: declaration!.cursorField,
          consent_time_field: declaration!.consentTimeField ?? null,
          query: {},
          views: [],
          relationships: [],
          // Grant-closed: the declared schema projected to exactly the
          // granted fields, so a client token learns record shape without
          // learning the existence of fields it was not granted. Falls back
          // to bare field names when the retained declaration carries no
          // schema, rather than fabricating one.
          schema: projectSchemaToFields(declaration!.schema, scope.fields),
          // The frozen selection capability the grant was resolved against.
          selection: declaration!.selection ?? null,
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

    try {
      rejectUnknownParams(c, "listRecords", context!.tokenKind);
      const stream = c.req.param("stream");

      const { declaration, ownerInstanceIds } = readDeclaration(
        context!,
        stream,
      );
      const scope = resolveReadScope(context!, stream, declaration);
      const effectiveInstanceIds =
        context!.tokenKind === "owner" ? ownerInstanceIds : scope.instanceIds;

      const { limit, clamped } = parseLimit(c.req.query("limit"));
      const order = parseOrder(c.req.query("order"));
      const requestedFields = c.req
        .query("fields")
        ?.split(",")
        .map((f) => f.trim());
      // §8: `fields` is a sparse fieldset on the durable client surface, and
      // an unsupported shape must not be silently ignored. A client token
      // previously had its `fields` parsed and then discarded, so
      // `?fields=id` returned every granted field — the response did
      // something other than what was asked, with a 200.
      //
      // A client may only NARROW within its grant; it can never widen. So the
      // request is validated against the granted set, then intersected with
      // it, then the schema-required floor is re-added.
      const fields =
        context!.tokenKind === "client"
          ? narrowClientFields(
              requestedFields,
              scope.fields,
              declaration,
              scope.schemaRequiredFloor,
            )
          : requestedFields
            ? [...requestedFields]
            : undefined;
      const cursor = c.req.query("cursor");

      if (c.req.query("changes_since") !== undefined) {
        // `fields` is passed here for ELIGIBILITY narrowing only (spec §4:
        // a record whose only change was to an unauthorized field must not
        // appear as "changed" at all). The store returns each row's RAW,
        // unprojected data regardless of `fields` — response-shaping
        // projection happens only at toRecordJson below, after
        // recordWithinGrantTimeConstraint has already run against the real
        // field value. This split matters: if the store projected the
        // returned data too, a grant whose fields exclude the
        // time_constraint field would silently break that filter.
        const page = deps.store.changesSince(stream, {
          instanceIds: effectiveInstanceIds,
          changesSince: c.req.query("changes_since"),
          cursor: c.req.query("cursor"),
          limit,
          fields,
        });
        const visible = page.data.filter((row) => {
          if (row.deleted) {
            return recordKeyWithinGrantResources(
              row.recordKey,
              scope.streamGrant,
            );
          }
          return (
            recordKeyWithinGrantResources(row.recordKey, scope.streamGrant) &&
            recordWithinGrantTimeConstraint(row.data, scope.streamGrant)
          );
        });
        const meta = clamped
          ? {
              warnings: [
                { code: "limit_clamped", message: "limit clamped to 100" },
              ],
            }
          : {};
        return c.json(
          {
            object: "list",
            has_more: page.hasMore,
            ...(page.nextCursor && { next_cursor: page.nextCursor }),
            ...(page.nextChangesSince && {
              next_changes_since: page.nextChangesSince,
            }),
            data: visible.map((row) => toRecordJson(stream, row, fields)),
            ...(clamped && { meta }),
          },
          200,
          { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
        );
      }

      // Same ordering requirement as the changes_since branch above: fetch
      // unprojected, filter by time_constraint against the real value, then
      // project fields only in toRecordJson.
      // Grant filtering happens after the store pages, so a page of `limit`
      // stored rows can yield fewer than `limit` visible rows. Returning that
      // short page directly would make `limit` mean "at most N stored rows"
      // rather than "at most N records you may see", and would report
      // has_more/next_cursor for a position in the unfiltered sequence.
      // Accumulate visible rows across store pages instead, then derive
      // paging state from the filtered view.
      const visible: PdppRecordRow[] = [];
      let pageCursor = cursor;
      let storeHasMore = false;
      let horizon: string | undefined;
      do {
        const page = deps.store.listRecords(stream, {
          instanceIds: effectiveInstanceIds,
          // One extra, so a page that is entirely filtered out still makes
          // progress rather than stalling on the same cursor.
          limit: limit + 1,
          order,
          cursor: pageCursor,
        });
        for (const row of page.data) {
          if (
            recordKeyWithinGrantResources(row.recordKey, scope.streamGrant) &&
            recordWithinGrantTimeConstraint(row.data, scope.streamGrant)
          ) {
            visible.push(row);
          }
          if (visible.length > limit) break;
        }
        horizon ??= page.horizon;
        pageCursor = page.nextCursor ?? undefined;
        storeHasMore = page.hasMore;
      } while (visible.length <= limit && storeHasMore && pageCursor);

      // limit + 1 visible rows means at least one more record the caller may
      // see; trim it and report has_more from the filtered view.
      const moreVisible = visible.length > limit;
      const data = moreVisible ? visible.slice(0, limit) : visible;
      const last = data[data.length - 1];
      const meta = clamped
        ? {
            warnings: [
              { code: "limit_clamped", message: "limit clamped to 100" },
            ],
          }
        : undefined;
      const response = c.json(
        {
          object: "list",
          has_more: moreVisible,
          ...(moreVisible &&
            last && {
              next_cursor: encodeCursor({
                kind: "list",
                order,
                // Must match the store's own sort key exactly or the cursor
                // resumes at the wrong position. Both backends sort by
                // (emitted_at, record_key).
                sortValue: last.emittedAt,
                recordKey: last.recordKey,
                // Carry the store's reset fence (P10c) to the next page.
                ...(horizon !== undefined && { horizon }),
              }),
            }),
          data: data.map((row) => toRecordJson(stream, row, fields)),
          ...(meta && { meta }),
        },
        200,
        { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
      );
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

    try {
      rejectUnknownParams(c, "getRecord", context!.tokenKind);
      // §8 requires client-token `expand[]` to be REJECTED before the
      // declaration is consulted, on single-record reads as well as lists.
      // Silently ignoring it told a client its request was honored when a
      // narrower thing happened instead.
      const stream = c.req.param("stream");
      const recordKey = decodeURIComponent(c.req.param("id"));
      const { declaration, ownerInstanceIds } = readDeclaration(
        context!,
        stream,
      );
      const scope = resolveReadScope(context!, stream, declaration);

      const effectiveInstanceIds =
        context!.tokenKind === "owner" ? ownerInstanceIds : scope.instanceIds;

      if (!recordKeyWithinGrantResources(recordKey, scope.streamGrant)) {
        throw new PdppError("not_found", "Record not found");
      }

      let found;
      for (const instance of effectiveInstanceIds) {
        const record = deps.store.getRecord(instance, stream, recordKey);
        if (record) {
          found = record;
          break;
        }
      }
      if (
        !found ||
        !recordWithinGrantTimeConstraint(found.data, scope.streamGrant)
      ) {
        throw new PdppError("not_found", "Record not found");
      }

      // `fields` is a declared parameter of this endpoint, and `v0.2-4-2`
      // builds disclosed `data` from the grant AND the request-time
      // selection. It was parsed nowhere, so `?fields=date` returned every
      // granted field with a 200 — the response did something other than what
      // was asked, and a client narrowing its own exposure did not get it.
      const requestedFields = c.req
        .query("fields")
        ?.split(",")
        .map((f) => f.trim());
      const fields =
        context!.tokenKind === "client"
          ? narrowClientFields(
              requestedFields,
              scope.fields,
              declaration,
              scope.schemaRequiredFloor,
            )
          : (requestedFields ?? scope.fields);

      const data = projectFields(found.data, fields);

      const response = c.json(
        {
          object: "record",
          id: recordKey,
          stream,
          data,
          emitted_at: found.emittedAt,
        },
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

    try {
      rejectUnknownParams(c, "deleteRecord");
      if (context!.tokenKind !== "owner") {
        throw new PdppError(
          "authentication_error",
          "Delete requires an owner token",
        );
      }
      const stream = c.req.param("stream");
      const recordKey = decodeURIComponent(c.req.param("id"));
      if (!deps.declarations.declares(stream)) {
        throw new PdppError("not_found", "Stream not found");
      }

      const effectiveInstanceIds =
        deps.instancesForSubject?.(requireSubjectId(context!)) ?? [];
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
      const ownedInstances =
        deps.instancesForSubject?.(context!.subjectId) ?? [];
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
        !deps.instancesForSubject?.(context!.subjectId).length
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
        (!instance ||
          !deps.instancesForSubject?.(context!.subjectId).includes(instance))
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
 * Applies the grant's field projection to a record's data for the response
 * body. Callers MUST filter by time_constraint against the record's
 * unprojected data BEFORE calling this — projecting first would strip the
 * time_constraint field before it can be compared, silently breaking the
 * filter for any grant whose fields don't happen to include that field.
 */
function projectFields(
  data: Record<string, unknown>,
  fields: string[] | undefined,
): Record<string, unknown> {
  if (!fields) return data;
  const projected: Record<string, unknown> = {};
  for (const field of fields) {
    if (field in data) projected[field] = data[field];
  }
  return projected;
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
  store: PdppRecordStore,
  stream: string,
  instanceIds: string[],
  streamGrant: StreamGrant | undefined,
): GrantVisibleSummary {
  // `listRecords` already excludes tombstones, so a deleted row should not
  // appear here; the guard keeps the narrowing honest rather than asserting.
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
      limit: MAX_LIMIT,
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
      limit: MAX_LIMIT,
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

function toRecordJson(
  stream: string,
  row: PdppRecordRow,
  fields: string[] | undefined,
) {
  if (row.deleted) {
    return {
      object: "record",
      id: row.recordKey,
      stream,
      deleted: true,
      deleted_at: row.deletedAt,
      emitted_at: row.emittedAt,
    };
  }
  return {
    object: "record",
    id: row.recordKey,
    stream,
    data: projectFields(row.data, fields),
    emitted_at: row.emittedAt,
  };
}
