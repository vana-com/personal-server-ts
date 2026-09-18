import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
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
  type PdppRecordRow,
  type PdppRecordStore,
  type StreamDeclaration,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

export interface PdppRecordsRouteDeps {
  store: PdppRecordStore;
  auth: PdppAuthorizationService;
  declarations: StreamDeclarationRegistry;
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
}

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
  throw err;
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

const CLIENT_REJECTED_PARAMS = ["filter", "view", "expand", "expand_limit"];

/**
 * Query parameters each endpoint implements in v0.1.
 *
 * Spec-core.md §8: "Unknown parameters return 400". Silently ignoring one is
 * worse than it looks -- a client that misspells `limit` as `limt`, or sends a
 * parameter a later version defines, gets a 200 that quietly did something
 * other than what was asked. Accepting an unknown constraint is
 * indistinguishable from applying it.
 *
 * `filter`/`view`/`expand`/`expand_limit` are deliberately absent here and
 * handled separately: they are KNOWN parameters that owner tokens may use and
 * client tokens may not, so they earn a more specific message than "unknown".
 */
const KNOWN_QUERY_PARAMS: Record<string, readonly string[]> = {
  listStreams: [],
  streamMetadata: [],
  listRecords: ["limit", "order", "cursor", "fields", "changes_since"],
  getRecord: ["fields"],
  deleteRecord: [],
};

/**
 * Rejects any query parameter this endpoint does not implement.
 *
 * Bracketed forms (`filter[x]`) count as the base name so the client-token
 * rejection above can give its more specific error rather than this one.
 */
function rejectUnknownParams(
  c: Context,
  endpoint: keyof typeof KNOWN_QUERY_PARAMS,
) {
  const allowed = KNOWN_QUERY_PARAMS[endpoint];
  const url = new URL(c.req.url);
  for (const key of url.searchParams.keys()) {
    const base = key.replace(/\[.*$/, "");
    if (allowed.includes(base)) continue;
    if (CLIENT_REJECTED_PARAMS.includes(base)) continue;
    throw new PdppError("invalid_request", `Unknown query parameter '${key}'`, {
      param: key,
    });
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
 *   - the declaration's required fields are re-added, because §8 keeps
 *     schema-required fields in every projection regardless of the request.
 *
 * Returns the full granted set when no `fields` was requested, preserving the
 * existing default.
 */
function narrowClientFields(
  requested: string[] | undefined,
  granted: string[] | undefined,
  declaration: StreamDeclaration | undefined,
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
  // The consent floor survives a sparse request.
  for (const required of declaration?.requiredFields ?? []) {
    if (grantedSet.has(required)) narrowed.add(required);
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

function rejectClientOnlyParams(c: Context) {
  const url = new URL(c.req.url);
  for (const key of url.searchParams.keys()) {
    if (
      CLIENT_REJECTED_PARAMS.some((p) => key === p || key.startsWith(`${p}[`))
    ) {
      throw new PdppError(
        "invalid_request",
        `Client tokens may not use '${key}' in v0.1`,
        { param: key },
      );
    }
  }
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

  app.get("/streams", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;
    try {
      rejectUnknownParams(c, "listStreams");
    } catch (err) {
      return sendError(c, toPdppError(err), reqId);
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
      const declaration = deps.declarations.get(stream);
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
      return sendError(c, toPdppError(err), reqId);
    }
  });

  app.get("/streams/:stream/records", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;

    try {
      rejectUnknownParams(c, "listRecords");
      const stream = c.req.param("stream");
      if (context!.tokenKind === "client") rejectClientOnlyParams(c);

      const declaration = deps.declarations.get(stream);
      const scope = resolveReadScope(context!, stream, declaration);
      const effectiveInstanceIds =
        context!.tokenKind === "owner"
          ? (deps.instancesForSubject?.(requireSubjectId(context!)) ?? [])
          : scope.instanceIds;

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
          ? narrowClientFields(requestedFields, scope.fields, declaration)
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
      const mapped = toPdppError(err);
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
      rejectUnknownParams(c, "getRecord");
      // §8 requires client-token `expand[]` to be REJECTED before the
      // declaration is consulted, on single-record reads as well as lists.
      // Silently ignoring it told a client its request was honored when a
      // narrower thing happened instead.
      if (context!.tokenKind === "client") rejectClientOnlyParams(c);
      const stream = c.req.param("stream");
      const recordKey = decodeURIComponent(c.req.param("id"));
      const declaration = deps.declarations.get(stream);
      const scope = resolveReadScope(context!, stream, declaration);

      const effectiveInstanceIds =
        context!.tokenKind === "owner"
          ? (deps.instancesForSubject?.(requireSubjectId(context!)) ?? [])
          : scope.instanceIds;

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

      const data = projectFields(found.data, scope.fields);

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
      const mapped = toPdppError(err);
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
      const declaration = deps.declarations.get(stream);
      if (!declaration) throw new PdppError("not_found", "Stream not found");

      const effectiveInstanceIds =
        deps.instancesForSubject?.(requireSubjectId(context!)) ?? [];
      let deletedAny = false;
      for (const instance of effectiveInstanceIds) {
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
      return sendError(c, toPdppError(err), reqId);
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
      if (context!.tokenKind !== "owner") {
        throw new PdppError(
          "authentication_error",
          "Ingest requires an owner token",
        );
      }
      const stream = c.req.param("stream");
      const declaration = deps.declarations.get(stream);
      if (!declaration) throw new PdppError("not_found", "Stream not found");

      const body = await c.req.json();
      const envelopes = (Array.isArray(body) ? body : [body]).map((e) => ({
        instance: e.instance,
        stream,
        key: e.key,
        data: e.data ?? null,
        emitted_at: e.emitted_at,
        op: e.op,
      }));

      const result = deps.store.ingestBatch(
        envelopes,
        () => declaration.semantics,
        () => declaration.primaryKey,
      );

      return c.json(
        { accepted: result.accepted, rejected: result.rejected },
        200,
        { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
      );
    } catch (err) {
      return sendError(c, toPdppError(err), reqId);
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
