import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import type {
  PdppAuthorizationService,
  PdppTokenContext,
  StreamGrant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  CursorExpiredError,
  encodeCursor,
  InvalidCursorError,
  recordKeyWithinGrantResources,
  recordWithinGrantTimeConstraint,
  resolveReadScope,
  type PdppRecordRow,
  type PdppRecordStore,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

const PDPP_VERSION = "2026-04-06";
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
  if (err instanceof InvalidCursorError) {
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
  return c.json(err.toJSON(reqId), err.status as never, {
    "Request-Id": reqId,
    "PDPP-Version": PDPP_VERSION,
  });
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
  const resourceMetadataUrl = "/.well-known/oauth-protected-resource";

  app.use("*", async (c, next) => {
    const reqId = requestId();
    c.set("reqId" as never, reqId as never);
    await next();
  });

  async function authenticate(c: Context, reqId: string) {
    const header = c.req.header("Authorization");
    const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      return { error: unauthorized(c, reqId, resourceMetadataUrl) };
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
    if (!context?.active)
      return sendError(
        c,
        new PdppError("authentication_error", "Invalid token"),
        reqId,
      );

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
            countCapped: false,
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
      .filter((s) => s.countCapped)
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
                message: `record_count is null for ${cappedStreams.join(", ")}: more than ${STREAM_COUNT_CAP} records match the grant`,
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
          schema: {
            properties: Object.fromEntries(
              (scope.fields ?? []).map((f) => [f, {}]),
            ),
          },
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
      const fields =
        context!.tokenKind === "client"
          ? scope.fields
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
      return c.json(
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
    } catch (err) {
      return sendError(c, toPdppError(err), reqId);
    }
  });

  app.get("/streams/:stream/records/:id", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;

    try {
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

      return c.json(
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
    } catch (err) {
      return sendError(c, toPdppError(err), reqId);
    }
  });

  app.delete("/streams/:stream/records/:id", async (c) => {
    const reqId = requestId();
    const { context, error } = await authenticate(c, reqId);
    if (error) return error;

    try {
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

interface GrantVisibleSummary {
  /** Exact count, or null when more than `STREAM_COUNT_CAP` records match. */
  recordCount: number | null;
  lastUpdated: string | null;
  countCapped: boolean;
}

/**
 * Summarize the records a grant exposes in one stream, for a client-token
 * stream listing.
 *
 * `last_updated` is answered by scanning newest-first and stopping at the
 * first grant-visible row, so the common case is a single store page rather
 * than a walk of the whole stream. The count then walks only until the cap.
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
  let pages = 0;
  outer: while (pages++ < STREAM_COUNT_CAP) {
    const page = store.listRecords(stream, {
      instanceIds,
      limit: MAX_LIMIT,
      order: "desc",
      cursor,
    });
    for (const row of page.data) {
      if (visible(row)) {
        lastUpdated = row.emittedAt;
        break outer;
      }
    }
    if (!page.hasMore || !page.nextCursor) break;
    cursor = page.nextCursor;
  }

  // Count forward, stopping at the cap rather than scanning without bound.
  let count = 0;
  let capped = false;
  cursor = undefined;
  for (;;) {
    const page = store.listRecords(stream, {
      instanceIds,
      limit: MAX_LIMIT,
      order: "asc",
      cursor,
    });
    for (const row of page.data) {
      if (visible(row)) count++;
      if (count > STREAM_COUNT_CAP) {
        capped = true;
        break;
      }
    }
    if (capped || !page.hasMore || !page.nextCursor) break;
    cursor = page.nextCursor;
  }

  return {
    recordCount: capped ? null : count,
    lastUpdated,
    countCapped: capped,
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
