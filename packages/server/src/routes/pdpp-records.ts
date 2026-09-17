import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  CursorExpiredError,
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
        ? (deps.instancesForSubject?.(context.subjectId) ?? [])
        : (context.grant?.streams.flatMap((s) => s.instance_ids) ?? []);

    const streams = deps.store.listStreams(instanceIds);
    return c.json(
      {
        object: "list",
        data: streams.map((s) => ({
          object: "stream",
          name: s.stream,
          record_count: s.recordCount,
          last_updated: s.lastUpdated,
        })),
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
          ? (deps.instancesForSubject?.(context!.subjectId) ?? [])
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
            data: visible.map((row) => toRecordJson(stream, row)),
            ...(clamped && { meta }),
          },
          200,
          { "Request-Id": reqId, "PDPP-Version": PDPP_VERSION },
        );
      }

      const page = deps.store.listRecords(stream, {
        instanceIds: effectiveInstanceIds,
        limit,
        order,
        cursor,
        fields,
      });
      const visible = page.data.filter(
        (row) =>
          recordKeyWithinGrantResources(row.recordKey, scope.streamGrant) &&
          recordWithinGrantTimeConstraint(row.data, scope.streamGrant),
      );
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
          has_more: page.hasMore,
          ...(page.nextCursor && { next_cursor: page.nextCursor }),
          data: visible.map((row) => toRecordJson(stream, row)),
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
          ? (deps.instancesForSubject?.(context!.subjectId) ?? [])
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

      const data =
        scope.fields !== undefined
          ? Object.fromEntries(
              Object.entries(found.data).filter(([k]) =>
                scope.fields!.includes(k),
              ),
            )
          : found.data;

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
        deps.instancesForSubject?.(context!.subjectId) ?? [];
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

function toRecordJson(stream: string, row: PdppRecordRow) {
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
    data: row.data,
    emitted_at: row.emittedAt,
  };
}
